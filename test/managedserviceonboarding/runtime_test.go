package managedserviceonboarding

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	adapterv1 "github.com/xiak/matrix/api/adapter/managedservice/v1"
	managedv1 "github.com/xiak/matrix/api/managedservice/v1"
	compose "github.com/xiak/matrix/app/adapter/apphosting/compose"
	localcontainer "github.com/xiak/matrix/app/adapter/managedservice/localcontainer"
	localelasticsearch "github.com/xiak/matrix/app/adapter/managedservice/localelasticsearch"
)

type sampleReport struct {
	Kind        string            `json:"kind"`
	Version     string            `json:"version"`
	StartedAt   time.Time         `json:"startedAt"`
	CompletedAt time.Time         `json:"completedAt"`
	Status      string            `json:"status"`
	Artifacts   map[string]string `json:"artifacts"`
	Checks      []string          `json:"passedChecks"`
	Publication string            `json:"platformAndReleaseGates"`
}

// TestElasticRuntime is opt-in so ordinary unit tests never start Docker.
// When requested, absent inputs/images are failures, never skips or downloads.
func TestElasticRuntime(t *testing.T) {
	if os.Getenv("MATRIX_ONBOARDING_RUNTIME") != "1" {
		t.Skip("set MATRIX_ONBOARDING_RUNTIME=1 for the real product-team gate")
	}
	if runtime.GOOS != "linux" {
		t.Fatal("real onboarding requires a Linux process on the Docker host")
	}
	base := os.Getenv("MATRIX_ONBOARDING_ROOT")
	if !filepath.IsAbs(base) || filepath.Clean(base) != base || filepath.Dir(base) == base {
		t.Fatal("MATRIX_ONBOARDING_ROOT must be an absolute task directory visible at the same path to Docker")
	}
	info, err := os.Lstat(base)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		t.Fatal("onboarding task directory is unavailable")
	}
	report := sampleReport{Kind: "MatrixProductOnboardingEvidence", Version: Version, StartedAt: time.Now().UTC(),
		Status: "FAILED", Publication: "NOT_RUN: no catalog, IAM, browser or signed-release acceptance"}
	report.Artifacts, err = ArtifactReferences()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		report.CompletedAt = time.Now().UTC()
		if !t.Failed() {
			report.Status = "INCOMPLETE"
			if len(report.Checks) == 10 {
				report.Status = "PASSED"
			}
		}
		encoded, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			t.Error("cannot encode non-secret acceptance report")
			return
		}
		if path := os.Getenv("MATRIX_ONBOARDING_REPORT"); path != "" {
			if err := os.WriteFile(path, append(encoded, '\n'), 0o600); err != nil {
				t.Error("cannot write acceptance report")
			}
		}
		t.Logf("product-team sample: %s; %d checks; platform publication remains NOT_RUN", report.Status, len(report.Checks))
	})
	imageIDs := make(map[string]string)
	for product, reference := range report.Artifacts {
		if !strings.HasPrefix(reference, "docker.elastic.co/"+product+"/"+product+"@sha256:") {
			t.Fatal("fixture image must be digest pinned")
		}
		var image struct {
			ID           string `json:"Id"`
			Architecture string `json:"Architecture"`
		}
		value := dockerOutput(t, "image", "inspect", "--format", "{{json .}}", reference)
		if json.Unmarshal([]byte(value), &image) != nil || !strings.HasPrefix(image.ID, "sha256:") || image.Architecture != "amd64" {
			t.Fatal("fixed linux/amd64 fixture image is unavailable")
		}
		imageIDs[product] = image.ID
	}
	root, err := os.MkdirTemp(base, "matrix-onboarding-")
	if err != nil {
		t.Fatal("cannot allocate onboarding run")
	}
	runID := filepath.Base(root)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	// Preserve failure evidence if an exact provider cleanup cannot be proved.
	clean := true
	t.Cleanup(func() {
		if clean && filepath.Dir(root) == base && strings.HasPrefix(filepath.Base(root), "matrix-onboarding-") {
			if err := os.RemoveAll(root); err != nil {
				t.Error("cannot remove owned acceptance files")
			}
		}
	})
	t.Run("Logstash", func(t *testing.T) { verifyLogstash(t, ctx, root, imageIDs["logstash"], &clean, &report) })
	t.Run("Kibana", func(t *testing.T) { verifyKibana(t, ctx, root, runID, imageIDs, &clean, &report) })
}

func verifyLogstash(t *testing.T, ctx context.Context, root, imageID string, clean *bool, report *sampleReport) {
	r := &lostResponseRuntime{LocalRuntime: compose.NewLocalRuntime(), loseNextApply: true}
	config := InstallationConfig{Root: filepath.Join(root, "managed-logstash"), ImageID: imageID, Runtime: r, Request: requestFor("logstash")}
	config.Request.TenantID = filepath.Base(root)
	provider, err := NewLogstash(config)
	if err != nil {
		t.Fatal(err)
	}
	registerCleanup(t, provider, config.Request, clean)
	if err := provider.Ready(ctx); err != nil {
		t.Fatal(err)
	}
	before := inventory(t, root)
	if _, err := provider.Ensure(ctx, config.Request); err == nil || !r.lost {
		t.Fatal("lost-response injection did not observe a real completed effect")
	}
	provider, err = NewLogstash(config)
	if err != nil {
		t.Fatal(err)
	}
	result, err := provider.Ensure(ctx, config.Request)
	if err != nil {
		observed, _ := r.Observe(ctx, projectFor(config))
		for _, container := range observed {
			t.Logf("Logstash readiness: state=%s health=%s publishedPorts=%d", container.State, container.Health, container.PublishedPorts)
		}
		t.Fatal(err)
	}
	project := projectFor(config)
	container := ownedContainer(t, ctx, r, project, config.Request)
	var engine struct {
		Version string `json:"version"`
	}
	engineContent := dockerOutput(t, "exec", container.ID, "curl", "--silent", "--fail", "http://127.0.0.1:9600/")
	if json.Unmarshal([]byte(engineContent), &engine) != nil || engine.Version != Version {
		t.Fatal("Logstash runtime version differs from its contract")
	}
	if inventory(t, root) == before {
		t.Fatal("new product is missing from recovery inventory")
	}
	secretPath := filepath.Join(project.Directory, "logstash-secret")
	secret := readSecret(t, secretPath)
	defer clear(secret)
	checkNoManifestSecret(t, project, secret)
	status, _ := callHTTP(t, http.MethodPost, result.Endpoint, "", nil, map[string]string{"message": "unauthorized"})
	if status != http.StatusUnauthorized {
		t.Fatal("Logstash input accepted an unauthenticated request")
	}
	status, _ = callHTTP(t, http.MethodPost, result.Endpoint, "matrix", secret, map[string]string{"message": "matrix-onboarding-retained"})
	if status != http.StatusOK {
		t.Fatalf("Logstash protocol write status=%d", status)
	}
	dataPath := filepath.Join(project.Directory, "data", "events.jsonl")
	await(t, ctx, "Logstash durable output", func() bool {
		content, _ := os.ReadFile(dataPath)
		if bytes.Contains(content, secret) || bytes.Contains(content, []byte(base64.StdEncoding.EncodeToString(append([]byte("matrix:"), secret...)))) {
			t.Fatal("input authentication leaked into event output")
		}
		for _, line := range bytes.Split(content, []byte{'\n'}) {
			var event map[string]any
			if json.Unmarshal(line, &event) == nil && event["message"] == "matrix-onboarding-retained" && event["matrix_profile"] == "http-json-file-v1" {
				return true
			}
		}
		return false
	})
	priorData, err := os.ReadFile(dataPath)
	if err != nil {
		t.Fatal("cannot inspect durable test output")
	}
	dockerOutput(t, "restart", "--time", "10", container.ID)
	awaitHealthy(t, ctx, r, project)
	provider, err = NewLogstash(config)
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := provider.Ensure(ctx, config.Request)
	if err != nil || replayed != result || ownedContainer(t, ctx, r, project, config.Request).ID != container.ID {
		t.Fatal("restart/replay changed Logstash identity")
	}
	currentData, _ := os.ReadFile(dataPath)
	if !bytes.Equal(priorData, currentData) || !bytes.Equal(secret, readSecret(t, secretPath)) {
		t.Fatal("restart changed Logstash data or credential")
	}
	bad := deletionFor(config.Request)
	bad.TenantID = "other-account"
	if err := provider.Delete(ctx, bad); err == nil {
		t.Fatal("accepted cross-tenant deletion")
	}
	_ = ownedContainer(t, ctx, r, project, config.Request)
	deleteAndProve(t, ctx, provider, config.Request, project, r)
	if inventory(t, root) != before {
		t.Fatal("deleted Logstash remains in recovery inventory")
	}
	report.Checks = append(report.Checks, "logstash/lost-response-recovery", "logstash/authenticated-input-and-durable-output",
		"logstash/restart-and-equal-replay", "logstash/tenant-isolation-and-exact-delete", "logstash/recovery-inventory-and-secret-custody")
}

func verifyKibana(t *testing.T, ctx context.Context, root, runID string, imageIDs map[string]string, clean *bool, report *sampleReport) {
	r := compose.NewLocalRuntime()
	esRequest := adapterv1.ProvisionRequest{TenantID: runID, InstallationID: "dependency-es", OperationID: "operation-es",
		OfferingID: managedv1.ElasticsearchOfferingID, EngineVersion: Version, RegionID: "local-primary",
		QuotaShape: managedv1.QuotaShape{ID: "elasticsearch-small", DisplayName: "开发型", CPUMillicores: 1000, MemoryMiB: 1536, StorageGiB: 10}}
	esRoot := filepath.Join(root, "managed-elasticsearch")
	es, err := localelasticsearch.New(localelasticsearch.Config{Root: esRoot, ImageID: imageIDs["elasticsearch"], Runtime: r})
	if err != nil {
		t.Fatal(err)
	}
	network := runID
	dockerOutput(t, "network", "create", "--internal", "--label", "com.xiak.matrix.onboarding="+runID, network)
	t.Cleanup(func() {
		cleanupContext, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		var observed struct {
			Labels     map[string]string
			Containers map[string]json.RawMessage
		}
		value, err := exec.CommandContext(cleanupContext, "docker", "network", "inspect", "--format", "{{json .}}", network).Output()
		if err != nil || json.Unmarshal(value, &observed) != nil || observed.Labels["com.xiak.matrix.onboarding"] != runID || len(observed.Containers) != 0 {
			*clean = false
			t.Error("test network cleanup lacks ownership or empty-endpoint proof")
			return
		}
		if err := exec.CommandContext(cleanupContext, "docker", "network", "rm", network).Run(); err != nil {
			*clean = false
			t.Error("exact test network cleanup failed; owned evidence preserved")
		}
	})
	registerCleanup(t, es, esRequest, clean)
	if err := es.Ready(ctx); err != nil {
		t.Fatal(err)
	}
	esResult, err := es.Ensure(ctx, esRequest)
	if err != nil {
		t.Fatal(err)
	}
	esProject := projectFor(InstallationConfig{Root: esRoot, Request: esRequest})
	esContainer := ownedContainer(t, ctx, r, esProject, esRequest)
	dockerOutput(t, "network", "connect", "--alias", "elasticsearch", network, esContainer.ID)
	esPassword := readSecret(t, filepath.Join(esProject.Directory, "elasticsearch-password"))
	defer clear(esPassword)
	password := make([]byte, 32)
	if _, err := rand.Read(password); err != nil {
		t.Fatal("cannot prepare fixture credential")
	}
	credential := []byte(hex.EncodeToString(password))
	clear(password)
	defer clear(credential)
	credentialPath := filepath.Join(root, "kibana-dependency-password")
	if err := os.WriteFile(credentialPath, credential, 0o600); err != nil {
		t.Fatal("cannot protect fixture credential")
	}
	status, _ := callHTTP(t, http.MethodPost, esResult.Endpoint+"/_security/user/kibana_system/_password", "elastic", esPassword, map[string]string{"password": string(credential)})
	if status != http.StatusOK {
		t.Fatalf("prepare Kibana service identity status=%d", status)
	}
	index := runID
	status, _ = callHTTP(t, http.MethodPut, esResult.Endpoint+"/"+index+"/_doc/one?refresh=true", "elastic", esPassword, map[string]string{"message": "retained-dependency-data"})
	if status != http.StatusCreated {
		t.Fatalf("dependency protocol write status=%d", status)
	}
	config := InstallationConfig{Root: filepath.Join(root, "managed-kibana"), ImageID: imageIDs["kibana"], Runtime: r, Request: requestFor("kibana")}
	config.Request.TenantID = runID
	dependency := ElasticsearchDependency{TenantID: config.Request.TenantID, InstallationID: esRequest.InstallationID,
		EngineVersion: Version, Revision: 1, Network: network, Endpoint: "http://elasticsearch:9200", PasswordFile: credentialPath}
	provider, err := NewKibana(config, dependency)
	if err != nil {
		t.Fatal(err)
	}
	registerCleanup(t, provider, config.Request, clean)
	if err := provider.Ready(ctx); err != nil {
		t.Fatal(err)
	}
	before := inventory(t, root)
	result, err := provider.Ensure(ctx, config.Request)
	if err != nil {
		observed, _ := r.Observe(ctx, projectFor(config))
		for _, container := range observed {
			t.Logf("Kibana readiness: state=%s health=%s publishedPorts=%d", container.State, container.Health, container.PublishedPorts)
		}
		t.Fatal(err)
	}
	project := projectFor(config)
	container := ownedContainer(t, ctx, r, project, config.Request)
	checkNoManifestSecret(t, project, credential)
	status, content := callHTTP(t, http.MethodGet, result.Endpoint+"/api/status?v8format=true", "elastic", esPassword, nil)
	var health struct {
		Version struct{ Number string }
		Status  struct{ Overall struct{ Level string } }
	}
	// The anonymous status mode can redact version even with an Authorization
	// header. Check the running instance's own package as well as API readiness.
	var runningPackage struct {
		Version string `json:"version"`
	}
	packageContent := dockerOutput(t, "exec", container.ID, "cat", "/usr/share/kibana/package.json")
	if json.Unmarshal([]byte(packageContent), &runningPackage) != nil {
		t.Fatal("cannot verify running Kibana package")
	}
	if status != http.StatusOK || json.Unmarshal(content, &health) != nil || runningPackage.Version != Version ||
		(health.Version.Number != "" && health.Version.Number != Version) || health.Status.Overall.Level != "available" {
		t.Fatalf("Kibana is not the expected available product; status=%d level=%s version=%s", status, health.Status.Overall.Level, runningPackage.Version)
	}
	dataViewRequest := map[string]any{"data_view": map[string]any{"title": index, "name": "Matrix onboarding"}}
	status, _ = callHTTP(t, http.MethodPost, result.Endpoint+"/api/data_views/data_view", "", nil, dataViewRequest)
	if status != http.StatusUnauthorized {
		t.Fatal("Kibana accepted an unauthenticated product write")
	}
	status, content = callHTTP(t, http.MethodPost, result.Endpoint+"/api/data_views/data_view", "elastic", esPassword, dataViewRequest)
	var created struct {
		DataView struct {
			ID    string `json:"id"`
			Title string `json:"title"`
		} `json:"data_view"`
	}
	if status != http.StatusOK || json.Unmarshal(content, &created) != nil || created.DataView.ID == "" || created.DataView.Title != index {
		t.Fatalf("Kibana data-view creation status=%d", status)
	}
	settings, err := os.ReadFile(filepath.Join(project.Directory, "kibana.yml"))
	if err != nil {
		t.Fatal("cannot inspect protected configuration")
	}
	settingsDigest := sha256.Sum256(settings)
	clear(settings)
	dockerOutput(t, "restart", "--time", "10", container.ID)
	awaitHealthy(t, ctx, r, project)
	provider, err = NewKibana(config, dependency)
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := provider.Ensure(ctx, config.Request)
	if err != nil || replayed != result || ownedContainer(t, ctx, r, project, config.Request).ID != container.ID {
		t.Fatal("restart/replay changed Kibana identity")
	}
	status, content = callHTTP(t, http.MethodGet, result.Endpoint+"/api/data_views/data_view/"+created.DataView.ID, "elastic", esPassword, nil)
	if status != http.StatusOK || !bytes.Contains(content, []byte(index)) {
		t.Fatal("Kibana state did not survive restart")
	}
	settings, err = os.ReadFile(filepath.Join(project.Directory, "kibana.yml"))
	if err != nil || sha256.Sum256(settings) != settingsDigest {
		t.Fatal("restart changed Kibana protected configuration")
	}
	clear(settings)
	deleteAndProve(t, ctx, provider, config.Request, project, r)
	if inventory(t, root) != before {
		t.Fatal("deleted Kibana remains in recovery inventory")
	}
	if ownedContainer(t, ctx, r, esProject, esRequest).ID != esContainer.ID {
		t.Fatal("Kibana deletion changed its dependency")
	}
	status, content = callHTTP(t, http.MethodGet, esResult.Endpoint+"/"+index+"/_doc/one", "elastic", esPassword, nil)
	if status != http.StatusOK || !bytes.Contains(content, []byte("retained-dependency-data")) {
		t.Fatal("Kibana deletion removed dependency data")
	}
	report.Checks = append(report.Checks, "kibana/version-and-readiness", "kibana/authenticated-data-view-create-and-read",
		"kibana/restart-and-equal-replay", "kibana/exact-delete-preserves-dependency", "kibana/recovery-inventory-and-secret-custody")
}

type lostResponseRuntime struct {
	*compose.LocalRuntime
	loseNextApply, hideObservation, lost bool
}

func (r *lostResponseRuntime) Apply(ctx context.Context, project compose.RuntimeProject) error {
	if err := r.LocalRuntime.Apply(ctx, project); err != nil {
		return err
	}
	if r.loseNextApply {
		r.loseNextApply = false
		r.hideObservation = true
		r.lost = true
		return compose.ErrEffectOutcomeUnknown
	}
	return nil
}
func (r *lostResponseRuntime) Observe(ctx context.Context, project compose.RuntimeProject) ([]compose.RuntimeContainer, error) {
	if r.hideObservation {
		r.hideObservation = false
		return nil, errors.New("injected observation transport failure")
	}
	return r.LocalRuntime.Observe(ctx, project)
}

func registerCleanup(t *testing.T, provider adapterv1.Provisioner, request adapterv1.ProvisionRequest, clean *bool) {
	t.Helper()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer cancel()
		if err := provider.Delete(ctx, deletionFor(request)); err != nil {
			*clean = false
			t.Error("exact provider cleanup failed; owned evidence preserved")
		}
	})
}
func projectFor(config InstallationConfig) compose.RuntimeProject {
	name := localcontainer.ProjectName(config.Request.TenantID, config.Request.InstallationID)
	directory := filepath.Join(config.Root, name)
	return compose.RuntimeProject{Name: name, Directory: directory, EffectDocument: filepath.Join(directory, "compose.json"), ObservationDocument: filepath.Join(directory, "observe.json"), TimeoutSeconds: 120}
}
func ownedContainer(t *testing.T, ctx context.Context, r compose.Runtime, project compose.RuntimeProject, request adapterv1.ProvisionRequest) compose.RuntimeContainer {
	t.Helper()
	containers, err := r.Observe(ctx, project)
	if err != nil || len(containers) != 1 {
		t.Fatal("expected one owned runtime instance")
	}
	c := containers[0]
	if c.ID == "" || c.Project != project.Name || c.Labels["com.xiak.matrix.managedservice.installation"] != request.InstallationID ||
		c.Labels["com.xiak.matrix.managedservice.offering"] != request.OfferingID || c.Labels["com.xiak.matrix.managedservice.region"] != request.RegionID {
		t.Fatal("runtime identity does not belong to the requested installation")
	}
	return c
}
func deleteAndProve(t *testing.T, ctx context.Context, provider adapterv1.Provisioner, request adapterv1.ProvisionRequest, project compose.RuntimeProject, r compose.Runtime) {
	t.Helper()
	if err := provider.Delete(ctx, deletionFor(request)); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(project.Directory); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("deleted product retains its protected files or data")
	}
	if err := provider.Delete(ctx, deletionFor(request)); err != nil {
		t.Fatal("equal delete failed")
	}
	// No observation document remains; query exact ownership labels instead.
	remaining := dockerOutput(t, "ps", "-aq", "--filter", "label=com.docker.compose.project="+project.Name)
	if remaining != "" {
		t.Fatal("deleted product retains runtime objects")
	}
}
func awaitHealthy(t *testing.T, ctx context.Context, r compose.Runtime, p compose.RuntimeProject) {
	t.Helper()
	await(t, ctx, "product restart readiness", func() bool {
		c, e := r.Observe(ctx, p)
		return e == nil && len(c) == 1 && c[0].State == "running" && c[0].Health == "healthy"
	})
}
func await(t *testing.T, ctx context.Context, what string, ready func() bool) {
	t.Helper()
	deadline := time.NewTimer(3 * time.Minute)
	defer deadline.Stop()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		if ready() {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("%s canceled", what)
		case <-deadline.C:
			t.Fatalf("%s timed out", what)
		case <-ticker.C:
		}
	}
}
func inventory(t *testing.T, root string) string {
	t.Helper()
	v, e := localcontainer.InspectRecoveryInventory(root)
	if e != nil {
		t.Fatal("cannot verify recovery inventory")
	}
	return v
}
func readSecret(t *testing.T, path string) []byte {
	t.Helper()
	v, e := readProtectedSecret(path)
	if e != nil {
		t.Fatal(e)
	}
	return v
}
func checkNoManifestSecret(t *testing.T, p compose.RuntimeProject, secret []byte) {
	t.Helper()
	b, e := os.ReadFile(p.EffectDocument)
	if e != nil || bytes.Contains(b, secret) {
		t.Fatal("secret entered deployment manifest")
	}
}
func dockerOutput(t *testing.T, args ...string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	value, err := exec.CommandContext(ctx, "docker", args...).Output()
	if err != nil {
		t.Fatalf("Docker %s failed; native output is withheld", args[0])
	}
	return strings.TrimSpace(string(value))
}
func callHTTP(t *testing.T, method, endpoint, user string, secret []byte, value any) (int, []byte) {
	t.Helper()
	var body []byte
	var err error
	if value != nil {
		body, err = json.Marshal(value)
		if err != nil {
			t.Fatal("cannot encode protocol probe")
		}
		defer clear(body)
	}
	req, err := http.NewRequest(method, endpoint, bytes.NewReader(body))
	if err != nil {
		t.Fatal("invalid protocol probe")
	}
	if user != "" {
		req.SetBasicAuth(user, string(secret))
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("kbn-xsrf", "matrix-onboarding")
	client := &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(req)
	if err != nil {
		t.Fatal("product protocol request failed")
	}
	defer response.Body.Close()
	content, err := io.ReadAll(io.LimitReader(response.Body, 2*1024*1024))
	if err != nil {
		t.Fatal("cannot read product protocol result")
	}
	return response.StatusCode, content
}
