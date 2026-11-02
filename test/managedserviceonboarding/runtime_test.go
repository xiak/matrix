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
	"net"
	"net/http"
	"net/url"
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
			if len(report.Checks) == 11 {
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
	endpointImageID := buildEndpointFixture(t, ctx, runID, &clean)
	report.Artifacts["endpoint"] = endpointImageID
	t.Run("Logstash", func(t *testing.T) {
		verifyLogstash(t, ctx, root, imageIDs["logstash"], endpointImageID, &clean, &report)
	})
	t.Run("Kibana", func(t *testing.T) { verifyKibana(t, ctx, root, runID, imageIDs, &clean, &report) })
}

func verifyLogstash(t *testing.T, ctx context.Context, root, imageID, endpointImageID string, clean *bool, report *sampleReport) {
	r := &lostResponseRuntime{LocalRuntime: compose.NewLocalRuntime(), loseNextApply: true}
	config := InstallationConfig{Root: filepath.Join(root, "managed-logstash"), ImageID: imageID, EndpointImageID: endpointImageID, Runtime: r, Request: requestFor("logstash")}
	config.Request.TenantID = filepath.Base(root)
	provider, err := newLogstash(config)
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
	provider, err = newLogstash(config)
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

	// A second tenant deliberately reuses the same public installation ID.
	peerConfig := config
	peerConfig.Request.TenantID += "-peer"
	peerConfig.Runtime = compose.NewLocalRuntime()
	peer, err := newLogstash(peerConfig)
	if err != nil {
		t.Fatal(err)
	}
	registerCleanup(t, peer, peerConfig.Request, clean)
	peerResult, err := peer.Ensure(ctx, peerConfig.Request)
	if err != nil {
		t.Fatal(err)
	}
	peerProject := projectFor(peerConfig)
	peerContainer := ownedContainer(t, ctx, peerConfig.Runtime, peerProject, peerConfig.Request)
	peerSecret := readSecret(t, filepath.Join(peerProject.Directory, "logstash-secret"))
	defer clear(peerSecret)
	if bytes.Equal(secret, peerSecret) || result.Endpoint == peerResult.Endpoint || result.CredentialReference == peerResult.CredentialReference || project.Directory == peerProject.Directory {
		t.Fatal("tenant resource or credential identity was shared")
	}
	peerDataPath := filepath.Join(peerProject.Directory, "data", "events.jsonl")
	assertLogstashWrite(t, ctx, peerResult.Endpoint, peerSecret, peerDataPath, "matrix-peer-retained")
	peerData, err := os.ReadFile(peerDataPath)
	if err != nil || bytes.Contains(peerData, []byte("matrix-onboarding-retained")) {
		t.Fatal("peer data boundary is invalid")
	}
	for _, attempt := range []struct {
		endpoint string
		password []byte
	}{{result.Endpoint, peerSecret}, {peerResult.Endpoint, secret}} {
		status, _ := callHTTP(t, http.MethodPost, attempt.endpoint, "matrix", attempt.password, map[string]string{"message": "foreign-password-must-not-write"})
		if status != http.StatusUnauthorized {
			t.Fatal("another tenant's credential was accepted")
		}
	}
	assertLogstashNetworkIsolation(t, ctx, config, result, peerConfig, peerResult)
	dockerOutput(t, "restart", "--time", "10", container.ID)
	awaitHealthy(t, ctx, r, project)
	provider, err = newLogstash(config)
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

	dockerOutput(t, "restart", "--time", "10", peerContainer.ID)
	awaitHealthy(t, ctx, peerConfig.Runtime, peerProject)
	if got, err := peer.Ensure(ctx, peerConfig.Request); err != nil || got != peerResult {
		t.Fatal("peer replay changed identity")
	}
	currentPeerData, _ := os.ReadFile(peerDataPath)
	if !bytes.Equal(peerData, currentPeerData) || !bytes.Equal(peerSecret, readSecret(t, filepath.Join(peerProject.Directory, "logstash-secret"))) {
		t.Fatal("peer restart changed data or credential")
	}
	assertLogstashNetworkIsolation(t, ctx, config, result, peerConfig, peerResult)
	peerBeforeDeletion := logstashRuntimeWitness(t, peerContainer.ID)
	bad := deletionFor(config.Request)
	bad.TenantID = "other-account"
	if err := provider.Delete(ctx, bad); err != nil {
		t.Fatal("deletion of an absent independently scoped identity did not converge")
	}
	_ = ownedContainer(t, ctx, r, project, config.Request)
	deleteAndProve(t, ctx, provider, config.Request, project, r)

	if logstashRuntimeWitness(t, peerContainer.ID) != peerBeforeDeletion {
		t.Fatal("deleting one tenant changed the other tenant's runtime")
	}
	preservedPeerData, _ := os.ReadFile(peerDataPath)
	if !bytes.Equal(peerData, preservedPeerData) || !bytes.Equal(peerSecret, readSecret(t, filepath.Join(peerProject.Directory, "logstash-secret"))) {
		t.Fatal("deleting one tenant changed the other's data or credential")
	}
	assertLogstashWrite(t, ctx, peerResult.Endpoint, peerSecret, peerDataPath, "matrix-peer-after-other-delete")
	if logstashRuntimeWitness(t, peerContainer.ID) != peerBeforeDeletion {
		t.Fatal("peer runtime was recreated while verifying continued use")
	}
	deleteAndProve(t, ctx, peer, peerConfig.Request, peerProject, peerConfig.Runtime)
	report.Checks = append(report.Checks, "logstash/two-tenant-network-data-credentials-and-independent-delete")
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
	if err != nil {
		t.Fatal("cannot observe owned product")
	}
	var product []compose.RuntimeContainer
	for _, item := range containers {
		if !strings.HasSuffix(item.Service, "-endpoint") {
			product = append(product, item)
		}
	}
	if len(product) != 1 {
		t.Fatal("expected one owned product instance")
	}
	c := product[0]
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
	if dockerOutput(t, "network", "ls", "-q", "--filter", "label=com.docker.compose.project="+project.Name) != "" {
		t.Fatal("deleted product retains an owned network")
	}
}
func awaitHealthy(t *testing.T, ctx context.Context, r compose.Runtime, p compose.RuntimeProject) {
	t.Helper()
	await(t, ctx, "product restart readiness", func() bool {
		c, e := r.Observe(ctx, p)
		if e != nil || len(c) == 0 {
			return false
		}
		for _, item := range c {
			if item.State != "running" || item.Health != "healthy" {
				return false
			}
		}
		return true
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
	v, e := localcontainer.ReadProtectedSecret(path)
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

// The trusted ingress fixture is built explicitly from this test's source before
// any product provisioning. Providers never download or build artifacts.
func buildEndpointFixture(t *testing.T, ctx context.Context, runID string, clean *bool) string {
	t.Helper()
	buildRoot := t.TempDir()
	binary := filepath.Join(buildRoot, "matrix-product-endpoint")
	command := exec.CommandContext(ctx, "go", "build", "-trimpath", "-o", binary, "../../app/service/paas/cmd/matrix-product-endpoint")
	command.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH=amd64")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build trusted endpoint fixture: %s", output)
	}
	dockerfile := "FROM scratch\nCOPY matrix-product-endpoint /matrix/bin/matrix-product-endpoint\nUSER 65532:65532\n"
	if err := os.WriteFile(filepath.Join(buildRoot, "Dockerfile"), []byte(dockerfile), 0o600); err != nil {
		t.Fatal(err)
	}
	tag := "matrix-onboarding-endpoint:" + runID
	build := exec.CommandContext(ctx, "docker", "build", "--network=none", "--pull=false", "--label", "com.xiak.matrix.onboarding="+runID, "-t", tag, buildRoot)
	if _, err := build.CombinedOutput(); err != nil {
		t.Fatal("build isolated endpoint image failed")
	}
	id := dockerOutput(t, "image", "inspect", "--format", "{{.Id}}", tag)
	t.Cleanup(func() {
		if !*clean {
			return
		}
		if owner := dockerOutput(t, "image", "inspect", "--format", `{{index .Config.Labels "com.xiak.matrix.onboarding"}}`, tag); owner != runID {
			t.Error("endpoint image ownership changed")
			return
		}
		dockerOutput(t, "image", "rm", tag)
	})
	return id
}

func assertLogstashWrite(t *testing.T, ctx context.Context, endpoint string, secret []byte, path, marker string) {
	t.Helper()
	status, _ := callHTTP(t, http.MethodPost, endpoint, "matrix", secret, map[string]string{"message": marker})
	if status != http.StatusOK {
		t.Fatal("authenticated Logstash input failed")
	}
	await(t, ctx, "Logstash output persistence", func() bool {
		content, err := os.ReadFile(path)
		return err == nil && bytes.Contains(content, []byte(marker))
	})
}
func logstashRuntimeWitness(t *testing.T, id string) string {
	t.Helper()
	return dockerOutput(t, "inspect", "--format", "{{.Id}} {{.State.StartedAt}} {{.RestartCount}} {{json .NetworkSettings.Networks}} {{json .Mounts}}", id)
}

type productNetwork struct{ IPAddress, Gateway, NetworkID string }

func productNetworks(t *testing.T, id string) map[string]productNetwork {
	t.Helper()
	var networks map[string]productNetwork
	if json.Unmarshal([]byte(dockerOutput(t, "inspect", "--format", "{{json .NetworkSettings.Networks}}", id)), &networks) != nil {
		t.Fatal("cannot inspect product networks")
	}
	return networks
}
func assertLogstashNetworkIsolation(t *testing.T, ctx context.Context, left InstallationConfig, leftResult adapterv1.ProvisionResult, right InstallationConfig, rightResult adapterv1.ProvisionResult) {
	t.Helper()
	type route struct{ container, address, network, gateway, hostPort string }
	routes := make([]route, 0, 2)
	for _, item := range []struct {
		config InstallationConfig
		result adapterv1.ProvisionResult
	}{{left, leftResult}, {right, rightResult}} {
		status, _ := callHTTP(t, http.MethodGet, item.result.Endpoint, "", nil, nil)
		if status != http.StatusUnauthorized {
			t.Fatal("positive host connectivity control failed")
		}
		project := projectFor(item.config)
		product := ownedContainer(t, ctx, item.config.Runtime, project, item.config.Request)
		networks := productNetworks(t, product.ID)
		if len(networks) != 1 {
			t.Fatal("tenant product has an unexpected network attachment")
		}
		value := route{container: product.ID}
		for name, network := range networks {
			if net.ParseIP(network.IPAddress) == nil || network.Gateway != "" {
				t.Fatal("tenant product has a host route or lacks its private address")
			}
			var config struct {
				Internal bool
				Options  map[string]string
			}
			if json.Unmarshal([]byte(dockerOutput(t, "network", "inspect", "--format", "{{json .}}", name)), &config) != nil || !config.Internal || config.Options["com.docker.network.bridge.gateway_mode_ipv4"] != "isolated" {
				t.Fatal("private network isolation contract is missing")
			}
			value.address, value.network = network.IPAddress, network.NetworkID
		}
		containers, err := item.config.Runtime.Observe(ctx, project)
		if err != nil || len(containers) != 2 {
			t.Fatal("trusted ingress inventory is invalid")
		}
		for _, c := range containers {
			if c.Service == "logstash-endpoint" {
				for _, network := range productNetworks(t, c.ID) {
					if network.Gateway != "" {
						if value.gateway != "" {
							t.Fatal("ingress has multiple host paths")
						}
						value.gateway = network.Gateway
					}
				}
			}
		}
		parsed, err := url.Parse(item.result.Endpoint)
		if err != nil || parsed.Hostname() != "127.0.0.1" || parsed.Port() == "" || net.ParseIP(value.gateway) == nil {
			t.Fatal("trusted ingress route is invalid")
		}
		value.hostPort = parsed.Port()
		routes = append(routes, value)
	}
	if routes[0].network == routes[1].network || routes[0].address == routes[1].address {
		t.Fatal("tenants share a private network")
	}
	for _, direction := range [][2]route{{routes[0], routes[1]}, {routes[1], routes[0]}} {
		for _, target := range []string{"http://" + net.JoinHostPort(direction[1].address, "8080"), "http://" + net.JoinHostPort(direction[1].gateway, direction[1].hostPort)} {
			probeCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
			probe := exec.CommandContext(probeCtx, "docker", "exec", direction[0].container, "curl", "--silent", "--connect-timeout", "1", "--max-time", "2", "--output", "/dev/null", target)
			err := probe.Run()
			expired := probeCtx.Err() != nil
			cancel()
			var exit *exec.ExitError
			if expired || !errors.As(err, &exit) || (exit.ExitCode() != 7 && exit.ExitCode() != 28) {
				t.Fatal("inter-tenant path was reachable or the connectivity probe could not be trusted")
			}
		}
	}
}
