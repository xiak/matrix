package managedserviceonboarding

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	adapterv1 "github.com/xiak/matrix/api/adapter/managedservice/v1"
	managedv1 "github.com/xiak/matrix/api/managedservice/v1"
	compose "github.com/xiak/matrix/app/adapter/apphosting/compose"
	localcontainer "github.com/xiak/matrix/app/adapter/managedservice/localcontainer"
	localelasticsearch "github.com/xiak/matrix/app/adapter/managedservice/localelasticsearch"
	localkibana "github.com/xiak/matrix/app/adapter/managedservice/localkibana"
	localredis "github.com/xiak/matrix/app/adapter/managedservice/localredis"
)

type sampleReport struct {
	Kind        string            `json:"kind"`
	Versions    map[string]string `json:"versions"`
	StartedAt   time.Time         `json:"startedAt"`
	CompletedAt time.Time         `json:"completedAt"`
	Status      string            `json:"status"`
	Artifacts   map[string]string `json:"artifacts"`
	Checks      []string          `json:"passedChecks"`
	Publication string            `json:"platformAndReleaseGates"`
}

// TestProductRuntime is opt-in so ordinary unit tests never start Docker.
// When requested, absent inputs/images are failures, never skips or downloads.
func TestProductRuntime(t *testing.T) {
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
	report := sampleReport{Kind: "MatrixProductOnboardingEvidence", Versions: map[string]string{"elasticsearch": ElasticVersion, "logstash": ElasticVersion, "kibana": ElasticVersion, "redis": localredis.Version}, StartedAt: time.Now().UTC(),
		Status: "FAILED", Publication: "NOT_RUN: no catalog, IAM, browser or signed-release acceptance"}
	report.Artifacts, err = ArtifactReferences()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		report.CompletedAt = time.Now().UTC()
		if !t.Failed() {
			report.Status = "INCOMPLETE"
			if len(report.Checks) == 18 {
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
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Minute)
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
	imageIDs["endpoint"] = endpointImageID
	t.Run("Redis", func(t *testing.T) { verifyRedis(t, ctx, root, imageIDs["redis"], endpointImageID, &clean, &report) })
	t.Run("Logstash", func(t *testing.T) {
		verifyLogstash(t, ctx, root, imageIDs["logstash"], endpointImageID, &clean, &report)
	})
	t.Run("Elasticsearch", func(t *testing.T) { verifyElasticsearch(t, ctx, root, runID, imageIDs, &clean, &report) })
	t.Run("Kibana", func(t *testing.T) { verifyKibana(t, ctx, root, runID, imageIDs, &clean, &report) })
}

func verifyRedis(t *testing.T, ctx context.Context, root, imageID, endpointImageID string, clean *bool, report *sampleReport) {
	r := &lostResponseRuntime{LocalRuntime: compose.NewLocalRuntime(), loseNextApply: true}
	configs := []InstallationConfig{{Root: filepath.Join(root, "managed-redis"), ImageID: imageID, EndpointImageID: endpointImageID, Runtime: r, Request: requestFor("redis")}}
	configs[0].Request.TenantID = filepath.Base(root)
	configs = append(configs, configs[0])
	configs[1].Request.TenantID += "-peer"
	configs[1].Runtime = compose.NewLocalRuntime()
	providers := make([]adapterv1.Provisioner, 2)
	projects := make([]compose.RuntimeProject, 2)
	results := make([]adapterv1.ProvisionResult, 2)
	secrets := make([][]byte, 2)
	containers := make([]compose.RuntimeContainer, 2)
	defer func() {
		for _, secret := range secrets {
			clear(secret)
		}
	}()
	before := inventory(t, root)
	for i, config := range configs {
		construct := func() (adapterv1.Provisioner, error) {
			return localredis.New(localredis.Config{Root: config.Root, ImageID: imageID, EndpointImageID: endpointImageID, Runtime: config.Runtime})
		}
		p, err := construct()
		if err != nil {
			t.Fatal(err)
		}
		registerCleanup(t, p, config.Request, clean)
		if err := p.Ready(ctx); err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			if _, err := p.Ensure(ctx, config.Request); err == nil || !r.lost {
				t.Fatal("Redis lost-response injection did not observe a completed effect")
			}
			p, err = construct()
			if err != nil {
				t.Fatal(err)
			}
		}
		result, err := p.Ensure(ctx, config.Request)
		if err != nil {
			t.Fatal(err)
		}
		project := projectFor(config)
		secret := readSecret(t, filepath.Join(project.Directory, "redis-password"))
		providers[i], projects[i], results[i], secrets[i] = p, project, result, secret
		containers[i] = ownedContainer(t, ctx, config.Runtime, project, config.Request)
		checkNoManifestSecret(t, project, secret)
		acl, err := os.ReadFile(filepath.Join(project.Directory, "users.acl"))
		if err != nil || bytes.Contains(acl, secret) {
			t.Fatal("Redis ACL exposed the original password")
		}
		session := redisProbe(t, ctx, result.Endpoint)
		assertRedisDenied(t, session, "NOAUTH", "PING")
		assertRedisDenied(t, session, "WRONGPASS", "AUTH", localredis.BusinessUser, "wrong-password")
		assertRedisDenied(t, session, "WRONGPASS", "AUTH", "default", string(secret))
		assertRedisValue(t, session, "OK", "AUTH", localredis.BusinessUser, string(secret))
		assertRedisValue(t, session, "PONG", "PING")
		version, err := session.Command("INFO", "server")
		if err != nil || !strings.Contains(fmt.Sprint(version), "redis_version:"+localredis.Version+"\r\n") {
			t.Fatal("Redis native engine version differs from the contract")
		}
		for _, command := range [][]string{
			{"CONFIG", "GET", "dir"}, {"ACL", "LIST"}, {"MODULE", "LIST"}, {"REPLICAOF", "NO", "ONE"},
			{"MIGRATE", "127.0.0.1", "1", "blocked-key", "0", "100"}, {"FLUSHALL"}, {"EVAL", "return 1", "0"}, {"SCRIPT", "LOAD", "return 1"},
		} {
			assertRedisDenied(t, session, "NOPERM", command...)
		}
		assertRedisValue(t, session, "OK", "SET", "matrix-retained", config.Request.TenantID)
		assertRedisValue(t, session, config.Request.TenantID, "GET", "matrix-retained")
		assertRedisValue(t, session, "OK", "SET", "matrix-expires", "temporary", "PX", "200")
		await(t, ctx, "Redis TTL expiration", func() bool { value, err := session.Command("GET", "matrix-expires"); return err == nil && value == nil })
		synced, err := session.Command("WAITAOF", "1", "0", "5000")
		values, ok := synced.([]any)
		if err != nil || !ok || len(values) != 2 || values[0] != int64(1) {
			t.Fatal("Redis did not confirm its local AOF persistence")
		}
		_ = session.Close()
		dockerOutput(t, "restart", "--time", "0", containers[i].ID)
		awaitHealthy(t, ctx, config.Runtime, project)
		p, err = construct()
		if err != nil {
			t.Fatal(err)
		}
		replayed, err := p.Ensure(ctx, config.Request)
		if err != nil || replayed != result || ownedContainer(t, ctx, config.Runtime, project, config.Request).ID != containers[i].ID || !bytes.Equal(secret, readSecret(t, filepath.Join(project.Directory, "redis-password"))) {
			t.Fatal("Redis restart/replay changed identity or credentials")
		}
		session = redisProbe(t, ctx, result.Endpoint)
		assertRedisValue(t, session, "OK", "AUTH", localredis.BusinessUser, string(secret))
		assertRedisValue(t, session, config.Request.TenantID, "GET", "matrix-retained")
		assertRedisValue(t, session, nil, "GET", "matrix-expires")
		_ = session.Close()
	}
	if bytes.Equal(secrets[0], secrets[1]) || results[0].Endpoint == results[1].Endpoint || results[0].CredentialReference == results[1].CredentialReference || projects[0].Directory == projects[1].Directory {
		t.Fatal("Redis tenant identity or credentials are shared")
	}
	for i := range configs {
		session := redisProbe(t, ctx, results[i].Endpoint)
		assertRedisDenied(t, session, "WRONGPASS", "AUTH", localredis.BusinessUser, string(secrets[1-i]))
		assertRedisDenied(t, session, "NOAUTH", "GET", "matrix-retained")
		_ = session.Close()
	}
	assertProductNetworkIsolation(t, ctx, configs[0], results[0], configs[1], results[1], 6379)
	if inventory(t, root) == before {
		t.Fatal("Redis is missing from recovery inventory")
	}
	peerBefore := productRuntimeWitness(t, containers[1].ID)
	bad := deletionFor(configs[0].Request)
	bad.TenantID = "absent-account"
	if err := providers[0].Delete(ctx, bad); err != nil {
		t.Fatal(err)
	}
	_ = ownedContainer(t, ctx, configs[0].Runtime, projects[0], configs[0].Request)
	deleteAndProve(t, ctx, providers[0], configs[0].Request, projects[0], configs[0].Runtime)
	if productRuntimeWitness(t, containers[1].ID) != peerBefore || !bytes.Equal(secrets[1], readSecret(t, filepath.Join(projects[1].Directory, "redis-password"))) {
		t.Fatal("deleting one Redis tenant changed the peer runtime or password")
	}
	session := redisProbe(t, ctx, results[1].Endpoint)
	assertRedisValue(t, session, "OK", "AUTH", localredis.BusinessUser, string(secrets[1]))
	assertRedisValue(t, session, configs[1].Request.TenantID, "GET", "matrix-retained")
	assertRedisValue(t, session, "OK", "SET", "matrix-after-peer-delete", "retained")
	assertRedisValue(t, session, "retained", "GET", "matrix-after-peer-delete")
	_ = session.Close()
	if productRuntimeWitness(t, containers[1].ID) != peerBefore {
		t.Fatal("Redis peer was recreated while proving continued use")
	}
	deleteAndProve(t, ctx, providers[1], configs[1].Request, projects[1], configs[1].Runtime)
	if inventory(t, root) != before {
		t.Fatal("Redis remains in recovery inventory after deletion")
	}
	report.Checks = append(report.Checks, "redis/authentication-and-restricted-business-acl", "redis/data-ttl-and-aof-restart", "redis/two-tenant-network-data-and-credentials", "redis/lost-response-and-equal-replay", "redis/independent-exact-delete", "redis/recovery-inventory-and-secret-custody")
}

func redisProbe(t *testing.T, ctx context.Context, endpoint string) *RedisSession {
	t.Helper()
	session, err := DialRedis(ctx, endpoint)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = session.Close() })
	return session
}
func assertRedisValue(t *testing.T, session *RedisSession, expected any, command ...string) {
	t.Helper()
	actual, err := session.Command(command...)
	if err != nil || actual != expected {
		t.Fatalf("Redis %s did not produce the expected non-secret result", command[0])
	}
}
func assertRedisDenied(t *testing.T, session *RedisSession, code string, command ...string) {
	t.Helper()
	_, err := session.Command(command...)
	var denied RedisError
	if !errors.As(err, &denied) || !strings.HasPrefix(string(denied), code+" ") {
		t.Fatalf("Redis %s did not reject with %s", command[0], code)
	}
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
	if json.Unmarshal([]byte(engineContent), &engine) != nil || engine.Version != ElasticVersion {
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
	assertProductNetworkIsolation(t, ctx, config, result, peerConfig, peerResult, 8080)
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
	assertProductNetworkIsolation(t, ctx, config, result, peerConfig, peerResult, 8080)
	peerBeforeDeletion := productRuntimeWitness(t, peerContainer.ID)
	bad := deletionFor(config.Request)
	bad.TenantID = "other-account"
	if err := provider.Delete(ctx, bad); err != nil {
		t.Fatal("deletion of an absent independently scoped identity did not converge")
	}
	_ = ownedContainer(t, ctx, r, project, config.Request)
	deleteAndProve(t, ctx, provider, config.Request, project, r)

	if productRuntimeWitness(t, peerContainer.ID) != peerBeforeDeletion {
		t.Fatal("deleting one tenant changed the other tenant's runtime")
	}
	preservedPeerData, _ := os.ReadFile(peerDataPath)
	if !bytes.Equal(peerData, preservedPeerData) || !bytes.Equal(peerSecret, readSecret(t, filepath.Join(peerProject.Directory, "logstash-secret"))) {
		t.Fatal("deleting one tenant changed the other's data or credential")
	}
	assertLogstashWrite(t, ctx, peerResult.Endpoint, peerSecret, peerDataPath, "matrix-peer-after-other-delete")
	if productRuntimeWitness(t, peerContainer.ID) != peerBeforeDeletion {
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

// verifyElasticsearch proves the dependency product's isolation before Kibana
// can acquire a bounded route to it. These are provider-owned scopes; real
// Account authorization remains a separate production-process gate.
func verifyElasticsearch(t *testing.T, ctx context.Context, root, runID string, images map[string]string, clean *bool, report *sampleReport) {
	r := compose.NewLocalRuntime()
	configs := make([]InstallationConfig, 2)
	providers := make([]*localelasticsearch.Provisioner, 2)
	results := make([]adapterv1.ProvisionResult, 2)
	projects := make([]compose.RuntimeProject, 2)
	secrets := make([][]byte, 2)
	defer func() {
		for _, secret := range secrets {
			clear(secret)
		}
	}()
	for i := range configs {
		configs[i] = InstallationConfig{Root: filepath.Join(root, "managed-elasticsearch"), ImageID: images["elasticsearch"], EndpointImageID: images["endpoint"], Runtime: r,
			Request: adapterv1.ProvisionRequest{TenantID: runID + "-" + strconv.Itoa(i), InstallationID: "same-elasticsearch", OperationID: "operation-es", OfferingID: managedv1.ElasticsearchOfferingID, EngineVersion: ElasticVersion, RegionID: "local-primary",
				QuotaShape: managedv1.QuotaShape{ID: "elasticsearch-small", DisplayName: "开发型", CPUMillicores: 1000, MemoryMiB: 1536, StorageGiB: 10}}}
		var err error
		providers[i], err = localelasticsearch.New(localelasticsearch.Config{Root: configs[i].Root, ImageID: configs[i].ImageID, EndpointImageID: configs[i].EndpointImageID, Runtime: r})
		if err != nil {
			t.Fatal(err)
		}
		registerCleanup(t, providers[i], configs[i].Request, clean)
		if err := providers[i].Ready(ctx); err != nil {
			t.Fatal(err)
		}
		results[i] = ensureElasticsearch(t, ctx, providers[i], configs[i], r)
		projects[i] = projectFor(configs[i])
		secrets[i] = readSecret(t, filepath.Join(projects[i].Directory, "elasticsearch-password"))
		checkNoManifestSecret(t, projects[i], secrets[i])
		status, versionBody := callHTTP(t, http.MethodGet, results[i].Endpoint, "elastic", secrets[i], nil)
		var version struct{ Version struct{ Number string } }
		if status != http.StatusOK || json.Unmarshal(versionBody, &version) != nil || version.Version.Number != ElasticVersion {
			t.Fatal("Elasticsearch runtime version differs from the pinned product")
		}
		status, _ = callHTTP(t, http.MethodPut, results[i].Endpoint+"/matrix-onboarding/_doc/one?refresh=true", "elastic", secrets[i], map[string]string{"message": "tenant-" + strconv.Itoa(i)})
		if status != http.StatusCreated {
			t.Fatal("Elasticsearch durable write failed")
		}
	}
	if results[0].Endpoint == results[1].Endpoint || results[0].CredentialReference == results[1].CredentialReference || bytes.Equal(secrets[0], secrets[1]) {
		t.Fatal("Elasticsearch tenant identities overlap")
	}
	verifyData := func(i int) {
		status, body := callHTTP(t, http.MethodGet, results[i].Endpoint+"/matrix-onboarding/_doc/one", "elastic", secrets[i], nil)
		var record struct {
			Source struct{ Message string } "json:\"_source\""
		}
		if status != http.StatusOK || json.Unmarshal(body, &record) != nil || record.Source.Message != "tenant-"+strconv.Itoa(i) {
			t.Fatal("Elasticsearch tenant data or credential changed")
		}
		if !bytes.Equal(secrets[i], readSecret(t, filepath.Join(projects[i].Directory, "elasticsearch-password"))) {
			t.Fatal("Elasticsearch credential rotated")
		}
	}
	for i := range configs {
		status, _ := callHTTP(t, http.MethodGet, results[i].Endpoint, "elastic", secrets[1-i], nil)
		if status != http.StatusUnauthorized {
			t.Fatal("other tenant's Elasticsearch credential accepted")
		}
		verifyData(i)
	}
	assertProductNetworkIsolation(t, ctx, configs[0], results[0], configs[1], results[1], 9200)
	peer := ownedContainer(t, ctx, r, projects[1], configs[1].Request)
	peerBefore := productRuntimeWitness(t, peer.ID)
	first := ownedContainer(t, ctx, r, projects[0], configs[0].Request)
	dockerOutput(t, "restart", first.ID)
	awaitHealthy(t, ctx, r, projects[0])
	replay, err := providers[0].Ensure(ctx, configs[0].Request)
	if err != nil || replay != results[0] {
		t.Fatal("Elasticsearch restart replay changed identity")
	}
	verifyData(0)
	assertProductNetworkIsolation(t, ctx, configs[0], results[0], configs[1], results[1], 9200)
	if productRuntimeWitness(t, peer.ID) != peerBefore {
		t.Fatal("Elasticsearch peer changed during restart")
	}

	// Reconstruct the authenticated direct-port predecessor from the fixed
	// product definition. Only task-owned instances are stopped/recreated.
	// Migration must retain live data and leave stopped peers off.
	makePredecessor := func(i int, stopped bool) {
		content, err := os.ReadFile(projects[i].EffectDocument)
		if err != nil {
			t.Fatal(err)
		}
		var document map[string]any
		if json.Unmarshal(content, &document) != nil {
			t.Fatal("cannot read predecessor fixture")
		}
		services := document["services"].(map[string]any)
		delete(services, "elasticsearch-endpoint")
		delete(document, "networks")
		backend := services["elasticsearch"].(map[string]any)
		delete(backend, "networks")
		endpoint, _ := url.Parse(results[i].Endpoint)
		backend["ports"] = []string{"127.0.0.1:" + endpoint.Port() + ":9200/tcp"}
		legacy, err := json.Marshal(document)
		if err != nil {
			t.Fatal(err)
		}
		if err := r.Stop(ctx, projects[i]); err != nil {
			t.Fatal(err)
		}
		for _, file := range []string{projects[i].EffectDocument, projects[i].ObservationDocument} {
			if err := os.WriteFile(file, legacy, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		if err := r.Apply(ctx, projects[i]); err != nil {
			t.Fatal(err)
		}
		verifyData(i)
		if stopped {
			c := ownedContainer(t, ctx, r, projects[i], configs[i].Request)
			dockerOutput(t, "stop", c.ID)
		}
	}
	makePredecessor(0, false)
	makePredecessor(1, true)
	if err := providers[0].UpgradeNetwork(ctx); err != nil {
		t.Fatal(err)
	}
	verifyData(0)
	stopped, err := r.Observe(ctx, projects[1])
	if err != nil || len(stopped) != 0 {
		t.Fatal("migration started or retained a stopped direct-port predecessor")
	}
	replay, err = providers[1].Ensure(ctx, configs[1].Request)
	if err != nil || replay != results[1] {
		t.Fatal("explicit restart of migrated Elasticsearch failed")
	}
	verifyData(1)
	assertProductNetworkIsolation(t, ctx, configs[0], results[0], configs[1], results[1], 9200)
	peer = ownedContainer(t, ctx, r, projects[1], configs[1].Request)
	peerBefore = productRuntimeWitness(t, peer.ID)
	deleteAndProve(t, ctx, providers[0], configs[0].Request, projects[0], r)
	verifyData(1)
	status, _ := callHTTP(t, http.MethodPut, results[1].Endpoint+"/matrix-onboarding/_doc/two?refresh=true", "elastic", secrets[1], map[string]string{"message": "after-other-delete"})
	if status != http.StatusCreated || productRuntimeWitness(t, peer.ID) != peerBefore {
		t.Fatal("deleting Elasticsearch A affected B")
	}
	deleteAndProve(t, ctx, providers[1], configs[1].Request, projects[1], r)
	report.Checks = append(report.Checks, "elasticsearch/two-tenant-isolation-retained-network-migration-and-independent-delete")
}

func verifyKibana(t *testing.T, ctx context.Context, root, runID string, images map[string]string, clean *bool, report *sampleReport) {
	r := compose.NewLocalRuntime()
	esConfig := InstallationConfig{Root: filepath.Join(root, "managed-elasticsearch"), ImageID: images["elasticsearch"], EndpointImageID: images["endpoint"], Runtime: r, Request: requestFor("elasticsearch")}
	esConfig.Request.TenantID, esConfig.Request.InstallationID = runID, "dependency-es"
	es, err := localelasticsearch.New(localelasticsearch.Config{Root: esConfig.Root, ImageID: esConfig.ImageID, EndpointImageID: esConfig.EndpointImageID, Runtime: r})
	if err != nil {
		t.Fatal(err)
	}
	registerCleanup(t, es, esConfig.Request, clean)
	esResult := ensureElasticsearch(t, ctx, es, esConfig, r)
	esProject := projectFor(esConfig)
	esContainer := ownedContainer(t, ctx, r, esProject, esConfig.Request)
	esWitness := productRuntimeWitness(t, esContainer.ID)
	esPassword := readSecret(t, filepath.Join(esProject.Directory, "elasticsearch-password"))
	defer clear(esPassword)
	index := runID
	status, _ := callHTTP(t, http.MethodPut, esResult.Endpoint+"/"+index+"/_doc/one?refresh=true", "elastic", esPassword, map[string]string{"message": "retained-dependency-data"})
	if status != http.StatusCreated {
		t.Fatalf("dependency protocol write status=%d", status)
	}
	before := inventory(t, root)
	configs := make([]InstallationConfig, 2)
	providers := make([]*localkibana.Provisioner, 2)
	results := make([]adapterv1.ProvisionResult, 2)
	projects := make([]compose.RuntimeProject, 2)
	tokens := make([][]byte, 2)
	settings := make([]map[string]any, 2)
	construct := func(config InstallationConfig, native compose.Runtime) *localkibana.Provisioner {
		if native == nil {
			native = r
		}
		p, e := localkibana.New(localkibana.Config{Root: config.Root, ImageID: config.ImageID, EndpointImageID: config.EndpointImageID, ElasticsearchRoot: esConfig.Root, ElasticsearchImageID: esConfig.ImageID, Runtime: native})
		if e != nil {
			t.Fatal(e)
		}
		return p
	}
	for i := range configs {
		configs[i] = InstallationConfig{Root: filepath.Join(root, "managed-kibana"), ImageID: images["kibana"], EndpointImageID: images["endpoint"], Runtime: r, Request: requestFor("kibana")}
		configs[i].Request.TenantID = runID
		configs[i].Request.InstallationID += "-" + strconv.Itoa(i)
		projects[i] = projectFor(configs[i])
		providers[i] = construct(configs[i], nil)
		registerCleanup(t, providers[i], configs[i].Request, clean)
		if err := providers[i].Ready(ctx); err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			// The real native API accepts creation; the adapter loses only its response.
			// A new provider must recover this exact token name without touching others.
			transport := &lostTokenResponse{LocalRuntime: r, method: http.MethodPost}
			uncertain := construct(configs[i], transport)
			if _, err := uncertain.Ensure(ctx, configs[i].Request); err == nil || !transport.lost || inventory(t, root) == before {
				t.Fatal("lost native token response was not fenced by recoverable installation custody")
			}
			if observed, e := r.Observe(ctx, projects[i]); e != nil || len(observed) != 0 {
				t.Fatal("failed token response started Kibana")
			}
		}
		results[i] = ensureKibana(t, ctx, providers[i], configs[i], r)
		token, e := os.ReadFile(filepath.Join(projects[i].Directory, "kibana-service-token"))
		if e != nil || len(token) < 32 {
			t.Fatal("protected service token is unavailable")
		}
		tokens[i] = token
		defer clear(token)
		assertServiceToken(t, esResult.Endpoint, token, projects[i].Name, http.StatusOK)
		checkNoManifestSecret(t, projects[i], token)
		checkNoManifestSecret(t, projects[i], esPassword)
		value, e := os.ReadFile(filepath.Join(projects[i].Directory, "kibana.yml"))
		if e != nil || json.Unmarshal(value, &settings[i]) != nil {
			t.Fatal("protected Kibana settings are invalid")
		}
		clear(value)
		var health struct {
			Status struct{ Overall struct{ Level string } }
		}
		status, body := callHTTP(t, http.MethodGet, results[i].Endpoint+"/api/status?v8format=true", "", nil, nil)
		if status != http.StatusOK || json.Unmarshal(body, &health) != nil || health.Status.Overall.Level != "available" {
			t.Fatal("Kibana is not available")
		}
		container := ownedContainer(t, ctx, r, projects[i], configs[i].Request)
		var pkg struct{ Version string }
		if json.Unmarshal([]byte(dockerOutput(t, "exec", container.ID, "cat", "/usr/share/kibana/package.json")), &pkg) != nil || pkg.Version != ElasticVersion {
			t.Fatal("Kibana runtime version differs from the pinned product")
		}
		assertKibanaDependencyRoute(t, ctx, r, projects[i], configs[i].Request, esContainer)
	}
	if results[0].Endpoint == results[1].Endpoint || results[0].CredentialReference == results[1].CredentialReference || bytes.Equal(tokens[0], tokens[1]) ||
		settings[0]["xpack.security.encryptionKey"] == settings[1]["xpack.security.encryptionKey"] || settings[0]["xpack.security.cookieName"] == settings[1]["xpack.security.cookieName"] {
		t.Fatal("Kibana instances share server credentials, browser session custody or endpoints")
	}
	for setting, file := range map[string]string{"xpack.encryptedSavedObjects.encryptionKey": "kibana-saved-objects-key", "xpack.reporting.encryptionKey": "kibana-reporting-key"} {
		key := readSecret(t, filepath.Join(esProject.Directory, file))
		if settings[0][setting] != string(key) || settings[1][setting] != string(key) {
			t.Fatal("shared saved-object custody differs between Kibana instances")
		}
		clear(key)
	}
	assertSharedKeys := func() {
		t.Helper()
		for setting, file := range map[string]string{"xpack.encryptedSavedObjects.encryptionKey": "kibana-saved-objects-key", "xpack.reporting.encryptionKey": "kibana-reporting-key"} {
			key := readSecret(t, filepath.Join(esProject.Directory, file))
			if settings[0][setting] != string(key) {
				t.Fatal("Kibana deletion or recreation rotated dependency-owned encryption material")
			}
			clear(key)
		}
	}
	assertProductNetworkIsolation(t, ctx, configs[0], results[0], configs[1], results[1], 5601)
	dataViewRequest := map[string]any{"data_view": map[string]any{"title": index, "name": "Matrix onboarding"}}
	status, _ = callHTTP(t, http.MethodPost, results[0].Endpoint+"/api/data_views/data_view", "", nil, dataViewRequest)
	if status != http.StatusUnauthorized {
		t.Fatal("Kibana accepted unauthenticated product writes")
	}
	status, body := callHTTP(t, http.MethodPost, results[0].Endpoint+"/api/data_views/data_view", "elastic", esPassword, dataViewRequest)
	var created struct{ DataView struct{ ID, Title string } }
	// The API uses a snake-case field; decode only the required public shape.
	var envelope map[string]json.RawMessage
	if status != http.StatusOK || json.Unmarshal(body, &envelope) != nil || json.Unmarshal(envelope["data_view"], &created.DataView) != nil || created.DataView.ID == "" || created.DataView.Title != index {
		t.Fatalf("Kibana data-view creation status=%d", status)
	}
	assertDataView := func(endpoint string) {
		status, content := callHTTP(t, http.MethodGet, endpoint+"/api/data_views/data_view/"+created.DataView.ID, "elastic", esPassword, nil)
		if status != http.StatusOK || !bytes.Contains(content, []byte(index)) {
			t.Fatal("shared Kibana saved object is unavailable")
		}
	}
	assertDataView(results[1].Endpoint)
	peer := ownedContainer(t, ctx, r, projects[1], configs[1].Request)
	peerWitness := productRuntimeWitness(t, peer.ID)
	first := ownedContainer(t, ctx, r, projects[0], configs[0].Request)
	settingsBytes, err := os.ReadFile(filepath.Join(projects[0].Directory, "kibana.yml"))
	if err != nil {
		t.Fatal("settings unavailable")
	}
	settingsDigest := sha256.Sum256(settingsBytes)
	clear(settingsBytes)
	dockerOutput(t, "restart", "--time", "10", first.ID)
	awaitHealthy(t, ctx, r, projects[0])
	providers[0] = construct(configs[0], nil)
	replayed, err := providers[0].Ensure(ctx, configs[0].Request)
	if err != nil || replayed != results[0] || ownedContainer(t, ctx, r, projects[0], configs[0].Request).ID != first.ID {
		t.Fatal("Kibana restart/replay changed its identity")
	}
	settingsBytes, err = os.ReadFile(filepath.Join(projects[0].Directory, "kibana.yml"))
	if err != nil || sha256.Sum256(settingsBytes) != settingsDigest {
		t.Fatal("Kibana restart changed credential configuration")
	}
	clear(settingsBytes)
	assertDataView(results[0].Endpoint)
	lostDelete := &lostTokenResponse{LocalRuntime: r, method: http.MethodDelete}
	uncertainDelete := construct(configs[0], lostDelete)
	if err := uncertainDelete.Delete(ctx, deletionFor(configs[0].Request)); err == nil || !lostDelete.lost {
		t.Fatal("lost native revocation response was not reported as uncertain")
	}
	if _, err := os.Stat(filepath.Join(projects[0].Directory, "kibana-service-token")); err != nil {
		t.Fatal("uncertain revocation discarded recovery custody")
	}
	if remaining, e := r.Observe(ctx, projects[0]); e != nil || len(remaining) != 0 {
		t.Fatal("uncertain revocation left Kibana running")
	}
	deleteAndProve(t, ctx, providers[0], configs[0].Request, projects[0], r)
	assertServiceToken(t, esResult.Endpoint, tokens[0], projects[0].Name, http.StatusUnauthorized)
	assertServiceToken(t, esResult.Endpoint, tokens[1], projects[1].Name, http.StatusOK)
	if productRuntimeWitness(t, peer.ID) != peerWitness || productRuntimeWitness(t, esContainer.ID) != esWitness {
		t.Fatal("Kibana deletion changed its peer or Elasticsearch runtime")
	}
	assertDataView(results[1].Endpoint)
	deleteAndProve(t, ctx, providers[1], configs[1].Request, projects[1], r)
	assertServiceToken(t, esResult.Endpoint, tokens[1], projects[1].Name, http.StatusUnauthorized)
	assertSharedKeys()
	if inventory(t, root) != before {
		t.Fatal("deleted Kibana remains in recovery inventory")
	}
	// Recreate the same accepted identity after exact deletion: credentials are
	// newly issued, while the dependency-owned saved objects and keys remain.
	providers[0] = construct(configs[0], nil)
	restored := ensureKibana(t, ctx, providers[0], configs[0], r)
	assertDataView(restored.Endpoint)
	assertSharedKeys()
	restoredSettingsBytes, settingsErr := os.ReadFile(filepath.Join(projects[0].Directory, "kibana.yml"))
	var restoredSettings map[string]any
	if settingsErr != nil || json.Unmarshal(restoredSettingsBytes, &restoredSettings) != nil {
		t.Fatal("recreated protected settings unavailable")
	}
	clear(restoredSettingsBytes)
	for _, setting := range []string{"xpack.encryptedSavedObjects.encryptionKey", "xpack.reporting.encryptionKey"} {
		if restoredSettings[setting] != settings[0][setting] {
			t.Fatal("recreated Kibana cannot use the retained encryption material")
		}
	}
	restoredToken, e := os.ReadFile(filepath.Join(projects[0].Directory, "kibana-service-token"))
	if e != nil {
		t.Fatal("recreated token unavailable")
	}
	defer clear(restoredToken)
	if bytes.Equal(restoredToken, tokens[0]) {
		t.Fatal("recreation reused a revoked credential")
	}
	assertServiceToken(t, esResult.Endpoint, tokens[0], projects[0].Name, http.StatusUnauthorized)
	assertServiceToken(t, esResult.Endpoint, restoredToken, projects[0].Name, http.StatusOK)
	deleteAndProve(t, ctx, providers[0], configs[0].Request, projects[0], r)
	if inventory(t, root) != before || productRuntimeWitness(t, esContainer.ID) != esWitness {
		t.Fatal("Kibana recreate/delete changed Elasticsearch or recovery custody")
	}
	status, body = callHTTP(t, http.MethodGet, esResult.Endpoint+"/"+index+"/_doc/one", "elastic", esPassword, nil)
	if status != http.StatusOK || !bytes.Contains(body, []byte("retained-dependency-data")) {
		t.Fatal("Kibana deletion removed dependency data")
	}
	report.Checks = append(report.Checks, "kibana/version-readiness-and-authenticated-shared-saved-objects", "kibana/independent-service-credentials-and-private-dependency-route", "kibana/native-issue-and-revocation-response-loss-and-equal-replay", "kibana/exact-delete-revokes-only-owned-credential", "kibana/recreate-retains-shared-keys-data-and-recovery-custody")
}

type lostTokenResponse struct {
	*compose.LocalRuntime
	method string
	lost   bool
}

func (r *lostTokenResponse) RequestContainerHTTP(ctx context.Context, request compose.ContainerHTTPRequest) (int, []byte, error) {
	status, body, err := r.LocalRuntime.RequestContainerHTTP(ctx, request)
	if err == nil && !r.lost && request.Method == r.method && strings.HasPrefix(request.Path, "/_security/service/elastic/kibana/credential/token/") && status == http.StatusOK {
		clear(body)
		r.lost = true
		return 0, nil, errors.New("injected lost native credential response")
	}
	return status, body, err
}

func assertServiceToken(t *testing.T, endpoint string, token []byte, name string, expected int) {
	t.Helper()
	request, err := http.NewRequest(http.MethodGet, endpoint+"/_security/_authenticate", nil)
	if err != nil {
		t.Fatal("invalid authentication probe")
	}
	request.Header.Set("Authorization", "Bearer "+string(token))
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal("service credential authentication unavailable")
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 65536))
	if err != nil || response.StatusCode != expected {
		t.Fatalf("service credential authentication status=%d expected=%d", response.StatusCode, expected)
	}
	defer clear(body)
	if expected == http.StatusOK {
		var auth struct {
			Username string
			Token    struct{ Name, Type string }
		}
		if json.Unmarshal(body, &auth) != nil || auth.Username != "elastic/kibana" || auth.Token.Name != name || auth.Token.Type != "_service_account_index" {
			t.Fatal("native service credential identity mismatch")
		}
	}
}

func ensureKibana(t *testing.T, ctx context.Context, p adapterv1.Provisioner, config InstallationConfig, r compose.Runtime) adapterv1.ProvisionResult {
	t.Helper()
	result, err := p.Ensure(ctx, config.Request)
	if err == nil {
		return result
	}
	project := projectFor(config)
	current, observeErr := r.Observe(ctx, project)
	if observeErr != nil {
		t.Fatal("uncertain Kibana installation cannot be observed")
	}
	backendID := ""
	for _, c := range current {
		t.Logf("Kibana uncertain attempt: service=%s state=%s health=%s", c.Service, c.State, c.Health)
		if c.Service == "kibana" && c.Project == project.Name && c.State == "running" && (c.Health == "starting" || c.Health == "healthy") && c.Labels["com.xiak.matrix.managedservice.installation"] == config.Request.InstallationID {
			backendID = c.ID
		}
	}
	if backendID == "" {
		t.Fatal(err)
	}
	await(t, ctx, "uncertain Kibana backend readiness", func() bool {
		current, e := r.Observe(ctx, project)
		if e != nil {
			return false
		}
		for _, c := range current {
			if c.ID == backendID {
				return c.State == "running" && c.Health == "healthy"
			}
		}
		return false
	})
	result, err = p.Ensure(ctx, config.Request)
	if err != nil || ownedContainer(t, ctx, r, project, config.Request).ID != backendID {
		t.Fatal("same-identity Kibana retry failed")
	}
	return result
}

func assertKibanaDependencyRoute(t *testing.T, ctx context.Context, r compose.Runtime, project compose.RuntimeProject, request adapterv1.ProvisionRequest, es compose.RuntimeContainer) {
	t.Helper()
	backend := ownedContainer(t, ctx, r, project, request)
	networks := productNetworks(t, backend.ID)
	if len(networks) != 1 {
		t.Fatal("Kibana bypasses its private dependency route")
	}
	var address string
	for name, n := range productNetworks(t, es.ID) {
		if _, shared := networks[name]; shared {
			t.Fatal("Kibana directly joins Elasticsearch private network")
		}
		address = n.IPAddress
	}
	if net.ParseIP(address) == nil {
		t.Fatal("Elasticsearch private address unavailable")
	}
	// Positive control uses the real product runtime and the exact allowed relay.
	nativeHTTP := "const h=require('http');const r=h.get(process.argv[1],s=>{s.resume();process.exit(s.statusCode===Number(process.argv[2])?0:1)});r.on('error',()=>process.exit(2));r.setTimeout(2000,()=>process.exit(3));"
	if err := exec.CommandContext(ctx, "docker", "exec", backend.ID, "/usr/share/kibana/node/glibc-217/bin/node", "-e", nativeHTTP, "http://kibana-elasticsearch-endpoint:13306", "401").Run(); err != nil {
		t.Fatal("allowed dependency relay is unreachable")
	}
	probeUnreachable(t, ctx, backend.ID, "kibana", "http://"+net.JoinHostPort(address, "9200"))
	for _, network := range networks {
		probeUnreachable(t, ctx, es.ID, "elasticsearch", "http://"+net.JoinHostPort(network.IPAddress, "5601"))
	}
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

// A single bounded Apply may time out while the exact backend is still
// starting. Mirror the production reconciler's same-identity retry instead of
// deleting and recreating it or treating timeout as completed installation.
func ensureElasticsearch(t *testing.T, ctx context.Context, provider adapterv1.Provisioner, config InstallationConfig, r compose.Runtime) adapterv1.ProvisionResult {
	t.Helper()
	result, err := provider.Ensure(ctx, config.Request)
	if err == nil {
		return result
	}
	project := projectFor(config)
	current, observeErr := r.Observe(ctx, project)
	if observeErr != nil {
		t.Fatal("cannot observe uncertain Elasticsearch installation")
	}
	backendID := ""
	for _, c := range current {
		t.Logf("Elasticsearch uncertain attempt: service=%s state=%s health=%s publishedPorts=%d", c.Service, c.State, c.Health, c.PublishedPorts)
		if c.Service == "elasticsearch" && c.State == "running" && (c.Health == "starting" || c.Health == "healthy") && c.Project == project.Name &&
			c.Labels["com.xiak.matrix.managedservice.installation"] == config.Request.InstallationID {
			backendID = c.ID
		}
	}
	if backendID == "" {
		t.Fatal("Elasticsearch failure has no owned starting backend to resume")
	}
	await(t, ctx, "same Elasticsearch backend readiness after uncertain attempt", func() bool {
		observed, err := r.Observe(ctx, project)
		if err != nil {
			return false
		}
		for _, c := range observed {
			if c.Service == "elasticsearch" {
				return c.ID == backendID && c.State == "running" && c.Health == "healthy"
			}
		}
		return false
	})
	result, err = provider.Ensure(ctx, config.Request)
	if err != nil || ownedContainer(t, ctx, r, project, config.Request).ID != backendID {
		t.Fatal("same-identity Elasticsearch retry failed or replaced the backend")
	}
	return result
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
	port, readErr := os.ReadFile(filepath.Join(project.Directory, "published-port"))
	if readErr != nil {
		t.Fatal("cannot observe owned endpoint before deletion")
	}
	if err := provider.Delete(ctx, deletionFor(request)); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(project.Directory); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("deleted product retains its protected files or data")
	}
	if err := provider.Delete(ctx, deletionFor(request)); err != nil {
		t.Fatal("equal delete failed")
	}
	if connection, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", string(port)), time.Second); err == nil {
		_ = connection.Close()
		t.Fatal("deleted product endpoint still accepts connections")
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
func productRuntimeWitness(t *testing.T, id string) string {
	t.Helper()
	var witness struct {
		ID              string `json:"Id"`
		State           struct{ StartedAt string }
		RestartCount    int
		NetworkSettings struct{ Networks map[string]json.RawMessage }
		Mounts          []struct {
			Type, Name, Source, Destination, Driver, Mode, Propagation string
			RW                                                         bool
		}
	}
	if json.Unmarshal([]byte(dockerOutput(t, "inspect", "--format", "{{json .}}", id)), &witness) != nil || witness.ID != id {
		t.Fatal("cannot inspect exact product runtime identity")
	}
	// Engine inspection does not promise mount order. Compare all mount
	// properties by their unique container destination, retaining identity,
	// start time, restart count and every network attachment in the witness.
	sort.Slice(witness.Mounts, func(i, j int) bool { return witness.Mounts[i].Destination < witness.Mounts[j].Destination })
	content, err := json.Marshal(witness)
	if err != nil {
		t.Fatal("cannot encode product runtime witness")
	}
	return string(content)
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
func assertProductNetworkIsolation(t *testing.T, ctx context.Context, left InstallationConfig, leftResult adapterv1.ProvisionResult, right InstallationConfig, rightResult adapterv1.ProvisionResult, targetPort int) {
	t.Helper()
	type route struct {
		container, address, network, gateway, hostPort string
		product                                        string
	}
	routes := make([]route, 0, 2)
	for _, item := range []struct {
		config InstallationConfig
		result adapterv1.ProvisionResult
	}{{left, leftResult}, {right, rightResult}} {
		endpoint, expectedStatus := item.result.Endpoint, http.StatusUnauthorized
		kibana := item.config.Request.OfferingID == managedv1.KibanaOfferingID
		if kibana {
			endpoint += "/api/status?v8format=true"
			expectedStatus = http.StatusOK
		}
		if item.config.Request.OfferingID == managedv1.RedisOfferingID {
			session := redisProbe(t, ctx, endpoint)
			assertRedisDenied(t, session, "NOAUTH", "PING")
			_ = session.Close()
		} else {
			status, _ := callHTTP(t, http.MethodGet, endpoint, "", nil, nil)
			if status != expectedStatus {
				t.Fatal("positive host connectivity control failed")
			}
		}
		project := projectFor(item.config)
		product := ownedContainer(t, ctx, item.config.Runtime, project, item.config.Request)
		networks := productNetworks(t, product.ID)
		if len(networks) != 1 {
			t.Fatal("tenant product has an unexpected network attachment")
		}
		value := route{container: product.ID, product: product.Service}
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
		expectedContainers := 2
		if kibana {
			expectedContainers = 3
		}
		if err != nil || len(containers) != expectedContainers {
			t.Fatal("trusted ingress inventory is invalid")
		}
		for _, c := range containers {
			if c.Service == product.Service+"-endpoint" {
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
		for _, target := range []string{"http://" + net.JoinHostPort(direction[1].address, strconv.Itoa(targetPort)), "http://" + net.JoinHostPort(direction[1].gateway, direction[1].hostPort)} {
			probeUnreachable(t, ctx, direction[0].container, direction[0].product, target)
		}
	}
}

func probeUnreachable(t *testing.T, ctx context.Context, container string, product string, target string) {
	t.Helper()
	probeCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	args := []string{"exec", container, "curl", "--silent", "--connect-timeout", "1", "--max-time", "2", "--output", "/dev/null", target}
	if product == "kibana" {
		script := "const h=require('http');const r=h.get(process.argv[1],s=>{s.resume();process.exit(0)});r.on('error',e=>process.exit(['ECONNREFUSED','ENETUNREACH','EHOSTUNREACH','ETIMEDOUT'].includes(e.code)?7:1));r.setTimeout(2000,()=>process.exit(28));"
		args = []string{"exec", container, "/usr/share/kibana/node/glibc-217/bin/node", "-e", script, target}
	}
	if product == "redis" {
		parsed, err := url.Parse(target)
		if err != nil || net.ParseIP(parsed.Hostname()) == nil || parsed.Port() == "" {
			t.Fatal("Redis private probe target is invalid")
		}
		// A password rejection proves reachability, not isolation.
		if output := dockerOutput(t, "exec", container, "redis-cli", "-t", "2", "--raw", "PING"); !strings.HasPrefix(output, "NOAUTH ") {
			t.Fatal("Redis native connectivity control failed")
		}
		args = []string{"exec", container, "redis-cli", "-h", parsed.Hostname(), "-p", parsed.Port(), "-t", "2", "--raw", "PING"}
		output, err := exec.CommandContext(probeCtx, "docker", args...).CombinedOutput()
		var exit *exec.ExitError
		text := string(output)
		if probeCtx.Err() != nil || !errors.As(err, &exit) || exit.ExitCode() != 1 || !strings.Contains(text, "Could not connect to Redis at ") || !(strings.Contains(text, "Network is unreachable") || strings.Contains(text, "No route to host") || strings.Contains(text, "Connection refused") || strings.Contains(text, "Connection timed out")) {
			t.Fatal("Redis private path was reachable or probe failed unexpectedly")
		}
		return
	}
	err := exec.CommandContext(probeCtx, "docker", args...).Run()
	var exit *exec.ExitError
	if probeCtx.Err() != nil || !errors.As(err, &exit) || (exit.ExitCode() != 7 && exit.ExitCode() != 28) {
		t.Fatal("private path was reachable or the connectivity probe could not be trusted")
	}
}
