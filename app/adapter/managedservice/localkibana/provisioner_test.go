package localkibana

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	adapterv1 "github.com/xiak/matrix/api/adapter/managedservice/v1"
	managedv1 "github.com/xiak/matrix/api/managedservice/v1"
	compose "github.com/xiak/matrix/app/adapter/apphosting/compose"
	localcontainer "github.com/xiak/matrix/app/adapter/managedservice/localcontainer"
)

func TestKibanaOwnCredentialSharedSavedObjectKeysAndExactDelete(t *testing.T) {
	config, r, native, first := kibanaFixture(t)
	provider, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	firstResult, err := provider.Ensure(t.Context(), first)
	if err != nil {
		t.Fatal(err)
	}
	firstProject := localcontainer.ProjectName(first.TenantID, first.InstallationID)
	firstSettings := readSettings(t, filepath.Join(config.Root, firstProject, "kibana.yml"))
	checkPrivateDeployment(t, filepath.Join(config.Root, firstProject, "compose.json"))
	second := first
	second.InstallationID = "second-kibana"
	secondResult, err := provider.Ensure(t.Context(), second)
	if err != nil {
		t.Fatal(err)
	}
	secondProject := localcontainer.ProjectName(second.TenantID, second.InstallationID)
	secondSettings := readSettings(t, filepath.Join(config.Root, secondProject, "kibana.yml"))
	if firstResult.Endpoint == secondResult.Endpoint || firstResult.CredentialReference == secondResult.CredentialReference ||
		firstSettings["elasticsearch.serviceAccountToken"] == secondSettings["elasticsearch.serviceAccountToken"] ||
		firstSettings["xpack.security.encryptionKey"] == secondSettings["xpack.security.encryptionKey"] ||
		firstSettings["xpack.security.cookieName"] == secondSettings["xpack.security.cookieName"] {
		t.Fatal("Kibana instances share runtime or session identities")
	}
	for _, key := range []string{"xpack.encryptedSavedObjects.encryptionKey", "xpack.reporting.encryptionKey"} {
		if firstSettings[key] != secondSettings[key] {
			t.Fatal("saved-object custody is not owned by the dependency")
		}
	}
	beforeApply, beforeIssue := r.applies, native.issued
	restarted, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := restarted.Ensure(t.Context(), first)
	if err != nil || replay != firstResult || r.applies != beforeApply || native.issued != beforeIssue {
		t.Fatal("equal replay rotated credentials or runtime")
	}
	if err := restarted.Delete(t.Context(), deletion(first)); err != nil {
		t.Fatal(err)
	}
	if err := restarted.Delete(t.Context(), deletion(first)); err != nil {
		t.Fatal("equal deletion failed")
	}
	if _, err := os.Stat(filepath.Join(config.Root, firstProject)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("deleted Kibana retains custody")
	}
	if len(native.tokens) != 1 || native.tokens[secondProject] == "" || !r.running[secondProject] {
		t.Fatal("deleting Kibana affected its peer")
	}
	esProject := localcontainer.ProjectName(first.TenantID, first.Elasticsearch.InstallationID)
	for _, name := range []string{"elasticsearch-password", "kibana-saved-objects-key", "kibana-reporting-key"} {
		if _, err := localcontainer.ReadProtectedSecret(filepath.Join(config.ElasticsearchRoot, esProject, name)); err != nil {
			t.Fatal("deletion removed dependency custody")
		}
	}
	if err := restarted.Delete(t.Context(), deletion(second)); err != nil {
		t.Fatal(err)
	}
	if len(native.tokens) != 0 {
		t.Fatal("terminated Kibana still has a valid native credential")
	}
}

func TestKibanaLostIssuanceResponseResumesOnlyItsOwnToken(t *testing.T) {
	config, r, native, request := kibanaFixture(t)
	native.loseCreate = true
	native.tokens["other-product-token"] = strings.Repeat("z", 64)
	provider, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.Ensure(t.Context(), request); err == nil || r.applies != 0 || native.issued != 1 {
		t.Fatal("lost token response did not preserve uncertain effect")
	}
	project := localcontainer.ProjectName(request.TenantID, request.InstallationID)
	if _, err := os.Stat(filepath.Join(config.Root, project, "compose.json")); err != nil {
		t.Fatal("credential effect has no durable runtime inventory")
	}
	restarted, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.Ensure(t.Context(), request); err != nil {
		t.Fatal(err)
	}
	if native.issued != 2 || len(native.tokens) != 2 || native.tokens["other-product-token"] != strings.Repeat("z", 64) {
		t.Fatal("uncertain credential retry affected another identity")
	}
	if err := restarted.Delete(t.Context(), deletion(request)); err != nil {
		t.Fatal(err)
	}
	if len(native.tokens) != 1 || native.tokens["other-product-token"] == "" {
		t.Fatal("cleanup revoked another product's token")
	}
}

func TestKibanaConcurrentProviderInstancesConvergeOnOneCredential(t *testing.T) {
	config, r, native, request := kibanaFixture(t)
	providers := make([]*Provisioner, 2)
	for i := range providers {
		var err error
		providers[i], err = New(config)
		if err != nil {
			t.Fatal(err)
		}
	}
	type outcome struct {
		result adapterv1.ProvisionResult
		err    error
	}
	start := make(chan struct{})
	outcomes := make(chan outcome, 2)
	for _, provider := range providers {
		go func() {
			<-start
			result, err := provider.Ensure(t.Context(), request)
			outcomes <- outcome{result, err}
		}()
	}
	close(start)
	first, second := <-outcomes, <-outcomes
	if first.err != nil || second.err != nil || first.result != second.result ||
		native.issued != 1 || r.applies != 1 || len(native.tokens) != 1 {
		t.Fatal("concurrent provider instances issued or applied more than one identity")
	}
	deletions := make(chan error, 2)
	for _, provider := range providers {
		go func() { deletions <- provider.Delete(t.Context(), deletion(request)) }()
	}
	firstErr, secondErr := <-deletions, <-deletions
	if firstErr != nil || secondErr != nil || r.stops != 1 || r.purges != 1 || len(native.tokens) != 0 {
		t.Fatal("concurrent deletion did not converge on exact cleanup")
	}
}

func TestKibanaRejectsDependencyDriftBeforeRuntimeEffects(t *testing.T) {
	config, r, native, request := kibanaFixture(t)
	provider, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.Ensure(t.Context(), request); err != nil {
		t.Fatal(err)
	}
	applies, stops, issued := r.applies, r.stops, native.issued
	changed := request
	dependency := *request.Elasticsearch
	dependency.InstallationID = "other-elasticsearch"
	changed.Elasticsearch = &dependency
	if _, err := provider.Ensure(t.Context(), changed); err == nil {
		t.Fatal("dependency drift accepted")
	}
	if err := provider.Delete(t.Context(), deletion(changed)); err == nil {
		t.Fatal("deletion drift accepted")
	}
	if r.applies != applies || r.stops != stops || native.issued != issued {
		t.Fatal("dependency drift reached effects")
	}
	for _, mutate := range []func(*adapterv1.ProvisionRequest){
		func(v *adapterv1.ProvisionRequest) { v.Elasticsearch = nil },
		func(v *adapterv1.ProvisionRequest) {
			d := *v.Elasticsearch
			d.EngineVersion = "8.0.0"
			v.Elasticsearch = &d
		},
		func(v *adapterv1.ProvisionRequest) {
			d := *v.Elasticsearch
			d.ResourceVersion = 0
			v.Elasticsearch = &d
		},
		func(v *adapterv1.ProvisionRequest) { d := *v.Elasticsearch; d.RegionID = "other"; v.Elasticsearch = &d },
		func(v *adapterv1.ProvisionRequest) { v.QuotaShape.MemoryMiB = 1 },
	} {
		invalid := request
		mutate(&invalid)
		if _, err := provider.Ensure(t.Context(), invalid); err == nil {
			t.Fatal("invalid dependency profile accepted")
		}
	}
	if r.applies != applies || r.stops != stops || native.issued != issued {
		t.Fatal("invalid profile reached effects")
	}
}

func TestKibanaMissingLiveTokenAndRevocationFailurePreserveCustody(t *testing.T) {
	config, r, native, request := kibanaFixture(t)
	provider, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.Ensure(t.Context(), request); err != nil {
		t.Fatal(err)
	}
	project := localcontainer.ProjectName(request.TenantID, request.InstallationID)
	tokenPath := filepath.Join(config.Root, project, "kibana-service-token")
	token, err := os.ReadFile(tokenPath)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(token)
	if err := os.Remove(tokenPath); err != nil {
		t.Fatal(err)
	}
	issued := native.issued
	if _, err := provider.Ensure(t.Context(), request); err == nil || native.issued != issued || !r.running[project] {
		t.Fatal("missing live token was silently rotated")
	}
	if err := localcontainer.WriteImmutable(tokenPath, token, 0o600); err != nil {
		t.Fatal(err)
	}
	native.rejectDelete = true
	if err := provider.Delete(t.Context(), deletion(request)); err == nil {
		t.Fatal("unrevoked credential was reported deleted")
	}
	if r.running[project] || r.purges != 0 {
		t.Fatal("revocation failure did not stop runtime and retain custody")
	}
	if _, err := os.Stat(tokenPath); err != nil {
		t.Fatal("failed revocation destroyed recovery material")
	}
	native.rejectDelete = false
	if err := provider.Delete(t.Context(), deletion(request)); err != nil {
		t.Fatal(err)
	}
}

func TestKibanaRefusesExistingSavedObjectsWithoutCustody(t *testing.T) {
	config, r, native, request := kibanaFixture(t)
	native.existingSavedObjects = true
	provider, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.Ensure(t.Context(), request); err == nil || r.applies != 0 || native.issued != 0 {
		t.Fatal("external saved objects adopted with invented keys")
	}
	if err := provider.Delete(t.Context(), deletion(request)); err != nil {
		t.Fatal("pre-issuance failure could not be cleaned")
	}
}

func deletion(request adapterv1.ProvisionRequest) adapterv1.DeprovisionRequest {
	return adapterv1.DeprovisionRequest{TenantID: request.TenantID, InstallationID: request.InstallationID, OperationID: "delete-kibana", OfferingID: request.OfferingID, EngineVersion: request.EngineVersion, RegionID: request.RegionID, Elasticsearch: request.Elasticsearch}
}

func kibanaFixture(t *testing.T) (Config, *fixtureRuntime, *fixtureNative, adapterv1.ProvisionRequest) {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	request := adapterv1.ProvisionRequest{TenantID: "tenant-one", InstallationID: "first-kibana", OperationID: "create-kibana", OfferingID: managedv1.KibanaOfferingID, EngineVersion: Version, RegionID: "local-primary",
		QuotaShape:    managedv1.QuotaShape{ID: "kibana-small", DisplayName: "开发型", CPUMillicores: 1000, MemoryMiB: 1536, StorageGiB: 10},
		Elasticsearch: &adapterv1.ElasticsearchDependency{InstallationID: "dependency-elasticsearch", ResourceVersion: 3, EngineVersion: Version, RegionID: "local-primary"}}
	esRoot := filepath.Join(root, "managed-elasticsearch")
	esProject := localcontainer.ProjectName(request.TenantID, request.Elasticsearch.InstallationID)
	esDirectory := filepath.Join(esRoot, esProject)
	if err := os.MkdirAll(esDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	imageID := "sha256:" + strings.Repeat("a", 64)
	labels := map[string]string{"com.xiak.matrix.managed": "true", "com.xiak.matrix.managedservice.installation": request.Elasticsearch.InstallationID, "com.xiak.matrix.managedservice.offering": managedv1.ElasticsearchOfferingID, "com.xiak.matrix.managedservice.region": "local-primary"}
	document, _ := json.Marshal(map[string]any{"name": esProject, "services": map[string]any{
		"elasticsearch":          map[string]any{"image": imageID, "labels": labels, "networks": []string{"private"}},
		"elasticsearch-endpoint": map[string]any{"image": imageID, "labels": labels, "ports": []string{"127.0.0.1:27123:13306/tcp"}},
	}})
	for name, content := range map[string][]byte{"compose.json": document, "observe.json": document, "published-port": []byte("27123"), "elasticsearch-password": []byte(strings.Repeat("p", 64))} {
		if err := os.WriteFile(filepath.Join(esDirectory, name), content, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	r := &fixtureRuntime{t: t, elasticsearchProject: esProject, elasticsearchLabels: labels, running: map[string]bool{}, requests: map[string]adapterv1.ProvisionRequest{}}
	native := &fixtureNative{t: t, tokens: map[string]string{}}
	r.native = native
	config := Config{Root: filepath.Join(root, "managed-kibana"), ImageID: imageID, EndpointImageID: imageID, ElasticsearchRoot: esRoot, ElasticsearchImageID: imageID, Runtime: r}
	return config, r, native, request
}

type fixtureRuntime struct {
	// Docker is a separate process in production. Protect the in-memory
	// substitute independently of the provider's OS file lock, which is not
	// a Go memory synchronization primitive.
	mu                     sync.Mutex
	t                      *testing.T
	elasticsearchProject   string
	elasticsearchLabels    map[string]string
	running                map[string]bool
	requests               map[string]adapterv1.ProvisionRequest
	native                 *fixtureNative
	applies, stops, purges int
}

func (r *fixtureRuntime) Ready(context.Context) error { return nil }
func (r *fixtureRuntime) RequestContainerHTTP(ctx context.Context, request compose.ContainerHTTPRequest) (int, []byte, error) {
	if request.ContainerID != r.elasticsearchProject+"-elasticsearch" || request.Port != 9200 {
		r.t.Fatal("native request escaped the exact observed dependency container")
	}
	httpRequest, err := http.NewRequestWithContext(ctx, request.Method, "http://127.0.0.1:9200"+request.Path, nil)
	if err != nil {
		return 0, nil, err
	}
	httpRequest.Header.Set("Authorization", request.Authorization)
	response, err := r.native.RoundTrip(httpRequest)
	if err != nil {
		return 0, nil, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	return response.StatusCode, body, err
}
func (r *fixtureRuntime) Apply(_ context.Context, project compose.RuntimeProject) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.applies++
	content, err := os.ReadFile(filepath.Join(project.Directory, "product-configuration.json"))
	if err != nil {
		return err
	}
	var binding struct{ Request adapterv1.ProvisionRequest }
	if json.Unmarshal(content, &binding) != nil {
		return errors.New("invalid fixture binding")
	}
	if _, err := os.Stat(filepath.Join(project.Directory, "kibana.yml")); err != nil {
		return err
	}
	r.requests[project.Name] = binding.Request
	r.running[project.Name] = true
	return nil
}
func (r *fixtureRuntime) Observe(_ context.Context, project compose.RuntimeProject) ([]compose.RuntimeContainer, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	labels := r.elasticsearchLabels
	services := map[string]uint32{"elasticsearch": 0, "elasticsearch-endpoint": 1}
	if project.Name != r.elasticsearchProject {
		if !r.running[project.Name] {
			return nil, nil
		}
		labels = ownershipLabels(r.requests[project.Name])
		services = map[string]uint32{"kibana": 0, "kibana-endpoint": 1, dependencyService: 0}
	}
	result := make([]compose.RuntimeContainer, 0, len(services))
	for service, ports := range services {
		result = append(result, compose.RuntimeContainer{ID: project.Name + "-" + service, Project: project.Name, Service: service, State: "running", Health: "healthy", PublishedPorts: ports, Labels: labels})
	}
	return result, nil
}
func (r *fixtureRuntime) Stop(_ context.Context, project compose.RuntimeProject) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.stops++
	delete(r.running, project.Name)
	return nil
}
func (r *fixtureRuntime) PurgeData(context.Context, compose.RuntimeProject, string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.purges++
	return nil
}

type fixtureNative struct {
	mu                                             sync.Mutex
	t                                              *testing.T
	tokens                                         map[string]string
	issued                                         int
	loseCreate, rejectDelete, existingSavedObjects bool
}

func (f *fixtureNative) RoundTrip(request *http.Request) (*http.Response, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.t.Helper()
	if request.URL.Host != "127.0.0.1:9200" {
		f.t.Fatal("dependency credential escaped its exact endpoint")
	}
	status := http.StatusOK
	var body any
	switch {
	case request.URL.Path == "/_security/_authenticate":
		body = map[string]any{"error": "unauthenticated"}
		status = http.StatusUnauthorized
		for name, token := range f.tokens {
			if request.Header.Get("Authorization") == "Bearer "+token {
				status = http.StatusOK
				body = map[string]any{"username": "elastic/kibana", "token": map[string]string{"name": name, "type": "_service_account_index"}}
			}
		}
	default:
		user, password, ok := request.BasicAuth()
		if !ok || user != "elastic" || password != strings.Repeat("p", 64) {
			f.t.Fatal("native custody request lacks its verified dependency credential")
		}
		if request.URL.Path == "/_resolve/index/.kibana*" {
			body = map[string]any{"indices": []string{}, "aliases": []string{}}
			if f.existingSavedObjects {
				body = map[string]any{"indices": []string{"existing"}, "aliases": []string{}}
			}
		} else if strings.HasPrefix(request.URL.Path, "/_security/service/elastic/kibana/credential/token/") {
			name := strings.TrimPrefix(request.URL.Path, "/_security/service/elastic/kibana/credential/token/")
			switch request.Method {
			case http.MethodDelete:
				if f.rejectDelete {
					return nil, errors.New("injected native transport failure")
				}
				_, found := f.tokens[name]
				delete(f.tokens, name)
				if !found {
					status = http.StatusNotFound
				}
				body = map[string]bool{"found": found}
			case http.MethodPost:
				if f.tokens[name] != "" {
					f.t.Fatal("existing token overwritten without own-name recovery")
				}
				f.issued++
				token := strings.Repeat(string(rune('a'+f.issued)), 64)
				f.tokens[name] = token
				if f.loseCreate {
					f.loseCreate = false
					return nil, errors.New("injected lost issuance response")
				}
				body = map[string]any{"created": true, "token": map[string]string{"name": name, "value": token}}
			default:
				f.t.Fatal("unexpected dependency method")
			}
		} else {
			f.t.Fatal("unexpected dependency path")
		}
	}
	content, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	return &http.Response{StatusCode: status, Body: io.NopCloser(bytes.NewReader(content)), Header: make(http.Header), Request: request}, nil
}

func readSettings(t *testing.T, path string) map[string]any {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(content)
	var settings map[string]any
	if json.Unmarshal(content, &settings) != nil {
		t.Fatal("invalid protected settings")
	}
	return settings
}

func checkPrivateDeployment(t *testing.T, path string) {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(content, []byte("serviceAccountToken")) || bytes.Contains(content, []byte("encryptionKey")) {
		t.Fatal("deployment embeds a secret")
	}
	var document struct {
		Services map[string]struct {
			Networks, Ports, CapDrop []string
			Sysctls                  map[string]string
		}
	}
	if json.Unmarshal(content, &document) != nil || len(document.Services) != 3 {
		t.Fatal("Kibana runtime inventory is not closed")
	}
	product := document.Services["kibana"]
	relay := document.Services[dependencyService]
	if len(product.Ports) != 0 || len(product.Networks) != 1 || product.Networks[0] != "private" ||
		len(relay.Ports) != 0 || len(relay.Networks) != 2 || relay.Sysctls["net.ipv4.ip_forward"] != "0" {
		t.Fatal("Kibana can bypass the bounded dependency route")
	}
}
