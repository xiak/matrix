package localkibana

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	adapterv1 "github.com/xiak/matrix/api/adapter/managedservice/v1"
	managedv1 "github.com/xiak/matrix/api/managedservice/v1"
	compose "github.com/xiak/matrix/app/adapter/apphosting/compose"
	localcontainer "github.com/xiak/matrix/app/adapter/managedservice/localcontainer"
)

type elasticsearchTarget struct {
	directory, endpoint string
	password            []byte
}

type tokenIntent struct {
	Dependency adapterv1.ElasticsearchDependency
	Name       string
}

func (p *Provisioner) resolveDependency(ctx context.Context, tenant string, dependency *adapterv1.ElasticsearchDependency) (elasticsearchTarget, error) {
	empty := elasticsearchTarget{}
	if dependency == nil || protectedDirectory(p.config.ElasticsearchRoot) != nil {
		return empty, errDependency
	}
	projectName := localcontainer.ProjectName(tenant, dependency.InstallationID)
	directory := filepath.Join(p.config.ElasticsearchRoot, projectName)
	if protectedDirectory(directory) != nil {
		return empty, errDependency
	}
	content, err := readPrivate(filepath.Join(directory, "compose.json"), 0o600, 65536)
	if err != nil {
		return empty, err
	}
	defer clear(content)
	var document struct {
		Name     string
		Services map[string]struct {
			Image           string
			Labels          map[string]string
			Networks, Ports []string
		}
	}
	if json.Unmarshal(content, &document) != nil || document.Name != projectName || len(document.Services) != 2 {
		return empty, errDependency
	}
	backend := document.Services["elasticsearch"]
	endpoint := document.Services["elasticsearch-endpoint"]
	if backend.Image != p.config.ElasticsearchImageID || len(backend.Ports) != 0 || len(backend.Networks) != 1 || backend.Networks[0] != "private" ||
		!imageIdentity.MatchString(endpoint.Image) || len(endpoint.Ports) != 1 ||
		backend.Labels["com.xiak.matrix.managed"] != "true" || backend.Labels["com.xiak.matrix.managedservice.installation"] != dependency.InstallationID ||
		backend.Labels["com.xiak.matrix.managedservice.offering"] != managedv1.ElasticsearchOfferingID || backend.Labels["com.xiak.matrix.managedservice.region"] != dependency.RegionID {
		return empty, errDependency
	}
	portBytes, err := readPrivate(filepath.Join(directory, "published-port"), 0o600, 5)
	if err != nil {
		return empty, err
	}
	port, err := strconv.Atoi(string(portBytes))
	if err != nil || port < 20000 || port > 39999 || string(portBytes) != strconv.Itoa(port) || endpoint.Ports[0] != "127.0.0.1:"+strconv.Itoa(port)+":13306/tcp" {
		return empty, errDependency
	}
	project := compose.RuntimeProject{Name: projectName, Directory: directory, EffectDocument: filepath.Join(directory, "compose.json"), ObservationDocument: filepath.Join(directory, "observe.json"), TimeoutSeconds: 120}
	observed, err := p.config.Runtime.Observe(ctx, project)
	if err != nil || len(observed) != 2 {
		return empty, errDependency
	}
	expected := map[string]uint32{"elasticsearch": 0, "elasticsearch-endpoint": 1}
	for _, c := range observed {
		ports, exists := expected[c.Service]
		if !exists || c.Project != projectName || c.OneOff || c.State != "running" || c.Health != "healthy" || c.PublishedPorts != ports {
			return empty, errDependency
		}
		for _, key := range []string{"com.xiak.matrix.managed", "com.xiak.matrix.managedservice.installation", "com.xiak.matrix.managedservice.offering", "com.xiak.matrix.managedservice.region"} {
			if c.Labels[key] != backend.Labels[key] {
				return empty, errDependency
			}
		}
		delete(expected, c.Service)
	}
	password, err := localcontainer.ReadProtectedSecret(filepath.Join(directory, "elasticsearch-password"))
	if err != nil {
		return empty, errDependency
	}
	return elasticsearchTarget{directory: directory, endpoint: "http://127.0.0.1:" + strconv.Itoa(port), password: password}, nil
}

func (p *Provisioner) prepareConfiguration(ctx context.Context, input localcontainer.DocumentInput) error {
	target, err := p.resolveDependency(ctx, input.Request.TenantID, input.Request.Elasticsearch)
	if err != nil {
		return err
	}
	defer clear(target.password)
	directory := filepath.Dir(input.DataDirectory)
	tokenPath := filepath.Join(directory, "kibana-service-token")
	savedKey, reportingKey, err := p.savedObjectKeys(ctx, target)
	if err != nil {
		return err
	}
	defer clear(savedKey)
	defer clear(reportingKey)
	intent := tokenIntent{Dependency: *input.Request.Elasticsearch, Name: input.ProjectName}
	intentBytes, err := json.Marshal(intent)
	if err != nil {
		return errDependency
	}
	if err := localcontainer.WriteImmutable(filepath.Join(directory, "kibana-token-intent.json"), intentBytes, 0o600); err != nil {
		return err
	}
	token, err := readToken(tokenPath)
	if errors.Is(err, os.ErrNotExist) {
		// A missing token can be reissued only before this exact runtime has
		// ever acquired settings. Never silently rotate a running credential.
		if _, settingsErr := os.Lstat(filepath.Join(directory, "kibana.yml")); !errors.Is(settingsErr, os.ErrNotExist) {
			return errDependency
		}
		project := compose.RuntimeProject{Name: input.ProjectName, Directory: directory, EffectDocument: filepath.Join(directory, "compose.json"), ObservationDocument: filepath.Join(directory, "observe.json"), TimeoutSeconds: 120}
		current, observeErr := p.config.Runtime.Observe(ctx, project)
		if observeErr != nil || len(current) != 0 {
			return errDependency
		}
		if err := p.deleteToken(ctx, target, intent.Name); err != nil {
			return err
		}
		status, body, createErr := p.callDependency(ctx, target, http.MethodPost, "/_security/service/elastic/kibana/credential/token/"+intent.Name, nil)
		defer clear(body)
		var created struct {
			Created bool
			Token   struct{ Name, Value string }
		}
		if createErr != nil || status != http.StatusOK || json.Unmarshal(body, &created) != nil || !created.Created || created.Token.Name != intent.Name {
			return errDependency
		}
		token = []byte(created.Token.Value)
		if !validToken(token) {
			clear(token)
			return errDependency
		}
		if err := localcontainer.WriteImmutable(tokenPath, token, 0o600); err != nil {
			clear(token)
			return err
		}
	} else if err != nil {
		return err
	}
	defer clear(token)
	if err := p.verifyToken(ctx, target, token, intent.Name); err != nil {
		return err
	}
	sessionKey, err := localcontainer.ReadProtectedSecret(input.CredentialPaths["kibana-session-key"])
	if err != nil {
		return err
	}
	defer clear(sessionKey)
	settings, err := json.Marshal(map[string]any{
		"server.host": "0.0.0.0", "server.port": 5601,
		"elasticsearch.hosts":                       []string{"http://" + dependencyService + ":13306"},
		"elasticsearch.serviceAccountToken":         string(token),
		"xpack.security.cookieName":                 "matrix-" + input.ProjectName,
		"xpack.security.encryptionKey":              string(sessionKey),
		"xpack.encryptedSavedObjects.encryptionKey": string(savedKey),
		"xpack.reporting.encryptionKey":             string(reportingKey),
		"telemetry.enabled":                         false, "newsfeed.enabled": false, "map.includeElasticMapsService": false,
		"xpack.fleet.isAirGapped": true, "xpack.fleet.registryUrl": "http://127.0.0.1:1",
		"status.allowAnonymous": true,
	})
	if err != nil {
		return errDependency
	}
	defer clear(settings)
	return localcontainer.WriteImmutable(filepath.Join(directory, "kibana.yml"), settings, 0o640)
}

func (p *Provisioner) releaseDependency(ctx context.Context, request adapterv1.DeprovisionRequest, directory string) error {
	content, err := readPrivate(filepath.Join(directory, "kibana-token-intent.json"), 0o600, 4096)
	if errors.Is(err, os.ErrNotExist) {
		if _, tokenErr := os.Lstat(filepath.Join(directory, "kibana-service-token")); errors.Is(tokenErr, os.ErrNotExist) {
			return nil
		}
		return errDependency
	}
	if err != nil {
		return err
	}
	var intent tokenIntent
	if json.Unmarshal(content, &intent) != nil || request.Elasticsearch == nil || intent.Dependency != *request.Elasticsearch ||
		intent.Name != localcontainer.ProjectName(request.TenantID, request.InstallationID) {
		return errDependency
	}
	target, err := p.resolveDependency(ctx, request.TenantID, request.Elasticsearch)
	if err != nil {
		return err
	}
	defer clear(target.password)
	if err := p.deleteToken(ctx, target, intent.Name); err != nil {
		return err
	}
	token, err := readToken(filepath.Join(directory, "kibana-service-token"))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer clear(token)
	status, body, err := p.callDependency(ctx, target, http.MethodGet, "/_security/_authenticate", token)
	clear(body)
	if err != nil || status != http.StatusUnauthorized {
		return errDependency
	}
	return nil
}

func (p *Provisioner) deleteToken(ctx context.Context, target elasticsearchTarget, name string) error {
	status, body, err := p.callDependency(ctx, target, http.MethodDelete, "/_security/service/elastic/kibana/credential/token/"+name, nil)
	defer clear(body)
	var response struct{ Found *bool }
	if err != nil || json.Unmarshal(body, &response) != nil || response.Found == nil ||
		!((status == http.StatusOK && *response.Found) || (status == http.StatusNotFound && !*response.Found)) {
		return errDependency
	}
	return nil
}

func (p *Provisioner) verifyToken(ctx context.Context, target elasticsearchTarget, token []byte, name string) error {
	status, body, err := p.callDependency(ctx, target, http.MethodGet, "/_security/_authenticate", token)
	defer clear(body)
	var response struct {
		Username string
		Token    struct{ Name, Type string }
	}
	if err != nil || status != http.StatusOK || json.Unmarshal(body, &response) != nil ||
		response.Username != "elastic/kibana" || response.Token.Name != name || response.Token.Type != "_service_account_index" {
		return errDependency
	}
	return nil
}

func (p *Provisioner) callDependency(ctx context.Context, target elasticsearchTarget, method, path string, token []byte) (int, []byte, error) {
	request, err := http.NewRequestWithContext(ctx, method, target.endpoint+path, nil)
	if err != nil {
		return 0, nil, errDependency
	}
	if token == nil {
		request.SetBasicAuth("elastic", string(target.password))
	} else {
		request.Header.Set("Authorization", "Bearer "+string(token))
	}
	response, err := p.config.HTTPClient.Do(request)
	if err != nil {
		return 0, nil, errDependency
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 65537))
	if err != nil || len(body) > 65536 {
		clear(body)
		return 0, nil, errDependency
	}
	return response.StatusCode, body, nil
}

func (p *Provisioner) savedObjectKeys(ctx context.Context, target elasticsearchTarget) ([]byte, []byte, error) {
	paths := []string{filepath.Join(target.directory, "kibana-saved-objects-key"), filepath.Join(target.directory, "kibana-reporting-key")}
	missing := false
	for _, path := range paths {
		if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
			missing = true
		} else if err != nil {
			return nil, nil, errDependency
		}
	}
	if missing {
		// Existing externally managed Kibana data must not be adopted with
		// invented keys. Import/rotation is outside this closed product profile.
		status, body, err := p.callDependency(ctx, target, http.MethodGet, "/_resolve/index/.kibana*?expand_wildcards=all", nil)
		defer clear(body)
		var indices struct {
			Indices []json.RawMessage
			Aliases []json.RawMessage
		}
		if err != nil || status != http.StatusOK || json.Unmarshal(body, &indices) != nil || len(indices.Indices) > 0 || len(indices.Aliases) > 0 {
			return nil, nil, errDependency
		}
	}
	keys := make([][]byte, 0, 2)
	for _, path := range paths {
		key, err := localcontainer.ReadProtectedSecret(path)
		if err != nil {
			if _, statErr := os.Lstat(path); !errors.Is(statErr, os.ErrNotExist) {
				for _, k := range keys {
					clear(k)
				}
				return nil, nil, errDependency
			}
			raw := make([]byte, 32)
			if _, err := rand.Read(raw); err != nil {
				for _, k := range keys {
					clear(k)
				}
				return nil, nil, errDependency
			}
			key = []byte(hex.EncodeToString(raw))
			clear(raw)
			publishErr := localcontainer.WriteImmutable(path, key, 0o600)
			if publishErr != nil {
				clear(key)
				// Another Kibana may have atomically published the shared key.
				key, err = localcontainer.ReadProtectedSecret(path)
				if err != nil {
					for _, k := range keys {
						clear(k)
					}
					return nil, nil, errDependency
				}
			}
		}
		keys = append(keys, key)
	}
	return keys[0], keys[1], nil
}

func readPrivate(path string, mode os.FileMode, limit int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, os.ErrNotExist
	}
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > limit ||
		(runtime.GOOS != "windows" && info.Mode().Perm() != mode) {
		return nil, errDependency
	}
	content, err := os.ReadFile(path)
	if err != nil || int64(len(content)) > limit {
		clear(content)
		return nil, errDependency
	}
	return content, nil
}

func readToken(path string) ([]byte, error) {
	content, err := readPrivate(path, 0o600, 1024)
	if err != nil {
		return nil, err
	}
	if !validToken(content) {
		clear(content)
		return nil, errDependency
	}
	return content, nil
}

func validToken(token []byte) bool {
	if len(token) < 32 || len(token) > 1024 || bytes.ContainsAny(token, " \r\n\t") {
		return false
	}
	for _, b := range token {
		if !strings.ContainsRune("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-+/=", rune(b)) {
			return false
		}
	}
	return true
}
