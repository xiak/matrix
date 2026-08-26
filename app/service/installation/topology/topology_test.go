package topology

import (
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/xiak/matrix/app/service/installation/release"
)

func TestCompileProducesClosedOfflinePlatformTopology(t *testing.T) {
	manifest := topologyManifest()
	options := Options{
		InstallationID: "mxi-" + strings.Repeat("a", 32),
		Root:           "/srv/matrix", Listener: "127.0.0.1", Port: 8443,
	}
	result, err := Compile(manifest, options)
	if err != nil {
		t.Fatalf("compile platform topology: %v", err)
	}
	if result.ProjectName != "matrix-"+strings.Repeat("a", 32) ||
		result.ContractDigest != manifest.TopologyDigest {
		t.Fatalf("compiled topology identity = %#v", result)
	}
	var document map[string]any
	if err := json.Unmarshal(result.ComposeJSON, &document); err != nil {
		t.Fatalf("decode Compose JSON: %v", err)
	}
	services, ok := document["services"].(map[string]any)
	if !ok {
		t.Fatal("compiled topology has no services object")
	}
	expectedServices := slices.Clone(platformServiceNames)
	actualServices := make([]string, 0, len(services))
	for name := range services {
		actualServices = append(actualServices, name)
	}
	slices.Sort(actualServices)
	if !slices.Equal(actualServices, expectedServices) {
		t.Fatalf("compiled services = %v, want %v", actualServices, expectedServices)
	}

	portCount := 0
	foundExecutorRoot := false
	foundDockerSocket := false
	expectedEntrypoints := map[string]string{
		"audit":                 "/matrix/bin/matrix-audit",
		"iam":                   "/matrix/bin/matrix-iam",
		"iam-audit-dispatcher":  "/matrix/bin/matrix-iam-audit-dispatcher",
		"paas-api":              "/matrix/bin/matrix-paas",
		"paas-audit-dispatcher": "/matrix/bin/matrix-paas-audit-dispatcher",
		"paas-worker":           "/matrix/bin/matrix-paas-worker",
	}
	expectedEnvironmentKeys := map[string][]string{
		"audit": {
			"MATRIX_AUDIT_CURSOR_KEY_FILE", "MATRIX_AUDIT_DATABASE_DSN_FILE",
			"MATRIX_AUDIT_IAM_ENDPOINT", "MATRIX_AUDIT_LISTEN_ADDRESS",
			"MATRIX_AUDIT_SERVICE_CREDENTIAL_FILE",
		},
		"iam": {
			"MATRIX_IAM_BOOTSTRAP_FILE", "MATRIX_IAM_DATABASE_DSN_FILE",
			"MATRIX_IAM_LISTEN_ADDRESS",
		},
		"iam-audit-dispatcher": {
			"MATRIX_IAM_AUDIT_CREDENTIAL_FILE", "MATRIX_IAM_AUDIT_DATABASE_DSN_FILE",
			"MATRIX_IAM_AUDIT_ENDPOINT", "MATRIX_IAM_AUDIT_LISTEN_ADDRESS",
			"MATRIX_IAM_AUDIT_WORKER_ID",
		},
		"paas-api": {
			"MATRIX_PAAS_DATABASE_DSN_FILE", "MATRIX_PAAS_IAM_ENDPOINT",
			"MATRIX_PAAS_INSTALLATION_ID", "MATRIX_PAAS_LISTEN_ADDRESS",
			"MATRIX_PAAS_RELEASE_ID", "MATRIX_PAAS_SERVICE_CREDENTIAL_FILE",
			"MATRIX_PAAS_VERIFICATION_ARTIFACT_DIGEST",
		},
		"paas-audit-dispatcher": {
			"MATRIX_PAAS_AUDIT_CREDENTIAL_FILE", "MATRIX_PAAS_AUDIT_DATABASE_DSN_FILE",
			"MATRIX_PAAS_AUDIT_ENDPOINT", "MATRIX_PAAS_AUDIT_LISTEN_ADDRESS",
			"MATRIX_PAAS_AUDIT_WORKER_ID",
		},
		"paas-worker": {
			"DOCKER_HOST",
			"MATRIX_PAAS_WORKER_ARTIFACT_CATALOG_FILE", "MATRIX_PAAS_WORKER_BINDING_REF",
			"MATRIX_PAAS_WORKER_BINDING_ROOT", "MATRIX_PAAS_WORKER_DATABASE_DSN_FILE",
			"MATRIX_PAAS_WORKER_EXECUTION_TENANT_ID", "MATRIX_PAAS_WORKER_ID",
			"MATRIX_PAAS_WORKER_LISTEN_ADDRESS", "MATRIX_PAAS_WORKER_MACHINE_BINDING_REF",
			"MATRIX_PAAS_WORKER_SECRET_ROOT",
		},
	}
	for name, raw := range services {
		service, ok := raw.(map[string]any)
		if !ok || service["pull_policy"] != "never" {
			t.Fatalf("service %q is not pull-never", name)
		}
		for _, forbidden := range []string{"build", "command", "privileged", "env_file", "network_mode"} {
			if _, found := service[forbidden]; found {
				t.Fatalf("service %q expresses forbidden capability %q", name, forbidden)
			}
		}
		image, ok := service["image"].(string)
		if !ok || !strings.HasPrefix(image, "sha256:") {
			t.Fatalf("service %q image is not immutable: %#v", name, service["image"])
		}
		if binary, expected := expectedEntrypoints[name]; expected {
			entrypoint, ok := service["entrypoint"].([]any)
			if !ok || len(entrypoint) != 1 || entrypoint[0] != binary {
				t.Fatalf("service %q entrypoint=%#v want=%q", name, service["entrypoint"], binary)
			}
		}
		if keys, expected := expectedEnvironmentKeys[name]; expected {
			environment, ok := service["environment"].(map[string]any)
			if !ok {
				t.Fatalf("service %q has no environment", name)
			}
			actualKeys := make([]string, 0, len(environment))
			for key := range environment {
				actualKeys = append(actualKeys, key)
			}
			slices.Sort(actualKeys)
			if !slices.Equal(actualKeys, keys) {
				t.Fatalf("service %q environment keys=%v want=%v", name, actualKeys, keys)
			}
		}
		if name != "postgres" {
			health, ok := service["healthcheck"].(map[string]any)
			test, testOK := health["test"].([]any)
			if !ok || !testOK || len(test) != 3 || test[0] != "CMD" ||
				test[1] != "/matrix/bin/matrix-health" ||
				!strings.HasPrefix(test[2].(string), "http://127.0.0.1:") {
				t.Fatalf("service %q health contract=%#v", name, service["healthcheck"])
			}
		}
		if ports, found := service["ports"].([]any); found {
			portCount += len(ports)
			if name != "apisix" || len(ports) != 1 || ports[0] != "127.0.0.1:8443:9080/tcp" {
				t.Fatalf("service %q has unexpected northbound ports %#v", name, ports)
			}
		}
		if volumes, found := service["volumes"].([]any); found {
			for _, rawMount := range volumes {
				mount := rawMount.(map[string]any)
				source := mount["source"].(string)
				target := mount["target"].(string)
				if source != "/var/run/docker.sock" &&
					!strings.HasPrefix(source, options.Root+"/") {
					t.Fatalf("service %q mount escapes installation root: %#v", name, mount)
				}
				if strings.Contains(source, "/secrets/") && mount["read_only"] != true {
					t.Fatalf("service %q secret mount is writable: %#v", name, mount)
				}
				if name == "paas-worker" && source == options.Root+"/runtime/executor" {
					foundExecutorRoot = target == source
				}
				if name == "paas-worker" && source == "/var/run/docker.sock" {
					foundDockerSocket = target == source
				}
			}
		}
	}
	if portCount != 1 || !foundExecutorRoot || !foundDockerSocket {
		t.Fatalf("platform capability closure: ports=%d executor=%t socket=%t", portCount, foundExecutorRoot, foundDockerSocket)
	}
	encoded := string(result.ComposeJSON)
	for _, forbidden := range []string{"latest", "secret-value", "dockerfile", "registry"} {
		if strings.Contains(strings.ToLower(encoded), forbidden) {
			t.Fatalf("compiled topology contains forbidden plaintext/provider input %q", forbidden)
		}
	}
}

func TestCompileRejectsUntrustedTopologyInputs(t *testing.T) {
	valid := Options{
		InstallationID: "mxi-" + strings.Repeat("a", 32),
		Root:           "/srv/matrix", Listener: "0.0.0.0", Port: 9080,
	}
	tests := map[string]func(*Options){
		"relative root": func(value *Options) { value.Root = "srv/matrix" },
		"volume root":   func(value *Options) { value.Root = "/" },
		"root traversal": func(value *Options) {
			value.Root = "/srv/../matrix"
		},
		"Compose interpolation root": func(value *Options) { value.Root = "/srv/$matrix" },
		"listener hostname":          func(value *Options) { value.Listener = "localhost" },
		"listener multicast":         func(value *Options) { value.Listener = "224.0.0.1" },
		"listener port":              func(value *Options) { value.Port = 0 },
		"installation ID": func(value *Options) {
			value.InstallationID = "customer"
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			options := valid
			mutate(&options)
			if _, err := Compile(topologyManifest(), options); err == nil {
				t.Fatal("untrusted topology input must fail")
			}
		})
	}
	manifest := topologyManifest()
	manifest.TopologyDigest = digest('0')
	if _, err := Compile(manifest, valid); err == nil {
		t.Fatal("an unrecognized topology contract digest must fail")
	}
}

func TestOptionsCannotCarryProviderNativeTopology(t *testing.T) {
	typeOfOptions := reflect.TypeFor[Options]()
	want := []string{"InstallationID", "Root", "Listener", "Port"}
	got := make([]string, 0, typeOfOptions.NumField())
	for index := 0; index < typeOfOptions.NumField(); index++ {
		got = append(got, typeOfOptions.Field(index).Name)
	}
	if !slices.Equal(got, want) {
		t.Fatalf("topology input capability surface = %v, want %v", got, want)
	}
}

func topologyManifest() release.Manifest {
	commit := strings.Repeat("a", 40)
	files := []release.File{{
		Path: "bin/mx", MediaType: "application/vnd.matrix.executable",
		Size: 1024, SHA256: digest('1'), Executable: true,
	}}
	required := release.RequiredImages()
	images := make([]release.Image, 0, len(required))
	fileDigests := "2345678"
	imageDigests := "89abcde"
	sourceDigests := "ef01234"
	for index, requirement := range required {
		archive := "images/" + requirement.Component + ".tar"
		files = append(files, release.File{
			Path: archive, MediaType: "application/vnd.docker.image.archive",
			Size: 1024 + uint64(index), SHA256: digest(fileDigests[index]),
		})
		images = append(images, release.Image{
			Component: requirement.Component, Purpose: requirement.Purpose, ArchivePath: archive,
			ImageID: digest(imageDigests[index]), SourceDigest: digest(sourceDigests[index]),
			OS: "linux", Architecture: "amd64", HealthContract: requirement.HealthContract,
		})
	}
	slices.SortFunc(files, func(left, right release.File) int {
		return strings.Compare(left.Path, right.Path)
	})
	return release.Manifest{
		APIVersion: release.ManifestAPIVersion, Kind: release.ManifestKind,
		Release: release.ReleaseIdentity{
			ID: "matrix-v0.1.0-" + commit[:12], Version: "v0.1.0", SourceCommit: commit,
			BuildID: "build-gate-a", CreatedAt: time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC),
		},
		Signer: release.Signer{KeyID: "xiak-release-2026", Algorithm: release.SignatureAlgorithm},
		Host: release.HostProfile{
			OS: "linux", Architecture: "amd64", MinimumDocker: "29.0.0",
			MinimumCompose: "2.40.0", CommandContract: "v1",
		},
		MinimumFreeBytes: 1 << 30,
		Database: release.DatabaseProfile{
			SchemaVersion: 1, Compatibility: "expand-contract-n-minus-one",
		},
		TopologyDigest: ContractDigest(), Files: files, Images: images,
	}
}

func digest(value byte) string {
	return "sha256:" + strings.Repeat(string(value), 64)
}
