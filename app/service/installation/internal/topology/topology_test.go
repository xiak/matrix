package topology

import (
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/xiak/matrix/app/service/installation/internal/release"
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
	for name, raw := range services {
		service, ok := raw.(map[string]any)
		if !ok || service["pull_policy"] != "never" {
			t.Fatalf("service %q is not pull-never", name)
		}
		for _, forbidden := range []string{"build", "privileged", "env_file", "network_mode"} {
			if _, found := service[forbidden]; found {
				t.Fatalf("service %q expresses forbidden capability %q", name, forbidden)
			}
		}
		image, ok := service["image"].(string)
		if !ok || !strings.HasPrefix(image, "sha256:") {
			t.Fatalf("service %q image is not immutable: %#v", name, service["image"])
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
		"listener hostname":  func(value *Options) { value.Listener = "localhost" },
		"listener multicast": func(value *Options) { value.Listener = "224.0.0.1" },
		"listener port":      func(value *Options) { value.Port = 0 },
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
	health := map[string]string{
		"apisix": "northbound-ready-v1", "audit": "audit-ready-deduplicate-v1",
		"iam": "iam-ready-authorize-v1", "paas": "paas-ready-worker-compose-v1",
		"paas-ui": "paas-ui-ready-v1", "postgres": "postgres-ready-schema-v1",
	}
	images := make([]release.Image, 0, len(release.RequiredImageComponents()))
	fileDigests := "234567"
	imageDigests := "89abcd"
	sourceDigests := "ef0123"
	for index, component := range release.RequiredImageComponents() {
		archive := "images/" + component + ".tar"
		files = append(files, release.File{
			Path: archive, MediaType: "application/vnd.docker.image.archive",
			Size: 1024 + uint64(index), SHA256: digest(fileDigests[index]),
		})
		images = append(images, release.Image{
			Component: component, ArchivePath: archive,
			ImageID: digest(imageDigests[index]), SourceDigest: digest(sourceDigests[index]),
			OS: "linux", Architecture: "amd64", HealthContract: health[component],
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
