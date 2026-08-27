package topology

import (
	"encoding/json"
	"path"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/xiak/matrix/app/service/installation/internal/layout"
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
	networks, ok := document["networks"].(map[string]any)
	if !ok {
		t.Fatal("compiled topology has no networks object")
	}
	expectedNetworks := map[string]bool{"control": true, "edge": false, "web": true}
	actualNetworks := make([]string, 0, len(networks))
	for name, raw := range networks {
		network, valid := raw.(map[string]any)
		internal, hasInternal := network["internal"].(bool)
		labels, hasLabels := network["labels"].(map[string]any)
		if !valid || !hasInternal || internal != expectedNetworks[name] || !hasLabels ||
			labels["com.xiak.matrix.managed"] != "true" ||
			labels["com.xiak.matrix.installation"] != options.InstallationID ||
			labels["com.xiak.matrix.release"] != manifest.Release.ID ||
			labels["com.xiak.matrix.role"] != "network-"+name {
			t.Fatalf("network %q violates the fixed ingress/isolation boundary: %#v", name, raw)
		}
		actualNetworks = append(actualNetworks, name)
	}
	slices.Sort(actualNetworks)
	if !slices.Equal(actualNetworks, []string{"control", "edge", "web"}) {
		t.Fatalf("compiled networks = %v", actualNetworks)
	}

	portCount := 0
	foundExecutorRoot := false
	foundDockerSocket := false
	foundPostgresData := false
	foundAPISIXRuntimeBoundary := false
	expectedEntrypoints := map[string]string{
		"audit":                 "/matrix/bin/matrix-audit",
		"iam":                   "/matrix/bin/matrix-iam",
		"iam-audit-dispatcher":  "/matrix/bin/matrix-iam-audit-dispatcher",
		"paas-api":              "/matrix/bin/matrix-paas",
		"paas-audit-dispatcher": "/matrix/bin/matrix-paas-audit-dispatcher",
		"paas-ui":               "/matrix/bin/matrix-paas-ui",
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
		"paas-ui": {"MATRIX_PAAS_UI_LISTEN_ADDRESS"},
		"paas-worker": {
			"DOCKER_CONFIG", "DOCKER_HOST",
			"MATRIX_PAAS_WORKER_ARTIFACT_CATALOG_FILE", "MATRIX_PAAS_WORKER_BINDING_REF",
			"MATRIX_PAAS_WORKER_BINDING_ROOT", "MATRIX_PAAS_WORKER_DATABASE_DSN_FILE",
			"MATRIX_PAAS_WORKER_EXECUTION_TENANT_ID", "MATRIX_PAAS_WORKER_ID",
			"MATRIX_PAAS_WORKER_LISTEN_ADDRESS", "MATRIX_PAAS_WORKER_MACHINE_BINDING_REF",
			"MATRIX_PAAS_WORKER_MANAGED_POSTGRES_IMAGE",
			"MATRIX_PAAS_WORKER_SECRET_ROOT",
		},
	}
	expectedImageComponents := map[string]string{
		"apisix": "apisix", "audit": "audit", "iam": "iam",
		"iam-audit-dispatcher": "iam", "paas-api": "paas",
		"paas-audit-dispatcher": "paas", "paas-ui": "paas-ui",
		"paas-worker": "paas",
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
		if name == "apisix" {
			if service["user"] != "0:0" {
				t.Fatalf("APISIX runtime user=%#v", service["user"])
			}
		} else if _, found := service["user"]; found {
			t.Fatalf("service %q unexpectedly overrides its image user", name)
		}
		serviceNetworks, ok := service["networks"].([]any)
		if !ok {
			t.Fatalf("service %q has no fixed network inventory", name)
		}
		actualServiceNetworks := make([]string, 0, len(serviceNetworks))
		for _, network := range serviceNetworks {
			value, valid := network.(string)
			if !valid {
				t.Fatalf("service %q network is invalid: %#v", name, network)
			}
			actualServiceNetworks = append(actualServiceNetworks, value)
		}
		slices.Sort(actualServiceNetworks)
		if name == "apisix" {
			if !slices.Equal(actualServiceNetworks, []string{"control", "edge", "web"}) {
				t.Fatalf("APISIX network boundary=%v", actualServiceNetworks)
			}
		} else if slices.Contains(actualServiceNetworks, "edge") {
			t.Fatalf("service %q can join the northbound edge network", name)
		}
		labels, ok := service["labels"].(map[string]any)
		if !ok || labels["com.xiak.matrix.managed"] != "true" ||
			labels["com.xiak.matrix.installation"] != options.InstallationID ||
			labels["com.xiak.matrix.release"] != manifest.Release.ID ||
			labels["com.xiak.matrix.role"] != name {
			t.Fatalf("service %q ownership labels=%#v", name, service["labels"])
		}
		if component, built := expectedImageComponents[name]; built {
			if labels[release.BuiltImageLabelReleaseBuild] != "true" ||
				labels[release.BuiltImageLabelComponent] != component ||
				labels[release.BuiltImageLabelSourceCommit] != manifest.Release.SourceCommit ||
				labels[release.BuiltImageLabelBuildID] != manifest.Release.BuildID {
				t.Fatalf("service %q signed build labels=%#v", name, labels)
			}
		} else {
			for key := range release.BuiltImageLabels(manifest.Release, "postgres") {
				if _, found := labels[key]; found {
					t.Fatalf("upstream PostgreSQL declares Matrix build label %q", key)
				}
			}
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
		switch name {
		case "postgres":
			actual := make([]string, 0)
			for _, value := range service["cap_add"].([]any) {
				actual = append(actual, value.(string))
			}
			expected := []string{
				"CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_FOWNER", "CAP_SETGID", "CAP_SETUID",
			}
			if !slices.Equal(actual, expected) {
				t.Fatalf("PostgreSQL bootstrap capabilities=%v want=%v", actual, expected)
			}
		case "apisix":
			actual := make([]string, 0)
			for _, value := range service["cap_add"].([]any) {
				actual = append(actual, value.(string))
			}
			expected := []string{"CAP_CHOWN", "CAP_SETGID", "CAP_SETUID"}
			if !slices.Equal(actual, expected) {
				t.Fatalf("APISIX bootstrap capabilities=%v want=%v", actual, expected)
			}
		default:
			if _, found := service["cap_add"]; found {
				t.Fatalf("service %q has unnecessary added capabilities", name)
			}
		}
		if name == "postgres" {
			health, ok := service["healthcheck"].(map[string]any)
			test, testOK := health["test"].([]any)
			arguments := make([]string, 0, len(test))
			for _, raw := range test {
				value, valid := raw.(string)
				if !valid {
					t.Fatalf("PostgreSQL health argument is invalid: %#v", raw)
				}
				arguments = append(arguments, value)
			}
			host := slices.Index(arguments, "-h")
			if !ok || !testOK || len(arguments) < 4 || arguments[0] != "CMD" ||
				arguments[1] != "pg_isready" || host < 2 || host+1 >= len(arguments) ||
				arguments[host+1] != "127.0.0.1" {
				t.Fatalf(
					"PostgreSQL health contract can admit its temporary init server: %#v",
					service["healthcheck"],
				)
			}
		} else {
			health, ok := service["healthcheck"].(map[string]any)
			test, testOK := health["test"].([]any)
			if !ok || !testOK || len(test) != 3 || test[0] != "CMD" ||
				test[1] != "/matrix/bin/matrix-health" ||
				!strings.HasPrefix(test[2].(string), "http://127.0.0.1:") {
				t.Fatalf("service %q health contract=%#v", name, service["healthcheck"])
			}
		}
		tmpfsValues := make([]string, 0)
		for _, value := range service["tmpfs"].([]any) {
			tmpfsValues = append(tmpfsValues, value.(string))
		}
		hasDockerStateTmpfs := slices.Contains(
			tmpfsValues, "/var/lib/docker:rw,noexec,nosuid,size=16m",
		)
		paasImageService := name == "paas-api" || name == "paas-worker" ||
			name == "paas-audit-dispatcher"
		if hasDockerStateTmpfs != paasImageService {
			t.Fatalf("service %q Docker image-volume suppression=%t", name, hasDockerStateTmpfs)
		}
		if (name == "apisix") != slices.Contains(
			tmpfsValues,
			"/usr/local/apisix/logs:rw,nosuid,size=16m,mode=0700,uid=0,gid=0",
		) {
			t.Fatalf("service %q APISIX log runtime boundary=%v", name, tmpfsValues)
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
				if name == "postgres" && source == options.Root+"/data/postgres" {
					foundPostgresData = target == "/var/lib/postgresql" && mount["read_only"] != true
				}
			}
			if name == "apisix" {
				expected := map[string]struct {
					source   string
					readOnly bool
				}{
					"/usr/local/apisix/conf/config.yaml": {
						path.Join(options.Root, layout.APISIXConfig), true,
					},
					"/usr/local/apisix/conf/apisix.yaml": {
						path.Join(options.Root, layout.APISIXRoutes), true,
					},
					"/usr/local/apisix/conf/apisix.uid": {
						path.Join(options.Root, layout.APISIXUID), true,
					},
					"/usr/local/apisix/conf/nginx.conf": {
						path.Join(options.Root, layout.APISIXNginx), false,
					},
				}
				if len(volumes) != len(expected) {
					t.Fatalf("APISIX mount count=%d want=%d", len(volumes), len(expected))
				}
				for _, rawMount := range volumes {
					mount := rawMount.(map[string]any)
					target := mount["target"].(string)
					want, found := expected[target]
					readOnly, _ := mount["read_only"].(bool)
					if !found || mount["source"] != want.source || readOnly != want.readOnly {
						t.Fatalf("APISIX mount=%#v", mount)
					}
				}
				foundAPISIXRuntimeBoundary = true
			}
		}
	}
	if portCount != 1 || !foundExecutorRoot || !foundDockerSocket || !foundPostgresData ||
		!foundAPISIXRuntimeBoundary {
		t.Fatalf(
			"platform capability closure: ports=%d executor=%t socket=%t postgres-data=%t apisix=%t",
			portCount, foundExecutorRoot, foundDockerSocket, foundPostgresData,
			foundAPISIXRuntimeBoundary,
		)
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
		Database:         release.CurrentDatabaseProfile(),
		TopologyDigest:   ContractDigest(), Files: files, Images: images,
	}
}

func digest(value byte) string {
	return "sha256:" + strings.Repeat(string(value), 64)
}
