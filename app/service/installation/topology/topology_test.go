package topology

import (
	"crypto/sha256"
	"encoding/hex"
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

func TestInstalledCompilerReproducesAcceptedProductlessTopology(t *testing.T) {
	if actual := ContractDigest(); actual != "sha256:e5db4722f738a46747f1f96a20f16d3188fc92ee0a3daf629ed92c5e822a46f1" {
		t.Fatalf("current topology contract digest drifted: %s", actual)
	}
	if actual := legacyProductlessImplementationDigest(); actual != legacyProductlessContractDigest {
		t.Fatalf("productless topology implementation drifted: %s", actual)
	}
	manifest := legacyTopologyManifest()
	options := Options{
		InstallationID: "mxi-" + strings.Repeat("a", 32),
		Root:           "/srv/matrix", Listener: "127.0.0.1", Port: 8443,
	}
	if _, err := Compile(manifest, options); err == nil {
		t.Fatal("strict candidate compiler admitted the productless predecessor")
	}
	result, err := CompileInstalled(manifest, options)
	if err != nil {
		t.Fatalf("compile installed productless predecessor: %v", err)
	}
	digest := sha256.Sum256(result.ComposeJSON)
	if actual := "sha256:" + hex.EncodeToString(digest[:]); actual != "sha256:885a2478e75f43719f54d89db4f51b653316ee099c8e85be938ba420832b4936" {
		t.Fatalf("productless Compose bytes drifted: %s", actual)
	}
	var document composeDocument
	if err := json.Unmarshal(result.ComposeJSON, &document); err != nil {
		t.Fatalf("decode productless Compose: %v", err)
	}
	wantServices := []string{
		"apisix", "audit", "iam", "iam-audit-dispatcher", "paas-api",
		"paas-audit-dispatcher", "paas-ui", "paas-worker", "postgres",
	}
	actualServices := make([]string, 0, len(document.Services))
	for name := range document.Services {
		actualServices = append(actualServices, name)
	}
	slices.Sort(actualServices)
	if !slices.Equal(actualServices, wantServices) {
		t.Fatalf("productless services = %v, want %v", actualServices, wantServices)
	}

	drifted := manifest
	drifted.TopologyDigest = digestValue('0')
	if err := ValidateInstalledContract(drifted); err == nil {
		t.Fatal("a different productless topology digest must fail")
	}
}

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
	expectedNetworks := map[string]bool{
		"control": true, "edge": false, "source": false, "web": true,
	}
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
	if !slices.Equal(actualNetworks, []string{"control", "edge", "source", "web"}) {
		t.Fatalf("compiled networks = %v", actualNetworks)
	}

	portCount := 0
	foundExecutorRoot := false
	foundDockerSocket := false
	foundPostgresData := false
	foundAPISIXRuntimeBoundary := false
	foundDevOpsSourceSecrets := false
	foundDevOpsSourceFetcherBoundary := false
	foundDevOpsSourceObserverBoundary := false
	foundDevOpsBuildWorkerBoundary := false
	foundDevOpsExecutorGatewayBoundary := false
	expectedEntrypoints := map[string]string{
		"audit":                   "/matrix/bin/matrix-audit",
		"devops-api":              "/matrix/bin/matrix-devops",
		"devops-audit-dispatcher": "/matrix/bin/matrix-devops-audit-dispatcher",
		"devops-build-worker":     "/matrix/bin/matrix-devops-build-worker",
		"devops-executor-gateway": "/matrix/bin/matrix-devops-executor-gateway",
		"devops-source-fetcher":   "/matrix/bin/matrix-devops-source-fetcher",
		"devops-source-observer":  "/matrix/bin/matrix-devops-source-observer",
		"iam":                     "/matrix/bin/matrix-iam",
		"iam-audit-dispatcher":    "/matrix/bin/matrix-iam-audit-dispatcher",
		"matrix-ui":               "/matrix/bin/matrix-ui",
		"paas-api":                "/matrix/bin/matrix-paas",
		"paas-audit-dispatcher":   "/matrix/bin/matrix-paas-audit-dispatcher",
		"paas-worker":             "/matrix/bin/matrix-paas-worker",
		"platform-api":            "/matrix/bin/matrix-platform",
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
		"devops-api": {
			"MATRIX_DEVOPS_DATABASE_DSN_FILE", "MATRIX_DEVOPS_IAM_ENDPOINT",
			"MATRIX_DEVOPS_LISTEN_ADDRESS", "MATRIX_DEVOPS_SERVICE_CREDENTIAL_FILE",
			"MATRIX_DEVOPS_WEBHOOK_SECRET_ROOT",
		},
		"devops-audit-dispatcher": {
			"MATRIX_DEVOPS_AUDIT_CREDENTIAL_FILE", "MATRIX_DEVOPS_AUDIT_DATABASE_DSN_FILE",
			"MATRIX_DEVOPS_AUDIT_ENDPOINT", "MATRIX_DEVOPS_AUDIT_LISTEN_ADDRESS",
			"MATRIX_DEVOPS_AUDIT_WORKER_ID",
		},
		"devops-build-worker": {
			"MATRIX_DEVOPS_BUILD_WORKER_CLIENT_CERT_FILE",
			"MATRIX_DEVOPS_BUILD_WORKER_CLIENT_IDENTITY",
			"MATRIX_DEVOPS_BUILD_WORKER_CLIENT_KEY_FILE",
			"MATRIX_DEVOPS_BUILD_WORKER_DATABASE_DSN_FILE",
			"MATRIX_DEVOPS_BUILD_WORKER_GATEWAY_ORIGIN",
			"MATRIX_DEVOPS_BUILD_WORKER_GATEWAY_SERVER_NAME",
			"MATRIX_DEVOPS_BUILD_WORKER_ID",
			"MATRIX_DEVOPS_BUILD_WORKER_LISTEN_ADDRESS",
			"MATRIX_DEVOPS_BUILD_WORKER_SERVER_CA_FILE",
			"MATRIX_DEVOPS_BUILD_WORKER_SOURCE_ARCHIVE_ROOT",
		},
		"devops-executor-gateway": {
			"MATRIX_DEVOPS_EXECUTOR_GATEWAY_ADMIN_CLIENT_CA_FILE",
			"MATRIX_DEVOPS_EXECUTOR_GATEWAY_ADMIN_CLIENT_IDENTITY",
			"MATRIX_DEVOPS_EXECUTOR_GATEWAY_ADMIN_LISTEN_ADDRESS",
			"MATRIX_DEVOPS_EXECUTOR_GATEWAY_READINESS_LISTEN_ADDRESS",
			"MATRIX_DEVOPS_EXECUTOR_GATEWAY_RUNNER_CLIENT_CA_FILE",
			"MATRIX_DEVOPS_EXECUTOR_GATEWAY_RUNNER_LISTEN_ADDRESS",
			"MATRIX_DEVOPS_EXECUTOR_GATEWAY_RUNNER_NAMESPACE",
			"MATRIX_DEVOPS_EXECUTOR_GATEWAY_SERVER_CERT_FILE",
			"MATRIX_DEVOPS_EXECUTOR_GATEWAY_SERVER_KEY_FILE",
			"MATRIX_DEVOPS_EXECUTOR_GATEWAY_SPOOL_ROOT",
		},
		"devops-source-fetcher": {
			"MATRIX_DEVOPS_SOURCE_FETCHER_ARCHIVE_ROOT",
			"MATRIX_DEVOPS_SOURCE_FETCHER_DATABASE_DSN_FILE",
			"MATRIX_DEVOPS_SOURCE_FETCHER_FETCH_ROOT",
			"MATRIX_DEVOPS_SOURCE_FETCHER_LISTEN_ADDRESS",
			"MATRIX_DEVOPS_SOURCE_FETCHER_WORKER_ID",
		},
		"devops-source-observer": {
			"MATRIX_DEVOPS_SOURCE_OBSERVER_DATABASE_DSN_FILE",
			"MATRIX_DEVOPS_SOURCE_OBSERVER_FETCH_ROOT",
			"MATRIX_DEVOPS_SOURCE_OBSERVER_LISTEN_ADDRESS",
			"MATRIX_DEVOPS_SOURCE_OBSERVER_REPORT_ROOT",
			"MATRIX_DEVOPS_SOURCE_OBSERVER_WEBHOOK_ROOT",
			"MATRIX_DEVOPS_SOURCE_OBSERVER_WORKER_ID",
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
		"matrix-ui": {"MATRIX_UI_LISTEN_ADDRESS"},
		"paas-worker": {
			"DOCKER_CONFIG", "DOCKER_HOST",
			"MATRIX_PAAS_WORKER_ARTIFACT_CATALOG_FILE", "MATRIX_PAAS_WORKER_BINDING_REF",
			"MATRIX_PAAS_WORKER_BINDING_ROOT", "MATRIX_PAAS_WORKER_DATABASE_DSN_FILE",
			"MATRIX_PAAS_WORKER_EXECUTION_TENANT_ID", "MATRIX_PAAS_WORKER_ID",
			"MATRIX_PAAS_WORKER_LISTEN_ADDRESS", "MATRIX_PAAS_WORKER_MACHINE_BINDING_REF",
			"MATRIX_PAAS_WORKER_SECRET_ROOT",
		},
		"platform-api": {
			"MATRIX_PLATFORM_DEVOPS_ENDPOINT", "MATRIX_PLATFORM_IAM_CREDENTIAL_FILE",
			"MATRIX_PLATFORM_IAM_ENDPOINT",
			"MATRIX_PLATFORM_INSTALLATION_ID", "MATRIX_PLATFORM_LISTEN_ADDRESS",
			"MATRIX_PLATFORM_PAAS_ENDPOINT", "MATRIX_PLATFORM_RELEASE_ID",
			"MATRIX_PLATFORM_RELEASE_MANIFEST_FILE", "MATRIX_PLATFORM_RELEASE_SIGNATURE_FILE",
			"MATRIX_PLATFORM_RELEASE_TRUST_FILE",
		},
	}
	expectedImageComponents := map[string]string{
		"apisix": "apisix", "audit": "audit", "devops-api": "devops",
		"devops-audit-dispatcher": "devops", "devops-build-worker": "devops",
		"devops-executor-gateway": "devops", "devops-source-fetcher": "devops",
		"devops-source-observer": "devops",
		"iam":                    "iam",
		"iam-audit-dispatcher":   "iam", "matrix-ui": "matrix-ui", "paas-api": "paas",
		"paas-audit-dispatcher": "paas",
		"paas-worker":           "paas", "platform-api": "platform",
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
		} else if name == "devops-source-fetcher" || name == "devops-source-observer" {
			if !slices.Equal(actualServiceNetworks, []string{"control", "source"}) {
				t.Fatalf("DevOps source service %q network boundary=%v", name, actualServiceNetworks)
			}
		} else if slices.Contains(actualServiceNetworks, "edge") ||
			slices.Contains(actualServiceNetworks, "source") {
			t.Fatalf("service %q can join an undeclared external network", name)
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
			installationIdentityRoot := "spiffe://matrix.xiak.com/installations/" +
				strings.Repeat("a", 32) + "/devops/"
			switch name {
			case "devops-build-worker":
				if environment["MATRIX_DEVOPS_BUILD_WORKER_CLIENT_IDENTITY"] !=
					installationIdentityRoot+"build-worker" ||
					environment["MATRIX_DEVOPS_BUILD_WORKER_GATEWAY_ORIGIN"] !=
						"https://devops-executor-gateway:8443" ||
					environment["MATRIX_DEVOPS_BUILD_WORKER_GATEWAY_SERVER_NAME"] !=
						"devops-executor-gateway" {
					t.Fatalf("DevOps build worker mTLS environment=%#v", environment)
				}
			case "devops-executor-gateway":
				if environment["MATRIX_DEVOPS_EXECUTOR_GATEWAY_ADMIN_CLIENT_IDENTITY"] !=
					installationIdentityRoot+"build-worker" ||
					environment["MATRIX_DEVOPS_EXECUTOR_GATEWAY_RUNNER_NAMESPACE"] !=
						installationIdentityRoot+"runners" ||
					environment["MATRIX_DEVOPS_EXECUTOR_GATEWAY_ADMIN_LISTEN_ADDRESS"] !=
						"0.0.0.0:8443" ||
					environment["MATRIX_DEVOPS_EXECUTOR_GATEWAY_RUNNER_LISTEN_ADDRESS"] !=
						"0.0.0.0:8444" {
					t.Fatalf("DevOps executor gateway mTLS environment=%#v", environment)
				}
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
			validAPISIX := name == "apisix" && len(ports) == 1 &&
				ports[0] == "127.0.0.1:8443:9080/tcp"
			validRunner := name == "devops-executor-gateway" && len(ports) == 1 &&
				ports[0] == "127.0.0.1:8444:8444/tcp"
			if !validAPISIX && !validRunner {
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
				if name == "devops-api" && source == options.Root+"/secrets/devops/source-webhooks" {
					foundDevOpsSourceSecrets = target == "/run/matrix/devops-source-secrets" && mount["read_only"] == true
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
			if name == "devops-source-observer" {
				expected := map[string]string{
					"/run/matrix/devops-source-observer-dsn": options.Root + "/secrets/database/devops-source-observer-dsn",
					"/run/matrix/devops-source-webhooks":     options.Root + "/secrets/devops/source-webhooks",
					"/run/matrix/devops-source-fetch":        options.Root + "/secrets/devops/source-fetch",
					"/run/matrix/devops-source-report":       options.Root + "/secrets/devops/source-report",
				}
				if len(volumes) != len(expected) {
					t.Fatalf("DevOps source observer mount count=%d", len(volumes))
				}
				for _, rawMount := range volumes {
					mount := rawMount.(map[string]any)
					target := mount["target"].(string)
					if expected[target] != mount["source"] || mount["read_only"] != true {
						t.Fatalf("DevOps source observer mount=%#v", mount)
					}
				}
				dependencies := service["depends_on"].(map[string]any)
				if len(dependencies) != 1 || dependencies["postgres"] == nil {
					t.Fatalf("DevOps source observer dependencies=%#v", dependencies)
				}
				foundDevOpsSourceObserverBoundary = true
			}
			if name == "devops-source-fetcher" {
				expected := map[string]struct {
					source   string
					readOnly bool
				}{
					"/run/matrix/devops-source-fetcher-dsn": {
						options.Root + "/secrets/database/devops-source-fetcher-dsn", true,
					},
					"/run/matrix/devops-source-fetch": {
						options.Root + "/secrets/devops/source-fetch", true,
					},
					"/var/lib/matrix/source-archives": {
						options.Root + "/data/devops/source-archives", false,
					},
				}
				if len(volumes) != len(expected) {
					t.Fatalf("DevOps source fetcher mount count=%d", len(volumes))
				}
				for _, rawMount := range volumes {
					mount := rawMount.(map[string]any)
					target := mount["target"].(string)
					want, found := expected[target]
					readOnly, _ := mount["read_only"].(bool)
					if !found || mount["source"] != want.source || readOnly != want.readOnly {
						t.Fatalf("DevOps source fetcher mount=%#v", mount)
					}
				}
				dependencies := service["depends_on"].(map[string]any)
				if len(dependencies) != 1 || dependencies["postgres"] == nil {
					t.Fatalf("DevOps source fetcher dependencies=%#v", dependencies)
				}
				foundDevOpsSourceFetcherBoundary = true
			}
			if name == "devops-build-worker" {
				expected := map[string]struct {
					source   string
					readOnly bool
				}{
					"/run/matrix/devops-worker-dsn": {
						options.Root + "/secrets/database/devops-worker-dsn", true,
					},
					"/var/lib/matrix/source-archives": {
						options.Root + "/data/devops/source-archives", true,
					},
					"/run/matrix/build-worker.crt": {
						options.Root + "/secrets/devops/executor-pki/build-worker.crt", true,
					},
					"/run/matrix/build-worker.key": {
						options.Root + "/secrets/devops/executor-pki/build-worker.key", true,
					},
					"/run/matrix/executor-server-ca.crt": {
						options.Root + "/secrets/devops/executor-pki/server-ca.crt", true,
					},
				}
				if len(volumes) != len(expected) {
					t.Fatalf("DevOps build worker mount count=%d", len(volumes))
				}
				for _, rawMount := range volumes {
					mount := rawMount.(map[string]any)
					target := mount["target"].(string)
					want, found := expected[target]
					readOnly, _ := mount["read_only"].(bool)
					if !found || mount["source"] != want.source || readOnly != want.readOnly {
						t.Fatalf("DevOps build worker mount=%#v", mount)
					}
				}
				dependencies := service["depends_on"].(map[string]any)
				if len(dependencies) != 2 || dependencies["postgres"] == nil ||
					dependencies["devops-executor-gateway"] == nil {
					t.Fatalf("DevOps build worker dependencies=%#v", dependencies)
				}
				foundDevOpsBuildWorkerBoundary = true
			}
			if name == "devops-executor-gateway" {
				expected := map[string]struct {
					source   string
					readOnly bool
				}{
					"/var/lib/matrix/executor-spool": {
						options.Root + "/data/devops/executor-spool", false,
					},
					"/run/matrix/executor-gateway-server.crt": {
						options.Root + "/secrets/devops/executor-pki/gateway-server.crt", true,
					},
					"/run/matrix/executor-gateway-server.key": {
						options.Root + "/secrets/devops/executor-pki/gateway-server.key", true,
					},
					"/run/matrix/executor-admin-client-ca.crt": {
						options.Root + "/secrets/devops/executor-pki/admin-client-ca.crt", true,
					},
					"/run/matrix/executor-runner-client-ca.crt": {
						options.Root + "/secrets/devops/executor-pki/runner-client-ca.crt", true,
					},
				}
				if len(volumes) != len(expected) {
					t.Fatalf("DevOps executor gateway mount count=%d", len(volumes))
				}
				for _, rawMount := range volumes {
					mount := rawMount.(map[string]any)
					target := mount["target"].(string)
					want, found := expected[target]
					readOnly, _ := mount["read_only"].(bool)
					if !found || mount["source"] != want.source || readOnly != want.readOnly {
						t.Fatalf("DevOps executor gateway mount=%#v", mount)
					}
				}
				if _, found := service["depends_on"]; found {
					t.Fatal("DevOps executor gateway unexpectedly depends on a product service")
				}
				foundDevOpsExecutorGatewayBoundary = true
			}
		}
	}
	if portCount != 2 || !foundExecutorRoot || !foundDockerSocket || !foundPostgresData ||
		!foundAPISIXRuntimeBoundary || !foundDevOpsSourceSecrets ||
		!foundDevOpsSourceFetcherBoundary || !foundDevOpsSourceObserverBoundary ||
		!foundDevOpsBuildWorkerBoundary || !foundDevOpsExecutorGatewayBoundary {
		t.Fatalf(
			"platform capability closure: ports=%d executor=%t socket=%t postgres-data=%t apisix=%t devops-source-secrets=%t source-fetcher=%t source-observer=%t build-worker=%t executor-gateway=%t",
			portCount, foundExecutorRoot, foundDockerSocket, foundPostgresData,
			foundAPISIXRuntimeBoundary, foundDevOpsSourceSecrets,
			foundDevOpsSourceFetcherBoundary, foundDevOpsSourceObserverBoundary,
			foundDevOpsBuildWorkerBoundary, foundDevOpsExecutorGatewayBoundary,
		)
	}
	encoded := string(result.ComposeJSON)
	for _, forbidden := range []string{"latest", "secret-value", "dockerfile", "registry"} {
		if strings.Contains(strings.ToLower(encoded), forbidden) {
			t.Fatalf("compiled topology contains forbidden plaintext/provider input %q", forbidden)
		}
	}
}

func TestCompileOmitsUnselectedDevOpsProduct(t *testing.T) {
	manifest := topologyManifest()
	manifest.Products = manifest.Products[:1]
	manifest.Images = slices.DeleteFunc(manifest.Images, func(image release.Image) bool {
		return image.Component == "devops"
	})
	manifest.Files = slices.DeleteFunc(manifest.Files, func(file release.File) bool {
		return file.Path == "images/devops.tar"
	})
	result, err := Compile(manifest, Options{
		InstallationID: "mxi-" + strings.Repeat("a", 32), Root: "/srv/matrix",
		Listener: "127.0.0.1", Port: 8443,
	})
	if err != nil {
		t.Fatalf("compile PaaS-only topology: %v", err)
	}
	var document composeDocument
	if err := json.Unmarshal(result.ComposeJSON, &document); err != nil {
		t.Fatalf("decode PaaS-only topology: %v", err)
	}
	if _, found := document.Services["devops-api"]; found {
		t.Fatal("PaaS-only topology contains DevOps API")
	}
	if _, found := document.Services["devops-audit-dispatcher"]; found {
		t.Fatal("PaaS-only topology contains DevOps Audit dispatcher")
	}
	if _, found := document.Services["devops-build-worker"]; found {
		t.Fatal("PaaS-only topology contains DevOps build worker")
	}
	if _, found := document.Services["devops-executor-gateway"]; found {
		t.Fatal("PaaS-only topology contains DevOps executor gateway")
	}
	if _, found := document.Services["devops-source-fetcher"]; found {
		t.Fatal("PaaS-only topology contains DevOps source fetcher")
	}
	if _, found := document.Services["devops-source-observer"]; found {
		t.Fatal("PaaS-only topology contains DevOps source observer")
	}
	if _, found := document.Networks["source"]; found {
		t.Fatal("PaaS-only topology contains DevOps provider-egress network")
	}
	platform := document.Services["platform-api"]
	if _, found := platform.Environment["MATRIX_PLATFORM_DEVOPS_ENDPOINT"]; found {
		t.Fatal("PaaS-only product discovery can probe an undeclared DevOps endpoint")
	}
	if _, found := document.Services["apisix"].DependsOn["devops-api"]; found {
		t.Fatal("PaaS-only gateway depends on unselected DevOps")
	}
	if _, err := Compile(manifest, Options{
		InstallationID: "mxi-" + strings.Repeat("a", 32), Root: "/srv/matrix",
		Listener: "127.0.0.1", Port: devOpsExecutorRunnerPort,
	}); err != nil {
		t.Fatalf("PaaS-only topology unnecessarily reserved the DevOps runner port: %v", err)
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
		"reserved runner port":       func(value *Options) { value.Port = devOpsExecutorRunnerPort },
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
	products := []release.Product{
		release.ApplicationPaaSProduct("v0.1.0"),
		release.DevOpsProduct("v0.1.0"),
	}
	required := release.RequiredImages(products)
	images := make([]release.Image, 0, len(required))
	fileDigests := "23456789a"
	imageDigests := "789abcdef"
	sourceDigests := "abcdef012"
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
		Products:       products,
		TopologyDigest: ContractDigest(), Files: files, Images: images,
	}
}

func legacyTopologyManifest() release.Manifest {
	commit := "c88a84f379afcf94431e2aca7332fe6ec3136dc7"
	requirements := []release.ImageRequirement{
		{Component: "apisix", Purpose: release.ImagePlatform, HealthContract: "northbound-ready-v1"},
		{Component: "audit", Purpose: release.ImagePlatform, HealthContract: "audit-ready-deduplicate-v1"},
		{Component: "iam", Purpose: release.ImagePlatform, HealthContract: "iam-ready-authorize-v1"},
		{Component: "paas", Purpose: release.ImagePlatform, HealthContract: "paas-ready-worker-compose-v1"},
		{Component: "paas-ui", Purpose: release.ImagePlatform, HealthContract: "paas-ui-ready-v1"},
		{Component: "postgres", Purpose: release.ImagePlatform, HealthContract: "postgres-ready-schema-v1"},
		{Component: "verification", Purpose: release.ImageWorkload, HealthContract: "application-probe-v1"},
	}
	files := []release.File{{
		Path: "bin/mx", MediaType: "application/vnd.matrix.executable",
		Size: 1024, SHA256: digestValue('1'), Executable: true,
	}}
	images := make([]release.Image, 0, len(requirements))
	fileDigests := "2345678"
	imageDigests := "89abcde"
	sourceDigests := "ef01234"
	for index, requirement := range requirements {
		archive := "images/" + requirement.Component + ".tar"
		files = append(files, release.File{
			Path: archive, MediaType: "application/vnd.docker.image.archive",
			Size: 1024 + uint64(index), SHA256: digestValue(fileDigests[index]),
		})
		images = append(images, release.Image{
			Component: requirement.Component, Purpose: requirement.Purpose, ArchivePath: archive,
			ImageID: digestValue(imageDigests[index]), SourceDigest: digestValue(sourceDigests[index]),
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
			OS: "linux", Architecture: "amd64", MinimumDocker: "27.5.1",
			MinimumCompose: "2.33.0", CommandContract: "v1",
		},
		MinimumFreeBytes: 4 * 1024 * 1024 * 1024,
		Database: release.DatabaseProfile{
			SchemaVersion: 1, Compatibility: "expand-contract-n-minus-one",
		},
		Products: nil, TopologyDigest: legacyProductlessContractDigest,
		Files: files, Images: images,
	}
}

func digestValue(value byte) string {
	return "sha256:" + strings.Repeat(string(value), 64)
}

func digest(value byte) string {
	return "sha256:" + strings.Repeat(string(value), 64)
}
