// Package topology compiles the one closed Phase 1 Matrix platform topology
// into deterministic Compose JSON. It intentionally has no caller-provided
// service, command, environment, mount, network, or provider-native input.
package topology

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"path"
	"strings"

	"github.com/xiak/matrix/app/service/installation/internal/layout"
	"github.com/xiak/matrix/app/service/installation/internal/lifecycle"
	"github.com/xiak/matrix/app/service/installation/release"
)

const ContractVersion = "matrix-platform-compose/v1"

type Options struct {
	InstallationID string
	Root           string
	Listener       string
	Port           uint16
}

type Result struct {
	ProjectName    string
	ContractDigest string
	ComposeJSON    []byte
}

type contract struct {
	Version       string          `json:"version"`
	Substitutions []string        `json:"substitutions"`
	Compose       composeDocument `json:"compose"`
}

var platformServiceNames = []string{
	"apisix", "audit", "iam", "iam-audit-dispatcher", "paas-api",
	"paas-audit-dispatcher", "paas-ui", "paas-worker", "postgres",
}

func ContractDigest() string {
	content, err := json.Marshal(contractDescription())
	if err != nil {
		panic("static platform topology contract cannot be encoded")
	}
	digest := sha256.Sum256(content)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func contractDescription() contract {
	options := Options{
		InstallationID: "mxi-00000000000000000000000000000000",
		Root:           "/matrix-installation-root",
		Listener:       "0.0.0.0",
		Port:           1,
	}
	manifest := release.Manifest{Release: release.ReleaseIdentity{
		ID: "matrix-v0.0.0-000000000000", SourceCommit: strings.Repeat("0", 40),
		BuildID: "matrix-release-build",
	}}
	images := make(map[string]string, len(release.RequiredImages()))
	for _, requirement := range release.RequiredImages() {
		images[requirement.Component] = "sha256:" + strings.Repeat("0", 64)
		manifest.Images = append(manifest.Images, release.Image{
			Component: requirement.Component, Purpose: requirement.Purpose,
			SourceDigest: "sha256:" + strings.Repeat("0", 64),
		})
	}
	document := composeDocument{
		Name:     "matrix-00000000000000000000000000000000",
		Services: compileServices(manifest, images, options),
		Networks: map[string]networkConfig{
			"control":    {Internal: true, Labels: ownershipLabels(options.InstallationID, manifest.Release.ID, "network-control")},
			"edge":       {Internal: false, Labels: ownershipLabels(options.InstallationID, manifest.Release.ID, "network-edge")},
			"web":        {Internal: true, Labels: ownershipLabels(options.InstallationID, manifest.Release.ID, "network-web")},
			"management": {Internal: false, Labels: ownershipLabels(options.InstallationID, manifest.Release.ID, "network-management")},
		},
	}
	return contract{
		Version: ContractVersion,
		Substitutions: []string{
			"installationId", "installationRoot", "listenerAddress", "listenerPort",
			"releaseId", "releaseBuildId", "sourceCommit", "signedImageIds",
			"verificationArtifactDigest",
		},
		Compose: document,
	}
}

func Compile(manifest release.Manifest, options Options) (Result, error) {
	if err := release.ValidateManifest(manifest); err != nil {
		return Result{}, fmt.Errorf("release manifest cannot supply platform topology: %w", err)
	}
	if manifest.TopologyDigest != ContractDigest() {
		return Result{}, errors.New("release topology contract digest is unsupported")
	}
	if err := validateOptions(options); err != nil {
		return Result{}, err
	}
	images := make(map[string]string, len(manifest.Images))
	for _, image := range manifest.Images {
		images[image.Component] = image.ImageID
	}
	document := composeDocument{
		Name:     "matrix-" + strings.TrimPrefix(options.InstallationID, "mxi-"),
		Services: compileServices(manifest, images, options),
		Networks: map[string]networkConfig{
			"control":    {Internal: true, Labels: ownershipLabels(options.InstallationID, manifest.Release.ID, "network-control")},
			"edge":       {Internal: false, Labels: ownershipLabels(options.InstallationID, manifest.Release.ID, "network-edge")},
			"web":        {Internal: true, Labels: ownershipLabels(options.InstallationID, manifest.Release.ID, "network-web")},
			"management": {Internal: false, Labels: ownershipLabels(options.InstallationID, manifest.Release.ID, "network-management")},
		},
	}
	content, err := json.Marshal(document)
	if err != nil {
		return Result{}, errors.New("encode platform Compose topology failed")
	}
	return Result{
		ProjectName: document.Name, ContractDigest: ContractDigest(), ComposeJSON: content,
	}, nil
}

func validateOptions(options Options) error {
	var problems []error
	problems = append(problems, lifecycle.ValidateInstallationID(options.InstallationID))
	if options.Root == "" || len(options.Root) > 4096 || !path.IsAbs(options.Root) ||
		path.Clean(options.Root) != options.Root || options.Root == "/" ||
		strings.ContainsAny(options.Root, "\\$\x00\r\n") {
		problems = append(problems, errors.New("platform installation root is invalid"))
	}
	address, err := netip.ParseAddr(options.Listener)
	if err != nil || !address.Is4() || address.IsMulticast() || address.String() != options.Listener {
		problems = append(problems, errors.New("platform listener address is invalid"))
	}
	if options.Port == 0 {
		problems = append(problems, errors.New("platform listener port is invalid"))
	}
	return errors.Join(problems...)
}

type composeDocument struct {
	Name     string                   `json:"name"`
	Services map[string]serviceConfig `json:"services"`
	Networks map[string]networkConfig `json:"networks"`
}

type serviceConfig struct {
	Image       string                `json:"image"`
	PullPolicy  string                `json:"pull_policy"`
	Restart     string                `json:"restart"`
	User        string                `json:"user,omitempty"`
	ReadOnly    bool                  `json:"read_only,omitempty"`
	Init        bool                  `json:"init,omitempty"`
	Entrypoint  []string              `json:"entrypoint,omitempty"`
	Environment map[string]string     `json:"environment,omitempty"`
	DependsOn   map[string]dependency `json:"depends_on,omitempty"`
	Networks    []string              `json:"networks"`
	Ports       []string              `json:"ports,omitempty"`
	Volumes     []mount               `json:"volumes,omitempty"`
	Tmpfs       []string              `json:"tmpfs,omitempty"`
	SecurityOpt []string              `json:"security_opt"`
	CapAdd      []string              `json:"cap_add,omitempty"`
	CapDrop     []string              `json:"cap_drop"`
	Healthcheck healthcheck           `json:"healthcheck"`
	Deploy      deploy                `json:"deploy"`
	Labels      map[string]string     `json:"labels"`
}

type dependency struct {
	Condition string `json:"condition"`
}

type mount struct {
	Type     string `json:"type"`
	Source   string `json:"source"`
	Target   string `json:"target"`
	ReadOnly bool   `json:"read_only,omitempty"`
}

type healthcheck struct {
	Test        []string `json:"test"`
	Interval    string   `json:"interval"`
	Timeout     string   `json:"timeout"`
	Retries     uint8    `json:"retries"`
	StartPeriod string   `json:"start_period"`
}

type deploy struct {
	Resources resources `json:"resources"`
}

type resources struct {
	Limits limits `json:"limits"`
}

type limits struct {
	CPUs   string `json:"cpus"`
	Memory string `json:"memory"`
}

type networkConfig struct {
	Internal bool              `json:"internal"`
	Labels   map[string]string `json:"labels"`
}

func compileServices(
	manifest release.Manifest,
	images map[string]string,
	options Options,
) map[string]serviceConfig {
	root := options.Root
	postgresPassword := path.Join(root, layout.PostgresPassword)
	iamAPIDSN := path.Join(root, layout.IAMAPI)
	iamWorkerDSN := path.Join(root, layout.IAMWorker)
	auditRuntimeDSN := path.Join(root, layout.AuditRuntime)
	paasAPIDSN := path.Join(root, layout.PaaSAPI)
	paasWorkerDSN := path.Join(root, layout.PaaSWorker)
	bootstrapIAM := path.Join(root, layout.IAMBootstrap)
	auditIAMCredential := path.Join(root, layout.AuditIAMCredential)
	iamAuditCredential := path.Join(root, layout.IAMAuditCredential)
	paasIAMCredential := path.Join(root, layout.PaaSIAMCredential)
	paasAuditCredential := path.Join(root, layout.PaaSAuditCredential)
	auditCursorKey := path.Join(root, layout.AuditCursorKey)
	apisixRoutes := path.Join(root, layout.APISIXRoutes)
	apisixConfig := path.Join(root, layout.APISIXConfig)
	apisixUID := path.Join(root, layout.APISIXUID)
	apisixNginx := path.Join(root, layout.APISIXNginx)
	artifactCatalog := path.Join(root, layout.ArtifactCatalog)
	executorRoot := path.Join(root, layout.ExecutorRoot)
	workloadSecretRoot := path.Join(root, layout.WorkloadSecretRoot)
	service := func(
		name string,
		component string,
		image string,
		networks []string,
		entrypoint []string,
		cpu string,
		memory string,
		readinessURL string,
	) serviceConfig {
		return serviceConfig{
			Image: image, PullPolicy: "never", Restart: "unless-stopped", ReadOnly: true, Init: true,
			Entrypoint: entrypoint, Networks: networks, Tmpfs: []string{"/tmp:rw,noexec,nosuid,size=64m"},
			SecurityOpt: []string{"no-new-privileges:true"}, CapDrop: []string{"ALL"},
			Healthcheck: healthcheck{
				Test:     []string{"CMD", "/matrix/bin/matrix-health", readinessURL},
				Interval: "10s", Timeout: "3s",
				Retries: 12, StartPeriod: "10s",
			},
			Deploy: deploy{Resources: resources{Limits: limits{CPUs: cpu, Memory: memory}}},
			Labels: platformServiceLabels(options.InstallationID, manifest, component, name),
		}
	}
	postgres := service(
		"postgres", "postgres", images["postgres"], []string{"control"}, nil,
		"2.0", "2G", "",
	)
	postgres.ReadOnly = false
	postgres.Init = false
	postgres.Environment = map[string]string{
		"POSTGRES_DB": "matrix", "POSTGRES_USER": "matrix",
		"POSTGRES_PASSWORD_FILE": "/run/secrets/postgres-password",
	}
	postgres.Volumes = []mount{
		bind(path.Join(root, layout.PostgresData), "/var/lib/postgresql", false),
		bind(postgresPassword, "/run/secrets/postgres-password", true),
	}
	postgres.CapAdd = []string{
		"CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_FOWNER", "CAP_SETGID", "CAP_SETUID",
	}
	postgres.Tmpfs = []string{"/tmp:rw,noexec,nosuid,size=64m", "/var/run/postgresql:rw,nosuid,size=16m"}
	// The PostgreSQL image's temporary initialization server listens only on
	// Unix sockets. A TCP probe prevents migrations from starting until the
	// final server has taken over.
	postgres.Healthcheck.Test = []string{
		"CMD", "pg_isready", "-h", "127.0.0.1", "-U", "matrix", "-d", "matrix",
	}

	iam := service(
		"iam", "iam", images["iam"], []string{"control"}, []string{"/matrix/bin/matrix-iam"},
		"1.0", "512M", "http://127.0.0.1:8080/ready",
	)
	iam.Environment = map[string]string{
		"MATRIX_IAM_DATABASE_DSN_FILE": "/run/matrix/iam-api-dsn",
		"MATRIX_IAM_BOOTSTRAP_FILE":    "/run/matrix/iam-bootstrap.json",
		"MATRIX_IAM_LISTEN_ADDRESS":    "0.0.0.0:8080",
	}
	iam.Volumes = []mount{
		bind(iamAPIDSN, "/run/matrix/iam-api-dsn", true),
		bind(bootstrapIAM, "/run/matrix/iam-bootstrap.json", true),
	}
	iam.DependsOn = healthy("postgres")

	audit := service(
		"audit", "audit", images["audit"], []string{"control"}, []string{"/matrix/bin/matrix-audit"},
		"1.0", "512M", "http://127.0.0.1:8080/ready",
	)
	audit.Environment = map[string]string{
		"MATRIX_AUDIT_DATABASE_DSN_FILE":       "/run/matrix/audit-runtime-dsn",
		"MATRIX_AUDIT_IAM_ENDPOINT":            "http://iam:8080",
		"MATRIX_AUDIT_SERVICE_CREDENTIAL_FILE": "/run/matrix/audit-iam-credential",
		"MATRIX_AUDIT_CURSOR_KEY_FILE":         "/run/matrix/audit-cursor-key",
		"MATRIX_AUDIT_LISTEN_ADDRESS":          "0.0.0.0:8080",
	}
	audit.Volumes = []mount{
		bind(auditRuntimeDSN, "/run/matrix/audit-runtime-dsn", true),
		bind(auditIAMCredential, "/run/matrix/audit-iam-credential", true),
		bind(auditCursorKey, "/run/matrix/audit-cursor-key", true),
	}
	audit.DependsOn = healthy("postgres", "iam")

	iamAudit := service(
		"iam-audit-dispatcher", "iam", images["iam"], []string{"control"},
		[]string{"/matrix/bin/matrix-iam-audit-dispatcher"},
		"0.5", "384M", "http://127.0.0.1:8080/ready",
	)
	iamAudit.Environment = map[string]string{
		"MATRIX_IAM_AUDIT_DATABASE_DSN_FILE": "/run/matrix/iam-worker-dsn",
		"MATRIX_IAM_AUDIT_ENDPOINT":          "http://audit:8080",
		"MATRIX_IAM_AUDIT_CREDENTIAL_FILE":   "/run/matrix/iam-audit-credential",
		"MATRIX_IAM_AUDIT_WORKER_ID":         "iam-audit-" + strings.TrimPrefix(options.InstallationID, "mxi-"),
		"MATRIX_IAM_AUDIT_LISTEN_ADDRESS":    "0.0.0.0:8080",
	}
	iamAudit.Volumes = []mount{
		bind(iamWorkerDSN, "/run/matrix/iam-worker-dsn", true),
		bind(iamAuditCredential, "/run/matrix/iam-audit-credential", true),
	}
	iamAudit.DependsOn = healthy("postgres", "audit")

	paasAPI := service(
		"paas-api", "paas", images["paas"], []string{"control", "management"}, []string{"/matrix/bin/matrix-paas"},
		"1.0", "768M", "http://127.0.0.1:8080/ready",
	)
	paasAPI.Environment = map[string]string{
		"MATRIX_PAAS_DATABASE_DSN_FILE":            "/run/matrix/paas-api-dsn",
		"MATRIX_PAAS_IAM_ENDPOINT":                 "http://iam:8080",
		"MATRIX_PAAS_INSTALLATION_ID":              options.InstallationID,
		"MATRIX_PAAS_RELEASE_ID":                   manifest.Release.ID,
		"MATRIX_PAAS_SERVICE_CREDENTIAL_FILE":      "/run/matrix/paas-iam-credential",
		"MATRIX_PAAS_VERIFICATION_ARTIFACT_DIGEST": verificationArtifactDigest(manifest),
		"MATRIX_PAAS_LISTEN_ADDRESS":               "0.0.0.0:8080",
		"MATRIX_PAAS_NODE_CONNECTIONS_FILE":        "/run/matrix/node-controller/configuration.json",
	}
	paasAPI.Volumes = []mount{
		bind(paasAPIDSN, "/run/matrix/paas-api-dsn", true),
		bind(paasIAMCredential, "/run/matrix/paas-iam-credential", true),
		bind(path.Join(root, layout.NodeControllerDirectory), "/run/matrix/node-controller", true),
	}
	paasAPI.Tmpfs = append(paasAPI.Tmpfs, "/var/lib/docker:rw,noexec,nosuid,size=16m")
	paasAPI.DependsOn = healthy("postgres", "iam")

	paasWorker := service(
		"paas-worker", "paas", images["paas"], []string{"control"},
		[]string{"/matrix/bin/matrix-paas-worker"},
		"2.0", "1G", "http://127.0.0.1:8080/ready",
	)
	paasWorker.Environment = map[string]string{
		"MATRIX_PAAS_WORKER_DATABASE_DSN_FILE":      "/run/matrix/paas-worker-dsn",
		"MATRIX_PAAS_WORKER_ID":                     "paas-worker-" + strings.TrimPrefix(options.InstallationID, "mxi-"),
		"MATRIX_PAAS_WORKER_BINDING_REF":            "compose-local-v1",
		"MATRIX_PAAS_WORKER_BINDING_ROOT":           executorRoot,
		"MATRIX_PAAS_WORKER_SECRET_ROOT":            workloadSecretRoot,
		"MATRIX_PAAS_WORKER_ARTIFACT_CATALOG_FILE":  "/run/matrix/artifact-catalog.json",
		"MATRIX_PAAS_WORKER_EXECUTION_TENANT_ID":    "organization-default",
		"MATRIX_PAAS_WORKER_MACHINE_BINDING_REF":    "local-machine-v1",
		"MATRIX_PAAS_WORKER_LISTEN_ADDRESS":         "0.0.0.0:8080",
		"MATRIX_PAAS_WORKER_MANAGED_POSTGRES_IMAGE": images["postgres"],
		"DOCKER_HOST":   "unix:///var/run/docker.sock",
		"DOCKER_CONFIG": "/tmp/docker-config",
	}
	paasWorker.Volumes = []mount{
		bind(paasWorkerDSN, "/run/matrix/paas-worker-dsn", true),
		bind(artifactCatalog, "/run/matrix/artifact-catalog.json", true),
		bind(executorRoot, executorRoot, false),
		bind(workloadSecretRoot, workloadSecretRoot, true),
		bind("/var/run/docker.sock", "/var/run/docker.sock", false),
	}
	paasWorker.Tmpfs = append(paasWorker.Tmpfs, "/var/lib/docker:rw,noexec,nosuid,size=16m")
	paasWorker.DependsOn = healthy("postgres")

	paasAudit := service(
		"paas-audit-dispatcher", "paas", images["paas"], []string{"control"},
		[]string{"/matrix/bin/matrix-paas-audit-dispatcher"},
		"0.5", "384M", "http://127.0.0.1:8080/ready",
	)
	paasAudit.Environment = map[string]string{
		"MATRIX_PAAS_AUDIT_DATABASE_DSN_FILE": "/run/matrix/paas-worker-dsn",
		"MATRIX_PAAS_AUDIT_ENDPOINT":          "http://audit:8080",
		"MATRIX_PAAS_AUDIT_CREDENTIAL_FILE":   "/run/matrix/paas-audit-credential",
		"MATRIX_PAAS_AUDIT_WORKER_ID":         "paas-audit-" + strings.TrimPrefix(options.InstallationID, "mxi-"),
		"MATRIX_PAAS_AUDIT_LISTEN_ADDRESS":    "0.0.0.0:8080",
	}
	paasAudit.Volumes = []mount{
		bind(paasWorkerDSN, "/run/matrix/paas-worker-dsn", true),
		bind(paasAuditCredential, "/run/matrix/paas-audit-credential", true),
	}
	paasAudit.Tmpfs = append(paasAudit.Tmpfs, "/var/lib/docker:rw,noexec,nosuid,size=16m")
	paasAudit.DependsOn = healthy("postgres", "audit")

	ui := service(
		"paas-ui", "paas-ui", images["paas-ui"], []string{"web"},
		[]string{"/matrix/bin/matrix-paas-ui"},
		"0.5", "256M", "http://127.0.0.1:8080/ready",
	)
	ui.Environment = map[string]string{
		"MATRIX_PAAS_UI_LISTEN_ADDRESS": "0.0.0.0:8080",
	}

	apisix := service(
		"apisix", "apisix", images["apisix"], []string{"control", "edge", "web"}, nil,
		"1.0", "512M", "http://127.0.0.1:9080/ready",
	)
	apisix.User = "0:0"
	apisix.Environment = map[string]string{"APISIX_STAND_ALONE": "true"}
	apisix.Ports = []string{net.JoinHostPort(options.Listener, fmt.Sprint(options.Port)) + ":9080/tcp"}
	apisix.Volumes = []mount{
		bind(apisixConfig, "/usr/local/apisix/conf/config.yaml", true),
		bind(apisixRoutes, "/usr/local/apisix/conf/apisix.yaml", true),
		bind(apisixUID, "/usr/local/apisix/conf/apisix.uid", true),
		bind(apisixNginx, "/usr/local/apisix/conf/nginx.conf", false),
	}
	apisix.Tmpfs = append(
		apisix.Tmpfs,
		"/usr/local/apisix/logs:rw,nosuid,size=16m,mode=0700,uid=0,gid=0",
	)
	apisix.CapAdd = []string{"CAP_CHOWN", "CAP_SETGID", "CAP_SETUID"}
	apisix.DependsOn = healthy("audit", "iam", "paas-api", "paas-ui")

	return map[string]serviceConfig{
		"apisix": apisix, "audit": audit, "iam": iam,
		"iam-audit-dispatcher": iamAudit, "paas-api": paasAPI,
		"paas-audit-dispatcher": paasAudit, "paas-ui": ui, "paas-worker": paasWorker,
		"postgres": postgres,
	}
}

func platformServiceLabels(
	installationID string,
	manifest release.Manifest,
	component string,
	role string,
) map[string]string {
	labels := ownershipLabels(installationID, manifest.Release.ID, role)
	if component == "postgres" {
		return labels
	}
	for key, value := range release.BuiltImageLabels(manifest.Release, component) {
		labels[key] = value
	}
	return labels
}

func verificationArtifactDigest(manifest release.Manifest) string {
	for _, image := range manifest.Images {
		if image.Component == "verification" && image.Purpose == release.ImageWorkload {
			return image.SourceDigest
		}
	}
	return ""
}

func bind(source, target string, readOnly bool) mount {
	return mount{Type: "bind", Source: source, Target: target, ReadOnly: readOnly}
}

func healthy(names ...string) map[string]dependency {
	result := make(map[string]dependency, len(names))
	for _, name := range names {
		result[name] = dependency{Condition: "service_healthy"}
	}
	return result
}

func ownershipLabels(installationID, releaseID, role string) map[string]string {
	return map[string]string{
		"com.xiak.matrix.managed":      "true",
		"com.xiak.matrix.installation": installationID,
		"com.xiak.matrix.release":      releaseID,
		"com.xiak.matrix.role":         role,
	}
}
