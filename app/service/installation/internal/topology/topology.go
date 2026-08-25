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
	"slices"
	"strings"

	"github.com/xiak/matrix/app/service/installation/internal/lifecycle"
	"github.com/xiak/matrix/app/service/installation/internal/release"
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
	"apisix", "audit", "iam", "paas-api", "paas-audit-dispatcher",
	"paas-ui", "paas-worker", "postgres",
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
	manifest := release.Manifest{Release: release.ReleaseIdentity{ID: "matrix-v0.0.0-000000000000"}}
	images := make(map[string]string, len(release.RequiredImageComponents()))
	for _, component := range release.RequiredImageComponents() {
		images[component] = "sha256:" + strings.Repeat("0", 64)
	}
	document := composeDocument{
		Name:     "matrix-00000000000000000000000000000000",
		Services: compileServices(manifest, images, options),
		Networks: map[string]networkConfig{
			"control": {Internal: true, Labels: ownershipLabels(options.InstallationID, manifest.Release.ID, "network-control")},
			"web":     {Internal: true, Labels: ownershipLabels(options.InstallationID, manifest.Release.ID, "network-web")},
		},
	}
	return contract{
		Version: ContractVersion,
		Substitutions: []string{
			"installationId", "installationRoot", "listenerAddress", "listenerPort",
			"releaseId", "signedImageIds",
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
			"control": {Internal: true, Labels: ownershipLabels(options.InstallationID, manifest.Release.ID, "network-control")},
			"web":     {Internal: true, Labels: ownershipLabels(options.InstallationID, manifest.Release.ID, "network-web")},
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
		strings.ContainsAny(options.Root, "\\\x00\r\n") {
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
	ReadOnly    bool                  `json:"read_only,omitempty"`
	Init        bool                  `json:"init,omitempty"`
	Command     []string              `json:"command,omitempty"`
	Environment map[string]string     `json:"environment,omitempty"`
	DependsOn   map[string]dependency `json:"depends_on,omitempty"`
	Networks    []string              `json:"networks"`
	Ports       []string              `json:"ports,omitempty"`
	Volumes     []mount               `json:"volumes,omitempty"`
	Tmpfs       []string              `json:"tmpfs,omitempty"`
	SecurityOpt []string              `json:"security_opt"`
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
	postgresPassword := path.Join(root, "secrets/postgres-password")
	iamCredential := path.Join(root, "secrets/iam-service-credential")
	auditCredential := path.Join(root, "secrets/audit-service-credential")
	bootstrapIAM := path.Join(root, "secrets/iam-bootstrap")
	executorRoot := path.Join(root, "runtime/executor")
	baseEnvironment := map[string]string{
		"MATRIX_INSTALLATION_ID": options.InstallationID,
		"MATRIX_POSTGRES_HOST":   "postgres",
		"MATRIX_POSTGRES_PORT":   "5432",
		"MATRIX_POSTGRES_USER":   "matrix",
		"MATRIX_POSTGRES_DB":     "matrix",
	}
	service := func(name, image string, networks []string, command []string, cpu, memory string) serviceConfig {
		return serviceConfig{
			Image: image, PullPolicy: "never", Restart: "unless-stopped", ReadOnly: true, Init: true,
			Command: command, Networks: networks, Tmpfs: []string{"/tmp:rw,noexec,nosuid,size=64m"},
			SecurityOpt: []string{"no-new-privileges:true"}, CapDrop: []string{"ALL"},
			Healthcheck: healthcheck{
				Test: []string{"CMD", "/matrix/bin/health", name}, Interval: "10s", Timeout: "3s",
				Retries: 12, StartPeriod: "10s",
			},
			Deploy: deploy{Resources: resources{Limits: limits{CPUs: cpu, Memory: memory}}},
			Labels: ownershipLabels(options.InstallationID, manifest.Release.ID, name),
		}
	}
	postgres := service("postgres", images["postgres"], []string{"control"}, nil, "2.0", "2G")
	postgres.ReadOnly = false
	postgres.Init = false
	postgres.Environment = map[string]string{
		"POSTGRES_DB": "matrix", "POSTGRES_USER": "matrix",
		"POSTGRES_PASSWORD_FILE": "/run/secrets/postgres-password",
	}
	postgres.Volumes = []mount{
		bind(path.Join(root, "data/postgres"), "/var/lib/postgresql/data", false),
		bind(postgresPassword, "/run/secrets/postgres-password", true),
	}
	postgres.Tmpfs = []string{"/tmp:rw,noexec,nosuid,size=64m", "/var/run/postgresql:rw,nosuid,size=16m"}
	postgres.Healthcheck.Test = []string{"CMD", "pg_isready", "-U", "matrix", "-d", "matrix"}

	iam := service("iam", images["iam"], []string{"control"}, nil, "1.0", "512M")
	iam.Environment = cloneEnvironment(baseEnvironment, map[string]string{
		"MATRIX_POSTGRES_PASSWORD_FILE": "/run/secrets/postgres-password",
		"MATRIX_IAM_BOOTSTRAP_FILE":     "/run/secrets/iam-bootstrap",
	})
	iam.Volumes = []mount{
		bind(postgresPassword, "/run/secrets/postgres-password", true),
		bind(bootstrapIAM, "/run/secrets/iam-bootstrap", true),
	}
	iam.DependsOn = healthy("postgres")

	audit := service("audit", images["audit"], []string{"control"}, nil, "1.0", "512M")
	audit.Environment = cloneEnvironment(baseEnvironment, map[string]string{
		"MATRIX_POSTGRES_PASSWORD_FILE": "/run/secrets/postgres-password",
		"MATRIX_AUDIT_CREDENTIAL_FILE":  "/run/secrets/audit-service-credential",
	})
	audit.Volumes = []mount{
		bind(postgresPassword, "/run/secrets/postgres-password", true),
		bind(auditCredential, "/run/secrets/audit-service-credential", true),
	}
	audit.DependsOn = healthy("postgres")

	paasEnvironment := cloneEnvironment(baseEnvironment, map[string]string{
		"MATRIX_POSTGRES_PASSWORD_FILE": "/run/secrets/postgres-password",
		"MATRIX_IAM_URL":                "http://iam:8080",
		"MATRIX_IAM_CREDENTIAL_FILE":    "/run/secrets/iam-service-credential",
		"MATRIX_AUDIT_URL":              "http://audit:8080",
		"MATRIX_AUDIT_CREDENTIAL_FILE":  "/run/secrets/audit-service-credential",
	})
	paasSecrets := []mount{
		bind(postgresPassword, "/run/secrets/postgres-password", true),
		bind(iamCredential, "/run/secrets/iam-service-credential", true),
		bind(auditCredential, "/run/secrets/audit-service-credential", true),
	}
	paasAPI := service("paas-api", images["paas"], []string{"control"}, []string{"api"}, "1.0", "768M")
	paasAPI.Environment = paasEnvironment
	paasAPI.Volumes = slices.Clone(paasSecrets)
	paasAPI.DependsOn = healthy("postgres", "iam", "audit")

	paasWorker := service("paas-worker", images["paas"], []string{"control"}, []string{"worker"}, "2.0", "1G")
	paasWorker.Environment = cloneEnvironment(paasEnvironment, map[string]string{
		"MATRIX_EXECUTOR_ROOT": executorRoot,
	})
	paasWorker.Volumes = append(slices.Clone(paasSecrets),
		bind(executorRoot, executorRoot, false),
		bind("/var/run/docker.sock", "/var/run/docker.sock", false),
	)
	paasWorker.DependsOn = healthy("postgres", "iam", "audit")

	paasAudit := service(
		"paas-audit-dispatcher", images["paas"], []string{"control"}, []string{"audit-dispatch"}, "0.5", "384M",
	)
	paasAudit.Environment = paasEnvironment
	paasAudit.Volumes = slices.Clone(paasSecrets)
	paasAudit.DependsOn = healthy("postgres", "audit")

	ui := service("paas-ui", images["paas-ui"], []string{"web"}, nil, "0.5", "256M")

	apisix := service("apisix", images["apisix"], []string{"control", "web"}, nil, "1.0", "512M")
	apisix.Ports = []string{net.JoinHostPort(options.Listener, fmt.Sprint(options.Port)) + ":9080/tcp"}
	apisix.Volumes = []mount{
		bind(path.Join(root, "config/apisix.yaml"), "/usr/local/apisix/conf/apisix.yaml", true),
		bind(iamCredential, "/run/secrets/iam-service-credential", true),
	}
	apisix.DependsOn = healthy("iam", "paas-api", "paas-ui")

	return map[string]serviceConfig{
		"apisix": apisix, "audit": audit, "iam": iam, "paas-api": paasAPI,
		"paas-audit-dispatcher": paasAudit, "paas-ui": ui, "paas-worker": paasWorker,
		"postgres": postgres,
	}
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

func cloneEnvironment(base, additions map[string]string) map[string]string {
	result := make(map[string]string, len(base)+len(additions))
	for key, value := range base {
		result[key] = value
	}
	for key, value := range additions {
		result[key] = value
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
