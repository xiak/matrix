// Package nodeconfig owns protected installation input consumed by the node
// process and its installer. It is not a northbound or node-request payload.
package nodeconfig

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	nodev1 "github.com/xiak/matrix/api/adapter/node/v1"
	"github.com/xiak/matrix/api/contractjson"
	paasv1 "github.com/xiak/matrix/api/paas/v1"
)

const (
	APIVersion        = "node.installation.matrix.xiak.com/v1"
	ConfigurationKind = "NodeConfiguration"
	EnrollmentKind    = "NodeEnrollment"
	MaximumBytes      = 64 * 1024
	RuntimeRevision   = 4
	MinimumSystemd    = 249
	MinimumDocker     = "27.5.1"
	MinimumCompose    = "2.33.0"
	CollectorVersion  = "1.12.1"
	NativeRootSyntax  = "absolute-posix-without-unit-syntax/v1"
)

// ServicePolicy is the fixed native supervision contract, not operator input.
// The provider consumes these values and the signed bundle commits to them.
type ServicePolicy struct {
	Type                     string `json:"type"`
	RemainAfterExit          bool   `json:"remainAfterExit"`
	DynamicUser              bool   `json:"dynamicUser"`
	MemoryMax                uint64 `json:"memoryMax"`
	TasksMax                 uint64 `json:"tasksMax"`
	CPUQuotaPerSecond        uint64 `json:"cpuQuotaPerSecond"`
	Restart                  string `json:"restart"`
	RestartMicros            uint64 `json:"restartMicros"`
	TimeoutStartMicros       uint64 `json:"timeoutStartMicros"`
	TimeoutStopMicros        uint64 `json:"timeoutStopMicros"`
	NoNewPrivileges          bool   `json:"noNewPrivileges"`
	ProtectSystem            string `json:"protectSystem"`
	ProtectHome              string `json:"protectHome"`
	PrivateDevices           bool   `json:"privateDevices"`
	RuntimeDirectoryMode     uint32 `json:"runtimeDirectoryMode"`
	RuntimeDirectoryPreserve string `json:"runtimeDirectoryPreserve"`
}

func Policy(collector bool) ServicePolicy {
	value := ServicePolicy{
		Type: "exec", TimeoutStartMicros: 30000000,
		MemoryMax: 512 * 1024 * 1024, TasksMax: 128, CPUQuotaPerSecond: 1000000,
		Restart: "on-failure", RestartMicros: 2000000, TimeoutStopMicros: 10000000,
		NoNewPrivileges: true, ProtectSystem: "strict", ProtectHome: "yes", PrivateDevices: true,
		RuntimeDirectoryMode: 0o700, RuntimeDirectoryPreserve: "no",
	}
	if collector {
		value.DynamicUser = true
		value.MemoryMax = 128 * 1024 * 1024
		value.TasksMax = 64
		value.CPUQuotaPerSecond = 500000
	}
	return value
}

func StartupPolicy() ServicePolicy {
	value := Policy(false)
	value.Type, value.RemainAfterExit = "oneshot", true
	value.TimeoutStartMicros, value.RestartMicros = 120000000, 30000000
	return value
}

// ServiceName binds native ownership to the platform installation and target,
// not a user-selected unit name or a reusable process label.
func ServiceName(identity nodev1.Identity, collector bool) (string, error) {
	if nodev1.ValidateIdentity(identity) != nil {
		return "", errors.New("node identity is invalid")
	}
	sum := sha256.Sum256([]byte(identity.InstallationID + "\x00" + string(identity.ExecutionTargetID)))
	prefix := "matrix-node-"
	if collector {
		prefix = "matrix-collector-"
	}
	return prefix + hex.EncodeToString(sum[:12]) + ".service", nil
}

func StartupServiceName(identity nodev1.Identity) (string, error) {
	name, err := ServiceName(identity, false)
	if err != nil {
		return "", err
	}
	return strings.Replace(name, "matrix-node-", "matrix-node-start-", 1), nil
}

// ValidateNativeRoot bounds native unit-file round trips on the minimum
// systemd. Its transient bind serialization does not quote source paths, so
// accepting setting syntax here could change a binding on daemon reload.
// Enrollment source files outside this root are not native mount sources.
func ValidateNativeRoot(value string) error {
	if value == "/" || !path.IsAbs(value) || path.Clean(value) != value || len(value) > 4096 || !utf8.ValidString(value) {
		return errors.New("native node root is invalid")
	}
	for _, character := range value {
		if unicode.IsSpace(character) || unicode.IsControl(character) || strings.ContainsRune(":\"'\\$%", character) {
			return errors.New("native node root contains unit-file syntax")
		}
	}
	return nil
}

func ContractDigest() string {
	value := struct {
		Protocol         string        `json:"protocol"`
		Revision         uint64        `json:"revision"`
		CollectorVersion string        `json:"collectorVersion"`
		MinimumSystemd   uint64        `json:"minimumSystemd"`
		MinimumDocker    string        `json:"minimumDocker"`
		MinimumCompose   string        `json:"minimumCompose"`
		NativeRootSyntax string        `json:"nativeRootSyntax"`
		Node             ServicePolicy `json:"node"`
		Collector        ServicePolicy `json:"collector"`
		Startup          ServicePolicy `json:"startup"`
	}{nodev1.APIVersion, RuntimeRevision, CollectorVersion, MinimumSystemd, MinimumDocker, MinimumCompose, NativeRootSyntax, Policy(false), Policy(true), StartupPolicy()}
	encoded, _ := json.Marshal(value)
	digest := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(digest[:])
}

type Configuration struct {
	APIVersion          string          `json:"apiVersion"`
	Kind                string          `json:"kind"`
	Identity            nodev1.Identity `json:"identity"`
	ControllerID        string          `json:"controllerId"`
	BindingRef          string          `json:"bindingRef"`
	ExpectedFingerprint string          `json:"expectedFingerprint"`
	ListenAddress       string          `json:"listenAddress"`
	CollectorEndpoint   string          `json:"collectorEndpoint"`
	StoragePath         string          `json:"storagePath"`
	CertificateFile     string          `json:"certificateFile"`
	PrivateKeyFile      string          `json:"privateKeyFile"`
	TrustFile           string          `json:"trustFile"`
	SystemReserve       paasv1.Capacity `json:"systemReserve"`
}

type Enrollment struct {
	APIVersion               string        `json:"apiVersion"`
	Kind                     string        `json:"kind"`
	Node                     Configuration `json:"node"`
	CollectorCertificateFile string        `json:"collectorCertificateFile"`
	CollectorPrivateKeyFile  string        `json:"collectorPrivateKeyFile"`
}

func DecodeConfiguration(source []byte) (Configuration, error) {
	var value Configuration
	if contractjson.DecodeObjectBytes(source, MaximumBytes, &value) != nil || ValidateConfiguration(value) != nil {
		return Configuration{}, errors.New("node configuration is invalid")
	}
	return value, nil
}

func DecodeEnrollment(source []byte) (Enrollment, error) {
	var value Enrollment
	if contractjson.DecodeObjectBytes(source, MaximumBytes, &value) != nil ||
		value.APIVersion != APIVersion || value.Kind != EnrollmentKind ||
		ValidateConfiguration(value.Node) != nil ||
		!absolutePath(value.CollectorCertificateFile) || !absolutePath(value.CollectorPrivateKeyFile) {
		return Enrollment{}, errors.New("node enrollment is invalid")
	}
	return value, nil
}

func ValidateConfiguration(value Configuration) error {
	if value.APIVersion != APIVersion || value.Kind != ConfigurationKind ||
		nodev1.ValidateIdentity(value.Identity) != nil ||
		paasv1.ValidateID("controllerId", value.ControllerID) != nil ||
		paasv1.ValidateID("bindingRef", value.BindingRef) != nil ||
		paasv1.ValidateDigest("expectedFingerprint", value.ExpectedFingerprint) != nil ||
		!privateListenAddress(value.ListenAddress) {
		return errors.New("node configuration is invalid")
	}
	for _, name := range []string{value.StoragePath, value.CertificateFile, value.PrivateKeyFile, value.TrustFile} {
		if !absolutePath(name) {
			return errors.New("node configuration path is invalid")
		}
	}
	if _, err := CollectorListenAddress(value); err != nil {
		return err
	}
	for _, reserve := range []int64{value.SystemReserve.CPUMillis, value.SystemReserve.MemoryBytes,
		value.SystemReserve.StorageBytes, value.SystemReserve.WorkloadSlots} {
		if reserve < 0 || reserve > 9007199254740991 {
			return errors.New("node reserve is invalid")
		}
	}
	return nil
}

func CollectorListenAddress(value Configuration) (string, error) {
	endpoint, err := url.Parse(value.CollectorEndpoint)
	if err != nil || endpoint.Scheme != "https" || endpoint.User != nil || endpoint.Opaque != "" ||
		endpoint.Path != "" || endpoint.RawPath != "" || endpoint.RawQuery != "" || endpoint.ForceQuery ||
		endpoint.Fragment != "" || strings.Contains(endpoint.Host, "%") {
		return "", errors.New("node collector endpoint is invalid")
	}
	host, port, err := net.SplitHostPort(endpoint.Host)
	parsedPort, portErr := strconv.ParseUint(port, 10, 16)
	address := net.ParseIP(host)
	if err != nil || portErr != nil || parsedPort == 0 || address == nil || !address.IsLoopback() ||
		endpoint.Host == value.ListenAddress {
		return "", errors.New("node collector endpoint is invalid")
	}
	nodeHost, nodePort, _ := net.SplitHostPort(value.ListenAddress)
	parsedNodePort, _ := strconv.ParseUint(nodePort, 10, 16)
	if address.Equal(net.ParseIP(nodeHost)) && parsedPort == parsedNodePort {
		return "", errors.New("node and collector listeners overlap")
	}
	return endpoint.Host, nil
}

func absolutePath(value string) bool {
	return value != "" && len(value) <= 4096 && filepath.IsAbs(value) && filepath.Clean(value) == value &&
		!strings.ContainsAny(value, "\x00\r\n")
}

func privateListenAddress(address string) bool {
	host, portText, err := net.SplitHostPort(address)
	port, portErr := strconv.ParseUint(portText, 10, 16)
	addressIP := net.ParseIP(host)
	return err == nil && portErr == nil && port > 0 && addressIP != nil &&
		(addressIP.IsLoopback() || addressIP.IsPrivate())
}
