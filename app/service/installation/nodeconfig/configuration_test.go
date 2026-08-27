package nodeconfig

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	nodev1 "github.com/xiak/matrix/api/adapter/node/v1"
	paasv1 "github.com/xiak/matrix/api/paas/v1"
)

func TestEnrollmentIsClosedAndKeepsCollectorLocal(t *testing.T) {
	root := t.TempDir()
	config := Configuration{APIVersion: APIVersion, Kind: ConfigurationKind,
		Identity:     nodev1.Identity{InstallationID: "mxi-" + strings.Repeat("a", 32), ExecutionTargetID: "target-a"},
		ControllerID: "controller-a", BindingRef: "binding-a", ExpectedFingerprint: "sha256:" + strings.Repeat("a", 64),
		ListenAddress: "192.168.50.10:16443", CollectorEndpoint: "https://127.0.0.1:19100",
		StoragePath: filepath.Join(root, "executor"), CertificateFile: filepath.Join(root, "node.pem"),
		PrivateKeyFile: filepath.Join(root, "node-key.pem"), TrustFile: filepath.Join(root, "trust.pem"),
		SystemReserve: paasv1.Capacity{CPUMillis: 250, MemoryBytes: 256 * 1024 * 1024}}
	enrollment := Enrollment{APIVersion: APIVersion, Kind: EnrollmentKind, Node: config,
		CollectorCertificateFile: filepath.Join(root, "collector.pem"), CollectorPrivateKeyFile: filepath.Join(root, "collector-key.pem")}
	encoded, err := json.Marshal(enrollment)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeEnrollment(encoded)
	if err != nil || decoded != enrollment {
		t.Fatal("protected node enrollment did not round-trip")
	}
	for name, source := range map[string]string{
		"unknown override": strings.Replace(string(encoded), `"node":`, `"controllerPrivateKey":"secret","node":`, 1),
		"duplicate field":  strings.Replace(string(encoded), `"controllerId":`, `"controllerId":"other","controllerId":`, 1),
		"case alias":       strings.Replace(string(encoded), `"controllerId":`, `"ControllerId":`, 1),
		"trailing object":  string(encoded) + `{}`,
		"root null":        `null`,
		"oversized":        string(encoded) + strings.Repeat(" ", MaximumBytes),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeEnrollment([]byte(source)); err == nil {
				t.Fatal("ambiguous enrollment was admitted")
			}
		})
	}
	for name, mutate := range map[string]func(*Configuration){
		"public node listener": func(c *Configuration) { c.ListenAddress = "8.8.8.8:16443" },
		"wildcard listener":    func(c *Configuration) { c.ListenAddress = "0.0.0.0:16443" },
		"DNS node listener":    func(c *Configuration) { c.ListenAddress = "node.example:16443" },
		"remote collector":     func(c *Configuration) { c.CollectorEndpoint = "https://192.168.50.10:19100" },
		"DNS collector":        func(c *Configuration) { c.CollectorEndpoint = "https://localhost:19100" },
		"cleartext collector":  func(c *Configuration) { c.CollectorEndpoint = "http://127.0.0.1:19100" },
		"collector userinfo":   func(c *Configuration) { c.CollectorEndpoint = "https://user@127.0.0.1:19100" },
		"collector path":       func(c *Configuration) { c.CollectorEndpoint = "https://127.0.0.1:19100/metrics" },
		"collector query":      func(c *Configuration) { c.CollectorEndpoint = "https://127.0.0.1:19100?" },
		"shared port": func(c *Configuration) {
			c.ListenAddress, c.CollectorEndpoint = "127.0.0.1:19100", "https://[::ffff:127.0.0.1]:19100"
		},
		"negative reserve":  func(c *Configuration) { c.SystemReserve.MemoryBytes = -1 },
		"unbounded reserve": func(c *Configuration) { c.SystemReserve.CPUMillis = 9007199254740992 },
		"relative key":      func(c *Configuration) { c.PrivateKeyFile = "node-key.pem" },
		"path injection":    func(c *Configuration) { c.StoragePath += "\nother" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := config
			mutate(&changed)
			source, err := json.Marshal(changed)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := DecodeConfiguration(source); err == nil {
				t.Fatal("unsafe node configuration was admitted")
			}
		})
	}
}

func TestNativeServiceIdentitySeparatesTargetsInstallationsAndRoles(t *testing.T) {
	identity := nodev1.Identity{InstallationID: "mxi-" + strings.Repeat("a", 32), ExecutionTargetID: "target-a"}
	first, err := ServiceName(identity, false)
	if err != nil {
		t.Fatal(err)
	}
	again, _ := ServiceName(identity, false)
	collector, _ := ServiceName(identity, true)
	other := identity
	other.ExecutionTargetID = "target-b"
	otherTarget, _ := ServiceName(other, false)
	other = identity
	other.InstallationID = "mxi-" + strings.Repeat("b", 32)
	otherInstallation, _ := ServiceName(other, false)
	if first != again || first == collector || first == otherTarget || first == otherInstallation {
		t.Fatal("native service identity aliases another authority or role")
	}
	if _, err := ServiceName(nodev1.Identity{}, false); err == nil {
		t.Fatal("missing node identity received a service name")
	}
}
