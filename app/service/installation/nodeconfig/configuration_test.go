package nodeconfig

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/url"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	nodev1 "github.com/xiak/matrix/api/adapter/node/v1"
	paasv1 "github.com/xiak/matrix/api/paas/v1"
)

func TestJoinFileBindsOneRawCredentialToSignedPublicMetadata(t *testing.T) {
	credential := []byte("0123456789abcdef0123456789abcdef")
	digest := sha256.Sum256(credential)
	installationID := "mxi-" + strings.Repeat("a", 32)
	issuerURI, err := paasv1.NodeEnrollmentIssuerURI(installationID)
	if err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	issuerTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Matrix join test issuer"},
		NotBefore:             time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC),
		BasicConstraintsValid: true, IsCA: true, MaxPathLenZero: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		URIs:     []*url.URL{issuerURI},
	}
	issuer, err := x509.CreateCertificate(rand.Reader, issuerTemplate, issuerTemplate, public, private)
	if err != nil {
		t.Fatal(err)
	}
	enrollmentID := paasv1.ResourceID("node-enrollment-" + strings.Repeat("a", 32))
	join := paasv1.NodeEnrollmentJoin{
		APIVersion: paasv1.NodeEnrollmentJoinAPIVersion, Kind: paasv1.NodeEnrollmentJoinKind,
		EnrollmentID: enrollmentID, InstallationID: installationID, ExecutionTargetID: "target-a",
		ControlPlaneURL:    "https://matrix.internal/api/paas/v1/node-enrollments/" + string(enrollmentID) + "/exchange",
		CredentialDigest:   "sha256:" + hex.EncodeToString(digest[:]),
		ExpiresAt:          time.Date(2026, 9, 7, 9, 30, 0, 0, time.UTC),
		IssuerCertificate:  base64.RawURLEncoding.EncodeToString(issuer),
		SignatureAlgorithm: paasv1.NodeJoinSignatureEd25519,
	}
	commitment, err := paasv1.NodeEnrollmentJoinSigningBytes(join)
	if err != nil {
		t.Fatal(err)
	}
	join.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, commitment))
	input := JoinFile{APIVersion: APIVersion, Kind: JoinFileKind, Join: join,
		Credential: base64.RawURLEncoding.EncodeToString(credential)}
	encoded, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeJoinFile(encoded)
	if err != nil || decoded != input {
		t.Fatal("signed join file did not round-trip")
	}
	if strings.Contains(fmt.Sprintf("%v %#v", decoded, decoded), input.Credential) ||
		SelfEnrollmentSystemReserve() != (paasv1.Capacity{MemoryBytes: 256 * 1024 * 1024}) {
		t.Fatal("join formatting exposed its credential or changed fixed reserve policy")
	}
	decoded.Clear()
	if decoded.Credential != "" {
		t.Fatal("join credential was not cleared")
	}

	for name, mutate := range map[string]func(*JoinFile){
		"different credential": func(value *JoinFile) {
			value.Credential = base64.RawURLEncoding.EncodeToString(bytesOf(0x42, 32))
		},
		"padded credential": func(value *JoinFile) { value.Credential += "=" },
		"tampered target":   func(value *JoinFile) { value.Join.ExecutionTargetID = "target-b" },
		"wrong kind":        func(value *JoinFile) { value.Kind = EnrollmentKind },
	} {
		t.Run(name, func(t *testing.T) {
			changed := input
			mutate(&changed)
			source, err := json.Marshal(changed)
			if err != nil {
				t.Fatal(err)
			}
			if value, err := DecodeJoinFile(source); err == nil {
				value.Clear()
				t.Fatal("unbound or ambiguous join input was admitted")
			}
		})
	}
	unknown := strings.Replace(string(encoded), `"join":`, `"privateKey":"forbidden","join":`, 1)
	duplicate := strings.Replace(string(encoded), `"credential":`, `"credential":"other","credential":`, 1)
	for _, source := range []string{unknown, duplicate, string(encoded) + `{}`, `null`} {
		if value, err := DecodeJoinFile([]byte(source)); err == nil {
			value.Clear()
			t.Fatal("non-closed join input was admitted")
		}
	}
}

func bytesOf(value byte, count int) []byte {
	result := make([]byte, count)
	for index := range result {
		result[index] = value
	}
	return result
}

func TestControllerConfigurationIsPrivateClosedAndAppendOnly(t *testing.T) {
	empty := EmptyController("mxi-" + strings.Repeat("a", 32))
	initial, err := EncodeController(empty)
	if err != nil {
		t.Fatal(err)
	}
	if decoded, err := DecodeController(initial); err != nil || !reflect.DeepEqual(decoded, empty) {
		t.Fatal("empty controller did not round trip")
	}
	configured := empty
	configured.Nodes = []Connection{{BindingRef: "binding-a", TargetID: "target-a", Endpoint: "https://192.168.5.10:16443", IdentityFingerprint: "sha256:" + strings.Repeat("b", 64)}}
	configured.Certificate, configured.PrivateKey, configured.Trust = []byte("certificate-fixture"), []byte("private-fixture-key"), []byte("trust-fixture")
	encoded, err := EncodeController(configured)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeController(encoded)
	if err != nil || !reflect.DeepEqual(decoded, configured) {
		t.Fatal("private controller did not round trip")
	}
	defer decoded.Clear()
	if _, err := json.Marshal(configured); err == nil || strings.Contains(fmt.Sprintf("%v %+v %#v", configured, configured, configured), "private-fixture-key") {
		t.Fatal("controller credentials were serialized or printed")
	}
	firstDigest, _ := ControllerDigest(configured)
	decoded.PrivateKey[0] ^= 1
	secondDigest, _ := ControllerDigest(decoded)
	if firstDigest == secondDigest {
		t.Fatal("controller commitment omitted the private credential")
	}
	if ValidateControllerUpdate(empty, configured) != nil {
		t.Fatal("first connection rejected")
	}
	appended := configured
	appended.Nodes = append(slices.Clone(configured.Nodes), Connection{BindingRef: "binding-b", TargetID: "target-b", Endpoint: "https://192.168.5.11:16443", IdentityFingerprint: "sha256:" + strings.Repeat("c", 64)})
	if ValidateControllerUpdate(configured, appended) != nil {
		t.Fatal("appended connection rejected")
	}
	for _, mutate := range []func(*ControllerConfiguration){
		func(c *ControllerConfiguration) { c.InstallationID = "other" },
		func(c *ControllerConfiguration) { c.ControllerID = "other" },
		func(c *ControllerConfiguration) {
			c.Nodes = []Connection{}
			c.Certificate = nil
			c.PrivateKey = nil
			c.Trust = nil
		},
		func(c *ControllerConfiguration) { c.Nodes[0].TargetID = "other" },
		func(c *ControllerConfiguration) { c.Nodes[0].BindingRef = "other" },
		func(c *ControllerConfiguration) { c.Nodes[0].Endpoint = "https://192.168.5.12:16443" },
		func(c *ControllerConfiguration) { c.Nodes[0].IdentityFingerprint = "sha256:" + strings.Repeat("d", 64) },
	} {
		candidate := configured
		candidate.Nodes = slices.Clone(configured.Nodes)
		mutate(&candidate)
		if ValidateControllerUpdate(configured, candidate) == nil {
			t.Fatal("controller replacement removed or rebound an existing identity")
		}
	}
	for _, invalid := range []string{
		"null", "{}", string(encoded) + "{}", string(encoded) + strings.Repeat(" ", MaximumControllerBytes),
		strings.Replace(string(encoded), `"nodes":`, `"caPrivateKey":"forbidden","nodes":`, 1),
		strings.Replace(string(encoded), `"controllerId":`, `"controllerId":"other","controllerId":`, 1),
		strings.Replace(string(encoded), `"controllerId":`, `"ControllerId":`, 1),
		strings.Replace(string(encoded), "https://192.168.5.10:16443", "https://8.8.8.8:16443", 1),
		strings.Replace(string(encoded), "https://192.168.5.10:16443", "https://customer-dns:16443", 1),
		strings.Replace(string(encoded), "https://192.168.5.10:16443", "https://192.168.5.10:16443?", 1),
	} {
		if value, err := DecodeController([]byte(invalid)); err == nil {
			value.Clear()
			t.Fatal("untrusted controller document admitted")
		}
	}
	for _, mutate := range []func(*ControllerConfiguration){
		func(c *ControllerConfiguration) { c.Nodes = nil },
		func(c *ControllerConfiguration) { c.Nodes = append(c.Nodes, c.Nodes[0]) },
		func(c *ControllerConfiguration) { c.Nodes = make([]Connection, MaximumConnections+1) },
		func(c *ControllerConfiguration) { c.PrivateKey = nil },
	} {
		candidate := configured
		candidate.Nodes = slices.Clone(configured.Nodes)
		mutate(&candidate)
		if ValidateController(candidate) == nil {
			t.Fatal("ambiguous or incomplete controller admitted")
		}
	}
}

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
	startup, _ := StartupServiceName(identity)
	other := identity
	other.ExecutionTargetID = "target-b"
	otherTarget, _ := ServiceName(other, false)
	other = identity
	other.InstallationID = "mxi-" + strings.Repeat("b", 32)
	otherInstallation, _ := ServiceName(other, false)
	if first != again || first == collector || first == otherTarget || first == otherInstallation || startup == first || startup == collector {
		t.Fatal("native service identity aliases another authority or role")
	}
	if _, err := ServiceName(nodev1.Identity{}, false); err == nil {
		t.Fatal("missing node identity received a service name")
	}
	if _, err := StartupServiceName(nodev1.Identity{}); err == nil {
		t.Fatal("missing node identity received a startup registration")
	}
}

func TestNativeRootRejectsUnitFileReinterpretation(t *testing.T) {
	for _, root := range []string{"/data/xiak/matrix-node", "/opt/matrix/node_a.1", "/data/节点-一"} {
		if err := ValidateNativeRoot(root); err != nil {
			t.Fatalf("supported native root rejected: %v", err)
		}
	}
	for _, root := range []string{"", "/", "relative", "/data/../other", "/data//node", "/data/node/", "/data/with space", "/data/tab\tpath",
		"/data/bind:target", "/data/\"quote", "/data/'quote", "/data/back\\slash", "/data/%n", "/data/${USER}", "/data/\u00a0space", "/data/control\x00", string([]byte{'/', 0xff})} {
		if err := ValidateNativeRoot(root); err == nil {
			t.Fatalf("unsafe native root admitted: %q", root)
		}
	}
}

func TestDeploymentRuntimePredecessorContractDigestIsFrozen(t *testing.T) {
	const expected = "sha256:f60ec594fc58390c8f7013d33406c9af0999abf33626a3d9a83ad6e21c3f823f"
	if actual := DeploymentRuntimePredecessorContractDigest(); actual != expected {
		t.Fatalf("predecessor contract digest = %q", actual)
	}
}
