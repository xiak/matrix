package release

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	nodev1 "github.com/xiak/matrix/api/adapter/node/v1"
	"github.com/xiak/matrix/app/service/installation/nodeconfig"
)

func TestNodeReleaseHasNoPlatformAuthorityAndKeepsStrictCanonicalBytes(t *testing.T) {
	manifest := validNodeManifest()
	encoded, err := EncodeCanonical(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte(`"database"`)) || bytes.Contains(encoded, []byte(`"images"`)) {
		t.Fatal("node release contains a fictitious platform inventory")
	}
	decoded, err := DecodeCanonical(encoded)
	if err != nil || decoded.Kind != NodeManifestKind || decoded.Node == nil {
		t.Fatal("node release did not round trip")
	}
	for name, change := range map[string]func(*Manifest){
		"database":                 func(value *Manifest) { value.Database = CurrentDatabaseProfile() },
		"platform image":           func(value *Manifest) { value.Images = validManifest().Images },
		"missing protocol":         func(value *Manifest) { value.Node.ProtocolAPIVersion = "" },
		"missing runtime revision": func(value *Manifest) { value.Node.RuntimeRevision = 0 },
		"missing supervision":      func(value *Manifest) { value.Host.MinimumSystemd = 0 },
		"legacy envelope":          func(value *Manifest) { value.APIVersion = LegacyManifestAPIVersion },
		"missing collector":        func(value *Manifest) { value.Files = slices.Delete(value.Files, 2, 3) },
		"missing attribution":      func(value *Manifest) { value.Files = value.Files[:4] },
		"wrong executable":         func(value *Manifest) { value.Files[0].Path = "bin/arbitrary-shell" },
		"platform substitution":    func(value *Manifest) { value.Kind = ManifestKind },
	} {
		t.Run(name, func(t *testing.T) {
			value := validNodeManifest()
			change(&value)
			if _, err := EncodeCanonical(value); err == nil {
				t.Fatal("invalid node release admitted")
			}
		})
	}
	for _, field := range []string{`"database":null,`, `"database":{},`, `"images":[],`, `"node":null,`} {
		altered := append([]byte("{"+field), encoded[1:]...)
		if _, err := DecodeCanonical(altered); err == nil {
			t.Fatal("ambiguous node selector admitted")
		}
	}
}

func validNodeManifest() Manifest {
	value := validManifest()
	value.Kind, value.Database, value.Images = NodeManifestKind, DatabaseProfile{}, nil
	value.Node = &NodeProfile{ProtocolAPIVersion: nodev1.APIVersion, RuntimeRevision: nodeconfig.RuntimeRevision, CollectorVersion: nodeconfig.CollectorVersion}
	value.Host.MinimumSystemd = nodeconfig.MinimumSystemd
	value.Host.MinimumDocker, value.Host.MinimumCompose = nodeconfig.MinimumDocker, nodeconfig.MinimumCompose
	value.TopologyDigest = nodeconfig.ContractDigest()
	value.Files = nil
	for _, name := range []string{"bin/matrix-node-agent", "bin/mx", "bin/node-exporter", "licenses/node-exporter-license.txt", "licenses/node-exporter-notice.txt"} {
		file := File{Path: name, MediaType: mediaPlainText, Size: 1, SHA256: digest('a')}
		if strings.HasPrefix(name, "bin/") {
			file.MediaType, file.Executable = mediaExecutable, true
		}
		value.Files = append(value.Files, file)
	}
	return value
}

func TestReadTrustRootFileUsesExactCanonicalRegularFile(t *testing.T) {
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate release key: %v", err)
	}
	trust, err := NewTrustRoot("xiak-release-2026", publicKey)
	if err != nil {
		t.Fatalf("create release trust root: %v", err)
	}
	content, err := EncodeTrustRoot(trust)
	if err != nil {
		t.Fatalf("encode release trust root: %v", err)
	}
	target := filepath.Join(t.TempDir(), "release-trust.json")
	if err := os.WriteFile(target, content, 0o600); err != nil {
		t.Fatalf("write release trust root: %v", err)
	}
	read, decoded, err := ReadTrustRootFile(target)
	if err != nil || !slices.Equal(read, content) || decoded != trust {
		t.Fatalf("read trust root = %#v / %v", decoded, err)
	}

	link := filepath.Join(t.TempDir(), "release-trust.json")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symbolic links are unavailable to this test user: %v", err)
	}
	if _, _, err := ReadTrustRootFile(link); err == nil {
		t.Fatal("linked trust root must fail")
	}
}

func TestManifestCanonicalSignatureAndTamperRejection(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate release key: %v", err)
	}
	trust, err := NewTrustRoot("xiak-release-2026", publicKey)
	if err != nil {
		t.Fatalf("create release trust root: %v", err)
	}
	trustBytes, err := EncodeTrustRoot(trust)
	if err != nil {
		t.Fatalf("encode release trust root: %v", err)
	}
	manifest := validManifest()
	manifestBytes, err := EncodeCanonical(manifest)
	if err != nil {
		t.Fatalf("encode release manifest: %v", err)
	}
	signature := ed25519.Sign(privateKey, manifestBytes)
	verified, err := Verify(manifestBytes, signature, trustBytes)
	if err != nil || verified.Release.ID != manifest.Release.ID {
		t.Fatalf("verify release manifest = %#v / %v", verified.Release, err)
	}

	pretty, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatalf("pretty encode manifest: %v", err)
	}
	if _, err := Verify(pretty, ed25519.Sign(privateKey, pretty), trustBytes); err == nil {
		t.Fatal("non-canonical manifest must fail even with a valid signature")
	}
	tampered := append([]byte(nil), manifestBytes...)
	index := strings.Index(string(tampered), "build-gate-a")
	if index < 0 {
		t.Fatal("manifest fixture does not contain build identity")
	}
	tampered[index] = 'B'
	if _, err := Verify(tampered, signature, trustBytes); err == nil {
		t.Fatal("tampered manifest must fail signature verification")
	}
	otherPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate other release key: %v", err)
	}
	otherTrust, err := NewTrustRoot("xiak-release-2026", otherPublic)
	if err != nil {
		t.Fatalf("create other trust root: %v", err)
	}
	otherTrustBytes, _ := EncodeTrustRoot(otherTrust)
	if _, err := Verify(manifestBytes, signature, otherTrustBytes); err == nil {
		t.Fatal("another public key must not verify the release")
	}
}

func TestManifestRejectsUnsafeOrIncompleteInventory(t *testing.T) {
	tests := map[string]func(*Manifest){
		"path traversal": func(value *Manifest) {
			value.Files[0].Path = "../bin/mx"
		},
		"case-fold collision": func(value *Manifest) {
			value.Files = append(value.Files, File{
				Path: "docs/OPERATOR.md", MediaType: mediaMarkdown,
				Size: 1, SHA256: digest('d'),
			})
		},
		"duplicate path": func(value *Manifest) {
			value.Files = append(value.Files, value.Files[len(value.Files)-1])
		},
		"payload metadata": func(value *Manifest) {
			value.Files[0].Size = 0
		},
		"missing image": func(value *Manifest) {
			value.Images = value.Images[:len(value.Images)-1]
		},
		"image identity": func(value *Manifest) {
			value.Images[0].ImageID = "apisix:latest"
		},
		"source identity": func(value *Manifest) {
			value.Images[0].SourceDigest = "apisix:latest"
		},
		"duplicate image identity": func(value *Manifest) {
			value.Images[1].ImageID = value.Images[0].ImageID
		},
		"duplicate source identity": func(value *Manifest) {
			value.Images[1].SourceDigest = value.Images[0].SourceDigest
		},
		"architecture": func(value *Manifest) {
			value.Host.Architecture = "arm64"
		},
		"signer": func(value *Manifest) {
			value.Signer.Algorithm = "RSA"
		},
		"health contract": func(value *Manifest) {
			value.Images[1].HealthContract = "ready"
		},
		"image purpose": func(value *Manifest) {
			value.Images[0].Purpose = ImageWorkload
		},
		"previous release": func(value *Manifest) {
			value.Release.PreviousID = "matrix-v0.0.9-0123456789ab"
		},
		"previous release identity": func(value *Manifest) {
			value.Release.PreviousVersion = "v0.0.9"
			value.Release.PreviousID = "matrix-v0.0.9-not-a-commit"
		},
		"missing IAM schema":                     func(value *Manifest) { value.Database.Authorities.IAM = 0 },
		"missing Audit schema":                   func(value *Manifest) { value.Database.Authorities.Audit = 0 },
		"missing PaaS schema":                    func(value *Manifest) { value.Database.Authorities.PaaS = 0 },
		"missing authority contract":             func(value *Manifest) { value.Database.ContractRevision = 0 },
		"unbounded schema":                       func(value *Manifest) { value.Database.Authorities.PaaS = 9007199254740992 },
		"mixed scalar and authority profile":     func(value *Manifest) { value.Database.SchemaVersion = 1 },
		"unproved compatibility":                 func(value *Manifest) { value.Database.Compatibility = "expand-contract-n-minus-one" },
		"legacy envelope with authority profile": func(value *Manifest) { value.APIVersion = LegacyManifestAPIVersion },
		"new envelope with legacy scalar": func(value *Manifest) {
			value.Database = DatabaseProfile{SchemaVersion: 1, Compatibility: "expand-contract-n-minus-one"}
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			value := validManifest()
			mutate(&value)
			if _, err := EncodeCanonical(value); err == nil {
				t.Fatal("invalid release manifest must fail")
			}
		})
	}
}

func TestPublishedManifestCanonicalDatabaseBytesRemainVerifiable(t *testing.T) {
	manifest := validManifest()
	current, err := EncodeCanonical(manifest)
	if err != nil {
		t.Fatal(err)
	}
	currentDatabase, err := json.Marshal(manifest.Database)
	if err != nil {
		t.Fatal(err)
	}
	// These are the database fields and order in the published Phase 1 v1
	// format. The rest of the signed envelope/payload contract is unchanged.
	legacyBytes := bytes.Replace(current, []byte(ManifestAPIVersion), []byte(LegacyManifestAPIVersion), 1)
	legacyBytes = bytes.Replace(legacyBytes,
		append([]byte(`"database":`), currentDatabase...),
		[]byte(`"database":{"schemaVersion":1,"compatibility":"expand-contract-n-minus-one"}`), 1)
	legacy, err := DecodeCanonical(legacyBytes)
	if err != nil || legacy.Database.SchemaVersion != 1 || legacy.Database.Authorities != (AuthoritySchemas{}) {
		t.Fatalf("decode published database format: %#v / %v", legacy.Database, err)
	}
	roundTrip, err := EncodeCanonical(legacy)
	if err != nil || !bytes.Equal(roundTrip, legacyBytes) {
		t.Fatalf("published canonical bytes changed: %v", err)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	trust, err := NewTrustRoot(legacy.Signer.KeyID, publicKey)
	if err != nil {
		t.Fatal(err)
	}
	trustBytes, err := EncodeTrustRoot(trust)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(legacyBytes, ed25519.Sign(privateKey, legacyBytes), trustBytes); err != nil {
		t.Fatalf("verify published manifest: %v", err)
	}
}

func TestDatabaseUpgradePathIsExactAndNotNumeric(t *testing.T) {
	current := CurrentDatabaseProfile()
	predecessor := current
	predecessor.ContractRevision--
	if err := ValidateDatabaseUpgradePath(predecessor, current); err != nil {
		t.Fatalf("admit exact deployment-runtime predecessor: %v", err)
	}
	if err := ValidateDatabaseUpgradePath(current, current); err != nil {
		t.Fatalf("admit equal current profile: %v", err)
	}
	for name, pair := range map[string][2]DatabaseProfile{
		"reverse":        {current, predecessor},
		"skipped source": {func() DatabaseProfile { value := predecessor; value.ContractRevision--; return value }(), current},
		"future target":  {current, func() DatabaseProfile { value := current; value.ContractRevision++; return value }()},
		"PaaS change": {predecessor, func() DatabaseProfile {
			value := current
			value.Authorities.PaaS = 3
			return value
		}()},
	} {
		if ValidateDatabaseUpgradePath(pair[0], pair[1]) == nil {
			t.Fatalf("%s profile pair was admitted", name)
		}
	}
}

func TestManifestAdmitsOnlyForwardSemanticSuccessors(t *testing.T) {
	tests := []struct {
		name     string
		previous string
		target   string
		valid    bool
	}{
		{name: "minor", previous: "v0.1.0", target: "v0.2.0", valid: true},
		{name: "downgrade", previous: "v0.2.0", target: "v0.1.0"},
		{name: "stable to prerelease", previous: "v0.2.0", target: "v0.2.0-rc.1"},
		{name: "prerelease to stable", previous: "v0.2.0-rc.1", target: "v0.2.0", valid: true},
		{name: "prerelease increment", previous: "v0.2.0-rc.1", target: "v0.2.0-rc.2", valid: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			manifest := validManifest()
			manifest.Release.Version = test.target
			manifest.Release.ID = "matrix-" + test.target + "-" + manifest.Release.SourceCommit[:12]
			manifest.Release.PreviousVersion = test.previous
			manifest.Release.PreviousID = "matrix-" + test.previous + "-0123456789ab"
			_, err := EncodeCanonical(manifest)
			if (err == nil) != test.valid {
				t.Fatalf("successor validation error = %v, valid=%t", err, test.valid)
			}
		})
	}
}

func TestManifestStrictDecodersRejectUnknownMetadataAndSignatureShape(t *testing.T) {
	manifestBytes, err := EncodeCanonical(validManifest())
	if err != nil {
		t.Fatalf("encode manifest: %v", err)
	}
	withUnknown := append([]byte(nil), manifestBytes[:len(manifestBytes)-1]...)
	withUnknown = append(withUnknown, []byte(`,"unknown":true}`)...)
	if _, err := DecodeCanonical(withUnknown); err == nil {
		t.Fatal("unknown release metadata must fail")
	}
	iamField := fmt.Sprintf(`"iam":%d`, validManifest().Database.Authorities.IAM)
	for _, field := range []string{
		iamField + "," + iamField, `"iam":null`, `"iam":-1`, iamField + ".0",
		iamField + `,"unregisteredAuthority":2`,
	} {
		malformed := bytes.Replace(manifestBytes, []byte(iamField), []byte(field), 1)
		if _, err := DecodeCanonical(malformed); err == nil {
			t.Fatalf("ambiguous authority schema field accepted: %s", field)
		}
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate release key: %v", err)
	}
	trust, err := NewTrustRoot("xiak-release-2026", publicKey)
	if err != nil {
		t.Fatalf("create trust root: %v", err)
	}
	trustBytes, err := EncodeTrustRoot(trust)
	if err != nil {
		t.Fatalf("encode trust root: %v", err)
	}
	signature := ed25519.Sign(privateKey, manifestBytes)
	if _, err := Verify(manifestBytes, signature[:len(signature)-1], trustBytes); err == nil {
		t.Fatal("non-Ed25519 signature length must fail")
	}
	changedKeyID := validManifest()
	changedKeyID.Signer.KeyID = "other-release-key"
	changedBytes, err := EncodeCanonical(changedKeyID)
	if err != nil {
		t.Fatalf("encode changed signer manifest: %v", err)
	}
	if _, err := Verify(changedBytes, ed25519.Sign(privateKey, changedBytes), trustBytes); err == nil {
		t.Fatal("manifest signer identity must match the pinned trust root")
	}
}

func validManifest() Manifest {
	commit := strings.Repeat("a", 40)
	files := []File{{
		Path: "bin/mx", MediaType: mediaExecutable,
		Size: 1024, SHA256: digest('1'), Executable: true,
	}}
	required := RequiredImages()
	images := make([]Image, 0, len(required))
	fileDigests := "2345678"
	imageDigests := "89abcde"
	sourceDigests := "ef01234"
	for index, requirement := range required {
		archive := "images/" + requirement.Component + ".tar"
		files = append(files, File{
			Path: archive, MediaType: mediaDockerArchive,
			Size: 1024 + uint64(index), SHA256: digest(fileDigests[index]),
		})
		images = append(images, Image{
			Component: requirement.Component, Purpose: requirement.Purpose, ArchivePath: archive,
			ImageID: digest(imageDigests[index]), SourceDigest: digest(sourceDigests[index]),
			OS: "linux", Architecture: "amd64", HealthContract: requirement.HealthContract,
		})
	}
	slices.SortFunc(files, func(left, right File) int {
		return strings.Compare(left.Path, right.Path)
	})
	return Manifest{
		APIVersion: ManifestAPIVersion, Kind: ManifestKind,
		Release: ReleaseIdentity{
			ID: "matrix-v0.1.0-" + commit[:12], Version: "v0.1.0",
			SourceCommit: commit, BuildID: "build-gate-a",
			CreatedAt: time.Date(2026, 8, 25, 12, 0, 0, 123000000, time.UTC),
		},
		Signer: Signer{KeyID: "xiak-release-2026", Algorithm: SignatureAlgorithm},
		Host: HostProfile{
			OS: "linux", Architecture: "amd64", MinimumDocker: "29.0.0",
			MinimumCompose: "2.40.0", CommandContract: "v1",
		},
		MinimumFreeBytes: minimumFreeBytes,
		Database:         CurrentDatabaseProfile(),
		TopologyDigest:   digest('f'), Files: files, Images: images,
	}
}

func digest(value byte) string {
	return "sha256:" + strings.Repeat(string(value), 64)
}
