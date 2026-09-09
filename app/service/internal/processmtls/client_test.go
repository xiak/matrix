package processmtls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

const clientIdentity = "spiffe://matrix.test/devops/build-worker"

func TestLoadClientCredentialsBindsProtectedIdentityAndServerRoots(t *testing.T) {
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	certificatePEM, keyPEM, serverRootsPEM := clientMaterialFixture(t, now, clientIdentity, nil)
	certificatePath, keyPath, rootsPath := writeClientMaterial(
		t, certificatePEM, keyPEM, serverRootsPEM,
	)
	credentials, err := LoadClientCredentials(
		certificatePath, keyPath, rootsPath, clientIdentity, now,
	)
	if err != nil {
		t.Fatal(err)
	}
	if credentials.Certificate.Leaf == nil ||
		len(credentials.Certificate.Leaf.URIs) != 1 ||
		credentials.Certificate.Leaf.URIs[0].String() != clientIdentity ||
		credentials.Certificate.PrivateKey == nil ||
		credentials.ServerRoots == nil || len(credentials.ServerRoots.Subjects()) != 1 {
		t.Fatalf("credentials = %#v", credentials)
	}
}

func TestLoadClientCredentialsRejectsAmbiguousOrChangedMaterial(t *testing.T) {
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	validCertificate, validKey, validRoots := clientMaterialFixture(
		t, now, clientIdentity, nil,
	)
	otherCertificate, otherKey, _ := clientMaterialFixture(
		t, now, "spiffe://matrix.test/devops/other-worker", nil,
	)
	ambiguousCertificate, ambiguousKey, _ := clientMaterialFixture(
		t, now, clientIdentity, []string{"unexpected.invalid"},
	)
	fixtures := map[string]struct {
		certificate []byte
		key         []byte
		roots       []byte
		identity    string
		at          time.Time
	}{
		"wrong identity": {
			certificate: validCertificate, key: validKey, roots: validRoots,
			identity: "spiffe://matrix.test/devops/not-this-worker", at: now,
		},
		"ambiguous SAN": {
			certificate: ambiguousCertificate, key: ambiguousKey,
			roots: validRoots, identity: clientIdentity, at: now,
		},
		"mismatched private key": {
			certificate: validCertificate, key: otherKey, roots: validRoots,
			identity: clientIdentity, at: now,
		},
		"duplicate server root": {
			certificate: validCertificate, key: validKey,
			roots:    append(append([]byte(nil), validRoots...), validRoots...),
			identity: clientIdentity, at: now,
		},
		"noncanonical certificate": {
			certificate: append(append([]byte(nil), validCertificate...), '\n'),
			key:         validKey, roots: validRoots, identity: clientIdentity, at: now,
		},
		"expired client": {
			certificate: validCertificate, key: validKey, roots: validRoots,
			identity: clientIdentity, at: now.Add(25 * time.Hour),
		},
		"invalid expected identity": {
			certificate: validCertificate, key: validKey, roots: validRoots,
			identity: "https://matrix.test/devops/build-worker", at: now,
		},
		"other valid client": {
			certificate: otherCertificate, key: otherKey, roots: validRoots,
			identity: clientIdentity, at: now,
		},
	}
	for name, fixture := range fixtures {
		t.Run(name, func(t *testing.T) {
			certificatePath, keyPath, rootsPath := writeClientMaterial(
				t, fixture.certificate, fixture.key, fixture.roots,
			)
			if _, err := LoadClientCredentials(
				certificatePath, keyPath, rootsPath, fixture.identity, fixture.at,
			); !errors.Is(err, ErrInvalidClientMaterial) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestLoadClientCredentialsRequiresProtectedPrivateKey(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows ACLs are enforced by installation ownership")
	}
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	certificatePEM, keyPEM, rootsPEM := clientMaterialFixture(t, now, clientIdentity, nil)
	certificatePath, keyPath, rootsPath := writeClientMaterial(
		t, certificatePEM, keyPEM, rootsPEM,
	)
	if err := os.Chmod(keyPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadClientCredentials(
		certificatePath, keyPath, rootsPath, clientIdentity, now,
	); !errors.Is(err, ErrInvalidClientMaterial) {
		t.Fatalf("public private-key permissions error = %v", err)
	}
}

func TestLoadSystemdClientCredentialsAcceptsReadOnlyCredentialMount(t *testing.T) {
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	certificatePEM, keyPEM, rootsPEM := clientMaterialFixture(t, now, clientIdentity, nil)
	directory := filepath.Join(t.TempDir(), "credentials")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string][]byte{
		"client.crt":    certificatePEM,
		"client.key":    keyPEM,
		"server-ca.pem": rootsPEM,
	} {
		path := filepath.Join(directory, name)
		if err := os.WriteFile(path, content, 0o600); err != nil || os.Chmod(path, 0o440) != nil {
			t.Fatalf("prepare systemd credential %s failed", name)
		}
	}
	if err := os.Chmod(directory, 0o550); err != nil {
		t.Fatal(err)
	}
	credentials, err := LoadSystemdClientCredentials(
		directory, "client.crt", "client.key", "server-ca.pem", clientIdentity, now,
	)
	if err != nil || credentials.Certificate.Leaf == nil ||
		credentials.Certificate.Leaf.URIs[0].String() != clientIdentity ||
		credentials.ServerRoots == nil {
		t.Fatalf("systemd credentials=%#v err=%v", credentials, err)
	}
}

func writeClientMaterial(
	t *testing.T,
	certificate []byte,
	key []byte,
	roots []byte,
) (string, string, string) {
	t.Helper()
	root := t.TempDir()
	certificatePath := filepath.Join(root, "client.crt")
	keyPath := filepath.Join(root, "client.key")
	rootsPath := filepath.Join(root, "server-ca.crt")
	if err := os.WriteFile(certificatePath, certificate, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, key, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rootsPath, roots, 0o644); err != nil {
		t.Fatal(err)
	}
	return certificatePath, keyPath, rootsPath
}

func clientMaterialFixture(
	t *testing.T,
	now time.Time,
	identity string,
	dnsNames []string,
) ([]byte, []byte, []byte) {
	t.Helper()
	clientCA, clientCAKey, clientCAPEM := certificateAuthority(t, now, "client-ca")
	_, _, serverCAPEM := certificateAuthority(t, now, "server-ca")
	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	identityURL, err := url.Parse(identity)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(10), Subject: pkix.Name{CommonName: "process-client"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		URIs:        []*url.URL{identityURL}, DNSNames: dnsNames,
	}
	der, err := x509.CreateCertificate(
		rand.Reader, template, clientCA, &clientKey.PublicKey, clientCAKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(clientKey)
	if err != nil {
		t.Fatal(err)
	}
	certificatePEM := append(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		clientCAPEM...,
	)
	return certificatePEM,
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
		serverCAPEM
}

func certificateAuthority(
	t *testing.T,
	now time.Time,
	name string,
) (*x509.Certificate, *ecdsa.PrivateKey, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true, IsCA: true,
	}
	der, err := x509.CreateCertificate(
		rand.Reader, template, template, &key.PublicKey, key,
	)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return certificate, key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
