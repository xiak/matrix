package sourcetrustfile

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	devopsv1 "github.com/xiak/matrix/api/devops/v1"
	"github.com/xiak/matrix/app/service/devops/sourcetrust"
)

func TestResolverUsesExactTenantAndOriginOrSystemFallback(t *testing.T) {
	now := time.Date(2026, 9, 10, 8, 0, 0, 0, time.UTC)
	root := privateRoot(t)
	scope := devopsv1.ResourceScope{TenantID: "tenant-one"}
	origin := "https://git.internal.example:3443"
	directory, err := sourcetrust.DirectoryName(scope, origin)
	if err != nil {
		t.Fatalf("DirectoryName() error = %v", err)
	}
	material := testRoot(t, now.Add(-time.Hour), now.Add(time.Hour))
	canonical, err := sourcetrust.Canonicalize(material, now)
	if err != nil {
		t.Fatalf("Canonicalize() error = %v", err)
	}
	writePrivate(t, filepath.Join(root, directory), sourcetrust.BundleFilename, canonical)

	resolver, err := newResolver(root, func() time.Time { return now })
	if err != nil {
		t.Fatalf("newResolver() error = %v", err)
	}
	pool, custom, err := resolver.Resolve(context.Background(), scope, origin)
	if err != nil || !custom || pool == nil || len(pool.Subjects()) != 1 {
		t.Fatalf("Resolve() = %#v, %t, %v", pool, custom, err)
	}
	for _, request := range []struct {
		scope  devopsv1.ResourceScope
		origin string
	}{
		{scope: devopsv1.ResourceScope{TenantID: "tenant-two"}, origin: origin},
		{scope: scope, origin: "https://git.internal.example:3444"},
	} {
		pool, custom, err = resolver.Resolve(context.Background(), request.scope, request.origin)
		if err != nil || custom || pool != nil {
			t.Fatalf("Resolve(system fallback) = %#v, %t, %v", pool, custom, err)
		}
	}
}

func TestResolverFailsClosedForPresentUnsafeMaterial(t *testing.T) {
	now := time.Date(2026, 9, 10, 8, 0, 0, 0, time.UTC)
	scope := devopsv1.ResourceScope{TenantID: "tenant-one"}
	origin := "https://git.internal.example"
	for name, mutate := range map[string]func(*testing.T, string, string){
		"invalid": func(t *testing.T, root, directory string) {
			writePrivate(t, filepath.Join(root, directory), sourcetrust.BundleFilename, []byte("invalid"))
		},
		"expired": func(t *testing.T, root, directory string) {
			material := testRoot(t, now.Add(-2*time.Hour), now.Add(-time.Hour))
			canonical, err := sourcetrust.Canonicalize(material, time.Time{})
			if err != nil {
				t.Fatalf("Canonicalize() error = %v", err)
			}
			writePrivate(t, filepath.Join(root, directory), sourcetrust.BundleFilename, canonical)
		},
		"extra": func(t *testing.T, root, directory string) {
			material := testRoot(t, now.Add(-time.Hour), now.Add(time.Hour))
			canonical, _ := sourcetrust.Canonicalize(material, now)
			writePrivate(t, filepath.Join(root, directory), sourcetrust.BundleFilename, canonical)
			if err := os.WriteFile(filepath.Join(root, directory, "extra"), []byte("x"), 0o600); err != nil {
				t.Fatalf("write extra file: %v", err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			root := privateRoot(t)
			directory, err := sourcetrust.DirectoryName(scope, origin)
			if err != nil {
				t.Fatalf("DirectoryName() error = %v", err)
			}
			mutate(t, root, directory)
			resolver, err := newResolver(root, func() time.Time { return now })
			if err != nil {
				t.Fatalf("newResolver() error = %v", err)
			}
			if pool, custom, err := resolver.Resolve(context.Background(), scope, origin); err == nil || custom || pool != nil {
				t.Fatalf("Resolve() = %#v, %t, %v", pool, custom, err)
			}
		})
	}
}

func TestResolverRejectsUnsafeRoot(t *testing.T) {
	root := privateRoot(t)
	if _, err := NewResolver(filepath.Join(root, "missing")); err == nil {
		t.Fatal("NewResolver() accepted a missing root")
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(root, 0o755); err != nil {
			t.Fatalf("chmod root: %v", err)
		}
		if _, err := NewResolver(root); err == nil {
			t.Fatal("NewResolver() accepted a public root")
		}
	}
}

func privateRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatalf("chmod root: %v", err)
	}
	return root
}

func writePrivate(t *testing.T, directory, name string, content []byte) {
	t.Helper()
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatalf("mkdir trust directory: %v", err)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatalf("chmod trust directory: %v", err)
	}
	if err := os.WriteFile(filepath.Join(directory, name), content, 0o600); err != nil {
		t.Fatalf("write trust file: %v", err)
	}
	if err := os.Chmod(filepath.Join(directory, name), 0o600); err != nil {
		t.Fatalf("chmod trust file: %v", err)
	}
}

func testRoot(t *testing.T, notBefore, notAfter time.Time) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Matrix resolver root"},
		NotBefore: notBefore, NotAfter: notAfter,
		BasicConstraintsValid: true, IsCA: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
