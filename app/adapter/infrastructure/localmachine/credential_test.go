package localmachine

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestNewSSHCredentialParsesAndRedactsPrivateKeyMaterial(t *testing.T) {
	expectedSigner, privateKeyPEM := mustSSHSignerAndPEM(t)
	credential, err := NewSSHCredential(SSHCredentialSpec{
		Username:      "matrix-worker",
		PrivateKeyPEM: privateKeyPEM,
	})
	if err != nil {
		t.Fatalf("NewSSHCredential() error = %v", err)
	}
	if err := ValidateSSHCredential(credential); err != nil {
		t.Fatalf("ValidateSSHCredential() error = %v", err)
	}
	if got, want := ssh.FingerprintSHA256(credential.signer.PublicKey()),
		ssh.FingerprintSHA256(expectedSigner.PublicKey()); got != want {
		t.Fatalf("parsed signer fingerprint = %q, want %q", got, want)
	}

	for index := range privateKeyPEM {
		privateKeyPEM[index] = 0
	}
	if credential.signer == nil {
		t.Fatal("credential retained no parsed signer")
	}
	rendered := fmt.Sprintf("%v %#v", credential, credential)
	for _, forbidden := range []string{
		"matrix-worker",
		"PRIVATE KEY",
		"ed25519.PrivateKey",
	} {
		if strings.Contains(rendered, forbidden) {
			t.Fatalf("credential formatting leaked %q: %q", forbidden, rendered)
		}
	}
	if !strings.Contains(rendered, "<redacted>") {
		t.Fatalf("credential formatting is not visibly redacted: %q", rendered)
	}
}

func TestNewSSHCredentialRejectsUnsafeOrInvalidInputWithoutEcho(t *testing.T) {
	_, validPEM := mustSSHSignerAndPEM(t)
	tests := map[string]SSHCredentialSpec{
		"empty username": {
			PrivateKeyPEM: validPEM,
		},
		"unsafe username": {
			Username:      "root\npassword=must-not-leak",
			PrivateKeyPEM: validPEM,
		},
		"empty key": {
			Username: "matrix",
		},
		"oversized key": {
			Username:      "matrix",
			PrivateKeyPEM: make([]byte, 64*1024+1),
		},
		"invalid key": {
			Username:      "matrix",
			PrivateKeyPEM: []byte("secret-key-material-must-not-leak"),
		},
		"oversized passphrase": {
			Username:      "matrix",
			PrivateKeyPEM: validPEM,
			Passphrase:    make([]byte, 4097),
		},
	}
	for name, spec := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := NewSSHCredential(spec); err == nil {
				t.Fatal("invalid credential must be rejected")
			} else if strings.Contains(err.Error(), "must-not-leak") {
				t.Fatalf("credential validation echoed sensitive input: %q", err)
			}
		})
	}
}

func TestStaticSSHCredentialResolverIsOpaqueAndFailClosed(t *testing.T) {
	_, privateKeyPEM := mustSSHSignerAndPEM(t)
	credential, err := NewSSHCredential(SSHCredentialSpec{
		Username:      "matrix",
		PrivateKeyPEM: privateKeyPEM,
	})
	if err != nil {
		t.Fatalf("NewSSHCredential() error = %v", err)
	}
	resolver, err := NewStaticSSHCredentialResolver(NamedSSHCredential{
		Ref:        "credential-node-1",
		Credential: credential,
	})
	if err != nil {
		t.Fatalf("NewStaticSSHCredentialResolver() error = %v", err)
	}
	resolved, err := resolver.ResolveSSHCredential(
		context.Background(),
		"credential-node-1",
	)
	if err != nil {
		t.Fatalf("ResolveSSHCredential() error = %v", err)
	}
	if resolved.signer == nil || resolved.username != "matrix" {
		t.Fatal("resolver returned an incomplete parsed credential")
	}
	if _, err := resolver.ResolveSSHCredential(
		context.Background(),
		"missing",
	); !errors.Is(err, ErrCredentialNotFound) {
		t.Fatalf("missing credential error = %v, want ErrCredentialNotFound", err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := resolver.ResolveSSHCredential(
		cancelled,
		"credential-node-1",
	); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled resolve error = %v, want context.Canceled", err)
	}
	if _, err := (*StaticSSHCredentialResolver)(nil).ResolveSSHCredential(
		context.Background(),
		"credential-node-1",
	); !errors.Is(err, ErrCredentialNotFound) {
		t.Fatalf("nil resolver error = %v, want ErrCredentialNotFound", err)
	}

	if _, err := NewStaticSSHCredentialResolver(
		NamedSSHCredential{Ref: "credential-node-1", Credential: credential},
		NamedSSHCredential{Ref: "credential-node-1", Credential: credential},
	); err == nil {
		t.Fatal("duplicate credential references must be rejected")
	}
	if _, err := NewStaticSSHCredentialResolver(NamedSSHCredential{
		Ref:        ".invalid-leading-character",
		Credential: credential,
	}); err == nil {
		t.Fatal("invalid credential reference must be rejected")
	}
}

func mustSSHSignerAndPEM(t *testing.T) (ssh.Signer, []byte) {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey() error = %v", err)
	}
	encoded, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatalf("x509.MarshalPKCS8PrivateKey() error = %v", err)
	}
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: encoded,
	})
	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatalf("ssh.NewSignerFromKey() error = %v", err)
	}
	return signer, privateKeyPEM
}
