package authority

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestOpaqueCredentialsAreRandomHashedAndBindingScoped(t *testing.T) {
	entropy := make([]byte, 64)
	for index := range entropy {
		entropy[index] = byte(index + 1)
	}
	issuer := NewCredentialIssuer(bytes.NewReader(entropy))
	sessionCredential, sessionDigest, err := issuer.Issue(CredentialSession, "session-a")
	if err != nil {
		t.Fatalf("issue session credential: %v", err)
	}
	serviceCredential, serviceDigest, err := issuer.Issue(CredentialService, "service-paas")
	if err != nil {
		t.Fatalf("issue service credential: %v", err)
	}
	if bytes.Equal(sessionCredential.CopyBytes(), serviceCredential.CopyBytes()) {
		t.Fatal("two issued credentials are equal")
	}
	if strings.Contains(sessionDigest, string(sessionCredential.CopyBytes())) ||
		strings.Contains(serviceDigest, string(serviceCredential.CopyBytes())) {
		t.Fatal("stored credential digest contains plaintext")
	}
	verified, err := VerifyCredential(CredentialSession, "session-a", sessionCredential, sessionDigest)
	if err != nil || !verified {
		t.Fatalf("verify bound session credential: verified=%v err=%v", verified, err)
	}
	for name, candidate := range map[string]struct {
		credentialType CredentialType
		bindingID      string
	}{
		"other type":    {CredentialService, "session-a"},
		"other binding": {CredentialSession, "session-b"},
	} {
		t.Run(name, func(t *testing.T) {
			verified, err := VerifyCredential(candidate.credentialType, candidate.bindingID, sessionCredential, sessionDigest)
			if err != nil || verified {
				t.Fatalf("cross-bound credential: verified=%v err=%v", verified, err)
			}
		})
	}
}

func TestCredentialFailuresAreNormalized(t *testing.T) {
	if _, _, err := NewCredentialIssuer(failingEntropy{}).Issue(CredentialSession, "session-a"); !errors.Is(err, ErrCredentialGeneration) || strings.Contains(err.Error(), "native") {
		t.Fatalf("credential entropy error was not normalized: %v", err)
	}
	credential := authoritySecret(t, "mx1.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	if _, err := VerifyCredential(CredentialSession, "session-a", credential, "not-a-digest"); !errors.Is(err, ErrInvalidCredentialHash) {
		t.Fatalf("invalid stored digest error = %v", err)
	}
}
