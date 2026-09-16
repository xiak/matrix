package authority

import (
	"bytes"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	iamv1 "github.com/xiak/matrix/api/iam/v1"
)

func TestOpaqueCredentialsAreRandomHashedAndBindingScoped(t *testing.T) {
	entropy := make([]byte, 64)
	for index := range entropy {
		entropy[index] = byte(index + 1)
	}
	issuer := NewCredentialIssuer(bytes.NewReader(entropy))
	session, err := issuer.Issue(CredentialSession, "session-a")
	if err != nil {
		t.Fatalf("issue session credential: %v", err)
	}
	service, err := issuer.Issue(CredentialService, "service-paas")
	if err != nil {
		t.Fatalf("issue service credential: %v", err)
	}
	if bytes.Equal(session.Credential.CopyBytes(), service.Credential.CopyBytes()) {
		t.Fatal("two issued credentials are equal")
	}
	if strings.Contains(session.LookupDigest, string(session.Credential.CopyBytes())) ||
		strings.Contains(session.VerificationDigest, string(session.Credential.CopyBytes())) ||
		strings.Contains(service.LookupDigest, string(service.Credential.CopyBytes())) ||
		strings.Contains(service.VerificationDigest, string(service.Credential.CopyBytes())) {
		t.Fatal("stored credential digest contains plaintext")
	}
	verified, err := VerifyCredential(
		CredentialSession, "session-a", session.Credential, session.VerificationDigest,
	)
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
			verified, err := VerifyCredential(
				candidate.credentialType, candidate.bindingID,
				session.Credential, session.VerificationDigest,
			)
			if err != nil || verified {
				t.Fatalf("cross-bound credential: verified=%v err=%v", verified, err)
			}
		})
	}
	lookup, err := LookupCredentialDigest(CredentialSession, session.Credential)
	if err != nil || lookup != session.LookupDigest {
		t.Fatalf("recompute lookup digest: digest=%q err=%v", lookup, err)
	}
	otherTypeLookup, err := LookupCredentialDigest(CredentialService, session.Credential)
	if err != nil || otherTypeLookup == session.LookupDigest {
		t.Fatalf("lookup digest is not type-bound: digest=%q err=%v", otherTypeLookup, err)
	}
}

func TestCredentialFailuresAreNormalized(t *testing.T) {
	if _, err := NewCredentialIssuer(failingEntropy{}).Issue(CredentialSession, "session-a"); !errors.Is(err, ErrCredentialGeneration) || strings.Contains(err.Error(), "native") {
		t.Fatalf("credential entropy error was not normalized: %v", err)
	}
	credential := authoritySecret(t, "mx1.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	if _, err := VerifyCredential(CredentialSession, "session-a", credential, "not-a-digest"); !errors.Is(err, ErrInvalidCredentialHash) {
		t.Fatalf("invalid stored digest error = %v", err)
	}
}

func TestRoleCredentialsCannotBeReinterpretedAsLoginOrServiceCredentials(t *testing.T) {
	// Identical entropy deliberately removes randomness as an explanation for
	// different digests. Purpose and binding must independently isolate them.
	types := []CredentialType{CredentialSession, CredentialService, CredentialRoleSession}
	for _, issuedType := range types {
		issued, err := NewCredentialIssuer(bytes.NewReader(bytes.Repeat([]byte{0x71}, 32))).Issue(issuedType, "same-id")
		if err != nil {
			t.Fatalf("issue %s: %v", issuedType, err)
		}
		for _, testedType := range types {
			lookup, err := LookupCredentialDigest(testedType, issued.Credential)
			if err != nil || (lookup == issued.LookupDigest) != (testedType == issuedType) {
				t.Fatalf("lookup purpose %s -> %s was not isolated", issuedType, testedType)
			}
			for _, id := range []string{"same-id", "other-id"} {
				verified, err := VerifyCredential(testedType, id, issued.Credential, issued.VerificationDigest)
				if err != nil || verified != (testedType == issuedType && id == "same-id") {
					t.Fatalf("verify purpose/binding %s -> %s/%s was not isolated", issuedType, testedType, id)
				}
			}
		}
	}
	if _, err := NewCredentialIssuer(failingEntropy{}).Issue(CredentialRoleSession, "role-session-a"); !errors.Is(err, ErrCredentialGeneration) {
		t.Fatalf("role credential entropy failure was not normalized: %v", err)
	}
	for _, unknown := range []CredentialType{"ROLE", "USER", "role_session", ""} {
		if _, err := NewCredentialIssuer(nil).Issue(unknown, "same-id"); !errors.Is(err, ErrCredentialGeneration) {
			t.Fatal("unknown credential purpose accepted")
		}
	}
}

func TestAccessKeySecretProtectionUsesIndependentHKDFAESGCMVector(t *testing.T) {
	// Produced independently with Node's crypto.hkdfSync and
	// crypto.createCipheriv(aes-256-gcm), not the Go encoder under test.
	// All bytes are public test material.
	wrappingKey := make([]byte, 32)
	for i := range wrappingKey {
		wrappingKey[i] = byte(i)
	}
	decode := func(value string) []byte {
		t.Helper()
		result, err := hex.DecodeString(value)
		if err != nil {
			t.Fatal("invalid fixed test vector")
		}
		return result
	}
	scope := AccessKeySecretScope{InstallationID: "install-a", AccountID: "account-a", UserID: "user-a", AccessKeyID: "key-a"}
	sealed := SealedAccessKeySecret{FormatVersion: 1, WrappingKeyID: "wrap-a",
		Nonce: decode("a0a1a2a3a4a5a6a7a8a9aaab"),
		Ciphertext: decode("67e6cba21a115e247ec5d90d0d8a9bac2aff84f18fe26adf50603711c0b57387" + // 32-byte ciphertext
			"917dda0087b6f9308fa877f4a16fa3de")} // 16-byte tag
	secret, err := OpenAccessKeySecret(scope, "wrap-a", wrappingKey, sealed)
	if err != nil || string(secret.CopyBytes()) != "mak1.gIGCg4SFhoeIiYqLjI2Oj5CRkpOUlZaXmJmam5ydnp8" {
		t.Fatal("independent HKDF/AES-GCM vector did not open")
	}
	for name, mutate := range map[string]func(*AccessKeySecretScope, *SealedAccessKeySecret){
		"installation":       func(s *AccessKeySecretScope, _ *SealedAccessKeySecret) { s.InstallationID = "install-b" },
		"account":            func(s *AccessKeySecretScope, _ *SealedAccessKeySecret) { s.AccountID = "account-b" },
		"user":               func(s *AccessKeySecretScope, _ *SealedAccessKeySecret) { s.UserID = "user-b" },
		"key identity":       func(s *AccessKeySecretScope, _ *SealedAccessKeySecret) { s.AccessKeyID = "key-b" },
		"invalid scope":      func(s *AccessKeySecretScope, _ *SealedAccessKeySecret) { s.AccessKeyID = "key-a\x00wrap-a" },
		"format":             func(_ *AccessKeySecretScope, s *SealedAccessKeySecret) { s.FormatVersion = 2 },
		"missing format":     func(_ *AccessKeySecretScope, s *SealedAccessKeySecret) { s.FormatVersion = 0 },
		"wrapping reference": func(_ *AccessKeySecretScope, s *SealedAccessKeySecret) { s.WrappingKeyID = "wrap-b" },
		"nonce":              func(_ *AccessKeySecretScope, s *SealedAccessKeySecret) { s.Nonce[0] ^= 1 },
		"short nonce":        func(_ *AccessKeySecretScope, s *SealedAccessKeySecret) { s.Nonce = s.Nonce[:11] },
		"extended nonce":     func(_ *AccessKeySecretScope, s *SealedAccessKeySecret) { s.Nonce = append(s.Nonce, 0) },
		"ciphertext":         func(_ *AccessKeySecretScope, s *SealedAccessKeySecret) { s.Ciphertext[0] ^= 1 },
		"tag":                func(_ *AccessKeySecretScope, s *SealedAccessKeySecret) { s.Ciphertext[len(s.Ciphertext)-1] ^= 1 },
		"short ciphertext": func(_ *AccessKeySecretScope, s *SealedAccessKeySecret) {
			s.Ciphertext = s.Ciphertext[:len(s.Ciphertext)-1]
		},
		"extended ciphertext": func(_ *AccessKeySecretScope, s *SealedAccessKeySecret) { s.Ciphertext = append(s.Ciphertext, 0) },
	} {
		t.Run(name, func(t *testing.T) {
			candidateScope, candidate := scope, sealed
			candidate.Nonce = bytes.Clone(sealed.Nonce)
			candidate.Ciphertext = bytes.Clone(sealed.Ciphertext)
			mutate(&candidateScope, &candidate)
			result, err := OpenAccessKeySecret(candidateScope, "wrap-a", wrappingKey, candidate)
			if !errors.Is(err, ErrAccessKeyProtection) || result.Present() {
				t.Fatal("corrupt or substituted secret produced plaintext")
			}
		})
	}
	// The wrapping identifier is also authenticated, even if two configured
	// references accidentally contain identical key bytes.
	otherReference := sealed
	otherReference.WrappingKeyID = "wrap-b"
	if result, err := OpenAccessKeySecret(scope, "wrap-b", wrappingKey, otherReference); !errors.Is(err, ErrAccessKeyProtection) || result.Present() {
		t.Fatal("wrapping-key identifier was not authenticated")
	}
	for _, key := range [][]byte{nil, make([]byte, 16), make([]byte, 31), make([]byte, 33), bytes.Repeat([]byte{0xff}, 32)} {
		if result, err := OpenAccessKeySecret(scope, "wrap-a", key, sealed); !errors.Is(err, ErrAccessKeyProtection) || result.Present() {
			t.Fatal("wrong wrapping key produced plaintext")
		}
	}
	if _, err := json.Marshal(sealed); !errors.Is(err, ErrAccessKeyProtection) || strings.Contains(fmt.Sprintf("%v %#v", sealed, sealed), hex.EncodeToString(sealed.Ciphertext)) {
		t.Fatal("private ciphertext leaked through ordinary encoding or formatting")
	}
	for _, value := range []string{`{}`, `null`, `{"FormatVersion":1,"WrappingKeyID":"wrap-a","Nonce":"","Ciphertext":""}`, `{"FormatVersion":1,"extra":true}`} {
		var parsed SealedAccessKeySecret
		if err := json.Unmarshal([]byte(value), &parsed); !errors.Is(err, ErrAccessKeyProtection) || parsed.FormatVersion != 0 || len(parsed.Ciphertext) != 0 {
			t.Fatal("private storage material was accepted through ordinary JSON")
		}
	}
}

func TestAccessKeySecretContextsDeriveIndependentRecordKeys(t *testing.T) {
	// Independent Node hkdfSync vectors cover the byte-level scope encoding,
	// not just two calls to the same production encoder agreeing with itself.
	wrappingKey := make([]byte, 32)
	for i := range wrappingKey {
		wrappingKey[i] = byte(i)
	}
	scope := AccessKeySecretScope{InstallationID: "install-a", AccountID: "account-a", UserID: "user-a", AccessKeyID: "key-a"}
	if hex.EncodeToString([]byte(accessKeySecretSalt)) != "6d61747269782e69616d2e6163636573732d6b65792d7365637265742e686b64662d73616c742e7631" {
		t.Fatal("HKDF salt differed from the independent vector")
	}
	wantInfo := "000000286d61747269782e69616d2e6163636573732d6b65792d7365637265742e6b64662d696e666f2e7631000000114143434553535f4b45595f534543524554000000010100000009696e7374616c6c2d61000000096163636f756e742d6100000006757365722d61000000056b65792d6100000006777261702d61"
	wantAAD := "000000236d61747269782e69616d2e6163636573732d6b65792d7365637265742e6161642e7631000000114143434553535f4b45595f534543524554000000010100000009696e7374616c6c2d61000000096163636f756e742d6100000006757365722d61000000056b65792d6100000006777261702d61"
	context := func(scope AccessKeySecretScope, wrappingID string) ([]byte, []byte) {
		t.Helper()
		info, aad, err := iamv1.AccessKeySecretContext(scope.InstallationID, scope.AccountID, scope.UserID, scope.AccessKeyID, wrappingID)
		if err != nil {
			t.Fatal("valid fixed secret context failed")
		}
		return info, aad
	}
	info, aad := context(scope, "wrap-a")
	if hex.EncodeToString(info) != wantInfo || hex.EncodeToString(aad) != wantAAD {
		t.Fatal("record context differed from the independent canonical vectors")
	}
	for keyID, expected := range map[string]string{
		"key-a": "061a7d30cec220b929cf4d835505d0e574e6ea86dd85ea062e844f7a3f4aa79a",
		"key-b": "722278556b9385923b5f007ffcaf6e94107b8bccbd8b4339a6a7cd7b02675d99",
	} {
		scope.AccessKeyID = keyID
		info, _ := context(scope, "wrap-a")
		for range 2 {
			key, err := hkdf.Key(sha256.New, wrappingKey, []byte(accessKeySecretSalt), string(info), 32)
			if err != nil || hex.EncodeToString(key) != expected || bytes.Equal(key, wrappingKey) {
				t.Fatal("record derivation was not deterministic and key-identity bound")
			}
			clear(key)
		}
	}
	// The same unframed bytes must not permit moving a field boundary.
	left := AccessKeySecretScope{InstallationID: "a", AccountID: "bc", UserID: "user", AccessKeyID: "key"}
	right := AccessKeySecretScope{InstallationID: "ab", AccountID: "c", UserID: "user", AccessKeyID: "key"}
	leftInfo, _ := context(left, "wrap")
	rightInfo, _ := context(right, "wrap")
	if bytes.Equal(leftInfo, rightInfo) {
		t.Fatal("scope encoding did not delimit field lengths")
	}
}

func TestAccessKeySecretIssuanceAndSealingDoNotReuseBearerOrCallerBuffers(t *testing.T) {
	entropy := bytes.Repeat([]byte{0x71}, 32)
	secret, err := NewCredentialIssuer(bytes.NewReader(entropy)).IssueAccessKeySecret()
	if err != nil || !strings.HasPrefix(string(secret.CopyBytes()), "mak1.") || len(secret.CopyBytes()) != 48 {
		t.Fatal("access key secret was not generated from exactly 256 bits")
	}
	bearer, err := NewCredentialIssuer(bytes.NewReader(entropy)).Issue(CredentialSession, "session-a")
	if err != nil || bytes.Equal(secret.CopyBytes(), bearer.Credential.CopyBytes()) {
		t.Fatal("access key was represented as a bearer credential")
	}
	scope := AccessKeySecretScope{InstallationID: "install-a", AccountID: "account-a", UserID: "user-a", AccessKeyID: "key-a"}
	wrappingKey := bytes.Repeat([]byte{0x31}, 32)
	first, err := SealAccessKeySecret(scope, "wrap-a", wrappingKey, secret)
	if err != nil {
		t.Fatal("seal valid secret")
	}
	otherScope := scope
	otherScope.AccessKeyID = "key-b"
	second, err := SealAccessKeySecret(otherScope, "wrap-a", wrappingKey, secret)
	if err != nil || bytes.Equal(first.Nonce, second.Nonce) || len(first.Nonce) != 12 || len(first.Ciphertext) != 48 || first.FormatVersion != 1 || first.WrappingKeyID != "wrap-a" {
		t.Fatal("standard random nonce or sealed shape was not preserved")
	}
	opened, err := OpenAccessKeySecret(scope, "wrap-a", wrappingKey, first)
	if err != nil || !bytes.Equal(opened.CopyBytes(), secret.CopyBytes()) || !bytes.Equal(wrappingKey, bytes.Repeat([]byte{0x31}, 32)) {
		t.Fatal("opening changed plaintext or caller-owned wrapping bytes")
	}
	for _, invalid := range []string{"password", string(bearer.Credential.CopyBytes()), "mak1." + strings.Repeat("A", 42), "mak1." + strings.Repeat("A", 44), "mak1." + strings.Repeat("_", 43)} {
		if _, err := SealAccessKeySecret(scope, "wrap-a", wrappingKey, authoritySecret(t, invalid)); !errors.Is(err, ErrAccessKeyProtection) {
			t.Fatal("noncanonical or wrong-purpose secret was sealed")
		}
	}
	if _, err := SealAccessKeySecret(AccessKeySecretScope{}, "wrap-a", wrappingKey, secret); !errors.Is(err, ErrAccessKeyProtection) {
		t.Fatal("unbound secret was sealed")
	}
	if _, err := SealAccessKeySecret(scope, "", wrappingKey, secret); !errors.Is(err, ErrAccessKeyProtection) {
		t.Fatal("unidentified wrapping key was accepted")
	}
	if _, err := SealAccessKeySecret(scope, "wrap-a", wrappingKey[:16], secret); !errors.Is(err, ErrAccessKeyProtection) {
		t.Fatal("non-256-bit wrapping key was accepted")
	}
	for _, invalid := range []string{"", " install-a", "install-a ", "\uFF49nstall-a", "install\x00a", strings.Repeat("a", 129)} {
		for field := range 5 {
			candidate, wrappingID := scope, "wrap-a"
			switch field {
			case 0:
				candidate.InstallationID = invalid
			case 1:
				candidate.AccountID = iamv1.AccountID(invalid)
			case 2:
				candidate.UserID = iamv1.PrincipalID(invalid)
			case 3:
				candidate.AccessKeyID = invalid
			case 4:
				wrappingID = invalid
			}
			if result, err := SealAccessKeySecret(candidate, wrappingID, wrappingKey, secret); !errors.Is(err, ErrAccessKeyProtection) || len(result.Ciphertext) != 0 {
				t.Fatal("invalid scope was normalized or encrypted")
			}
		}
	}
	for _, issuer := range []*CredentialIssuer{nil, NewCredentialIssuer(failingEntropy{}), NewCredentialIssuer(bytes.NewReader(make([]byte, 31)))} {
		if result, err := issuer.IssueAccessKeySecret(); !errors.Is(err, ErrCredentialGeneration) || result.Present() {
			t.Fatal("failed entropy produced a secret")
		}
	}
}
