package authority

import (
	"bytes"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	iamv1 "github.com/xiak/matrix/api/iam/v1"
	"golang.org/x/crypto/argon2"
)

func TestPasswordHasherUsesFixedVersionedArgon2idProfile(t *testing.T) {
	password := authoritySecret(t, "Correct-Horse-49!")
	entropy := append(bytes.Repeat([]byte{0x11}, passwordSaltBytes), bytes.Repeat([]byte{0x22}, passwordSaltBytes)...)
	hasher := NewPasswordHasher(bytes.NewReader(entropy))
	first, err := hasher.Hash(password)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	second, err := hasher.Hash(password)
	if err != nil {
		t.Fatalf("hash password with a second salt: %v", err)
	}
	if first == second {
		t.Fatal("equal passwords reused an Argon2id salt")
	}
	if !strings.HasPrefix(string(first), "$matrix-iam-v1$argon2id$v=19$m=65536,t=3,p=1$") {
		t.Fatalf("password hash does not identify the fixed profile: %q", first)
	}
	if strings.Contains(string(first), string(password.CopyBytes())) {
		t.Fatal("password hash contains plaintext")
	}
	verified, err := hasher.Verify(password, first)
	if err != nil || !verified {
		t.Fatalf("verify correct password: verified=%v err=%v", verified, err)
	}
	wrong := authoritySecret(t, "Different-Horse-73!")
	verified, err = hasher.Verify(wrong, first)
	if err != nil || verified {
		t.Fatalf("verify wrong password: verified=%v err=%v", verified, err)
	}
}

func TestPasswordPolicyAndStoredProfileFailClosed(t *testing.T) {
	hasher := NewPasswordHasher(bytes.NewReader(bytes.Repeat([]byte{0x33}, passwordSaltBytes)))
	for _, plaintext := range []string{
		"Short-49!",
		"passwordpassword",
		"PASSWORDPASSWORD",
	} {
		if _, err := hasher.Hash(authoritySecret(t, plaintext)); !errors.Is(err, ErrWeakPassword) {
			t.Fatalf("weak password %q error = %v, want fixed policy rejection", plaintext, err)
		}
	}
	password := authoritySecret(t, "Correct-Horse-49!")
	hash, err := hasher.Hash(password)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	tampered := PasswordHash(strings.Replace(string(hash), "m=65536", "m=32768", 1))
	if _, err := hasher.Verify(password, tampered); !errors.Is(err, ErrInvalidPasswordHash) {
		t.Fatalf("tampered profile error = %v, want invalid stored hash", err)
	}
	if _, err := NewPasswordHasher(failingEntropy{}).Hash(password); !errors.Is(err, ErrPasswordHashing) ||
		strings.Contains(err.Error(), string(password.CopyBytes())) {
		t.Fatalf("entropy failure was not normalized: %v", err)
	}
}

func TestPasswordBaselineCountsCodePointsAndPreservesPassphrases(t *testing.T) {
	for _, test := range []struct {
		name, password string
		allowed        bool
	}{
		{"fourteen ASCII", "Valid-Short-49", false},
		{"fifteen ASCII", "Valid-Floor-49!", true},
		{"exact floor", "a useful phrase", true},
		{"lowercase phrase", "all-lowercase-password", true},
		{"spaces retained", "  an ordinary long phrase  ", true},
		{"fourteen multi byte", strings.Repeat("界", 14), false},
		{"fifteen multi byte", strings.Repeat("界", 15), true},
		{"combining points", strings.Repeat("e\u0301", 8), true},
		{"ASCII maximum", strings.Repeat("x", 128), true},
		{"ASCII over maximum", strings.Repeat("x", 129), false},
		{"four byte maximum", strings.Repeat("🦊", 128), true},
		{"four byte over maximum", strings.Repeat("🦊", 129), false},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := ValidatePassword(authoritySecret(t, test.password))
			if (err == nil) != test.allowed {
				t.Fatalf("allowed=%t error=%v", test.allowed, err)
			}
		})
	}
	for _, malformed := range [][]byte{nil, []byte("long\ncontrol-password"), append([]byte("long-invalid-password"), 0xff)} {
		if !errors.Is(validatePasswordPolicy(malformed), ErrWeakPassword) {
			t.Fatal("malformed new password was accepted")
		}
	}
	password := authoritySecret(t, "  an ordinary long phrase  ")
	hasher := NewPasswordHasher(nil)
	hash, err := hasher.Hash(password)
	if err != nil {
		t.Fatal(err)
	}
	for _, candidate := range []struct {
		value   string
		matches bool
	}{
		{"  an ordinary long phrase  ", true},
		{"an ordinary long phrase", false},
		{"  An ordinary long phrase  ", false},
	} {
		matched, err := hasher.Verify(authoritySecret(t, candidate.value), hash)
		if err != nil || matched != candidate.matches {
			t.Fatal("password verification altered the original bytes", err)
		}
	}
}

func TestPasswordVerifierDoesNotApplyNewAdmissionToStoredSecrets(t *testing.T) {
	// Build the original fixed cryptographic profile independently of today's
	// admission path. Neither a short historical password nor a newly blocked
	// password may become impossible to authenticate for a controlled change.
	for _, plaintext := range []string{"Old-Secret-49!", "passwordpassword"} {
		password := authoritySecret(t, plaintext)
		salt := bytes.Repeat([]byte{0x19}, 16)
		key := argon2.IDKey([]byte(plaintext), salt, 3, 65536, 1, 32)
		stored := PasswordHash("$matrix-iam-v1$argon2id$v=19$m=65536,t=3,p=1$" +
			base64.RawStdEncoding.EncodeToString(salt) + "$" + base64.RawStdEncoding.EncodeToString(key))
		clear(key)
		if err := ValidatePassword(password); !errors.Is(err, ErrWeakPassword) {
			t.Fatal("historical test secret is not excluded from new writes", err)
		}
		if matched, err := NewPasswordHasher(nil).Verify(password, stored); err != nil || !matched {
			t.Fatal("new admission was applied to a historical verifier", err)
		}
	}
}

func TestOfflineCommonPasswordAdmissionIsWholeSecretAndFailsClosed(t *testing.T) {
	for _, document := range []string{"", commonPasswordDocument + "unreviewed\n", strings.Replace(commonPasswordDocument, "passwordpassword", "newpasswordvalue", 1)} {
		if values, err := parseCommonPasswords(document); err == nil || values != nil {
			t.Fatal("unknown build asset silently changed the password blocklist")
		}
	}
	for _, blocked := range commonPasswords {
		if err := ValidatePassword(authoritySecret(t, blocked)); !errors.Is(err, ErrWeakPassword) {
			t.Fatal("fixed offline entry escaped new-password admission", err)
		}
	}
	for _, input := range []string{"PaSsWoRdPaSsWoRd", "123456789012345", "qwertyuiopasdfghjkl"} {
		if err := ValidatePassword(authoritySecret(t, input)); !errors.Is(err, ErrWeakPassword) {
			t.Fatal("common whole password or case variant was accepted", err)
		}
	}
	if err := ValidatePassword(authoritySecret(t, "passwordpassword in a longer unrelated phrase")); err != nil {
		t.Fatal("blocklist rejected a substring rather than the whole password", err)
	}
}

func authoritySecret(t *testing.T, value string) iamv1.Secret {
	t.Helper()
	secret, err := iamv1.NewSecret(value)
	if err != nil {
		t.Fatalf("create test secret: %v", err)
	}
	return secret
}

type failingEntropy struct{}

func (failingEntropy) Read([]byte) (int, error) {
	return 0, errors.New("native entropy failure with secret-shaped diagnostics")
}
