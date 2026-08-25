package authority

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	iamv1 "github.com/xiak/matrix/api/iam/v1"
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
		"all-lowercase-password",
		"NoWhitespace 49!",
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
