package authority

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
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
		if !errors.Is(validatePasswordPolicy(malformed, DefaultPasswordSettings()), ErrWeakPassword) {
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

func TestAccountPasswordRulesUseExplicitUnicodeCategories(t *testing.T) {
	baseline := DefaultPasswordSettings()
	if baseline != (iamv1.AccountPasswordSettings{ExpiryMode: iamv1.PasswordExpiryChange, MinimumLength: 15, HistoryCount: 1}) {
		t.Fatal("product baseline introduced composition requirements or lost known history")
	}
	for _, test := range []struct {
		name, password string
		change         func(*iamv1.AccountPasswordSettings)
		allowed        bool
	}{
		{"ordinary phrase", "an ordinary long phrase", func(*iamv1.AccountPasswordSettings) {}, true},
		{"account length rejected", "an ordinary long phrase", func(r *iamv1.AccountPasswordSettings) { r.MinimumLength = 30 }, false},
		{"Unicode length", strings.Repeat("界", 30), func(r *iamv1.AccountPasswordSettings) { r.MinimumLength = 30 }, true},
		{"lowercase Unicode", strings.Repeat("界", 14) + "ß", func(r *iamv1.AccountPasswordSettings) { r.RequireLowercase = true }, true},
		{"uncased is not lowercase", strings.Repeat("界", 15), func(r *iamv1.AccountPasswordSettings) { r.RequireLowercase = true }, false},
		{"uppercase Unicode", strings.Repeat("界", 14) + "Ω", func(r *iamv1.AccountPasswordSettings) { r.RequireUppercase = true }, true},
		{"titlecase is not uppercase", strings.Repeat("界", 14) + "ǅ", func(r *iamv1.AccountPasswordSettings) { r.RequireUppercase = true }, false},
		{"decimal Unicode", strings.Repeat("界", 14) + "٣", func(r *iamv1.AccountPasswordSettings) { r.RequireDigit = true }, true},
		{"number letter is not decimal", strings.Repeat("界", 14) + "Ⅻ", func(r *iamv1.AccountPasswordSettings) { r.RequireDigit = true }, false},
		{"space is not symbol", "a phrase with spaces", func(r *iamv1.AccountPasswordSettings) { r.RequireSymbol = true }, false},
		{"mark is not symbol", strings.Repeat("e\u0301", 8), func(r *iamv1.AccountPasswordSettings) { r.RequireSymbol = true }, false},
		{"punctuation", "an ordinary phrase-", func(r *iamv1.AccountPasswordSettings) { r.RequireSymbol = true }, true},
		{"Unicode symbol", "an ordinary phrase🦊", func(r *iamv1.AccountPasswordSettings) { r.RequireSymbol = true }, true},
		{"all required", "An ordinary phrase ٣🦊", func(r *iamv1.AccountPasswordSettings) {
			r.RequireLowercase, r.RequireUppercase, r.RequireDigit, r.RequireSymbol = true, true, true, true
		}, true},
		{"missing one required", "An ordinary phrase 🦊", func(r *iamv1.AccountPasswordSettings) {
			r.RequireLowercase, r.RequireUppercase, r.RequireDigit, r.RequireSymbol = true, true, true, true
		}, false},
		{"common password still refused", "passwordpassword", func(*iamv1.AccountPasswordSettings) {}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			rules := baseline
			test.change(&rules)
			err := ValidatePasswordWithSettings(authoritySecret(t, test.password), rules)
			if (err == nil) != test.allowed || (err != nil && !errors.Is(err, ErrWeakPassword)) {
				t.Fatal("explicit new-password rule differs", err)
			}
		})
	}
	for _, rules := range []iamv1.AccountPasswordSettings{{}, {MinimumLength: 14}, {MinimumLength: 129}, {MinimumLength: 15, HistoryCount: -1}, {MinimumLength: 15, HistoryCount: 25}} {
		if !errors.Is(ValidatePasswordWithSettings(authoritySecret(t, "an ordinary long phrase"), rules), ErrInvalidPasswordSettings) {
			t.Fatal("invalid stored settings fell back to weaker defaults")
		}
	}
}

func TestPasswordReplacementChecksCurrentAndBoundedRealVerifiers(t *testing.T) {
	hasher := NewPasswordHasher(nil)
	current := authoritySecret(t, "the current long phrase")
	previous := authoritySecret(t, "the previous long phrase")
	older := authoritySecret(t, "a much older long phrase")
	fresh := authoritySecret(t, "an entirely new long phrase")
	var hashes []PasswordHash
	for _, password := range []iamv1.Secret{current, previous, older} {
		hash, err := hasher.Hash(password)
		if err != nil {
			t.Fatal(err)
		}
		hashes = append(hashes, hash)
	}
	for _, test := range []struct {
		name    string
		value   iamv1.Secret
		count   int
		history []PasswordHash
		want    error
	}{
		{"current always rejected", current, 0, nil, ErrWeakPassword},
		{"history disabled", previous, 0, hashes[1:], nil},
		{"latest retained rejected", previous, 1, hashes[1:], ErrWeakPassword},
		{"outside chosen history", older, 1, hashes[1:], nil},
		{"second historical rejected", older, 2, hashes[1:], ErrWeakPassword},
		{"new value", fresh, 24, hashes[1:], nil},
		{"no fabricated history", previous, 24, nil, nil},
		{"oversized stored history", fresh, 24, make([]PasswordHash, 25), ErrInvalidPasswordHistory},
		{"corrupt selected history", fresh, 1, []PasswordHash{"not-a-verifier"}, ErrInvalidPasswordHash},
		{"corrupt retained history not ignored", fresh, 0, []PasswordHash{"not-a-verifier"}, ErrInvalidPasswordHash},
	} {
		t.Run(test.name, func(t *testing.T) {
			rules := DefaultPasswordSettings()
			rules.HistoryCount = test.count
			before := append([]PasswordHash(nil), test.history...)
			err := hasher.ValidateReplacement(context.Background(), test.value, rules, hashes[0], test.history)
			if !errors.Is(err, test.want) {
				t.Fatal("password history outcome differs", err)
			}
			for i := range before {
				if before[i] != test.history[i] {
					t.Fatal("validation changed retained verifiers")
				}
			}
		})
	}
	if !errors.Is(hasher.ValidateReplacement(context.Background(), fresh, DefaultPasswordSettings(), "", nil), ErrInvalidPasswordHash) {
		t.Fatal("missing current verifier treated as new-user creation")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if !errors.Is(hasher.ValidateReplacement(ctx, fresh, DefaultPasswordSettings(), hashes[0], hashes[1:]), context.Canceled) {
		t.Fatal("cancelled history comparison continued")
	}
	var boundedHistory []PasswordHash
	var oldest iamv1.Secret
	for i := range 24 {
		password := authoritySecret(t, fmt.Sprintf("bounded historical phrase %02d", i))
		hash, err := hasher.Hash(password)
		if err != nil {
			t.Fatal(err)
		}
		boundedHistory = append(boundedHistory, hash)
		oldest = password
	}
	rules := DefaultPasswordSettings()
	rules.HistoryCount = 24
	if !errors.Is(hasher.ValidateReplacement(context.Background(), oldest, rules, hashes[0], boundedHistory), ErrWeakPassword) {
		t.Fatal("the twenty-fourth actual historical verifier escaped the configured window")
	}
	rules.HistoryCount = 23
	if err := hasher.ValidateReplacement(context.Background(), oldest, rules, hashes[0], boundedHistory); err != nil {
		t.Fatal("the caller's selected history window was widened", err)
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
