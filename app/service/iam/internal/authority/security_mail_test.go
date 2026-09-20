package authority

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	iamv1 "github.com/xiak/matrix/api/iam/v1"
)

func TestEmailVerificationCodeIsUniformPurposeLimitedMaterial(t *testing.T) {
	for _, test := range []struct {
		entropy []byte
		want    string
	}{
		{[]byte{0, 0, 0, 0}, "00000000"},
		{[]byte{0, 0x12, 0xd6, 0x87}, "01234567"},
		{[]byte{0x05, 0xf5, 0xe0, 0xff}, "99999999"},
		// The out-of-range value must be discarded, not reduced modulo 10^8.
		{[]byte{0x07, 0xff, 0xff, 0xff, 0, 0x12, 0xd6, 0x87}, "01234567"},
	} {
		code, err := NewCredentialIssuer(bytes.NewReader(test.entropy)).IssueEmailVerificationCode()
		if err != nil || !bytes.Equal(code.CopyBytes(), []byte(test.want)) {
			t.Fatal("decimal sampling or fixed-width encoding differs")
		}
		for _, purpose := range []CredentialType{CredentialSession, CredentialService, CredentialRoleSession} {
			issued, err := NewCredentialIssuer(bytes.NewReader(bytes.Repeat([]byte{0x51}, 32))).Issue(purpose, "mailbox-identity")
			if err != nil {
				t.Fatal("identity credential fixture failed")
			}
			if valid, err := VerifyCredential(purpose, "mailbox-identity", issued.Credential, issued.VerificationDigest); !valid || err != nil {
				t.Fatal("normal identity credential rejected")
			}
			if valid, err := VerifyCredential(purpose, "mailbox-identity", code, issued.VerificationDigest); valid || err != nil {
				t.Fatal("email code accepted as an identity credential")
			}
		}
	}
	for _, issuer := range []*CredentialIssuer{nil, {}, NewCredentialIssuer(bytes.NewReader([]byte{0, 1})), NewCredentialIssuer(failingEntropy{})} {
		code, err := issuer.IssueEmailVerificationCode()
		if !errors.Is(err, ErrCredentialGeneration) || code.Present() {
			t.Fatal("failed entropy issued a partial code or leaked its error")
		}
	}
	code, err := NewCredentialIssuer(nil).IssueEmailVerificationCode()
	if err != nil || !validEmailVerificationCode(code.CopyBytes()) {
		t.Fatal("OS entropy did not produce an address-verification code")
	}
}

func TestEmailVerificationComparisonDoesNotProveIntentOrConsumption(t *testing.T) {
	expected, _ := iamv1.NewSecret("01234567")
	for _, value := range []string{"01234567", "11234567", "0123456", "012345678", "0123456a", "０１２３４５６７"} {
		candidate, _ := iamv1.NewSecret(value)
		match, err := CompareEmailVerificationCode(expected, candidate)
		if value == "01234567" {
			if !match || err != nil {
				t.Fatal("matching fixed-width code rejected")
			}
		} else if match || !errors.Is(err, ErrEmailVerificationRejected) {
			t.Fatal("invalid candidate was not safely rejected")
		}
	}
	if match, err := CompareEmailVerificationCode(iamv1.Secret{}, expected); match || !errors.Is(err, ErrAuthorityUnavailable) {
		t.Fatal("missing original code treated as normal validation")
	}
	if match, err := CompareEmailVerificationCode(expected, iamv1.Secret{}); match || !errors.Is(err, ErrEmailVerificationRejected) {
		t.Fatal("missing candidate accepted")
	}
	// Comparison itself has no state; a second equality is not evidence that
	// two requests may both consume the original purpose-bound intent.
	for range 2 {
		if match, err := CompareEmailVerificationCode(expected, expected); !match || err != nil {
			t.Fatal("pure comparison unexpectedly acquired lifecycle state")
		}
	}
}

func TestEmailVerificationSealingBindsTheOriginalPrivateIntent(t *testing.T) {
	now := time.Date(2026, 9, 20, 8, 0, 0, 123000, time.UTC)
	binding := iamv1.EmailVerificationBinding{InstallationID: "install-one", BootstrapDigest: "sha256:" + strings.Repeat("a", 64),
		AccountID: "account-one", UserID: "user-one", VerificationID: "verify-one", Recipient: "User@matrix.test",
		CredentialGeneration: 2, ContactRevision: 0, IssuedAt: now, ExpiresAt: now.Add(10 * time.Minute)}
	key := bytes.Repeat([]byte{0x62}, 32)
	code, _ := iamv1.NewSecret("01234567")
	sealed, err := SealEmailVerificationCode(binding, "mail-key", key, code)
	if err != nil || sealed.FormatVersion != 1 || sealed.KeyID != "mail-key" || len(sealed.Nonce) != 12 || len(sealed.Ciphertext) != 24 {
		t.Fatal("email verification sealing failed")
	}
	opened, err := OpenEmailVerificationCode(binding, "mail-key", key, sealed)
	if err != nil || !bytes.Equal(opened.CopyBytes(), code.CopyBytes()) || !bytes.Equal(key, bytes.Repeat([]byte{0x62}, 32)) {
		t.Fatal("email code round trip or caller-owned key differs")
	}
	other := binding
	other.VerificationID = "verify-two"
	second, err := SealEmailVerificationCode(other, "mail-key", key, code)
	if err != nil || bytes.Equal(second.Nonce, sealed.Nonce) || bytes.Equal(second.Ciphertext, sealed.Ciphertext) {
		t.Fatal("distinct intent did not receive independent protected material")
	}
	for _, change := range []func(*iamv1.EmailVerificationBinding){
		func(b *iamv1.EmailVerificationBinding) { b.InstallationID = "install-two" },
		func(b *iamv1.EmailVerificationBinding) { b.BootstrapDigest = "sha256:" + strings.Repeat("b", 64) },
		func(b *iamv1.EmailVerificationBinding) { b.AccountID = "account-two" },
		func(b *iamv1.EmailVerificationBinding) { b.UserID = "user-two" },
		func(b *iamv1.EmailVerificationBinding) { b.VerificationID = "verify-two" },
		func(b *iamv1.EmailVerificationBinding) { b.Recipient = "user@matrix.test" },
		func(b *iamv1.EmailVerificationBinding) { b.CredentialGeneration++ },
		func(b *iamv1.EmailVerificationBinding) { b.ContactRevision++ },
		func(b *iamv1.EmailVerificationBinding) { b.IssuedAt = b.IssuedAt.Add(time.Microsecond) },
		func(b *iamv1.EmailVerificationBinding) { b.ExpiresAt = b.ExpiresAt.Add(-time.Microsecond) },
	} {
		candidate := binding
		change(&candidate)
		if secret, err := OpenEmailVerificationCode(candidate, "mail-key", key, sealed); !errors.Is(err, ErrEmailVerificationProtection) || secret.Present() {
			t.Fatal("ciphertext moved across its immutable intent binding")
		}
	}
	for _, change := range []func(*SealedEmailVerificationCode){
		func(s *SealedEmailVerificationCode) { s.FormatVersion = 2 },
		func(s *SealedEmailVerificationCode) { s.KeyID = "other-key" },
		func(s *SealedEmailVerificationCode) { s.Nonce = s.Nonce[:11] },
		func(s *SealedEmailVerificationCode) { s.Ciphertext = s.Ciphertext[:23] },
		func(s *SealedEmailVerificationCode) { s.Nonce[0] ^= 1 },
		func(s *SealedEmailVerificationCode) { s.Ciphertext[0] ^= 1 },
	} {
		candidate := sealed
		candidate.Nonce, candidate.Ciphertext = bytes.Clone(sealed.Nonce), bytes.Clone(sealed.Ciphertext)
		change(&candidate)
		if secret, err := OpenEmailVerificationCode(binding, "mail-key", key, candidate); !errors.Is(err, ErrEmailVerificationProtection) || secret.Present() {
			t.Fatal("corrupt encrypted code accepted")
		}
	}
	for _, wrongKey := range [][]byte{nil, make([]byte, 31), bytes.Repeat([]byte{0x63}, 32)} {
		if secret, err := OpenEmailVerificationCode(binding, "mail-key", wrongKey, sealed); !errors.Is(err, ErrEmailVerificationProtection) || secret.Present() {
			t.Fatal("missing or wrong key accepted")
		}
	}
	for _, value := range []string{"short", "0123456x", "012345678"} {
		invalid, _ := iamv1.NewSecret(value)
		if secret, err := SealEmailVerificationCode(binding, "mail-key", key, invalid); !errors.Is(err, ErrEmailVerificationProtection) || len(secret.Ciphertext) != 0 {
			t.Fatal("arbitrary secret sealed under email purpose")
		}
	}
	for _, value := range []any{binding, sealed} {
		for _, format := range []string{"%v", "%+v", "%#v", "%s"} {
			printed := fmt.Sprintf(format, value)
			if !strings.Contains(printed, "REDACTED") || strings.Contains(printed, binding.Recipient) || strings.Contains(printed, "01234567") {
				t.Fatal("private email material formatted")
			}
		}
		if _, err := json.Marshal(value); err == nil {
			t.Fatal("private email material serialized")
		}
	}
	var ordinary SealedEmailVerificationCode
	if json.Unmarshal([]byte(`{}`), &ordinary) == nil {
		t.Fatal("ordinary JSON accepted encrypted email material")
	}
}

func TestSecurityMailClosedContentsAndAddress(t *testing.T) {
	for _, address := range []string{"User+tag@matrix.test", "user.name@sub.matrix.test", "a!#$%&'*+-/=?^_`{|}~@matrix.test"} {
		if iamv1.ValidateSecurityMailAddress(address) != nil {
			t.Fatal("valid ASCII mailbox refused")
		}
	}
	for _, address := range []string{"", "user", "user@localhost", "user@matrix.TEST", "user@matrix.test.",
		".user@matrix.test", "user.@matrix.test", "u..ser@matrix.test", "u@-matrix.test", "u@matrix-.test",
		"name <user@matrix.test>", "user@matrix.test,other@matrix.test", "u(comment)@matrix.test",
		"\"user\"@matrix.test", "u@[127.0.0.1]", "用户@matrix.test", "u@例子.test", "u@matrix.test\r\nBcc:a@matrix.test",
		"u@matrix.test\x00", strings.Repeat("u", 65) + "@matrix.test", "u@" + strings.Repeat("a", 64) + ".test"} {
		if iamv1.ValidateSecurityMailAddress(address) == nil {
			t.Fatal("unsupported mailbox accepted")
		}
	}
	mail := SecurityMail{NotificationID: "notice-1", Recipient: "User@matrix.test", Kind: MailAuthenticatorBound,
		OccurredAt: time.Date(2026, 9, 20, 0, 0, 0, 0, time.UTC)}
	for _, kind := range []SecurityMailKind{MailAuthenticatorBound, MailAuthenticatorReplaced, MailAuthenticatorRemoved,
		MailRecoveryStarted, MailAuthenticatorRecovered, MailRecoveryCodesChanged, MailSecuritySettingsChanged} {
		mail.Kind = kind
		if err := mail.Validate(); err != nil {
			t.Fatalf("closed security notice: %v", err)
		}
	}
	code, _ := iamv1.NewSecret("01234567")
	mail.Kind = MailAddressVerification
	mail.VerificationCode = code
	mail.VerificationExpiresAt = mail.OccurredAt.Add(10 * time.Minute)
	if err := mail.Validate(); err != nil {
		t.Fatalf("valid verification mail: %v", err)
	}
	for _, mutate := range []func(*SecurityMail){
		func(m *SecurityMail) { m.Kind = "CUSTOM" },
		func(m *SecurityMail) { m.Kind = MailAuthenticatorBound },
		func(m *SecurityMail) { m.NotificationID = "notice\r\nBcc" },
		func(m *SecurityMail) { m.Recipient = "u@matrix.test\n" },
		func(m *SecurityMail) { m.OccurredAt = time.Time{} },
		func(m *SecurityMail) { m.OccurredAt = m.OccurredAt.In(time.FixedZone("local", 3600)) },
		func(m *SecurityMail) { m.VerificationExpiresAt = m.OccurredAt },
		func(m *SecurityMail) { m.VerificationExpiresAt = m.OccurredAt.Add(10*time.Minute + time.Second) },
		func(m *SecurityMail) { m.VerificationCode, _ = iamv1.NewSecret("0123456") },
		func(m *SecurityMail) { m.VerificationCode, _ = iamv1.NewSecret("0123456a") },
		func(m *SecurityMail) { m.VerificationCode, _ = iamv1.NewSecret("０１２３４５６７") },
	} {
		candidate := mail
		mutate(&candidate)
		if candidate.Validate() == nil {
			t.Fatal("invalid closed message accepted")
		}
	}
	for _, format := range []string{"%s", "%v", "%+v", "%#v"} {
		printed := fmt.Sprintf(format, mail)
		if strings.Contains(printed, "01234567") || strings.Contains(printed, mail.Recipient) {
			t.Fatal("secret-bearing delivery projection was formatted")
		}
	}
	if _, err := json.Marshal(mail); err == nil {
		t.Fatal("mail serialized as ordinary JSON")
	}
	if err := json.Unmarshal([]byte(`{}`), &mail); err == nil {
		t.Fatal("ordinary JSON constructed mail")
	}
}

func FuzzSecurityMailAddress(f *testing.F) {
	for _, value := range []string{"User+tag@matrix.test", "name <u@matrix.test>", "a@b\r\n", "u@例子.test"} {
		f.Add(value)
	}
	f.Fuzz(func(t *testing.T, value string) {
		if iamv1.ValidateSecurityMailAddress(value) != nil {
			return
		}
		if len(value) > 254 || strings.Count(value, "@") != 1 {
			t.Fatal("accepted mailbox exceeds its framing")
		}
		for _, c := range value {
			if c < 33 || c > 126 {
				t.Fatal("accepted mailbox contains control/non-ASCII content")
			}
		}
	})
}
