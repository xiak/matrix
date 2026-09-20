package authority

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	iamv1 "github.com/xiak/matrix/api/iam/v1"
)

func TestSecurityMailClosedContentsAndAddress(t *testing.T) {
	for _, address := range []string{"User+tag@matrix.test", "user.name@sub.matrix.test", "a!#$%&'*+-/=?^_`{|}~@matrix.test"} {
		if ValidateSecurityMailAddress(address) != nil {
			t.Fatal("valid ASCII mailbox refused")
		}
	}
	for _, address := range []string{"", "user", "user@localhost", "user@matrix.TEST", "user@matrix.test.",
		".user@matrix.test", "user.@matrix.test", "u..ser@matrix.test", "u@-matrix.test", "u@matrix-.test",
		"name <user@matrix.test>", "user@matrix.test,other@matrix.test", "u(comment)@matrix.test",
		"\"user\"@matrix.test", "u@[127.0.0.1]", "用户@matrix.test", "u@例子.test", "u@matrix.test\r\nBcc:a@matrix.test",
		"u@matrix.test\x00", strings.Repeat("u", 65) + "@matrix.test", "u@" + strings.Repeat("a", 64) + ".test"} {
		if ValidateSecurityMailAddress(address) == nil {
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
		if ValidateSecurityMailAddress(value) != nil {
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
