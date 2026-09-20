package authority

import (
	"errors"
	"strings"
	"time"

	iamv1 "github.com/xiak/matrix/api/iam/v1"
)

var ErrSecurityMail = errors.New("security mail is invalid")

type SecurityMailKind string

const (
	MailAddressVerification     SecurityMailKind = "ADDRESS_VERIFICATION"
	MailAuthenticatorBound      SecurityMailKind = "AUTHENTICATOR_BOUND"
	MailAuthenticatorReplaced   SecurityMailKind = "AUTHENTICATOR_REPLACED"
	MailAuthenticatorRemoved    SecurityMailKind = "AUTHENTICATOR_REMOVED"
	MailRecoveryStarted         SecurityMailKind = "RECOVERY_STARTED"
	MailAuthenticatorRecovered  SecurityMailKind = "AUTHENTICATOR_RECOVERED"
	MailRecoveryCodesChanged    SecurityMailKind = "RECOVERY_CODES_CHANGED"
	MailSecuritySettingsChanged SecurityMailKind = "SECURITY_SETTINGS_CHANGED"
)

// SecurityMail is a purpose-limited delivery projection, not a recipient
// selector or proof of address ownership. The originating transaction owns
// eligibility, the fixed recipient revision and durable delivery identity.
type SecurityMail struct {
	NotificationID        string
	Recipient             string
	Kind                  SecurityMailKind
	OccurredAt            time.Time
	VerificationCode      iamv1.Secret
	VerificationExpiresAt time.Time
}

func (SecurityMail) String() string               { return "[REDACTED]" }
func (SecurityMail) GoString() string             { return "authority.SecurityMail{[REDACTED]}" }
func (SecurityMail) MarshalJSON() ([]byte, error) { return nil, ErrSecurityMail }
func (*SecurityMail) UnmarshalJSON([]byte) error  { return ErrSecurityMail }

func (message SecurityMail) Validate() error {
	if iamv1.ValidateID("notificationId", message.NotificationID) != nil ||
		ValidateSecurityMailAddress(message.Recipient) != nil || !securityMailTime(message.OccurredAt) {
		return ErrSecurityMail
	}
	if message.Kind == MailAddressVerification {
		code := message.VerificationCode.CopyBytes()
		defer clear(code)
		if len(code) != 8 || !securityMailTime(message.VerificationExpiresAt) ||
			!message.VerificationExpiresAt.After(message.OccurredAt) ||
			message.VerificationExpiresAt.Sub(message.OccurredAt) > 10*time.Minute {
			return ErrSecurityMail
		}
		for _, digit := range code {
			if digit < '0' || digit > '9' {
				return ErrSecurityMail
			}
		}
		return nil
	}
	if message.VerificationCode.Present() || !message.VerificationExpiresAt.IsZero() {
		return ErrSecurityMail
	}
	switch message.Kind {
	case MailAuthenticatorBound, MailAuthenticatorReplaced, MailAuthenticatorRemoved,
		MailRecoveryStarted, MailAuthenticatorRecovered, MailRecoveryCodesChanged, MailSecuritySettingsChanged:
		return nil
	default:
		return ErrSecurityMail
	}
}

func securityMailTime(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC && value == value.Round(0) &&
		value.Year() >= 1970 && value.Year() <= 9999 && value.Nanosecond()%1000 == 0
}

// ValidateSecurityMailAddress intentionally supports a bounded ASCII subset,
// not display names, lists, comments, quoted local parts or SMTPUTF8. The local
// part is case-sensitive; callers must not silently normalize it.
func ValidateSecurityMailAddress(value string) error {
	local, domain, ok := strings.Cut(value, "@")
	if !ok || len(value) > 254 || len(local) == 0 || len(local) > 64 ||
		strings.HasPrefix(local, ".") || strings.HasSuffix(local, ".") || strings.Contains(local, "..") ||
		!SecurityMailDNSName(domain) {
		return ErrSecurityMail
	}
	for _, c := range local {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
			strings.ContainsRune(".!#$%&'*+-/=?^_`{|}~", c) {
			continue
		}
		return ErrSecurityMail
	}
	return nil
}

// SecurityMailDNSName permits private DNS zones but not resolver search names,
// address literals, Unicode, trailing dots or non-canonical uppercase labels.
func SecurityMailDNSName(value string) bool {
	if len(value) == 0 || len(value) > 253 || !strings.Contains(value, ".") {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}
