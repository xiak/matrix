package iamv1

import (
	"bytes"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"strings"
	"time"

	"github.com/xiak/matrix/api/contractjson"
)

const (
	EmailVerificationWrappingPurpose       = "IAM_EMAIL_VERIFICATION_WRAPPING"
	SecurityMailSubmissionPurpose          = "IAM_SECURITY_MAIL_SUBMISSION"
	MaxSecurityMailSMTPChannelBytes  int64 = 32768
)

var (
	ErrInvalidSecurityMailAddress      = errors.New("security mail address is invalid")
	ErrInvalidEmailVerificationBinding = errors.New("email verification binding is invalid")
	ErrInvalidSecurityMailSMTPChannel  = errors.New("security mail SMTP channel is invalid")
)

type SecurityMailInstallationScope struct {
	InstallationID  string `json:"installationId"`
	BootstrapDigest string `json:"bootstrapDigest"`
}

type SecurityMailTLSMode string

const (
	SecurityMailSTARTTLS    SecurityMailTLSMode = "STARTTLS"
	SecurityMailImplicitTLS SecurityMailTLSMode = "IMPLICIT_TLS"
)

// SecurityMailSMTPChannel is an installation-private file, not an HTTP body
// or a permission. Runtime must match its exact scope against sealed authority
// before connecting; only the dedicated notification process may hold it.
type SecurityMailSMTPChannel struct {
	APIVersion   string
	Kind         string
	Purpose      string
	Scope        SecurityMailInstallationScope
	Host         string
	Port         uint16
	TLSMode      SecurityMailTLSMode
	Username     string
	Password     Secret
	From         string
	TrustedCAPEM string
}

func (SecurityMailSMTPChannel) String() string { return "[REDACTED]" }
func (SecurityMailSMTPChannel) GoString() string {
	return "iamv1.SecurityMailSMTPChannel{[REDACTED]}"
}
func (SecurityMailSMTPChannel) MarshalJSON() ([]byte, error) {
	return nil, ErrInvalidSecurityMailSMTPChannel
}
func (*SecurityMailSMTPChannel) UnmarshalJSON([]byte) error {
	return ErrInvalidSecurityMailSMTPChannel
}

func ValidateSecurityMailSMTPChannel(value SecurityMailSMTPChannel) error {
	if value.APIVersion != APIVersion || value.Kind != "SecurityMailSMTPChannel" || value.Purpose != SecurityMailSubmissionPurpose ||
		ValidateID("installationId", value.Scope.InstallationID) != nil || ValidateDigest("bootstrapDigest", value.Scope.BootstrapDigest) != nil ||
		value.Port == 0 || (value.TLSMode != SecurityMailSTARTTLS && value.TLSMode != SecurityMailImplicitTLS) ||
		(net.ParseIP(value.Host) == nil && !SecurityMailDNSName(value.Host)) || ValidateSecurityMailAddress(value.From) != nil ||
		len(value.Username) == 0 || len(value.Username) > 254 || !value.Password.Present() || len(value.TrustedCAPEM) > 16384 {
		return ErrInvalidSecurityMailSMTPChannel
	}
	for _, c := range value.Username {
		if c < 33 || c > 126 {
			return ErrInvalidSecurityMailSMTPChannel
		}
	}
	password := value.Password.CopyBytes()
	defer clear(password)
	if len(password) > 1024 {
		return ErrInvalidSecurityMailSMTPChannel
	}
	if value.TrustedCAPEM != "" {
		rest := []byte(value.TrustedCAPEM)
		count := 0
		seen := make(map[string]bool)
		for len(rest) > 0 {
			if !bytes.HasPrefix(rest, []byte("-----BEGIN CERTIFICATE-----\n")) {
				return ErrInvalidSecurityMailSMTPChannel
			}
			block, remaining := pem.Decode(rest)
			if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || count >= 8 || seen[string(block.Bytes)] {
				return ErrInvalidSecurityMailSMTPChannel
			}
			if !bytes.Equal(rest[:len(rest)-len(remaining)], pem.EncodeToMemory(block)) {
				return ErrInvalidSecurityMailSMTPChannel
			}
			certificate, err := x509.ParseCertificate(block.Bytes)
			if err != nil || !certificate.IsCA || !certificate.BasicConstraintsValid ||
				(certificate.KeyUsage != 0 && certificate.KeyUsage&x509.KeyUsageCertSign == 0) {
				return ErrInvalidSecurityMailSMTPChannel
			}
			seen[string(block.Bytes)] = true
			count++
			rest = remaining
		}
		if count == 0 {
			return ErrInvalidSecurityMailSMTPChannel
		}
	}
	return nil
}

type securityMailSMTPWire struct {
	APIVersion   string                        `json:"apiVersion"`
	Kind         string                        `json:"kind"`
	Purpose      string                        `json:"purpose"`
	Scope        SecurityMailInstallationScope `json:"scope"`
	Host         string                        `json:"host"`
	Port         uint16                        `json:"port"`
	TLSMode      SecurityMailTLSMode           `json:"tlsMode"`
	Username     string                        `json:"username"`
	Password     string                        `json:"password"`
	From         string                        `json:"from"`
	TrustedCAPEM string                        `json:"trustedCaPem,omitempty"`
}

func EncodeSecurityMailSMTPChannel(value SecurityMailSMTPChannel) ([]byte, error) {
	if ValidateSecurityMailSMTPChannel(value) != nil {
		return nil, ErrInvalidSecurityMailSMTPChannel
	}
	wire := securityMailSMTPWire{APIVersion: value.APIVersion, Kind: value.Kind, Purpose: value.Purpose, Scope: value.Scope,
		Host: value.Host, Port: value.Port, TLSMode: value.TLSMode, Username: value.Username,
		Password: value.Password.reveal(), From: value.From, TrustedCAPEM: value.TrustedCAPEM}
	encoded, err := json.Marshal(wire)
	if err != nil || int64(len(encoded)) > MaxSecurityMailSMTPChannelBytes {
		clear(encoded)
		return nil, ErrInvalidSecurityMailSMTPChannel
	}
	return encoded, nil
}

func DecodeSecurityMailSMTPChannel(reader io.Reader) (SecurityMailSMTPChannel, error) {
	if reader == nil {
		return SecurityMailSMTPChannel{}, ErrInvalidSecurityMailSMTPChannel
	}
	encoded, err := io.ReadAll(io.LimitReader(reader, MaxSecurityMailSMTPChannelBytes+1))
	defer clear(encoded)
	var wire securityMailSMTPWire
	if err != nil || len(encoded) == 0 || int64(len(encoded)) > MaxSecurityMailSMTPChannelBytes ||
		contractjson.DecodeObjectBytes(encoded, MaxSecurityMailSMTPChannelBytes, &wire) != nil {
		return SecurityMailSMTPChannel{}, ErrInvalidSecurityMailSMTPChannel
	}
	password, err := NewSecret(wire.Password)
	if err != nil {
		return SecurityMailSMTPChannel{}, ErrInvalidSecurityMailSMTPChannel
	}
	value := SecurityMailSMTPChannel{APIVersion: wire.APIVersion, Kind: wire.Kind, Purpose: wire.Purpose, Scope: wire.Scope,
		Host: wire.Host, Port: wire.Port, TLSMode: wire.TLSMode, Username: wire.Username,
		Password: password, From: wire.From, TrustedCAPEM: wire.TrustedCAPEM}
	canonical, err := EncodeSecurityMailSMTPChannel(value)
	defer clear(canonical)
	if err != nil || !bytes.Equal(encoded, canonical) {
		return SecurityMailSMTPChannel{}, ErrInvalidSecurityMailSMTPChannel
	}
	return value, nil
}

// EmailVerificationBinding is private record identity, not proof of current
// contact ownership or an HTTP selector. Lifecycle code must recheck its
// actual Session, credential generation, contact revision and expiry in SQL.
// Installation owns key custody; this pure encoding grants no recovery right.
type EmailVerificationBinding struct {
	InstallationID       string
	BootstrapDigest      string
	AccountID            AccountID
	UserID               PrincipalID
	VerificationID       string
	Recipient            string
	CredentialGeneration uint64
	ContactRevision      uint64
	IssuedAt             time.Time
	ExpiresAt            time.Time
}

func (EmailVerificationBinding) String() string { return "[REDACTED]" }
func (EmailVerificationBinding) GoString() string {
	return "iamv1.EmailVerificationBinding{[REDACTED]}"
}
func (EmailVerificationBinding) MarshalJSON() ([]byte, error) {
	return nil, ErrInvalidEmailVerificationBinding
}
func (*EmailVerificationBinding) UnmarshalJSON([]byte) error {
	return ErrInvalidEmailVerificationBinding
}

// EmailVerificationCipherContext is the sole format-1 HKDF info/AAD encoder.
// It does not include mutable attempt/lease state or claim replay protection.
func EmailVerificationCipherContext(value EmailVerificationBinding, keyID string) (info, aad []byte, err error) {
	for _, id := range []string{value.InstallationID, string(value.AccountID), string(value.UserID), value.VerificationID, keyID} {
		if ValidateID("verificationScope", id) != nil {
			return nil, nil, ErrInvalidEmailVerificationBinding
		}
	}
	if ValidateDigest("bootstrapDigest", value.BootstrapDigest) != nil || ValidateSecurityMailAddress(value.Recipient) != nil ||
		validatePositiveVersion(value.CredentialGeneration) != nil || value.ContactRevision > 9007199254740991 ||
		validateTime("issuedAt", value.IssuedAt) != nil || validateTime("expiresAt", value.ExpiresAt) != nil ||
		value.IssuedAt.Year() < 1970 || value.ExpiresAt.Year() > 9999 ||
		!value.ExpiresAt.After(value.IssuedAt) || value.ExpiresAt.Sub(value.IssuedAt) > 10*time.Minute {
		return nil, nil, ErrInvalidEmailVerificationBinding
	}
	fields := [][]byte{[]byte(EmailVerificationWrappingPurpose), {1}, []byte(value.InstallationID), []byte(value.BootstrapDigest),
		[]byte(value.AccountID), []byte(value.UserID), []byte(value.VerificationID), []byte(value.Recipient),
		binary.BigEndian.AppendUint64(nil, value.CredentialGeneration), binary.BigEndian.AppendUint64(nil, value.ContactRevision),
		binary.BigEndian.AppendUint64(nil, uint64(value.IssuedAt.UnixMicro())), binary.BigEndian.AppendUint64(nil, uint64(value.ExpiresAt.UnixMicro())),
		[]byte(keyID)}
	return credentialBindingBytes("matrix.iam.email-verification.kdf-info.v1", fields...),
		credentialBindingBytes("matrix.iam.email-verification.aad.v1", fields...), nil
}

// ValidateSecurityMailAddress intentionally supports a bounded ASCII subset,
// not display names, lists, comments, quoted local parts or SMTPUTF8. The local
// part is case-sensitive; callers must not silently normalize it.
func ValidateSecurityMailAddress(value string) error {
	local, domain, ok := strings.Cut(value, "@")
	if !ok || len(value) > 254 || len(local) == 0 || len(local) > 64 ||
		strings.HasPrefix(local, ".") || strings.HasSuffix(local, ".") || strings.Contains(local, "..") ||
		!SecurityMailDNSName(domain) {
		return ErrInvalidSecurityMailAddress
	}
	for _, c := range local {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
			strings.ContainsRune(".!#$%&'*+-/=?^_`{|}~", c) {
			continue
		}
		return ErrInvalidSecurityMailAddress
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
