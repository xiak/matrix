package installationv1

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"

	"github.com/xiak/matrix/api/contractjson"
	iamv1 "github.com/xiak/matrix/api/iam/v1"
)

const (
	SecurityMailConfigurationAPIVersion         = "installation.matrix.xiak.com/v1"
	SecurityMailConfigurationKind               = "SecurityMailConfiguration"
	MaximumSecurityMailConfigurationBytes int64 = 24576
)

var ErrInvalidSecurityMailConfiguration = errors.New("security mail configuration is invalid")

// SecurityMailConfiguration is an operator-private input file. It deliberately
// omits installation scope: the installation owner binds the canonical input
// to its sealed installation and IAM bootstrap identities before writing the
// purpose-only IAM channel. It is neither an HTTP body nor an SMTP credential
// that may be printed, journaled or copied into support evidence.
type SecurityMailConfiguration struct {
	APIVersion   string
	Kind         string
	Host         string
	Port         uint16
	TLSMode      iamv1.SecurityMailTLSMode
	Username     string
	Password     iamv1.Secret
	From         string
	TrustedCAPEM string
}

func (SecurityMailConfiguration) String() string { return "[REDACTED]" }
func (SecurityMailConfiguration) GoString() string {
	return "installationv1.SecurityMailConfiguration{[REDACTED]}"
}
func (SecurityMailConfiguration) MarshalJSON() ([]byte, error) {
	return nil, ErrInvalidSecurityMailConfiguration
}
func (*SecurityMailConfiguration) UnmarshalJSON([]byte) error {
	return ErrInvalidSecurityMailConfiguration
}

func (value *SecurityMailConfiguration) Clear() {
	if value == nil {
		return
	}
	*value = SecurityMailConfiguration{}
}

func ValidateSecurityMailConfiguration(value SecurityMailConfiguration) error {
	if value.APIVersion != SecurityMailConfigurationAPIVersion || value.Kind != SecurityMailConfigurationKind {
		return ErrInvalidSecurityMailConfiguration
	}
	channel := iamv1.SecurityMailSMTPChannel{
		APIVersion: iamv1.APIVersion,
		Kind:       "SecurityMailSMTPChannel",
		Purpose:    iamv1.SecurityMailSubmissionPurpose,
		Scope: iamv1.SecurityMailInstallationScope{
			InstallationID:  "mxi-00000000000000000000000000000000",
			BootstrapDigest: "sha256:" + string(bytes.Repeat([]byte{'0'}, 64)),
		},
		Host: value.Host, Port: value.Port, TLSMode: value.TLSMode,
		Username: value.Username, Password: value.Password, From: value.From,
		TrustedCAPEM: value.TrustedCAPEM,
	}
	if iamv1.ValidateSecurityMailSMTPChannel(channel) != nil {
		return ErrInvalidSecurityMailConfiguration
	}
	return nil
}

type securityMailConfigurationWire struct {
	APIVersion   string                    `json:"apiVersion"`
	Kind         string                    `json:"kind"`
	Host         string                    `json:"host"`
	Port         uint16                    `json:"port"`
	TLSMode      iamv1.SecurityMailTLSMode `json:"tlsMode"`
	Username     string                    `json:"username"`
	Password     string                    `json:"password"`
	From         string                    `json:"from"`
	TrustedCAPEM string                    `json:"trustedCaPem,omitempty"`
}

func EncodeSecurityMailConfiguration(value SecurityMailConfiguration) ([]byte, error) {
	if ValidateSecurityMailConfiguration(value) != nil {
		return nil, ErrInvalidSecurityMailConfiguration
	}
	password := value.Password.CopyBytes()
	defer clear(password)
	encoded, err := json.Marshal(securityMailConfigurationWire{
		APIVersion: value.APIVersion, Kind: value.Kind, Host: value.Host, Port: value.Port,
		TLSMode: value.TLSMode, Username: value.Username, Password: string(password),
		From: value.From, TrustedCAPEM: value.TrustedCAPEM,
	})
	if err != nil || len(encoded) == 0 || int64(len(encoded)) > MaximumSecurityMailConfigurationBytes {
		clear(encoded)
		return nil, ErrInvalidSecurityMailConfiguration
	}
	return encoded, nil
}

func DecodeSecurityMailConfiguration(reader io.Reader) (SecurityMailConfiguration, error) {
	if reader == nil {
		return SecurityMailConfiguration{}, ErrInvalidSecurityMailConfiguration
	}
	encoded, err := io.ReadAll(io.LimitReader(reader, MaximumSecurityMailConfigurationBytes+1))
	defer clear(encoded)
	var wire securityMailConfigurationWire
	if err != nil || len(encoded) == 0 || int64(len(encoded)) > MaximumSecurityMailConfigurationBytes ||
		contractjson.DecodeObjectBytes(encoded, MaximumSecurityMailConfigurationBytes, &wire) != nil {
		return SecurityMailConfiguration{}, ErrInvalidSecurityMailConfiguration
	}
	password, err := iamv1.NewSecret(wire.Password)
	if err != nil {
		return SecurityMailConfiguration{}, ErrInvalidSecurityMailConfiguration
	}
	value := SecurityMailConfiguration{
		APIVersion: wire.APIVersion, Kind: wire.Kind, Host: wire.Host, Port: wire.Port,
		TLSMode: wire.TLSMode, Username: wire.Username, Password: password,
		From: wire.From, TrustedCAPEM: wire.TrustedCAPEM,
	}
	canonical, err := EncodeSecurityMailConfiguration(value)
	defer clear(canonical)
	if err != nil || !bytes.Equal(encoded, canonical) {
		value.Clear()
		return SecurityMailConfiguration{}, ErrInvalidSecurityMailConfiguration
	}
	return value, nil
}

func SecurityMailConfigurationDigest(value SecurityMailConfiguration) (string, error) {
	encoded, err := EncodeSecurityMailConfiguration(value)
	defer clear(encoded)
	if err != nil {
		return "", ErrInvalidSecurityMailConfiguration
	}
	digest := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}
