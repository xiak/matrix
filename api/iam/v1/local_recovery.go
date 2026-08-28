package iamv1

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/xiak/matrix/api/contractjson"
)

// These contracts are private files for the signed one-shot IAM entry, not
// HTTP requests or authority conferred on a USER/service credential.
const (
	LocalCredentialRecoveryPurpose  = "INSTALLATION_PRIMARY_CREDENTIAL_RECOVERY"
	LocalCredentialRecoveryActor    = "iam-local-recovery"
	MaxLocalCredentialRecoveryBytes = 32 * 1024
)

var ErrInvalidLocalCredentialRecovery = errors.New("local IAM credential recovery is invalid")

type LocalCredentialRecoveryScope struct {
	InstallationID  string         `json:"installationId"`
	BootstrapDigest string         `json:"bootstrapDigest"`
	OrganizationID  OrganizationID `json:"organizationId"`
	PrincipalID     PrincipalID    `json:"principalId"`
}

type LocalCredentialRecoveryExpected struct {
	OrganizationResourceVersion    uint64        `json:"organizationResourceVersion"`
	PrincipalResourceVersion       uint64        `json:"principalResourceVersion"`
	CredentialGeneration           uint64        `json:"credentialGeneration"`
	PlatformBindingID              RoleBindingID `json:"platformBindingId"`
	PlatformBindingResourceVersion uint64        `json:"platformBindingResourceVersion"`
}

// Authority is installation-private issuing authority. The database login is
// dedicated to the two local-recovery functions; the key authenticates one
// intent, including its password. Neither is an ordinary journal field.
type LocalCredentialRecoveryAuthority struct {
	APIVersion    string                       `json:"apiVersion"`
	Kind          string                       `json:"kind"`
	Purpose       string                       `json:"purpose"`
	Scope         LocalCredentialRecoveryScope `json:"scope"`
	CapabilityKey Secret                       `json:"capabilityKey"`
}

type LocalCredentialRecoveryInspection struct {
	APIVersion      string                           `json:"apiVersion"`
	Kind            string                           `json:"kind"`
	Scope           LocalCredentialRecoveryScope     `json:"scope"`
	State           string                           `json:"state"`
	CommandID       string                           `json:"commandId,omitempty"`
	InputCommitment string                           `json:"inputCommitment,omitempty"`
	Expected        *LocalCredentialRecoveryExpected `json:"expected,omitempty"`
	Result          *LocalCredentialRecoveryResult   `json:"result,omitempty"`
}

// A query selects one completion already committed for the sealed authority.
// NOT_FOUND never supplies fresh expected versions or authorizes a new intent.
type LocalCredentialRecoveryReceiptQuery struct {
	APIVersion      string `json:"apiVersion"`
	Kind            string `json:"kind"`
	CommandID       string `json:"commandId"`
	InputCommitment string `json:"inputCommitment"`
}

type LocalCredentialRecoveryRequest struct {
	APIVersion  string                          `json:"apiVersion"`
	Kind        string                          `json:"kind"`
	Purpose     string                          `json:"purpose"`
	CommandID   string                          `json:"commandId"`
	Scope       LocalCredentialRecoveryScope    `json:"scope"`
	Expected    LocalCredentialRecoveryExpected `json:"expected"`
	NewPassword Secret                          `json:"newPassword"`
	Capability  Secret                          `json:"capability"`
}

// Result is historical completion metadata, never proof of current access.
// An EQUAL_REPLAY retains the original generations, event and completion time.
type LocalCredentialRecoveryResult struct {
	APIVersion                   string                       `json:"apiVersion"`
	Kind                         string                       `json:"kind"`
	State                        string                       `json:"state"`
	CommandID                    string                       `json:"commandId"`
	InputCommitment              string                       `json:"inputCommitment"`
	Scope                        LocalCredentialRecoveryScope `json:"scope"`
	PreviousCredentialGeneration uint64                       `json:"previousCredentialGeneration"`
	CredentialGeneration         uint64                       `json:"credentialGeneration"`
	PrincipalResourceVersion     uint64                       `json:"principalResourceVersion"`
	RevokedSessions              uint64                       `json:"revokedSessions"`
	AuditEventID                 string                       `json:"auditEventId"`
	CompletedAt                  time.Time                    `json:"completedAt"`
}

func ValidateLocalCredentialRecoveryScope(value LocalCredentialRecoveryScope) error {
	if ValidateID("installationId", value.InstallationID) != nil ||
		ValidateDigest("bootstrapDigest", value.BootstrapDigest) != nil ||
		ValidateID("organizationId", string(value.OrganizationID)) != nil ||
		ValidateID("principalId", string(value.PrincipalID)) != nil {
		return ErrInvalidLocalCredentialRecovery
	}
	return nil
}

func ValidateLocalCredentialRecoveryExpected(value LocalCredentialRecoveryExpected) error {
	if validatePositiveVersion(value.OrganizationResourceVersion) != nil ||
		validatePositiveVersion(value.PrincipalResourceVersion) != nil ||
		validatePositiveVersion(value.CredentialGeneration) != nil ||
		validatePositiveVersion(value.PlatformBindingResourceVersion) != nil ||
		value.PrincipalResourceVersion == 9007199254740991 ||
		value.CredentialGeneration == 9007199254740991 ||
		ValidateID("platformBindingId", string(value.PlatformBindingID)) != nil {
		return ErrInvalidLocalCredentialRecovery
	}
	return nil
}

func ValidateLocalCredentialRecoveryAuthority(value LocalCredentialRecoveryAuthority) error {
	if value.APIVersion != APIVersion || value.Kind != "LocalCredentialRecoveryAuthority" ||
		value.Purpose != LocalCredentialRecoveryPurpose ||
		ValidateLocalCredentialRecoveryScope(value.Scope) != nil {
		return ErrInvalidLocalCredentialRecovery
	}
	key, err := localRecoverySecretBytes(value.CapabilityKey)
	clear(key)
	return err
}

func ValidateLocalCredentialRecoveryInspection(value LocalCredentialRecoveryInspection) error {
	if value.APIVersion != APIVersion || value.Kind != "LocalCredentialRecoveryInspection" ||
		ValidateLocalCredentialRecoveryScope(value.Scope) != nil {
		return ErrInvalidLocalCredentialRecovery
	}
	switch value.State {
	case "ELIGIBLE":
		if value.Expected == nil || ValidateLocalCredentialRecoveryExpected(*value.Expected) != nil ||
			value.Result != nil || value.CommandID != "" || value.InputCommitment != "" {
			return ErrInvalidLocalCredentialRecovery
		}
	case "COMPLETED", "NOT_FOUND":
		if ValidateID("commandId", value.CommandID) != nil || ValidateDigest("inputCommitment", value.InputCommitment) != nil {
			return ErrInvalidLocalCredentialRecovery
		}
		if value.State == "NOT_FOUND" {
			if value.Expected != nil || value.Result != nil {
				return ErrInvalidLocalCredentialRecovery
			}
		} else if value.Expected == nil || ValidateLocalCredentialRecoveryExpected(*value.Expected) != nil ||
			value.Result == nil || ValidateLocalCredentialRecoveryResult(*value.Result) != nil ||
			value.Result.Scope != value.Scope || value.Result.CommandID != value.CommandID ||
			value.Result.InputCommitment != value.InputCommitment ||
			value.Expected.CredentialGeneration != value.Result.PreviousCredentialGeneration ||
			value.Expected.PrincipalResourceVersion+1 != value.Result.PrincipalResourceVersion {
			return ErrInvalidLocalCredentialRecovery
		}
	default:
		return ErrInvalidLocalCredentialRecovery
	}
	return nil
}

func ValidateLocalCredentialRecoveryReceiptQuery(value LocalCredentialRecoveryReceiptQuery) error {
	if value.APIVersion != APIVersion || value.Kind != "LocalCredentialRecoveryReceiptQuery" ||
		ValidateID("commandId", value.CommandID) != nil || ValidateDigest("inputCommitment", value.InputCommitment) != nil {
		return ErrInvalidLocalCredentialRecovery
	}
	return nil
}

func ValidateLocalCredentialRecoveryResult(value LocalCredentialRecoveryResult) error {
	if value.APIVersion != APIVersion || value.Kind != "LocalCredentialRecoveryResult" ||
		(value.State != "APPLIED" && value.State != "EQUAL_REPLAY") ||
		ValidateID("commandId", value.CommandID) != nil ||
		ValidateLocalCredentialRecoveryScope(value.Scope) != nil ||
		ValidateDigest("inputCommitment", value.InputCommitment) != nil ||
		validatePositiveVersion(value.PreviousCredentialGeneration) != nil ||
		validatePositiveVersion(value.CredentialGeneration) != nil ||
		value.CredentialGeneration != value.PreviousCredentialGeneration+1 ||
		validatePositiveVersion(value.PrincipalResourceVersion) != nil ||
		value.RevokedSessions > 9007199254740991 ||
		ValidateID("auditEventId", value.AuditEventID) != nil ||
		validateTime("completedAt", value.CompletedAt) != nil {
		return ErrInvalidLocalCredentialRecovery
	}
	return nil
}

// SignLocalCredentialRecoveryRequest is the installation's deliberate private
// capability encoder. The complete intent, not just a caller-chosen tenant,
// is authenticated. The authority document remains outside ordinary journals.
func SignLocalCredentialRecoveryRequest(authority LocalCredentialRecoveryAuthority, request LocalCredentialRecoveryRequest) (LocalCredentialRecoveryRequest, error) {
	mac, err := localRecoveryMAC(authority, request)
	if err != nil {
		return LocalCredentialRecoveryRequest{}, err
	}
	defer clear(mac)
	request.Capability, err = NewSecret(base64.RawURLEncoding.EncodeToString(mac))
	if err != nil {
		return LocalCredentialRecoveryRequest{}, ErrInvalidLocalCredentialRecovery
	}
	return request, nil
}

// VerifyLocalCredentialRecoveryRequest returns only a non-secret commitment.
// The capability itself is never an Audit digest or a reusable append permit.
func VerifyLocalCredentialRecoveryRequest(authority LocalCredentialRecoveryAuthority, request LocalCredentialRecoveryRequest) (string, error) {
	expected, err := localRecoveryMAC(authority, request)
	if err != nil {
		return "", err
	}
	defer clear(expected)
	actual, err := localRecoverySecretBytes(request.Capability)
	if err != nil {
		return "", err
	}
	defer clear(actual)
	if !hmac.Equal(expected, actual) {
		return "", ErrInvalidLocalCredentialRecovery
	}
	commitment := sha256.Sum256(actual)
	return "sha256:" + hex.EncodeToString(commitment[:]), nil
}

func localRecoveryMAC(authority LocalCredentialRecoveryAuthority, request LocalCredentialRecoveryRequest) ([]byte, error) {
	if ValidateLocalCredentialRecoveryAuthority(authority) != nil ||
		request.Scope != authority.Scope || validateLocalRecoveryIntent(request) != nil {
		return nil, ErrInvalidLocalCredentialRecovery
	}
	key, err := localRecoverySecretBytes(authority.CapabilityKey)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	encoded, err := json.Marshal(localRecoveryRequestWire(request, false))
	if err != nil {
		return nil, ErrInvalidLocalCredentialRecovery
	}
	defer clear(encoded)
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte("matrix.iam.local-credential-recovery.v1\x00"))
	_, _ = mac.Write(encoded)
	return mac.Sum(nil), nil
}

func validateLocalRecoveryIntent(value LocalCredentialRecoveryRequest) error {
	if value.APIVersion != APIVersion || value.Kind != "LocalCredentialRecoveryRequest" ||
		value.Purpose != LocalCredentialRecoveryPurpose ||
		ValidateID("commandId", value.CommandID) != nil ||
		ValidateLocalCredentialRecoveryScope(value.Scope) != nil ||
		ValidateLocalCredentialRecoveryExpected(value.Expected) != nil || !value.NewPassword.Present() {
		return ErrInvalidLocalCredentialRecovery
	}
	return nil
}

func localRecoverySecretBytes(secret Secret) ([]byte, error) {
	value := secret.CopyBytes()
	defer clear(value)
	decoded := make([]byte, base64.RawURLEncoding.DecodedLen(len(value)))
	n, err := base64.RawURLEncoding.Strict().Decode(decoded, value)
	if err != nil || n != sha256.Size || len(value) != 43 {
		clear(decoded)
		return nil, ErrInvalidLocalCredentialRecovery
	}
	return decoded[:n], nil
}

func DecodeLocalCredentialRecoveryAuthority(reader io.Reader) (LocalCredentialRecoveryAuthority, error) {
	var value LocalCredentialRecoveryAuthority
	if contractjson.DecodeObject(reader, MaxLocalCredentialRecoveryBytes, &value) != nil ||
		ValidateLocalCredentialRecoveryAuthority(value) != nil {
		return LocalCredentialRecoveryAuthority{}, ErrInvalidLocalCredentialRecovery
	}
	return value, nil
}

func DecodeLocalCredentialRecoveryRequest(reader io.Reader) (LocalCredentialRecoveryRequest, error) {
	var value LocalCredentialRecoveryRequest
	if contractjson.DecodeObject(reader, MaxLocalCredentialRecoveryBytes, &value) != nil ||
		validateLocalRecoveryIntent(value) != nil {
		return LocalCredentialRecoveryRequest{}, ErrInvalidLocalCredentialRecovery
	}
	capability, err := localRecoverySecretBytes(value.Capability)
	clear(capability)
	if err != nil {
		return LocalCredentialRecoveryRequest{}, err
	}
	return value, nil
}

func EncodeLocalCredentialRecoveryAuthority(value LocalCredentialRecoveryAuthority) ([]byte, error) {
	if err := ValidateLocalCredentialRecoveryAuthority(value); err != nil {
		return nil, err
	}
	return json.Marshal(struct {
		APIVersion    string                       `json:"apiVersion"`
		Kind          string                       `json:"kind"`
		Purpose       string                       `json:"purpose"`
		Scope         LocalCredentialRecoveryScope `json:"scope"`
		CapabilityKey string                       `json:"capabilityKey"`
	}{value.APIVersion, value.Kind, value.Purpose, value.Scope, value.CapabilityKey.reveal()})
}

func EncodeLocalCredentialRecoveryRequest(value LocalCredentialRecoveryRequest) ([]byte, error) {
	if err := validateLocalRecoveryIntent(value); err != nil {
		return nil, err
	}
	capability, err := localRecoverySecretBytes(value.Capability)
	clear(capability)
	if err != nil {
		return nil, err
	}
	return json.Marshal(localRecoveryRequestWire(value, true))
}

type localCredentialRecoveryWire struct {
	APIVersion  string                          `json:"apiVersion"`
	Kind        string                          `json:"kind"`
	Purpose     string                          `json:"purpose"`
	CommandID   string                          `json:"commandId"`
	Scope       LocalCredentialRecoveryScope    `json:"scope"`
	Expected    LocalCredentialRecoveryExpected `json:"expected"`
	NewPassword string                          `json:"newPassword"`
	Capability  string                          `json:"capability,omitempty"`
}

func localRecoveryRequestWire(value LocalCredentialRecoveryRequest, includeCapability bool) localCredentialRecoveryWire {
	wire := localCredentialRecoveryWire{
		APIVersion: value.APIVersion, Kind: value.Kind, Purpose: value.Purpose,
		CommandID: value.CommandID, Scope: value.Scope, Expected: value.Expected,
		NewPassword: value.NewPassword.reveal(),
	}
	if includeCapability {
		wire.Capability = value.Capability.reveal()
	}
	return wire
}
