package iamv1

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/xiak/matrix/api/contractjson"
)

var ErrEncodingFailed = errors.New("IAM contract encoding failed")

// credentialBindingBytes is the existing uint32BE framing, shared only by
// closed credential encodings in this package. Every caller first validates
// its own bounded fields and supplies a fixed, purpose-specific domain.
// Moving this primitive does not change any AccessKey context/signature bytes.
func credentialBindingBytes(domain string, fields ...[]byte) []byte {
	encoded := binary.BigEndian.AppendUint32(nil, uint32(len(domain)))
	encoded = append(encoded, domain...)
	for _, field := range fields {
		encoded = binary.BigEndian.AppendUint32(encoded, uint32(len(field)))
		encoded = append(encoded, field...)
	}
	return encoded
}

// BootstrapDigest is the single byte-preserving commitment to the sealed
// installer bootstrap document. It deliberately reuses its private encoder.
func BootstrapDigest(document BootstrapDocument) (string, error) {
	encoded, err := EncodeBootstrapDocument(document)
	if err != nil {
		return "", err
	}
	defer clear(encoded)
	digest := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

// DecodeRequest applies the common strict IAM request decoder.
func DecodeRequest(reader io.Reader, destination any) error {
	return contractjson.DecodeObject(reader, MaxRequestBytes, destination)
}

func (value *UserPasswordResetCompletion) UnmarshalJSON(source []byte) error {
	type wire UserPasswordResetCompletion
	var decoded wire
	if value == nil || contractjson.DecodeObjectBytes(source, MaxRequestBytes, &decoded) != nil ||
		ValidateUserPasswordResetCompletion(UserPasswordResetCompletion(decoded)) != nil {
		return contractjson.ErrInvalidDocument
	}
	*value = UserPasswordResetCompletion(decoded)
	return nil
}

func (value *PasswordRequirements) UnmarshalJSON(source []byte) error {
	type wire PasswordRequirements
	var decoded wire
	if value == nil || contractjson.DecodeObjectBytes(source, MaxRequestBytes, &decoded) != nil ||
		ValidatePasswordRequirements(PasswordRequirements(decoded)) != nil {
		return contractjson.ErrInvalidDocument
	}
	*value = PasswordRequirements(decoded)
	return nil
}

func (value *ChallengePasswordRequirementsRequest) UnmarshalJSON(source []byte) error {
	type wire ChallengePasswordRequirementsRequest
	var decoded wire
	if value == nil || contractjson.DecodeObjectBytes(source, MaxRequestBytes, &decoded) != nil ||
		ValidateChallengePasswordRequirementsRequest(ChallengePasswordRequirementsRequest(decoded)) != nil {
		return contractjson.ErrInvalidDocument
	}
	*value = ChallengePasswordRequirementsRequest(decoded)
	return nil
}

func EncodeChallengePasswordRequirementsRequest(value ChallengePasswordRequirementsRequest) ([]byte, error) {
	if err := ValidateChallengePasswordRequirementsRequest(value); err != nil {
		return nil, err
	}
	return json.Marshal(struct {
		ChallengeCredential string `json:"challengeCredential"`
	}{value.ChallengeCredential.reveal()})
}

func (value *InspectEnrollmentChallengeRequest) UnmarshalJSON(source []byte) error {
	type wire InspectEnrollmentChallengeRequest
	var decoded wire
	if value == nil || contractjson.DecodeObjectBytes(source, MaxRequestBytes, &decoded) != nil ||
		ValidateInspectEnrollmentChallengeRequest(InspectEnrollmentChallengeRequest(decoded)) != nil {
		return contractjson.ErrInvalidDocument
	}
	*value = InspectEnrollmentChallengeRequest(decoded)
	return nil
}

func EncodeInspectEnrollmentChallengeRequest(value InspectEnrollmentChallengeRequest) ([]byte, error) {
	if err := ValidateInspectEnrollmentChallengeRequest(value); err != nil {
		return nil, err
	}
	return json.Marshal(struct {
		ChallengeCredential string `json:"challengeCredential"`
	}{value.ChallengeCredential.reveal()})
}

func (value *StartChallengeTOTPEnrollmentRequest) UnmarshalJSON(source []byte) error {
	type wire StartChallengeTOTPEnrollmentRequest
	var decoded wire
	if value == nil || contractjson.DecodeObjectBytes(source, MaxRequestBytes, &decoded) != nil ||
		ValidateStartChallengeTOTPEnrollmentRequest(StartChallengeTOTPEnrollmentRequest(decoded)) != nil {
		return contractjson.ErrInvalidDocument
	}
	*value = StartChallengeTOTPEnrollmentRequest(decoded)
	return nil
}

func EncodeStartChallengeTOTPEnrollmentRequest(value StartChallengeTOTPEnrollmentRequest) ([]byte, error) {
	if err := ValidateStartChallengeTOTPEnrollmentRequest(value); err != nil {
		return nil, err
	}
	return json.Marshal(struct {
		RequestID           string `json:"requestId"`
		ChallengeCredential string `json:"challengeCredential"`
	}{value.RequestID, value.ChallengeCredential.reveal()})
}

func (value *EnrollmentChallengeState) UnmarshalJSON(source []byte) error {
	type wire EnrollmentChallengeState
	var decoded wire
	if value == nil || contractjson.DecodeObjectBytes(source, MaxRequestBytes, &decoded) != nil ||
		ValidateEnrollmentChallengeState(EnrollmentChallengeState(decoded)) != nil {
		return contractjson.ErrInvalidDocument
	}
	// Optional means absent, not explicit null. The password stage must not
	// carry even empty placeholders for subsequent authentication authority.
	var fields map[string]json.RawMessage
	if json.Unmarshal(source, &fields) != nil {
		return contractjson.ErrInvalidDocument
	}
	for _, field := range []string{"notificationContact", "enrollment"} {
		if raw, present := fields[field]; present && bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return contractjson.ErrInvalidDocument
		}
	}
	*value = EnrollmentChallengeState(decoded)
	return nil
}

func (value *StartChallengeNotificationContactVerificationRequest) UnmarshalJSON(source []byte) error {
	type wire StartChallengeNotificationContactVerificationRequest
	var decoded wire
	if value == nil || contractjson.DecodeObjectBytes(source, MaxRequestBytes, &decoded) != nil ||
		ValidateStartChallengeNotificationContactVerificationRequest(StartChallengeNotificationContactVerificationRequest(decoded)) != nil {
		return contractjson.ErrInvalidDocument
	}
	*value = StartChallengeNotificationContactVerificationRequest(decoded)
	return nil
}

func EncodeStartChallengeNotificationContactVerificationRequest(value StartChallengeNotificationContactVerificationRequest) ([]byte, error) {
	if err := ValidateStartChallengeNotificationContactVerificationRequest(value); err != nil {
		return nil, err
	}
	return json.Marshal(struct {
		Email               string `json:"email"`
		RequestID           string `json:"requestId"`
		ChallengeCredential string `json:"challengeCredential"`
	}{value.Email, value.RequestID, value.ChallengeCredential.reveal()})
}

func (value *ConfirmChallengeNotificationContactVerificationRequest) UnmarshalJSON(source []byte) error {
	type wire ConfirmChallengeNotificationContactVerificationRequest
	var decoded wire
	if value == nil || contractjson.DecodeObjectBytes(source, MaxRequestBytes, &decoded) != nil ||
		ValidateConfirmChallengeNotificationContactVerificationRequest(ConfirmChallengeNotificationContactVerificationRequest(decoded)) != nil {
		return contractjson.ErrInvalidDocument
	}
	*value = ConfirmChallengeNotificationContactVerificationRequest(decoded)
	return nil
}

func EncodeConfirmChallengeNotificationContactVerificationRequest(value ConfirmChallengeNotificationContactVerificationRequest) ([]byte, error) {
	if err := ValidateConfirmChallengeNotificationContactVerificationRequest(value); err != nil {
		return nil, err
	}
	return json.Marshal(struct {
		Code                string `json:"code"`
		RequestID           string `json:"requestId"`
		ChallengeCredential string `json:"challengeCredential"`
	}{value.Code.reveal(), value.RequestID, value.ChallengeCredential.reveal()})
}

func (value *VerifyAuthenticationChallengeRequest) UnmarshalJSON(source []byte) error {
	type wire VerifyAuthenticationChallengeRequest
	var decoded wire
	if value == nil || contractjson.DecodeObjectBytes(source, MaxRequestBytes, &decoded) != nil ||
		ValidateVerifyAuthenticationChallengeRequest(VerifyAuthenticationChallengeRequest(decoded)) != nil {
		return contractjson.ErrInvalidDocument
	}
	*value = VerifyAuthenticationChallengeRequest(decoded)
	return nil
}

func EncodeVerifyAuthenticationChallengeRequest(value VerifyAuthenticationChallengeRequest) ([]byte, error) {
	if err := ValidateVerifyAuthenticationChallengeRequest(value); err != nil {
		return nil, err
	}
	return json.Marshal(struct {
		RequestID           string `json:"requestId"`
		ChallengeCredential string `json:"challengeCredential"`
		Code                string `json:"code"`
	}{value.RequestID, value.ChallengeCredential.reveal(), value.Code.reveal()})
}

func (value *ChallengePasswordChangeRequest) UnmarshalJSON(source []byte) error {
	type wire ChallengePasswordChangeRequest
	var decoded wire
	if value == nil || contractjson.DecodeObjectBytes(source, MaxRequestBytes, &decoded) != nil || ValidateChallengePasswordChangeRequest(ChallengePasswordChangeRequest(decoded)) != nil {
		return contractjson.ErrInvalidDocument
	}
	*value = ChallengePasswordChangeRequest(decoded)
	return nil
}

func EncodeChallengePasswordChangeRequest(value ChallengePasswordChangeRequest) ([]byte, error) {
	if err := ValidateChallengePasswordChangeRequest(value); err != nil {
		return nil, err
	}
	return json.Marshal(struct {
		RequestID           string `json:"requestId"`
		ChallengeCredential string `json:"challengeCredential"`
		NewPassword         string `json:"newPassword"`
	}{value.RequestID, value.ChallengeCredential.reveal(), value.NewPassword.reveal()})
}

func (value *ChallengePasswordChangeResponse) UnmarshalJSON(source []byte) error {
	type wire ChallengePasswordChangeResponse
	var decoded wire
	if value == nil || contractjson.DecodeObjectBytes(source, MaxRequestBytes, &decoded) != nil || ValidateChallengePasswordChangeResponse(ChallengePasswordChangeResponse(decoded)) != nil {
		return contractjson.ErrInvalidDocument
	}
	*value = ChallengePasswordChangeResponse(decoded)
	return nil
}

func (value *StartTOTPEnrollmentRequest) UnmarshalJSON(source []byte) error {
	type wire StartTOTPEnrollmentRequest
	var decoded wire
	if value == nil || contractjson.DecodeObjectBytes(source, MaxRequestBytes, &decoded) != nil || ValidateStartTOTPEnrollmentRequest(StartTOTPEnrollmentRequest(decoded)) != nil {
		return contractjson.ErrInvalidDocument
	}
	*value = StartTOTPEnrollmentRequest(decoded)
	return nil
}

func EncodeStartTOTPEnrollmentRequest(value StartTOTPEnrollmentRequest) ([]byte, error) {
	if err := ValidateStartTOTPEnrollmentRequest(value); err != nil {
		return nil, err
	}
	return json.Marshal(struct {
		RequestID              string `json:"requestId"`
		Password               string `json:"password"`
		ExpectedFactorRevision uint64 `json:"expectedFactorRevision"`
	}{value.RequestID, value.Password.reveal(), value.ExpectedFactorRevision})
}

func (value *ConfirmTOTPEnrollmentRequest) UnmarshalJSON(source []byte) error {
	type wire ConfirmTOTPEnrollmentRequest
	var decoded wire
	if value == nil || contractjson.DecodeObjectBytes(source, MaxRequestBytes, &decoded) != nil || ValidateConfirmTOTPEnrollmentRequest(ConfirmTOTPEnrollmentRequest(decoded)) != nil {
		return contractjson.ErrInvalidDocument
	}
	*value = ConfirmTOTPEnrollmentRequest(decoded)
	return nil
}

func EncodeConfirmTOTPEnrollmentRequest(value ConfirmTOTPEnrollmentRequest) ([]byte, error) {
	if err := ValidateConfirmTOTPEnrollmentRequest(value); err != nil {
		return nil, err
	}
	return json.Marshal(struct {
		RequestID string `json:"requestId"`
		Code      string `json:"code"`
	}{value.RequestID, value.Code.reveal()})
}

func (StartTOTPEnrollmentResponse) MarshalJSON() ([]byte, error) { return nil, ErrSecretSerialization }
func (ConfirmTOTPEnrollmentResponse) MarshalJSON() ([]byte, error) {
	return nil, ErrSecretSerialization
}

func (value *StartTOTPEnrollmentResponse) UnmarshalJSON(source []byte) error {
	type wire StartTOTPEnrollmentResponse
	var decoded wire
	if value == nil || contractjson.DecodeObjectBytes(source, MaxRequestBytes, &decoded) != nil || ValidateStartTOTPEnrollmentResponse(StartTOTPEnrollmentResponse(decoded)) != nil {
		return contractjson.ErrInvalidDocument
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(source, &fields) != nil {
		return contractjson.ErrInvalidDocument
	}
	_, provisioning := fields["provisioning"]
	if provisioning != (decoded.Outcome == "APPLIED") {
		return contractjson.ErrInvalidDocument
	}
	*value = StartTOTPEnrollmentResponse(decoded)
	return nil
}

func EncodeStartTOTPEnrollmentResponse(value StartTOTPEnrollmentResponse) ([]byte, error) {
	if err := ValidateStartTOTPEnrollmentResponse(value); err != nil {
		return nil, err
	}
	type provisioningWire struct {
		Seed string `json:"seed"`
		URI  string `json:"uri"`
	}
	var provisioning *provisioningWire
	if value.Provisioning != nil {
		provisioning = &provisioningWire{value.Provisioning.Seed.reveal(), value.Provisioning.URI.reveal()}
	}
	return json.Marshal(struct {
		Outcome      string            `json:"outcome"`
		Enrollment   TOTPEnrollment    `json:"enrollment"`
		Provisioning *provisioningWire `json:"provisioning,omitempty"`
	}{value.Outcome, value.Enrollment, provisioning})
}

func (value *ConfirmTOTPEnrollmentResponse) UnmarshalJSON(source []byte) error {
	type wire ConfirmTOTPEnrollmentResponse
	var decoded wire
	if value == nil || contractjson.DecodeObjectBytes(source, MaxRequestBytes, &decoded) != nil || ValidateConfirmTOTPEnrollmentResponse(ConfirmTOTPEnrollmentResponse(decoded)) != nil {
		return contractjson.ErrInvalidDocument
	}
	*value = ConfirmTOTPEnrollmentResponse(decoded)
	return nil
}

func EncodeConfirmTOTPEnrollmentResponse(value ConfirmTOTPEnrollmentResponse) ([]byte, error) {
	if err := ValidateConfirmTOTPEnrollmentResponse(value); err != nil {
		return nil, err
	}
	codes := make([]string, len(value.RecoveryCodes))
	defer clear(codes)
	for i, code := range value.RecoveryCodes {
		codes[i] = code.reveal()
	}
	return json.Marshal(struct {
		Enrollment    TOTPEnrollment `json:"enrollment"`
		NextStep      string         `json:"nextStep"`
		RecoveryCodes []string       `json:"recoveryCodes"`
	}{value.Enrollment, value.NextStep, codes})
}

func (value *AuthenticatorRecovery) UnmarshalJSON(source []byte) error {
	type wire AuthenticatorRecovery
	var decoded wire
	if value == nil || contractjson.DecodeObjectBytes(source, MaxRequestBytes, &decoded) != nil || ValidateAuthenticatorRecovery(AuthenticatorRecovery(decoded)) != nil {
		return contractjson.ErrInvalidDocument
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(source, &fields) != nil {
		return contractjson.ErrInvalidDocument
	}
	_, completed := fields["completedAt"]
	if completed != (decoded.State != "STARTED") {
		return contractjson.ErrInvalidDocument
	}
	*value = AuthenticatorRecovery(decoded)
	return nil
}

func (value *StartAuthenticatorRecoveryRequest) UnmarshalJSON(source []byte) error {
	type wire StartAuthenticatorRecoveryRequest
	var decoded wire
	if value == nil || contractjson.DecodeObjectBytes(source, MaxRequestBytes, &decoded) != nil || ValidateStartAuthenticatorRecoveryRequest(StartAuthenticatorRecoveryRequest(decoded)) != nil {
		return contractjson.ErrInvalidDocument
	}
	*value = StartAuthenticatorRecoveryRequest(decoded)
	return nil
}

func EncodeStartAuthenticatorRecoveryRequest(value StartAuthenticatorRecoveryRequest) ([]byte, error) {
	if err := ValidateStartAuthenticatorRecoveryRequest(value); err != nil {
		return nil, err
	}
	return json.Marshal(struct {
		RequestID           string `json:"requestId"`
		ChallengeCredential string `json:"challengeCredential"`
		RecoveryCode        string `json:"recoveryCode"`
	}{value.RequestID, value.ChallengeCredential.reveal(), value.RecoveryCode.reveal()})
}

func (value *InspectAuthenticatorRecoveryRequest) UnmarshalJSON(source []byte) error {
	type wire InspectAuthenticatorRecoveryRequest
	var decoded wire
	if value == nil || contractjson.DecodeObjectBytes(source, MaxRequestBytes, &decoded) != nil || ValidateInspectAuthenticatorRecoveryRequest(InspectAuthenticatorRecoveryRequest(decoded)) != nil {
		return contractjson.ErrInvalidDocument
	}
	*value = InspectAuthenticatorRecoveryRequest(decoded)
	return nil
}

func EncodeInspectAuthenticatorRecoveryRequest(value InspectAuthenticatorRecoveryRequest) ([]byte, error) {
	if err := ValidateInspectAuthenticatorRecoveryRequest(value); err != nil {
		return nil, err
	}
	return json.Marshal(struct {
		RequestID           string `json:"requestId"`
		ChallengeCredential string `json:"challengeCredential"`
	}{value.RequestID, value.ChallengeCredential.reveal()})
}

func (StartAuthenticatorRecoveryResponse) MarshalJSON() ([]byte, error) {
	return nil, ErrSecretSerialization
}
func (ConfirmAuthenticatorRecoveryResponse) MarshalJSON() ([]byte, error) {
	return nil, ErrSecretSerialization
}

func (value *StartAuthenticatorRecoveryResponse) UnmarshalJSON(source []byte) error {
	type wire StartAuthenticatorRecoveryResponse
	var decoded wire
	if value == nil || contractjson.DecodeObjectBytes(source, MaxRequestBytes, &decoded) != nil || ValidateStartAuthenticatorRecoveryResponse(StartAuthenticatorRecoveryResponse(decoded)) != nil {
		return contractjson.ErrInvalidDocument
	}
	*value = StartAuthenticatorRecoveryResponse(decoded)
	return nil
}

func EncodeStartAuthenticatorRecoveryResponse(value StartAuthenticatorRecoveryResponse) ([]byte, error) {
	if err := ValidateStartAuthenticatorRecoveryResponse(value); err != nil {
		return nil, err
	}
	type provisioningWire struct {
		Seed string `json:"seed"`
		URI  string `json:"uri"`
	}
	return json.Marshal(struct {
		Recovery            AuthenticatorRecovery   `json:"recovery"`
		Challenge           AuthenticationChallenge `json:"challenge"`
		ChallengeCredential string                  `json:"challengeCredential"`
		Provisioning        provisioningWire        `json:"provisioning"`
	}{value.Recovery, value.Challenge, value.ChallengeCredential.reveal(), provisioningWire{value.Provisioning.Seed.reveal(), value.Provisioning.URI.reveal()}})
}

func (value *ConfirmAuthenticatorRecoveryResponse) UnmarshalJSON(source []byte) error {
	type wire ConfirmAuthenticatorRecoveryResponse
	var decoded wire
	if value == nil || contractjson.DecodeObjectBytes(source, MaxRequestBytes, &decoded) != nil || ValidateConfirmAuthenticatorRecoveryResponse(ConfirmAuthenticatorRecoveryResponse(decoded)) != nil {
		return contractjson.ErrInvalidDocument
	}
	*value = ConfirmAuthenticatorRecoveryResponse(decoded)
	return nil
}

func EncodeConfirmAuthenticatorRecoveryResponse(value ConfirmAuthenticatorRecoveryResponse) ([]byte, error) {
	if err := ValidateConfirmAuthenticatorRecoveryResponse(value); err != nil {
		return nil, err
	}
	codes := make([]string, len(value.RecoveryCodes))
	defer clear(codes)
	for i, code := range value.RecoveryCodes {
		codes[i] = code.reveal()
	}
	return json.Marshal(struct {
		Recovery      AuthenticatorRecovery `json:"recovery"`
		NextStep      string                `json:"nextStep"`
		RecoveryCodes []string              `json:"recoveryCodes"`
	}{value.Recovery, value.NextStep, codes})
}

func (value *AccountPasswordSettings) UnmarshalJSON(source []byte) error {
	if value == nil {
		return contractjson.ErrInvalidDocument
	}
	decoded, err := decodeAccountPasswordSettings(source, false)
	if err != nil {
		return err
	}
	*value = decoded
	return nil
}

// Only immutable settings completions and CONSUMED proofs may decode the
// exact six-field predecessor shape. No historical defaults are inferred.
func decodeAccountPasswordSettings(source []byte, historical bool) (AccountPasswordSettings, error) {
	var decoded struct {
		MinimumLength    *int                `json:"minimumLength"`
		RequireLowercase *bool               `json:"requireLowercase"`
		RequireUppercase *bool               `json:"requireUppercase"`
		RequireDigit     *bool               `json:"requireDigit"`
		RequireSymbol    *bool               `json:"requireSymbol"`
		HistoryCount     *int                `json:"historyCount"`
		MaxAgeDays       *int                `json:"maxAgeDays"`
		ExpiryMode       *PasswordExpiryMode `json:"expiryMode"`
	}
	if contractjson.DecodeObjectBytes(source, MaxRequestBytes, &decoded) != nil ||
		decoded.MinimumLength == nil || decoded.RequireLowercase == nil || decoded.RequireUppercase == nil ||
		decoded.RequireDigit == nil || decoded.RequireSymbol == nil || decoded.HistoryCount == nil {
		return AccountPasswordSettings{}, contractjson.ErrInvalidDocument
	}
	result := AccountPasswordSettings{MinimumLength: *decoded.MinimumLength, RequireLowercase: *decoded.RequireLowercase,
		RequireUppercase: *decoded.RequireUppercase, RequireDigit: *decoded.RequireDigit, RequireSymbol: *decoded.RequireSymbol,
		HistoryCount: *decoded.HistoryCount}
	if decoded.MaxAgeDays != nil && decoded.ExpiryMode != nil {
		result.MaxAgeDays, result.ExpiryMode = *decoded.MaxAgeDays, *decoded.ExpiryMode
		// Even historical records cannot represent an explicitly empty mode.
		if ValidateAccountPasswordSettings(result) != nil {
			return AccountPasswordSettings{}, contractjson.ErrInvalidDocument
		}
	} else {
		var fields map[string]json.RawMessage
		if !historical || json.Unmarshal(source, &fields) != nil || fields["maxAgeDays"] != nil || fields["expiryMode"] != nil {
			return AccountPasswordSettings{}, contractjson.ErrInvalidDocument
		}
	}
	if validateAccountPasswordSettings(result, historical) != nil {
		return AccountPasswordSettings{}, contractjson.ErrInvalidDocument
	}
	return result, nil
}

func (value AccountPasswordSettings) MarshalJSON() ([]byte, error) {
	if validateAccountPasswordSettings(value, true) != nil {
		return nil, contractjson.ErrInvalidDocument
	}
	var days *int
	if value.ExpiryMode != "" {
		days = &value.MaxAgeDays
	}
	// Preserve original history without manufacturing expiry fields. Current
	// values always emit both, including explicit zero (disabled).
	return json.Marshal(struct {
		MinimumLength    int                `json:"minimumLength"`
		RequireLowercase bool               `json:"requireLowercase"`
		RequireUppercase bool               `json:"requireUppercase"`
		RequireDigit     bool               `json:"requireDigit"`
		RequireSymbol    bool               `json:"requireSymbol"`
		HistoryCount     int                `json:"historyCount"`
		MaxAgeDays       *int               `json:"maxAgeDays,omitempty"`
		ExpiryMode       PasswordExpiryMode `json:"expiryMode,omitempty"`
	}{value.MinimumLength, value.RequireLowercase, value.RequireUppercase, value.RequireDigit, value.RequireSymbol, value.HistoryCount, days, value.ExpiryMode})
}

func (value *AccountMFASettings) UnmarshalJSON(source []byte) error {
	var decoded struct {
		RequiredForUsers *bool `json:"requiredForUsers"`
	}
	if value == nil || contractjson.DecodeObjectBytes(source, MaxRequestBytes, &decoded) != nil || decoded.RequiredForUsers == nil {
		return contractjson.ErrInvalidDocument
	}
	*value = AccountMFASettings{RequiredForUsers: *decoded.RequiredForUsers}
	return nil
}

func (value *AccountSessionSettings) UnmarshalJSON(source []byte) error {
	var decoded struct {
		IdleTimeoutMinutes *int `json:"idleTimeoutMinutes"`
	}
	if value == nil || contractjson.DecodeObjectBytes(source, MaxRequestBytes, &decoded) != nil || decoded.IdleTimeoutMinutes == nil {
		return contractjson.ErrInvalidDocument
	}
	result := AccountSessionSettings{IdleTimeoutMinutes: *decoded.IdleTimeoutMinutes}
	if ValidateAccountSessionSettings(result) != nil {
		return contractjson.ErrInvalidDocument
	}
	*value = result
	return nil
}

func (value *AccountSecuritySettings) UnmarshalJSON(source []byte) error {
	if value == nil {
		return contractjson.ErrInvalidDocument
	}
	decoded, err := decodeAccountSecuritySettings(source, false)
	if err != nil {
		return err
	}
	*value = decoded
	return nil
}

func decodeAccountSecuritySettings(source []byte, historical bool) (AccountSecuritySettings, error) {
	var decoded struct {
		APIVersion      string              `json:"apiVersion"`
		Kind            string              `json:"kind"`
		AccountID       AccountID           `json:"accountId"`
		ResourceVersion uint64              `json:"resourceVersion"`
		MFA             *AccountMFASettings `json:"mfa"`
		Password        json.RawMessage     `json:"password"`
		Session         json.RawMessage     `json:"session"`
		UpdatedAt       time.Time           `json:"updatedAt"`
	}
	if contractjson.DecodeObjectBytes(source, MaxRequestBytes, &decoded) != nil || decoded.MFA == nil {
		return AccountSecuritySettings{}, contractjson.ErrInvalidDocument
	}
	result := AccountSecuritySettings{APIVersion: decoded.APIVersion, Kind: decoded.Kind, AccountID: decoded.AccountID,
		ResourceVersion: decoded.ResourceVersion, MFA: *decoded.MFA, UpdatedAt: decoded.UpdatedAt}
	if decoded.Password != nil {
		password, err := decodeAccountPasswordSettings(decoded.Password, historical)
		if err != nil {
			return AccountSecuritySettings{}, err
		}
		result.Password = &password
	}
	if decoded.Session != nil {
		var session AccountSessionSettings
		if contractjson.DecodeObjectBytes(decoded.Session, MaxRequestBytes, &session) != nil || ValidateAccountSessionSettings(session) != nil {
			return AccountSecuritySettings{}, contractjson.ErrInvalidDocument
		}
		result.Session = &session
	}
	if validateAccountSecuritySettings(result, historical) != nil {
		return AccountSecuritySettings{}, contractjson.ErrInvalidDocument
	}
	return result, nil
}

func (value *SecuritySettingsUpdateIntent) UnmarshalJSON(source []byte) error {
	if value == nil {
		return contractjson.ErrInvalidDocument
	}
	decoded, err := decodeSecuritySettingsIntent(source, false)
	if err != nil {
		return err
	}
	*value = decoded
	return nil
}

func decodeSecuritySettingsIntent(source []byte, historical bool) (SecuritySettingsUpdateIntent, error) {
	var decoded struct {
		ExpectedResourceVersion uint64              `json:"expectedResourceVersion"`
		MFA                     *AccountMFASettings `json:"mfa"`
		Password                json.RawMessage     `json:"password"`
		Session                 json.RawMessage     `json:"session"`
	}
	if contractjson.DecodeObjectBytes(source, MaxRequestBytes, &decoded) != nil || decoded.MFA == nil {
		return SecuritySettingsUpdateIntent{}, contractjson.ErrInvalidDocument
	}
	result := SecuritySettingsUpdateIntent{ExpectedResourceVersion: decoded.ExpectedResourceVersion, MFA: *decoded.MFA}
	if decoded.Password != nil {
		password, err := decodeAccountPasswordSettings(decoded.Password, historical)
		if err != nil {
			return SecuritySettingsUpdateIntent{}, err
		}
		result.Password = &password
	}
	if decoded.Session != nil {
		var session AccountSessionSettings
		if contractjson.DecodeObjectBytes(decoded.Session, MaxRequestBytes, &session) != nil || ValidateAccountSessionSettings(session) != nil {
			return SecuritySettingsUpdateIntent{}, contractjson.ErrInvalidDocument
		}
		result.Session = &session
	}
	if validateSecuritySettingsUpdateIntent(result, historical) != nil {
		return SecuritySettingsUpdateIntent{}, contractjson.ErrInvalidDocument
	}
	return result, nil
}

func (value *UpdateAccountSecuritySettingsRequest) UnmarshalJSON(source []byte) error {
	type wire UpdateAccountSecuritySettingsRequest
	var decoded wire
	var fields map[string]json.RawMessage
	if value == nil || contractjson.DecodeObjectBytes(source, MaxRequestBytes, &decoded) != nil ||
		ValidateUpdateAccountSecuritySettingsRequest(UpdateAccountSecuritySettingsRequest(decoded)) != nil || json.Unmarshal(source, &fields) != nil || fields["mfa"] == nil {
		return contractjson.ErrInvalidDocument
	}
	*value = UpdateAccountSecuritySettingsRequest(decoded)
	return nil
}

func (value *AccountSecuritySettingsChange) UnmarshalJSON(source []byte) error {
	// Only this immutable completion can carry the actual pre-password shape.
	// It must never pass the current-settings decoder or acquire default rules.
	var decoded struct {
		APIVersion              string          `json:"apiVersion"`
		Kind                    string          `json:"kind"`
		RequestID               string          `json:"requestId"`
		ExpectedResourceVersion uint64          `json:"expectedResourceVersion"`
		Settings                json.RawMessage `json:"settings"`
		CallerSessionEnded      *bool           `json:"callerSessionEnded"`
	}
	if value == nil || contractjson.DecodeObjectBytes(source, MaxRequestBytes, &decoded) != nil || decoded.CallerSessionEnded == nil {
		return contractjson.ErrInvalidDocument
	}
	settings, err := decodeAccountSecuritySettings(decoded.Settings, true)
	result := AccountSecuritySettingsChange{APIVersion: decoded.APIVersion, Kind: decoded.Kind, RequestID: decoded.RequestID,
		ExpectedResourceVersion: decoded.ExpectedResourceVersion, Settings: settings, CallerSessionEnded: *decoded.CallerSessionEnded}
	if err != nil || ValidateAccountSecuritySettingsChange(result) != nil {
		return contractjson.ErrInvalidDocument
	}
	*value = result
	return nil
}

func (value *UpdateAccountSecuritySettingsResponse) UnmarshalJSON(source []byte) error {
	type wire UpdateAccountSecuritySettingsResponse
	var decoded wire
	if value == nil || contractjson.DecodeObjectBytes(source, MaxRequestBytes, &decoded) != nil ||
		ValidateUpdateAccountSecuritySettingsResponse(UpdateAccountSecuritySettingsResponse(decoded)) != nil {
		return contractjson.ErrInvalidDocument
	}
	*value = UpdateAccountSecuritySettingsResponse(decoded)
	return nil
}

func (value *StepUp) UnmarshalJSON(source []byte) error {
	var decoded struct {
		APIVersion             string          `json:"apiVersion"`
		Kind                   string          `json:"kind"`
		ID                     string          `json:"id"`
		RequestID              string          `json:"requestId"`
		Operation              StepUpOperation `json:"operation"`
		ExpectedFactorRevision uint64          `json:"expectedFactorRevision"`
		SecuritySettings       json.RawMessage `json:"securitySettings,omitempty"`
		State                  string          `json:"state"`
		CreatedAt              time.Time       `json:"createdAt"`
		ExpiresAt              time.Time       `json:"expiresAt"`
		ProvedAt               *time.Time      `json:"provedAt,omitempty"`
		ConsumedAt             *time.Time      `json:"consumedAt,omitempty"`
	}
	if value == nil || contractjson.DecodeObjectBytes(source, MaxRequestBytes, &decoded) != nil {
		return contractjson.ErrInvalidDocument
	}
	result := StepUp{APIVersion: decoded.APIVersion, Kind: decoded.Kind, ID: decoded.ID, RequestID: decoded.RequestID,
		Operation: decoded.Operation, ExpectedFactorRevision: decoded.ExpectedFactorRevision, State: decoded.State,
		CreatedAt: decoded.CreatedAt, ExpiresAt: decoded.ExpiresAt, ProvedAt: decoded.ProvedAt, ConsumedAt: decoded.ConsumedAt}
	if decoded.SecuritySettings != nil {
		intent, err := decodeSecuritySettingsIntent(decoded.SecuritySettings, decoded.State == "CONSUMED")
		if err != nil {
			return contractjson.ErrInvalidDocument
		}
		result.SecuritySettings = &intent
	}
	if ValidateStepUp(result) != nil {
		return contractjson.ErrInvalidDocument
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(source, &fields) != nil {
		return contractjson.ErrInvalidDocument
	}
	_, proved := fields["provedAt"]
	_, consumed := fields["consumedAt"]
	_, settings := fields["securitySettings"]
	if proved != (result.ProvedAt != nil) || consumed != (result.ConsumedAt != nil) || settings != (result.SecuritySettings != nil) {
		return contractjson.ErrInvalidDocument
	}
	*value = result
	return nil
}

func (value *StartStepUpRequest) UnmarshalJSON(source []byte) error {
	type wire StartStepUpRequest
	var decoded wire
	if value == nil || contractjson.DecodeObjectBytes(source, MaxRequestBytes, &decoded) != nil || ValidateStartStepUpRequest(StartStepUpRequest(decoded)) != nil {
		return contractjson.ErrInvalidDocument
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(source, &fields) != nil {
		return contractjson.ErrInvalidDocument
	}
	if _, present := fields["securitySettings"]; present != (decoded.SecuritySettings != nil) {
		return contractjson.ErrInvalidDocument
	}
	*value = StartStepUpRequest(decoded)
	return nil
}

func (value *VerifyStepUpRequest) UnmarshalJSON(source []byte) error {
	type wire VerifyStepUpRequest
	var decoded wire
	if value == nil || contractjson.DecodeObjectBytes(source, MaxRequestBytes, &decoded) != nil || ValidateVerifyStepUpRequest(VerifyStepUpRequest(decoded)) != nil {
		return contractjson.ErrInvalidDocument
	}
	*value = VerifyStepUpRequest(decoded)
	return nil
}

func EncodeVerifyStepUpRequest(value VerifyStepUpRequest) ([]byte, error) {
	if err := ValidateVerifyStepUpRequest(value); err != nil {
		return nil, err
	}
	return json.Marshal(struct {
		RequestID string `json:"requestId"`
		Password  string `json:"password"`
		Code      string `json:"code"`
	}{value.RequestID, value.Password.reveal(), value.Code.reveal()})
}

func (value *StartTOTPReplacementRequest) UnmarshalJSON(source []byte) error {
	type wire StartTOTPReplacementRequest
	var decoded wire
	if value == nil || contractjson.DecodeObjectBytes(source, MaxRequestBytes, &decoded) != nil || ValidateStartTOTPReplacementRequest(StartTOTPReplacementRequest(decoded)) != nil {
		return contractjson.ErrInvalidDocument
	}
	*value = StartTOTPReplacementRequest(decoded)
	return nil
}

func (value *RemoveTOTPRequest) UnmarshalJSON(source []byte) error {
	type wire RemoveTOTPRequest
	var decoded wire
	if value == nil || contractjson.DecodeObjectBytes(source, MaxRequestBytes, &decoded) != nil || ValidateRemoveTOTPRequest(RemoveTOTPRequest(decoded)) != nil {
		return contractjson.ErrInvalidDocument
	}
	*value = RemoveTOTPRequest(decoded)
	return nil
}

func (value *AuthenticatorRemoval) UnmarshalJSON(source []byte) error {
	type wire AuthenticatorRemoval
	var decoded wire
	if value == nil || contractjson.DecodeObjectBytes(source, MaxRequestBytes, &decoded) != nil || ValidateAuthenticatorRemoval(AuthenticatorRemoval(decoded)) != nil {
		return contractjson.ErrInvalidDocument
	}
	*value = AuthenticatorRemoval(decoded)
	return nil
}

func (value *RemoveTOTPResponse) UnmarshalJSON(source []byte) error {
	type wire RemoveTOTPResponse
	var decoded wire
	if value == nil || contractjson.DecodeObjectBytes(source, MaxRequestBytes, &decoded) != nil || ValidateRemoveTOTPResponse(RemoveTOTPResponse(decoded)) != nil {
		return contractjson.ErrInvalidDocument
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(source, &fields) != nil {
		return contractjson.ErrInvalidDocument
	}
	// Even null or an empty instruction is not part of a historical read.
	if _, present := fields["nextStep"]; present != (decoded.Outcome == "APPLIED") {
		return contractjson.ErrInvalidDocument
	}
	*value = RemoveTOTPResponse(decoded)
	return nil
}

func (value *RegenerateRecoveryCodesRequest) UnmarshalJSON(source []byte) error {
	type wire RegenerateRecoveryCodesRequest
	var decoded wire
	if value == nil || contractjson.DecodeObjectBytes(source, MaxRequestBytes, &decoded) != nil || ValidateRegenerateRecoveryCodesRequest(RegenerateRecoveryCodesRequest(decoded)) != nil {
		return contractjson.ErrInvalidDocument
	}
	*value = RegenerateRecoveryCodesRequest(decoded)
	return nil
}

func (value *RecoveryCodeRegeneration) UnmarshalJSON(source []byte) error {
	type wire RecoveryCodeRegeneration
	var decoded wire
	if value == nil || contractjson.DecodeObjectBytes(source, MaxRequestBytes, &decoded) != nil || ValidateRecoveryCodeRegeneration(RecoveryCodeRegeneration(decoded)) != nil {
		return contractjson.ErrInvalidDocument
	}
	*value = RecoveryCodeRegeneration(decoded)
	return nil
}

func (RegenerateRecoveryCodesResponse) MarshalJSON() ([]byte, error) {
	return nil, ErrSecretSerialization
}

func (value *RegenerateRecoveryCodesResponse) UnmarshalJSON(source []byte) error {
	type wire RegenerateRecoveryCodesResponse
	var decoded wire
	if value == nil || contractjson.DecodeObjectBytes(source, MaxRequestBytes, &decoded) != nil || ValidateRegenerateRecoveryCodesResponse(RegenerateRecoveryCodesResponse(decoded)) != nil {
		return contractjson.ErrInvalidDocument
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(source, &fields) != nil {
		return contractjson.ErrInvalidDocument
	}
	_, codes := fields["recoveryCodes"]
	if codes != (decoded.Outcome == "APPLIED") {
		return contractjson.ErrInvalidDocument
	}
	*value = RegenerateRecoveryCodesResponse(decoded)
	return nil
}

func EncodeRegenerateRecoveryCodesResponse(value RegenerateRecoveryCodesResponse) ([]byte, error) {
	if err := ValidateRegenerateRecoveryCodesResponse(value); err != nil {
		return nil, err
	}
	var codes []string
	if value.Outcome == "APPLIED" {
		codes = make([]string, len(value.RecoveryCodes))
		defer clear(codes)
		for index, code := range value.RecoveryCodes {
			codes[index] = code.reveal()
		}
	}
	return json.Marshal(struct {
		Outcome      string                   `json:"outcome"`
		Regeneration RecoveryCodeRegeneration `json:"regeneration"`
		Codes        []string                 `json:"recoveryCodes,omitempty"`
	}{value.Outcome, value.Regeneration, codes})
}

func (subject *Subject) UnmarshalJSON(source []byte) error {
	type wire Subject
	var decoded wire
	if err := contractjson.DecodeObjectBytes(source, MaxRequestBytes, &decoded); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(source, &fields) != nil {
		return contractjson.ErrInvalidDocument
	}
	_, hasRoleSession := fields["roleSession"]
	_, hasAccessKey := fields["accessKeyId"]
	if (decoded.Type == SubjectRole) != hasRoleSession || hasAccessKey && decoded.AccessKeyID == "" || ValidateSubject(Subject(decoded)) != nil {
		return contractjson.ErrInvalidDocument
	}
	*subject = Subject(decoded)
	return nil
}

func (context *AuthorizationNetworkContext) UnmarshalJSON(source []byte) error {
	type wire AuthorizationNetworkContext
	var decoded wire
	if context == nil || contractjson.DecodeObjectBytes(source, MaxRequestBytes, &decoded) != nil ||
		ValidateAuthorizationNetworkContext(AuthorizationNetworkContext(decoded)) != nil {
		return contractjson.ErrInvalidDocument
	}
	*context = AuthorizationNetworkContext(decoded)
	return nil
}

func (request *AuthorizationRequest) UnmarshalJSON(source []byte) error {
	type wire AuthorizationRequest
	var decoded wire
	if err := contractjson.DecodeObjectBytes(source, MaxRequestBytes, &decoded); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(source, &fields) != nil || checkOptionalNetworkContextEncoding(fields, decoded.NetworkContext) != nil ||
		checkAuthorizationTargetEncoding(source, decoded.ResourceMode) != nil {
		return contractjson.ErrInvalidDocument
	}
	*request = AuthorizationRequest(decoded)
	return nil
}

func (decision *AuthorizationDecision) UnmarshalJSON(source []byte) error {
	type wire AuthorizationDecision
	var decoded wire
	if err := contractjson.DecodeObjectBytes(source, MaxRequestBytes, &decoded); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(source, &fields) != nil {
		return contractjson.ErrInvalidDocument
	}
	current := false
	for _, key := range []string{"profile", "resourceMode", "collectionUsage", "networkContext", "correlationId"} {
		if _, exists := fields[key]; exists {
			current = true
		}
	}
	// This preserves only historical syntax. It does not establish legacy row
	// eligibility; current consumers validate the mandatory full binding.
	if current {
		if checkOptionalNetworkContextEncoding(fields, decoded.NetworkContext) != nil || checkAuthorizationTargetEncoding(source, decoded.ResourceMode) != nil || decoded.Profile == nil || decoded.CorrelationID == "" {
			return contractjson.ErrInvalidDocument
		}
	}
	*decision = AuthorizationDecision(decoded)
	return nil
}

func checkOptionalNetworkContextEncoding(fields map[string]json.RawMessage, value *AuthorizationNetworkContext) error {
	encoded, present := fields["networkContext"]
	if !present {
		if value != nil {
			return contractjson.ErrInvalidDocument
		}
		return nil
	}
	if value == nil || bytes.Equal(bytes.TrimSpace(encoded), []byte("null")) {
		return contractjson.ErrInvalidDocument
	}
	return nil
}

func checkAuthorizationTargetEncoding(source []byte, mode AuthorizationResourceMode) error {
	var fields map[string]json.RawMessage
	if json.Unmarshal(source, &fields) != nil {
		return contractjson.ErrInvalidDocument
	}
	for _, key := range []string{"profile", "resourceMode", "correlationId"} {
		if value, exists := fields[key]; !exists || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return contractjson.ErrInvalidDocument
		}
	}
	usage, exists := fields["collectionUsage"]
	switch mode {
	case AuthorizationResourceInstance:
		if exists {
			return contractjson.ErrInvalidDocument
		}
	case AuthorizationResourceCollection:
		var value AuthorizationCollectionUsage
		if !exists || json.Unmarshal(usage, &value) != nil || (value != AuthorizationCollectionCreate && value != AuthorizationCollectionList) {
			return contractjson.ErrInvalidDocument
		}
	default:
		return contractjson.ErrInvalidDocument
	}
	return nil
}

func (value *UserPermissionBoundary) UnmarshalJSON(source []byte) error {
	type wire UserPermissionBoundary
	var decoded wire
	if err := contractjson.DecodeObjectBytes(source, MaxRequestBytes, &decoded); err != nil {
		return err
	}
	var fields struct {
		Policy json.RawMessage `json:"policy"`
	}
	if err := json.Unmarshal(source, &fields); err != nil || len(fields.Policy) == 0 {
		return contractjson.ErrInvalidDocument
	}
	result := UserPermissionBoundary(decoded)
	if err := ValidateUserPermissionBoundary(result); err != nil {
		return err
	}
	*value = result
	return nil
}

func (request *ChangePasswordRequest) UnmarshalJSON(source []byte) error {
	// A missing policy defaults to true; explicit null is not a boolean choice.
	// Reuse the strict decoder rather than bypassing its field/duplicate checks.
	type wire ChangePasswordRequest
	var decoded wire
	if err := contractjson.DecodeObjectBytes(source, MaxRequestBytes, &decoded); err != nil {
		return err
	}
	var policy struct {
		Value json.RawMessage `json:"revokeOtherSessions"`
	}
	if err := json.Unmarshal(source, &policy); err != nil || bytes.Equal(bytes.TrimSpace(policy.Value), []byte("null")) {
		return contractjson.ErrInvalidDocument
	}
	*request = ChangePasswordRequest(decoded)
	return nil
}

func DecodeBootstrapDocument(reader io.Reader) (BootstrapDocument, error) {
	var document BootstrapDocument
	if err := contractjson.DecodeObject(reader, MaxBootstrapBytes, &document); err != nil {
		return BootstrapDocument{}, err
	}
	if err := ValidateBootstrapDocument(document); err != nil {
		return BootstrapDocument{}, err
	}
	return document, nil
}

// EncodeBootstrapDocument is the only contract encoder that intentionally
// emits bootstrap credential material.
func EncodeBootstrapDocument(document BootstrapDocument) ([]byte, error) {
	if err := ValidateBootstrapDocument(document); err != nil {
		return nil, err
	}
	type administratorWire struct {
		ID          PrincipalID `json:"id"`
		LoginName   string      `json:"loginName"`
		DisplayName string      `json:"displayName"`
		Password    string      `json:"password"`
	}
	type serviceWire struct {
		Purpose     ServicePurpose `json:"purpose"`
		PrincipalID PrincipalID    `json:"principalId"`
		Credential  string         `json:"credential"`
	}
	services := make([]serviceWire, len(document.Services))
	for index, service := range document.Services {
		services[index] = serviceWire{
			Purpose: service.Purpose, PrincipalID: service.PrincipalID,
			Credential: service.Credential.reveal(),
		}
	}
	wire := struct {
		APIVersion     string              `json:"apiVersion"`
		Kind           string              `json:"kind"`
		InstallationID string              `json:"installationId"`
		Organization   InitialOrganization `json:"organization"`
		Administrator  administratorWire   `json:"administrator"`
		Services       []serviceWire       `json:"services"`
	}{
		APIVersion: document.APIVersion, Kind: document.Kind,
		InstallationID: document.InstallationID,
		Organization:   document.Organization,
		Administrator: administratorWire{
			ID: document.Administrator.ID, LoginName: document.Administrator.LoginName,
			DisplayName: document.Administrator.DisplayName,
			Password:    document.Administrator.Password.reveal(),
		},
		Services: services,
	}
	encoded, err := json.Marshal(wire)
	if err != nil {
		return nil, ErrEncodingFailed
	}
	return encoded, nil
}

func (LoginResponse) MarshalJSON() ([]byte, error) { return nil, ErrSecretSerialization }

func (value *LoginResponse) UnmarshalJSON(source []byte) error {
	var wire struct {
		Outcome             LoginOutcome             `json:"outcome"`
		Session             *Session                 `json:"session,omitempty"`
		Credential          Secret                   `json:"credential,omitempty"`
		MustChangePassword  *bool                    `json:"mustChangePassword,omitempty"`
		Challenge           *AuthenticationChallenge `json:"challenge,omitempty"`
		ChallengeCredential Secret                   `json:"challengeCredential,omitempty"`
		PasswordResetReason *PasswordResetReason     `json:"passwordResetReason,omitempty"`
	}
	if value == nil || contractjson.DecodeObjectBytes(source, MaxRequestBytes, &wire) != nil {
		return contractjson.ErrInvalidDocument
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(source, &fields) != nil {
		return contractjson.ErrInvalidDocument
	}
	result := LoginResponse{Outcome: wire.Outcome, Credential: wire.Credential,
		Challenge: wire.Challenge, ChallengeCredential: wire.ChallengeCredential}
	switch wire.Outcome {
	case LoginAuthenticated:
		if len(fields) != 4 || wire.Session == nil || wire.MustChangePassword == nil {
			return contractjson.ErrInvalidDocument
		}
		result.Session, result.MustChangePassword = *wire.Session, *wire.MustChangePassword
	case LoginChallengeRequired:
		// Presence is significant: even null/false/empty Session fields are not
		// legal in this branch. A challenge never silently becomes a Session.
		if len(fields) != 3 || wire.Session != nil || wire.MustChangePassword != nil {
			return contractjson.ErrInvalidDocument
		}
	case LoginAdminResetRequired:
		// Even null, false or empty credential fields are forbidden: this is a
		// terminal instruction, not a restricted authentication capability.
		if len(fields) != 2 || wire.PasswordResetReason == nil {
			return contractjson.ErrInvalidDocument
		}
		result.PasswordResetReason = *wire.PasswordResetReason
	default:
		return contractjson.ErrInvalidDocument
	}
	if ValidateLoginResponse(result) != nil {
		return contractjson.ErrInvalidDocument
	}
	*value = result
	return nil
}

// EncodeLoginResponse emits only the selected branch. A reset requirement has
// no credential, including an empty or null credential placeholder.
func EncodeLoginResponse(response LoginResponse) ([]byte, error) {
	if err := ValidateLoginResponse(response); err != nil {
		return nil, err
	}
	if response.Outcome == LoginAdminResetRequired {
		encoded, err := json.Marshal(struct {
			Outcome             LoginOutcome        `json:"outcome"`
			PasswordResetReason PasswordResetReason `json:"passwordResetReason"`
		}{response.Outcome, response.PasswordResetReason})
		if err != nil {
			return nil, ErrEncodingFailed
		}
		return encoded, nil
	}
	if response.Outcome == LoginChallengeRequired {
		encoded, err := json.Marshal(struct {
			Outcome             LoginOutcome             `json:"outcome"`
			Challenge           *AuthenticationChallenge `json:"challenge"`
			ChallengeCredential string                   `json:"challengeCredential"`
		}{response.Outcome, response.Challenge, response.ChallengeCredential.reveal()})
		if err != nil {
			return nil, ErrEncodingFailed
		}
		return encoded, nil
	}
	wire := struct {
		Outcome            LoginOutcome `json:"outcome"`
		Session            Session      `json:"session"`
		Credential         string       `json:"credential"`
		MustChangePassword bool         `json:"mustChangePassword"`
	}{
		Outcome:            response.Outcome,
		Session:            response.Session,
		Credential:         response.Credential.reveal(),
		MustChangePassword: response.MustChangePassword,
	}
	encoded, err := json.Marshal(wire)
	if err != nil {
		return nil, ErrEncodingFailed
	}
	return encoded, nil
}

func EncodeStartNotificationContactVerificationRequest(request StartNotificationContactVerificationRequest) ([]byte, error) {
	if err := ValidateStartNotificationContactVerificationRequest(request); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(struct {
		Email     string `json:"email"`
		Password  string `json:"password"`
		RequestID string `json:"requestId"`
	}{request.Email, request.Password.reveal(), request.RequestID})
	if err != nil {
		return nil, ErrEncodingFailed
	}
	return encoded, nil
}

func EncodeConfirmNotificationContactVerificationRequest(request ConfirmNotificationContactVerificationRequest) ([]byte, error) {
	if err := ValidateConfirmNotificationContactVerificationRequest(request); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(struct {
		Code      string `json:"code"`
		RequestID string `json:"requestId"`
	}{request.Code.reveal(), request.RequestID})
	if err != nil {
		return nil, ErrEncodingFailed
	}
	return encoded, nil
}

// EncodeAssumeRoleResponse is the sole role-credential response encoder.
// An equal replay carries only the original non-secret issuance record.
func EncodeAssumeRoleResponse(response AssumeRoleResponse) ([]byte, error) {
	if err := ValidateAssumeRoleResponse(response); err != nil {
		return nil, err
	}
	wire := struct {
		Outcome    string      `json:"outcome"`
		Session    RoleSession `json:"session"`
		Credential string      `json:"credential,omitempty"`
	}{response.Outcome, response.Session, response.Credential.reveal()}
	encoded, err := json.Marshal(wire)
	if err != nil {
		return nil, ErrEncodingFailed
	}
	return encoded, nil
}

// EncodeCreateAccessKeyResponse discloses a new Secret exactly in APPLIED.
// Receipt replay never emits a secret, ciphertext or replacement credential.
func EncodeCreateAccessKeyResponse(response CreateAccessKeyResponse) ([]byte, error) {
	if err := ValidateCreateAccessKeyResponse(response); err != nil {
		return nil, err
	}
	wire := struct {
		Outcome string    `json:"outcome"`
		Key     AccessKey `json:"key"`
		Secret  string    `json:"secret,omitempty"`
	}{response.Outcome, response.Key, response.Secret.reveal()}
	encoded, err := json.Marshal(wire)
	if err != nil {
		return nil, ErrEncodingFailed
	}
	return encoded, nil
}
