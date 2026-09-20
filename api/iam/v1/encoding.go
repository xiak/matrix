package iamv1

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"

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

func (value *StepUp) UnmarshalJSON(source []byte) error {
	type wire StepUp
	var decoded wire
	if value == nil || contractjson.DecodeObjectBytes(source, MaxRequestBytes, &decoded) != nil || ValidateStepUp(StepUp(decoded)) != nil {
		return contractjson.ErrInvalidDocument
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(source, &fields) != nil {
		return contractjson.ErrInvalidDocument
	}
	_, proved := fields["provedAt"]
	_, consumed := fields["consumedAt"]
	if proved != (decoded.ProvedAt != nil) || consumed != (decoded.ConsumedAt != nil) {
		return contractjson.ErrInvalidDocument
	}
	*value = StepUp(decoded)
	return nil
}

func (value *StartStepUpRequest) UnmarshalJSON(source []byte) error {
	type wire StartStepUpRequest
	var decoded wire
	if value == nil || contractjson.DecodeObjectBytes(source, MaxRequestBytes, &decoded) != nil || ValidateStartStepUpRequest(StartStepUpRequest(decoded)) != nil {
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

func (request *AuthorizationRequest) UnmarshalJSON(source []byte) error {
	type wire AuthorizationRequest
	var decoded wire
	if err := contractjson.DecodeObjectBytes(source, MaxRequestBytes, &decoded); err != nil {
		return err
	}
	if checkAuthorizationTargetEncoding(source, decoded.ResourceMode) != nil {
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
	for _, key := range []string{"profile", "resourceMode", "collectionUsage", "correlationId"} {
		if _, exists := fields[key]; exists {
			current = true
		}
	}
	// This preserves only historical syntax. It does not establish legacy row
	// eligibility; current consumers validate the mandatory full binding.
	if current {
		if checkAuthorizationTargetEncoding(source, decoded.ResourceMode) != nil || decoded.Profile == nil || decoded.CorrelationID == "" {
			return contractjson.ErrInvalidDocument
		}
	}
	*decision = AuthorizationDecision(decoded)
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
	default:
		return contractjson.ErrInvalidDocument
	}
	if ValidateLoginResponse(result) != nil {
		return contractjson.ErrInvalidDocument
	}
	*value = result
	return nil
}

// EncodeLoginResponse explicitly emits only the selected one-time credential.
func EncodeLoginResponse(response LoginResponse) ([]byte, error) {
	if err := ValidateLoginResponse(response); err != nil {
		return nil, err
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
