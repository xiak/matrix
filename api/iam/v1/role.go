package iamv1

import (
	"bytes"
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/xiak/matrix/api/contractjson"
)

type RoleID string
type RoleTrustVersionID string
type RoleSessionID string
type RoleStatus string
type RoleManagement string

const (
	RoleActive                        RoleStatus     = "ACTIVE"
	RoleDisabled                      RoleStatus     = "DISABLED"
	RoleCustomerManaged               RoleManagement = "CUSTOMER"
	DefaultRoleSessionDurationSeconds uint32         = 3600
	MinRoleSessionDurationSeconds     uint32         = 60
	MaxRoleSessionDurationSeconds     uint32         = 43200
	MaxRoleListBytes                  int64          = 4 * 1024 * 1024
	MaxRoleAccessBytes                int64          = 512 * 1024
	RoleDiscoveryPageSize                            = 20
	MaxAssumableRoleListBytes         int64          = 64 * 1024
)

// Tags are bounded literal metadata, never an authenticated condition source.
type RoleTag struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type Role struct {
	APIVersion                string             `json:"apiVersion"`
	Kind                      string             `json:"kind"`
	ID                        RoleID             `json:"id"`
	AccountID                 AccountID          `json:"accountId"`
	Name                      string             `json:"name"`
	Description               string             `json:"description"`
	Tags                      []RoleTag          `json:"tags"`
	Management                RoleManagement     `json:"management"`
	Status                    RoleStatus         `json:"status"`
	MaxSessionDurationSeconds uint32             `json:"maxSessionDurationSeconds"`
	ResourceVersion           uint64             `json:"resourceVersion"`
	CurrentTrustVersionID     RoleTrustVersionID `json:"currentTrustVersionId"`
	CreatedAt                 time.Time          `json:"createdAt"`
	UpdatedAt                 time.Time          `json:"updatedAt"`
}

// A directory row does not expand every trust document or policy attachment.
// Detail reads separately authorize the exact Role.
type RoleListing struct {
	Role         Role               `json:"role"`
	Capabilities []ActionCapability `json:"capabilities"`
}

type RoleList struct {
	APIVersion string        `json:"apiVersion"`
	Kind       string        `json:"kind"`
	AccountID  AccountID     `json:"accountId"`
	Items      []RoleListing `json:"items"`
	NextAfter  string        `json:"nextAfter,omitempty"`
}

type RoleAccess struct {
	Role              Role               `json:"role"`
	TrustVersion      RoleTrustVersion   `json:"trustVersion"`
	PolicyAttachments []PolicyAttachment `json:"policyAttachments"`
	Capabilities      []ActionCapability `json:"capabilities"`
}

type RoleTrustVersionList struct {
	APIVersion string             `json:"apiVersion"`
	Kind       string             `json:"kind"`
	AccountID  AccountID          `json:"accountId"`
	RoleID     RoleID             `json:"roleId"`
	Items      []RoleTrustVersion `json:"items"`
	NextAfter  string             `json:"nextAfter,omitempty"`
}

type CreateRoleRequest struct {
	Name                      string              `json:"name"`
	Description               string              `json:"description,omitempty"`
	Tags                      []RoleTag           `json:"tags"`
	MaxSessionDurationSeconds *uint32             `json:"maxSessionDurationSeconds,omitempty"`
	TrustPolicy               TrustPolicyDocument `json:"trustPolicy"`
	RequestID                 string              `json:"requestId"`
}

type UpdateRoleRequest struct {
	Name                      string    `json:"name"`
	Description               string    `json:"description"`
	Tags                      []RoleTag `json:"tags"`
	MaxSessionDurationSeconds uint32    `json:"maxSessionDurationSeconds"`
	ResourceVersion           uint64    `json:"resourceVersion"`
	RequestID                 string    `json:"requestId"`
}

type SetRoleStatusRequest struct {
	Status          RoleStatus `json:"status"`
	ResourceVersion uint64     `json:"resourceVersion"`
	RequestID       string     `json:"requestId"`
}

type SetRoleTrustPolicyRequest struct {
	Document        TrustPolicyDocument `json:"document"`
	ResourceVersion uint64              `json:"resourceVersion"`
	RequestID       string              `json:"requestId"`
}

type DeleteRoleRequest struct {
	ResourceVersion uint64 `json:"resourceVersion"`
	RequestID       string `json:"requestId"`
}

// AssumeRoleRequest contains intent, never authenticated identity or compiled
// authority. The caller selects a Role by path; the issuing transaction owns
// account, source session, generation, trust selection and policy compilation.
type AssumeRoleRequest struct {
	ResourceVersion uint64          `json:"resourceVersion"`
	DurationSeconds *uint32         `json:"durationSeconds,omitempty"`
	SessionPolicy   *PolicyDocument `json:"sessionPolicy,omitempty"`
	RequestID       string          `json:"requestId"`
}

// RoleSession is the non-secret issuance record, not a cached authorization.
// ACTIVE means not explicitly revoked; expiry and current source/role authority
// must still be checked for every protected request.
type RoleSession struct {
	APIVersion   string        `json:"apiVersion"`
	Kind         string        `json:"kind"`
	ID           RoleSessionID `json:"id"`
	AccountID    AccountID     `json:"accountId"`
	RoleID       RoleID        `json:"roleId"`
	SourceUserID PrincipalID   `json:"sourceUserId"`
	Status       SessionStatus `json:"status"`
	IssuedAt     time.Time     `json:"issuedAt"`
	ExpiresAt    time.Time     `json:"expiresAt"`
	RevokedAt    *time.Time    `json:"revokedAt,omitempty"`
}

// These display projections deliberately omit the Account root relationship,
// login-session lineage and role authorization evidence.
type RoleAccountDisplay struct {
	ID          AccountID `json:"id"`
	DisplayName string    `json:"displayName"`
}

type RoleDisplay struct {
	ID   RoleID `json:"id"`
	Name string `json:"name"`
}

type RoleSourceUserDisplay struct {
	ID          PrincipalID `json:"id"`
	LoginName   string      `json:"loginName"`
	DisplayName string      `json:"displayName"`
}

func ValidateRoleSourceUserDisplay(value RoleSourceUserDisplay) error {
	return errors.Join(ValidateID("sourceUser.id", string(value.ID)), validateLoginName(value.LoginName), validateText("sourceUser.displayName", value.DisplayName, 1, 128))
}

// CurrentRoleIdentity is a current authenticated projection, not the durable
// issuance receipt. A cached copy never establishes continuing authority.
type CurrentRoleIdentity struct {
	APIVersion string                `json:"apiVersion"`
	Kind       string                `json:"kind"`
	Session    RoleSession           `json:"session"`
	Account    RoleAccountDisplay    `json:"account"`
	Role       RoleDisplay           `json:"role"`
	SourceUser RoleSourceUserDisplay `json:"sourceUser"`
}

type AssumableRole struct {
	RoleID                    RoleID           `json:"roleId"`
	AccountID                 AccountID        `json:"accountId"`
	Name                      string           `json:"name"`
	Status                    RoleStatus       `json:"status"`
	MaxSessionDurationSeconds uint32           `json:"maxSessionDurationSeconds"`
	ResourceVersion           uint64           `json:"resourceVersion"`
	Capability                ActionCapability `json:"capability"`
}

// Items contains only eligible results from one bounded candidate window.
// Empty Items with NextAfter still means another window is available.
type AssumableRoleList struct {
	APIVersion   string          `json:"apiVersion"`
	Kind         string          `json:"kind"`
	AccountID    AccountID       `json:"accountId"`
	SourceUserID PrincipalID     `json:"sourceUserId"`
	Items        []AssumableRole `json:"items"`
	NextAfter    string          `json:"nextAfter,omitempty"`
}

func ValidateCurrentRoleIdentity(value CurrentRoleIdentity) error {
	if value.APIVersion != APIVersion || value.Kind != "CurrentRoleIdentity" || ValidateRoleSession(value.Session) != nil ||
		value.Session.Status != SessionActive || value.Account.ID != value.Session.AccountID || value.Role.ID != value.Session.RoleID ||
		value.SourceUser.ID != value.Session.SourceUserID {
		return errors.New("current role identity is invalid")
	}
	return errors.Join(validateText("account.displayName", value.Account.DisplayName, 1, 128),
		validateText("role.name", value.Role.Name, 1, 64), validateLoginName(value.SourceUser.LoginName),
		validateText("sourceUser.displayName", value.SourceUser.DisplayName, 1, 128))
}

func (value *CurrentRoleIdentity) UnmarshalJSON(source []byte) error {
	type wire CurrentRoleIdentity
	var decoded wire
	if contractjson.DecodeObjectBytes(source, MaxRequestBytes, &decoded) != nil || ValidateCurrentRoleIdentity(CurrentRoleIdentity(decoded)) != nil {
		return contractjson.ErrInvalidDocument
	}
	var fields struct {
		Session map[string]json.RawMessage `json:"session"`
	}
	if json.Unmarshal(source, &fields) != nil {
		return contractjson.ErrInvalidDocument
	}
	if _, supplied := fields.Session["revokedAt"]; supplied {
		return contractjson.ErrInvalidDocument
	}
	*value = CurrentRoleIdentity(decoded)
	return nil
}

func ValidateAssumableRole(value AssumableRole) error {
	if value.Status != RoleActive || value.MaxSessionDurationSeconds < MinRoleSessionDurationSeconds || value.MaxSessionDurationSeconds > MaxRoleSessionDurationSeconds ||
		value.Capability.Action != ActionIAMRoleAssume || value.Capability.Resource != (ResourceReference{Kind: ResourceRole, ID: string(value.RoleID)}) ||
		!value.Capability.Available || value.Capability.RestrictionReason != "" {
		return errors.New("assumable role is invalid")
	}
	return errors.Join(ValidateID("roleId", string(value.RoleID)), ValidateID("accountId", string(value.AccountID)),
		validateText("name", value.Name, 1, 64), validatePositiveVersion(value.ResourceVersion))
}

func ValidateAssumableRoleList(value AssumableRoleList) error {
	if value.APIVersion != APIVersion || value.Kind != "AssumableRoleList" || ValidateID("accountId", string(value.AccountID)) != nil ||
		ValidateID("sourceUserId", string(value.SourceUserID)) != nil || value.Items == nil || len(value.Items) > RoleDiscoveryPageSize ||
		(value.NextAfter != "" && ValidateRoleDiscoveryCursor(value.NextAfter) != nil) {
		return errors.New("assumable role list is invalid")
	}
	var previous RoleID
	for _, item := range value.Items {
		if ValidateAssumableRole(item) != nil || item.AccountID != value.AccountID || item.RoleID <= previous {
			return errors.New("assumable role list item is invalid")
		}
		previous = item.RoleID
	}
	encoded, err := json.Marshal(value)
	if err != nil || int64(len(encoded)) > MaxAssumableRoleListBytes {
		return errors.New("assumable role list exceeds its byte budget")
	}
	return nil
}

func (value *AssumableRole) UnmarshalJSON(source []byte) error {
	type wire AssumableRole
	var decoded wire
	if contractjson.DecodeObjectBytes(source, MaxAssumableRoleListBytes, &decoded) != nil || ValidateAssumableRole(AssumableRole(decoded)) != nil {
		return contractjson.ErrInvalidDocument
	}
	var fields struct {
		Capability map[string]json.RawMessage `json:"capability"`
	}
	if json.Unmarshal(source, &fields) != nil {
		return contractjson.ErrInvalidDocument
	}
	if _, supplied := fields.Capability["restrictionReason"]; supplied {
		return contractjson.ErrInvalidDocument
	}
	*value = AssumableRole(decoded)
	return nil
}

func (value *AssumableRoleList) UnmarshalJSON(source []byte) error {
	type wire AssumableRoleList
	var decoded wire
	if contractjson.DecodeObjectBytes(source, MaxAssumableRoleListBytes, &decoded) != nil {
		return contractjson.ErrInvalidDocument
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(source, &fields) != nil {
		return contractjson.ErrInvalidDocument
	}
	if _, supplied := fields["nextAfter"]; supplied && ValidateRoleDiscoveryCursor(decoded.NextAfter) != nil {
		return contractjson.ErrInvalidDocument
	}
	if ValidateAssumableRoleList(AssumableRoleList(decoded)) != nil {
		return contractjson.ErrInvalidDocument
	}
	*value = AssumableRoleList(decoded)
	return nil
}

type AssumeRoleResponse struct {
	Outcome    string      `json:"outcome"`
	Session    RoleSession `json:"session"`
	Credential Secret      `json:"credential"`
}

type RevokeRoleSessionRequest struct {
	RequestID string `json:"requestId"`
}

// Lifecycle observes only expiry and the irreversible explicit revocation.
// UNREVOKED never promises continuing source, trust or business authority.
type RoleSessionLifecycle string

const (
	RoleSessionUnrevoked    RoleSessionLifecycle = "UNREVOKED"
	RoleSessionExpired      RoleSessionLifecycle = "EXPIRED"
	RoleSessionRevoked      RoleSessionLifecycle = "REVOKED"
	MaxRoleSessionListBytes int64                = 512 * 1024
)

// RoleSessionFilter contains only public list filters, never identity selectors.
// Lifecycle may also be ALL; its empty query value means UNREVOKED.
type RoleSessionFilter struct {
	SourceUserID PrincipalID   `json:"sourceUserId,omitempty"`
	SessionID    RoleSessionID `json:"sessionId,omitempty"`
	Lifecycle    string        `json:"lifecycle"`
}

func NormalizeRoleSessionFilter(value RoleSessionFilter) (RoleSessionFilter, error) {
	if value.Lifecycle == "" {
		value.Lifecycle = string(RoleSessionUnrevoked)
	}
	if (value.SourceUserID != "" && ValidateID("sourceUserId", string(value.SourceUserID)) != nil) ||
		(value.SessionID != "" && ValidateID("sessionId", string(value.SessionID)) != nil) {
		return RoleSessionFilter{}, errors.New("role session filter is invalid")
	}
	switch value.Lifecycle {
	case "ALL", string(RoleSessionUnrevoked), string(RoleSessionExpired), string(RoleSessionRevoked):
		return value, nil
	default:
		return RoleSessionFilter{}, errors.New("role session filter is invalid")
	}
}

func ObserveRoleSession(value RoleSession, observedAt time.Time) (RoleSessionLifecycle, error) {
	if ValidateRoleSession(value) != nil || validateTime("observedAt", observedAt) != nil || observedAt.Before(value.IssuedAt) ||
		(value.RevokedAt != nil && observedAt.Before(*value.RevokedAt)) {
		return "", errors.New("role session observation is invalid")
	}
	if value.RevokedAt != nil {
		return RoleSessionRevoked, nil
	}
	if !observedAt.Before(value.ExpiresAt) {
		return RoleSessionExpired, nil
	}
	return RoleSessionUnrevoked, nil
}

type RoleSessionListing struct {
	Session          RoleSession           `json:"session"`
	SourceUser       RoleSourceUserDisplay `json:"sourceUser"`
	Lifecycle        RoleSessionLifecycle  `json:"lifecycle"`
	RevokeCapability ActionCapability      `json:"revokeCapability"`
}

type RoleSessionList struct {
	APIVersion string               `json:"apiVersion"`
	Kind       string               `json:"kind"`
	AccountID  AccountID            `json:"accountId"`
	RoleID     RoleID               `json:"roleId"`
	ObservedAt time.Time            `json:"observedAt"`
	Items      []RoleSessionListing `json:"items"`
	NextAfter  string               `json:"nextAfter,omitempty"`
}

type RoleSessionAccess struct {
	APIVersion string             `json:"apiVersion"`
	Kind       string             `json:"kind"`
	ObservedAt time.Time          `json:"observedAt"`
	Item       RoleSessionListing `json:"item"`
}

// This response contains neither a new credential nor a cached read permit.
type RevokeRoleSessionResponse struct {
	Outcome string      `json:"outcome"`
	Session RoleSession `json:"session"`
}

func ValidateRoleSessionListing(value RoleSessionListing, observedAt time.Time) error {
	lifecycle, err := ObserveRoleSession(value.Session, observedAt)
	if err != nil || lifecycle != value.Lifecycle || value.SourceUser.ID != value.Session.SourceUserID ||
		ValidateActionCapability(value.RevokeCapability) != nil || value.RevokeCapability.Action != ActionIAMRoleSessionRevoke ||
		value.RevokeCapability.Resource != (ResourceReference{Kind: ResourceRoleSession, ID: string(value.Session.ID)}) ||
		(lifecycle != RoleSessionUnrevoked && value.RevokeCapability.Available) {
		return errors.New("role session listing is invalid")
	}
	return ValidateRoleSourceUserDisplay(value.SourceUser)
}

func ValidateRoleSessionList(value RoleSessionList) error {
	if value.APIVersion != APIVersion || value.Kind != "RoleSessionList" || ValidateID("accountId", string(value.AccountID)) != nil ||
		ValidateID("roleId", string(value.RoleID)) != nil || validateTime("observedAt", value.ObservedAt) != nil ||
		value.Items == nil || len(value.Items) > DirectoryPageSize || (value.NextAfter != "" && ValidatePageCursor(value.NextAfter) != nil) {
		return errors.New("role session list is invalid")
	}
	var previous RoleSessionID
	for _, item := range value.Items {
		if item.Session.AccountID != value.AccountID || item.Session.RoleID != value.RoleID || item.Session.ID <= previous ||
			ValidateRoleSessionListing(item, value.ObservedAt) != nil {
			return errors.New("role session list item is invalid")
		}
		previous = item.Session.ID
	}
	return nil
}

func ValidateRoleSessionAccess(value RoleSessionAccess) error {
	if value.APIVersion != APIVersion || value.Kind != "RoleSessionAccess" {
		return errors.New("role session access is invalid")
	}
	return ValidateRoleSessionListing(value.Item, value.ObservedAt)
}

func ValidateRevokeRoleSessionResponse(value RevokeRoleSessionResponse) error {
	if (value.Outcome != "APPLIED" && value.Outcome != "EQUAL_REPLAY") || ValidateRoleSession(value.Session) != nil || value.Session.Status != SessionRevoked {
		return errors.New("role session revocation response is invalid")
	}
	return nil
}

func (value *RoleSessionAccess) UnmarshalJSON(source []byte) error {
	type wire RoleSessionAccess
	var decoded wire
	if contractjson.DecodeObjectBytes(source, MaxRequestBytes, &decoded) != nil || ValidateRoleSessionAccess(RoleSessionAccess(decoded)) != nil {
		return contractjson.ErrInvalidDocument
	}
	*value = RoleSessionAccess(decoded)
	return nil
}

func (value *RoleSessionList) UnmarshalJSON(source []byte) error {
	type wire RoleSessionList
	var decoded wire
	if contractjson.DecodeObjectBytes(source, MaxRoleSessionListBytes, &decoded) != nil || ValidateRoleSessionList(RoleSessionList(decoded)) != nil {
		return contractjson.ErrInvalidDocument
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(source, &fields) != nil {
		return contractjson.ErrInvalidDocument
	}
	if _, supplied := fields["nextAfter"]; supplied && ValidatePageCursor(decoded.NextAfter) != nil {
		return contractjson.ErrInvalidDocument
	}
	*value = RoleSessionList(decoded)
	return nil
}

func (value *RevokeRoleSessionResponse) UnmarshalJSON(source []byte) error {
	type wire RevokeRoleSessionResponse
	var decoded wire
	if contractjson.DecodeObjectBytes(source, MaxRequestBytes, &decoded) != nil || ValidateRevokeRoleSessionResponse(RevokeRoleSessionResponse(decoded)) != nil {
		return contractjson.ErrInvalidDocument
	}
	*value = RevokeRoleSessionResponse(decoded)
	return nil
}

func ValidateRoleSession(value RoleSession) error {
	if value.APIVersion != APIVersion || value.Kind != "RoleSession" ||
		(value.Status != SessionActive && value.Status != SessionRevoked) ||
		(value.Status == SessionRevoked) != (value.RevokedAt != nil) ||
		!value.ExpiresAt.After(value.IssuedAt) || value.ExpiresAt.Sub(value.IssuedAt) > time.Duration(MaxRoleSessionDurationSeconds)*time.Second {
		return errors.New("role session is invalid")
	}
	if value.RevokedAt != nil && (validateTime("revokedAt", *value.RevokedAt) != nil || value.RevokedAt.Before(value.IssuedAt)) {
		return errors.New("role session revocation is invalid")
	}
	return errors.Join(ValidateID("sessionId", string(value.ID)), ValidateID("accountId", string(value.AccountID)),
		ValidateID("roleId", string(value.RoleID)), ValidateID("sourceUserId", string(value.SourceUserID)),
		validateTime("issuedAt", value.IssuedAt), validateTime("expiresAt", value.ExpiresAt))
}

func ValidateAssumeRoleResponse(value AssumeRoleResponse) error {
	if ValidateRoleSession(value.Session) != nil {
		return errors.New("role session response is invalid")
	}
	switch value.Outcome {
	case "APPLIED":
		if !value.Credential.Present() || value.Session.Status != SessionActive {
			return errors.New("role session credential is missing")
		}
	case "EQUAL_REPLAY":
		if value.Credential.Present() {
			return errors.New("role session replay cannot emit a credential")
		}
	default:
		return errors.New("role session outcome is invalid")
	}
	return nil
}

// A nil Policy closes role assumption; unlike a User boundary it does not
// mean unlimited authority. The revision is the owning Role's revision.
type RolePermissionBoundary struct {
	APIVersion      string                  `json:"apiVersion"`
	Kind            string                  `json:"kind"`
	AccountID       AccountID               `json:"accountId"`
	RoleID          RoleID                  `json:"roleId"`
	ResourceVersion uint64                  `json:"resourceVersion"`
	Policy          *PolicyVersionReference `json:"policy"`
}

type SetRolePermissionBoundaryRequest struct {
	PolicyID              PolicyID `json:"policyId"`
	PolicyResourceVersion uint64   `json:"policyResourceVersion"`
	ResourceVersion       uint64   `json:"resourceVersion"`
	RequestID             string   `json:"requestId"`
}

type RemoveRolePermissionBoundaryRequest struct {
	ResourceVersion uint64 `json:"resourceVersion"`
	RequestID       string `json:"requestId"`
}

func (value *RolePermissionBoundary) UnmarshalJSON(source []byte) error {
	type wire RolePermissionBoundary
	var decoded wire
	if contractjson.DecodeObjectBytes(source, MaxRequestBytes, &decoded) != nil {
		return contractjson.ErrInvalidDocument
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(source, &fields) != nil || fields["policy"] == nil {
		return contractjson.ErrInvalidDocument
	}
	*value = RolePermissionBoundary(decoded)
	return nil
}

func ValidateRolePermissionBoundary(value RolePermissionBoundary) error {
	if value.APIVersion != APIVersion || value.Kind != "RolePermissionBoundary" ||
		ValidateID("accountId", string(value.AccountID)) != nil || ValidateID("roleId", string(value.RoleID)) != nil ||
		validatePositiveVersion(value.ResourceVersion) != nil {
		return ErrInvalidPolicy
	}
	if value.Policy != nil {
		return errors.Join(ValidateID("policyId", string(value.Policy.PolicyID)),
			ValidateID("versionId", string(value.Policy.VersionID)), ValidateDigest("contentDigest", value.Policy.ContentDigest))
	}
	return nil
}

func ValidateSetRolePermissionBoundaryRequest(value SetRolePermissionBoundaryRequest) error {
	if validatePositiveVersion(value.ResourceVersion) != nil || value.ResourceVersion == 9007199254740991 {
		return ErrInvalidPolicy
	}
	return errors.Join(ValidateID("policyId", string(value.PolicyID)),
		validatePositiveVersion(value.PolicyResourceVersion), ValidateID("requestId", value.RequestID))
}

func ValidateRemoveRolePermissionBoundaryRequest(value RemoveRolePermissionBoundaryRequest) error {
	if validatePositiveVersion(value.ResourceVersion) != nil || value.ResourceVersion == 9007199254740991 {
		return ErrInvalidPolicy
	}
	return ValidateID("requestId", value.RequestID)
}

func (request *AssumeRoleRequest) UnmarshalJSON(source []byte) error {
	type wire AssumeRoleRequest
	var decoded wire
	if contractjson.DecodeObjectBytes(source, MaxRequestBytes, &decoded) != nil {
		return contractjson.ErrInvalidDocument
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(source, &fields) != nil {
		return contractjson.ErrInvalidDocument
	}
	for _, key := range []string{"durationSeconds", "sessionPolicy"} {
		if bytes.Equal(bytes.TrimSpace(fields[key]), []byte("null")) {
			return contractjson.ErrInvalidDocument
		}
	}
	*request = AssumeRoleRequest(decoded)
	return nil
}

func ValidateAssumeRoleRequest(value AssumeRoleRequest) error {
	if value.DurationSeconds != nil && (*value.DurationSeconds < MinRoleSessionDurationSeconds || *value.DurationSeconds > MaxRoleSessionDurationSeconds) {
		return errors.New("role session duration is invalid")
	}
	if value.SessionPolicy != nil && (value.SessionPolicy.Scope != AuthorityScopeTenant || ValidatePolicyDocument(*value.SessionPolicy) != nil) {
		return ErrInvalidPolicy
	}
	return errors.Join(validatePositiveVersion(value.ResourceVersion), ValidateID("requestId", value.RequestID))
}

func (tag *RoleTag) UnmarshalJSON(source []byte) error {
	var wire struct {
		Key   *string `json:"key"`
		Value *string `json:"value"`
	}
	if contractjson.DecodeObjectBytes(source, MaxRequestBytes, &wire) != nil || wire.Key == nil || wire.Value == nil {
		return contractjson.ErrInvalidDocument
	}
	*tag = RoleTag{Key: *wire.Key, Value: *wire.Value}
	return nil
}

func (request *CreateRoleRequest) UnmarshalJSON(source []byte) error {
	type wire CreateRoleRequest
	var decoded wire
	if err := contractjson.DecodeObjectBytes(source, MaxRequestBytes, &decoded); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(source, &fields) != nil {
		return contractjson.ErrInvalidDocument
	}
	// Omission selects the documented default; null is not that choice.
	for _, name := range []string{"description", "maxSessionDurationSeconds"} {
		if bytes.Equal(bytes.TrimSpace(fields[name]), []byte("null")) {
			return contractjson.ErrInvalidDocument
		}
	}
	*request = CreateRoleRequest(decoded)
	return nil
}

func (request *UpdateRoleRequest) UnmarshalJSON(source []byte) error {
	type wire UpdateRoleRequest
	var decoded wire
	if err := contractjson.DecodeObjectBytes(source, MaxRequestBytes, &decoded); err != nil {
		return err
	}
	var fields struct {
		Description *string `json:"description"`
	}
	if json.Unmarshal(source, &fields) != nil || fields.Description == nil {
		return contractjson.ErrInvalidDocument
	}
	*request = UpdateRoleRequest(decoded)
	return nil
}

type RoleDeletion struct {
	APIVersion               string    `json:"apiVersion"`
	Kind                     string    `json:"kind"`
	ID                       RoleID    `json:"id"`
	AccountID                AccountID `json:"accountId"`
	Name                     string    `json:"name"`
	ResourceVersion          uint64    `json:"resourceVersion"`
	RevokedPolicyAttachments uint32    `json:"revokedPolicyAttachments"`
	DeletedAt                time.Time `json:"deletedAt"`
}

func validateRoleMetadata(name, description string, tags []RoleTag, duration uint32) error {
	if validateText("role.name", name, 1, 64) != nil || validateText("role.description", description, 0, 512) != nil ||
		tags == nil || len(tags) > 50 || duration < MinRoleSessionDurationSeconds || duration > MaxRoleSessionDurationSeconds {
		return errors.New("role metadata is invalid")
	}
	keys := make(map[string]bool, len(tags))
	metadataBytes := len(name) + len(description)
	for _, tag := range tags {
		if !utf8.ValidString(tag.Key) || !utf8.ValidString(tag.Value) || len(tag.Key) < 1 || len(tag.Key) > 64 || len(tag.Value) > 256 || keys[tag.Key] {
			return errors.New("role tag is invalid")
		}
		for _, value := range []string{tag.Key, tag.Value} {
			for _, character := range value {
				if unicode.IsControl(character) {
					return errors.New("role tag is invalid")
				}
			}
		}
		keys[tag.Key] = true
		metadataBytes += len(tag.Key) + len(tag.Value)
	}
	// The aggregate literal budget also bounds JSON expansion of HTML-sensitive
	// characters, so one hundred valid rows fit the declared directory budget.
	if metadataBytes > 4096 {
		return errors.New("role metadata exceeds its aggregate budget")
	}
	return nil
}

func ValidateRole(value Role) error {
	if value.APIVersion != APIVersion || value.Kind != "Role" || value.Management != RoleCustomerManaged ||
		(value.Status != RoleActive && value.Status != RoleDisabled) {
		return errors.New("role is invalid")
	}
	return errors.Join(ValidateID("role.id", string(value.ID)), ValidateID("role.accountId", string(value.AccountID)),
		ValidateID("role.currentTrustVersionId", string(value.CurrentTrustVersionID)), validatePositiveVersion(value.ResourceVersion),
		validateChronology(value.CreatedAt, value.UpdatedAt), validateRoleMetadata(value.Name, value.Description, value.Tags, value.MaxSessionDurationSeconds))
}

func ValidateCreateRoleRequest(value CreateRoleRequest) error {
	duration := DefaultRoleSessionDurationSeconds
	if value.MaxSessionDurationSeconds != nil {
		duration = *value.MaxSessionDurationSeconds
	}
	return errors.Join(validateRoleMetadata(value.Name, value.Description, value.Tags, duration),
		ValidateTrustPolicyDocument(value.TrustPolicy), ValidateID("requestId", value.RequestID))
}

func ValidateUpdateRoleRequest(value UpdateRoleRequest) error {
	return errors.Join(validateRoleMetadata(value.Name, value.Description, value.Tags, value.MaxSessionDurationSeconds),
		validatePositiveVersion(value.ResourceVersion), ValidateID("requestId", value.RequestID))
}

func ValidateSetRoleStatusRequest(value SetRoleStatusRequest) error {
	if value.Status != RoleActive && value.Status != RoleDisabled {
		return errors.New("role status is invalid")
	}
	return errors.Join(validatePositiveVersion(value.ResourceVersion), ValidateID("requestId", value.RequestID))
}

func ValidateSetRoleTrustPolicyRequest(value SetRoleTrustPolicyRequest) error {
	return errors.Join(ValidateTrustPolicyDocument(value.Document), validatePositiveVersion(value.ResourceVersion), ValidateID("requestId", value.RequestID))
}

func ValidateDeleteRoleRequest(value DeleteRoleRequest) error {
	return errors.Join(validatePositiveVersion(value.ResourceVersion), ValidateID("requestId", value.RequestID))
}

func ValidateRoleDeletion(value RoleDeletion) error {
	if value.APIVersion != APIVersion || value.Kind != "RoleDeletion" || value.ResourceVersion < 2 {
		return errors.New("role deletion is invalid")
	}
	return errors.Join(ValidateID("role.id", string(value.ID)), ValidateID("role.accountId", string(value.AccountID)),
		validateText("role.name", value.Name, 1, 64), validatePositiveVersion(value.ResourceVersion), validateTime("role.deletedAt", value.DeletedAt))
}

func roleCapabilitySet(id RoleID) map[string]struct{} {
	result := make(map[string]struct{}, 8)
	for _, action := range []Action{ActionIAMRoleRead, ActionIAMRoleUpdate, ActionIAMRoleSetStatus, ActionIAMRoleDelete, ActionIAMRoleTrustSet,
		ActionIAMRolePolicyAttachmentCreate, ActionIAMRolePermissionBoundarySet, ActionIAMRolePermissionBoundaryRemove, ActionIAMRoleSessionList} {
		result[capabilityKey(action, ResourceReference{Kind: ResourceRole, ID: string(id)})] = struct{}{}
	}
	return result
}

func ValidateRoleList(value RoleList) error {
	if value.APIVersion != APIVersion || value.Kind != "RoleList" || ValidateID("accountId", string(value.AccountID)) != nil ||
		value.Items == nil || len(value.Items) > DirectoryPageSize {
		return errors.New("role list is invalid")
	}
	var previous RoleID
	for _, item := range value.Items {
		if ValidateRole(item.Role) != nil || item.Role.AccountID != value.AccountID || item.Role.ID <= previous ||
			validateCapabilities(item.Capabilities, roleCapabilitySet(item.Role.ID)) != nil {
			return errors.New("role list item is invalid")
		}
		previous = item.Role.ID
	}
	if value.NextAfter != "" && (len(value.Items) != DirectoryPageSize || ValidatePageCursor(value.NextAfter) != nil) {
		return errors.New("role page boundary is invalid")
	}
	encoded, err := json.Marshal(value)
	if err != nil || int64(len(encoded)) > MaxRoleListBytes {
		return errors.New("role list exceeds its byte budget")
	}
	return nil
}

func ValidateRoleAccess(value RoleAccess) error {
	if ValidateRole(value.Role) != nil || ValidateRoleTrustVersion(value.TrustVersion) != nil ||
		value.TrustVersion.AccountID != value.Role.AccountID || value.TrustVersion.RoleID != value.Role.ID ||
		value.TrustVersion.ID != value.Role.CurrentTrustVersionID || value.TrustVersion.CreatedAt.Before(value.Role.CreatedAt) ||
		value.TrustVersion.CreatedAt.After(value.Role.UpdatedAt) || value.PolicyAttachments == nil || len(value.PolicyAttachments) > 256 {
		return errors.New("role access is invalid")
	}
	expected := roleCapabilitySet(value.Role.ID)
	expected[capabilityKey(ActionIAMRoleAssume, ResourceReference{Kind: ResourceRole, ID: string(value.Role.ID)})] = struct{}{}
	attachments, policies := map[PolicyAttachmentID]bool{}, map[PolicyID]bool{}
	for _, attachment := range value.PolicyAttachments {
		if ValidatePolicyAttachment(attachment) != nil || attachment.AccountID != value.Role.AccountID || attachment.Target.Kind != PolicyTargetRole ||
			attachment.Target.ID != string(value.Role.ID) || attachment.Scope != AuthorityScopeTenant || attachment.RevokedAt != nil || attachments[attachment.ID] || policies[attachment.PolicyID] {
			return errors.New("role attachment is invalid")
		}
		attachments[attachment.ID], policies[attachment.PolicyID] = true, true
		expected[capabilityKey(ActionIAMRolePolicyAttachmentRevoke, ResourceReference{Kind: ResourcePolicyAttachment, ID: string(attachment.ID)})] = struct{}{}
	}
	if validateCapabilities(value.Capabilities, expected) != nil {
		return errors.New("role capabilities are invalid")
	}
	encoded, err := json.Marshal(value)
	if err != nil || int64(len(encoded)) > MaxRoleAccessBytes {
		return errors.New("role access exceeds its byte budget")
	}
	return nil
}

func ValidateRoleTrustVersionList(value RoleTrustVersionList) error {
	if value.APIVersion != APIVersion || value.Kind != "RoleTrustVersionList" || ValidateID("accountId", string(value.AccountID)) != nil ||
		ValidateID("roleId", string(value.RoleID)) != nil || value.Items == nil || len(value.Items) > DirectoryPageSize {
		return errors.New("role trust list is invalid")
	}
	var previous RoleTrustVersionID
	for _, item := range value.Items {
		if ValidateRoleTrustVersion(item) != nil || item.AccountID != value.AccountID || item.RoleID != value.RoleID || item.ID <= previous {
			return errors.New("role trust list item is invalid")
		}
		previous = item.ID
	}
	if value.NextAfter != "" && (len(value.Items) != DirectoryPageSize || ValidatePageCursor(value.NextAfter) != nil) {
		return errors.New("role trust page boundary is invalid")
	}
	return nil
}

const (
	TrustPolicyLanguageVersion          = "1"
	MaxTrustPolicyStatements            = 8
	MaxTrustStatementPrincipals         = 32
	MaxTrustPolicyPrincipalVisits       = 256
	MaxTrustPolicyBytes           int64 = 16 * 1024
)

var ErrInvalidTrustPolicy = errors.New("IAM role trust policy is invalid")

// TrustPolicyDocument declares carrier admission, not identity permissions.
// Its owning Role supplies the account. Valid syntax proves neither that a
// USER exists in that account nor that the USER may assume or use the Role.
type TrustPolicyDocument struct {
	LanguageVersion string                 `json:"languageVersion"`
	Statements      []TrustPolicyStatement `json:"statements"`
}

type TrustPolicyStatement struct {
	SID        string           `json:"sid"`
	Effect     PolicyEffect     `json:"effect"`
	Principals []TrustPrincipal `json:"principals"`
}

// R1 accepts only the exact USER discriminator. Role, Group, service and
// provider carriers require their own admission contracts before acceptance.
type TrustPrincipal struct {
	Type PrincipalType `json:"type"`
	ID   PrincipalID   `json:"id"`
}

// RoleTrustVersion is immutable content bound to an account and one Role.
// A valid content digest is not evidence that it is selected or authorized.
type RoleTrustVersion struct {
	APIVersion    string              `json:"apiVersion"`
	Kind          string              `json:"kind"`
	ID            RoleTrustVersionID  `json:"id"`
	AccountID     AccountID           `json:"accountId"`
	RoleID        RoleID              `json:"roleId"`
	Document      TrustPolicyDocument `json:"document"`
	ContentDigest string              `json:"contentDigest"`
	CreatedAt     time.Time           `json:"createdAt"`
}

func (document *TrustPolicyDocument) UnmarshalJSON(source []byte) error {
	type wire TrustPolicyDocument
	var decoded wire
	if contractjson.DecodeObjectBytes(source, MaxTrustPolicyBytes, &decoded) != nil ||
		ValidateTrustPolicyDocument(TrustPolicyDocument(decoded)) != nil {
		return ErrInvalidTrustPolicy
	}
	*document = TrustPolicyDocument(decoded)
	return nil
}

func DecodeTrustPolicyDocument(reader io.Reader) (TrustPolicyDocument, error) {
	var document TrustPolicyDocument
	if contractjson.DecodeObject(reader, MaxTrustPolicyBytes, &document) != nil {
		return TrustPolicyDocument{}, ErrInvalidTrustPolicy
	}
	return document, nil
}

func DecodeRoleTrustVersion(reader io.Reader) (RoleTrustVersion, error) {
	var version RoleTrustVersion
	if contractjson.DecodeObject(reader, MaxRequestBytes, &version) != nil || ValidateRoleTrustVersion(version) != nil {
		return RoleTrustVersion{}, ErrInvalidTrustPolicy
	}
	return version, nil
}

func ValidateTrustPolicyDocument(document TrustPolicyDocument) error {
	if document.LanguageVersion != TrustPolicyLanguageVersion || document.Statements == nil ||
		len(document.Statements) > MaxTrustPolicyStatements {
		return ErrInvalidTrustPolicy
	}
	sids := make(map[string]bool, len(document.Statements))
	visits := 0
	for _, statement := range document.Statements {
		if ValidateID("sid", statement.SID) != nil || sids[statement.SID] ||
			(statement.Effect != PolicyAllow && statement.Effect != PolicyDeny) ||
			len(statement.Principals) == 0 || len(statement.Principals) > MaxTrustStatementPrincipals {
			return ErrInvalidTrustPolicy
		}
		sids[statement.SID] = true
		visits += len(statement.Principals)
		if visits > MaxTrustPolicyPrincipalVisits {
			return ErrInvalidTrustPolicy
		}
		principals := make(map[PrincipalID]bool, len(statement.Principals))
		for _, principal := range statement.Principals {
			if principal.Type != PrincipalUser || ValidateID("principal.id", string(principal.ID)) != nil || principals[principal.ID] {
				return ErrInvalidTrustPolicy
			}
			principals[principal.ID] = true
		}
	}
	encoded, err := json.Marshal(document)
	if err != nil || int64(len(encoded)) > MaxTrustPolicyBytes {
		return ErrInvalidTrustPolicy
	}
	return nil
}

// CanonicalizeTrustPolicyDocument is the sole role-trust content encoder.
// Order is not authority. Normalize copies and preserve explicit empty [].
// Neither this digest nor identity-policy digests replace Audit encoding.
func CanonicalizeTrustPolicyDocument(document TrustPolicyDocument) (string, string, error) {
	if ValidateTrustPolicyDocument(document) != nil {
		return "", "", ErrInvalidTrustPolicy
	}
	statements := make([]TrustPolicyStatement, len(document.Statements))
	copy(statements, document.Statements)
	for index := range statements {
		statement := &statements[index]
		statement.Principals = slices.Clone(statement.Principals)
		slices.SortFunc(statement.Principals, func(left, right TrustPrincipal) int {
			return cmp.Compare(left.ID, right.ID)
		})
	}
	slices.SortFunc(statements, func(left, right TrustPolicyStatement) int { return cmp.Compare(left.SID, right.SID) })
	document.Statements = statements
	encoded, err := json.Marshal(document)
	if err != nil {
		return "", "", ErrInvalidTrustPolicy
	}
	digest := sha256.Sum256(append([]byte("matrix.iam.role-trust.v1\x00"), encoded...))
	return string(encoded), "sha256:" + hex.EncodeToString(digest[:]), nil
}

func ValidateRoleTrustVersion(value RoleTrustVersion) error {
	if value.APIVersion != APIVersion || value.Kind != "RoleTrustVersion" ||
		ValidateID("trustVersion.id", string(value.ID)) != nil ||
		ValidateID("trustVersion.accountId", string(value.AccountID)) != nil ||
		ValidateID("trustVersion.roleId", string(value.RoleID)) != nil ||
		validateTime("trustVersion.createdAt", value.CreatedAt) != nil {
		return ErrInvalidTrustPolicy
	}
	_, digest, err := CanonicalizeTrustPolicyDocument(value.Document)
	if err != nil || value.ContentDigest != digest {
		return ErrInvalidTrustPolicy
	}
	return nil
}
