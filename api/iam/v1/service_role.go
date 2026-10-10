package iamv1

import (
	"bytes"
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"github.com/xiak/matrix/api/contractjson"
)

type ServiceRoleTemplateID string
type ServiceRoleTemplateStatus string
type WorkloadRoleBindingID string
type WorkloadRoleBindingStatus string

const (
	ServiceRoleTemplateActive       ServiceRoleTemplateStatus = "ACTIVE"
	ServiceRoleTemplateRetired      ServiceRoleTemplateStatus = "RETIRED"
	WorkloadRoleBindingActive       WorkloadRoleBindingStatus = "ACTIVE"
	WorkloadRoleBindingRevoked      WorkloadRoleBindingStatus = "REVOKED"
	MaxServiceRoleTemplateWorkloads                           = 16
	MaxServiceRoleTemplateListBytes int64                     = 256 * 1024
	MaxServiceLinkedRoleListBytes   int64                     = 4 * 1024 * 1024
)

// ServiceRoleWorkloadSpec is the product-owned consent surface for one
// workload kind. IAM validates these exact registered Actions and never
// derives them from a product, service, Role or resource name.
type ServiceRoleWorkloadSpec struct {
	ResourceKind ResourceKind `json:"resourceKind"`
	BindAction   Action       `json:"bindAction"`
	UnbindAction Action       `json:"unbindAction"`
}

// ServiceRoleTemplateSpec is release-owned authority, not a tenant policy or
// a caller-selected service name. The exact immutable PolicyVersion is the
// permission ceiling; workload kinds only constrain where that ceiling may be
// delegated and never grant those permissions by themselves.
type ServiceRoleTemplateSpec struct {
	Product                   ProductID                 `json:"product"`
	ServicePurpose            ServicePurpose            `json:"servicePurpose"`
	RoleName                  string                    `json:"roleName"`
	RoleDescription           string                    `json:"roleDescription"`
	PolicyVersion             PolicyVersionReference    `json:"policyVersion"`
	Workloads                 []ServiceRoleWorkloadSpec `json:"workloads"`
	MaxSessionDurationSeconds uint32                    `json:"maxSessionDurationSeconds"`
}

// ServiceRoleTemplate is an immutable template version. Retirement prevents
// new bindings and sessions without rewriting an existing consent or history.
type ServiceRoleTemplate struct {
	APIVersion    string                    `json:"apiVersion"`
	Kind          string                    `json:"kind"`
	ID            ServiceRoleTemplateID     `json:"id"`
	Version       uint64                    `json:"version"`
	Spec          ServiceRoleTemplateSpec   `json:"spec"`
	ContentDigest string                    `json:"contentDigest"`
	Status        ServiceRoleTemplateStatus `json:"status"`
}

type ServiceRoleTemplateReference struct {
	ID            ServiceRoleTemplateID `json:"id"`
	Version       uint64                `json:"version"`
	ContentDigest string                `json:"contentDigest"`
}

type ServiceRoleTemplateList struct {
	APIVersion string                `json:"apiVersion"`
	Kind       string                `json:"kind"`
	Items      []ServiceRoleTemplate `json:"items"`
}

// ServicePrincipalReference is non-secret lineage for one registered service
// principal in one installation. It is not a bearer credential and purpose is
// not permission to any customer Account.
type ServicePrincipalReference struct {
	InstallationID string         `json:"installationId"`
	PrincipalID    PrincipalID    `json:"principalId"`
	Purpose        ServicePurpose `json:"purpose"`
}

// ServiceLinkedRole binds a normal Role authorization identity to immutable
// release authority and one registered service principal. Account consent is
// represented by this relationship, never by changing the service identity's
// home Account or by granting that service principal a tenant policy.
type ServiceLinkedRole struct {
	APIVersion        string                       `json:"apiVersion"`
	Kind              string                       `json:"kind"`
	Role              Role                         `json:"role"`
	Template          ServiceRoleTemplateReference `json:"template"`
	ServicePrincipal  ServicePrincipalReference    `json:"servicePrincipal"`
	PermissionCeiling PolicyVersionReference       `json:"permissionCeiling"`
}

// WorkloadRoleBinding is the revocable Account consent for one exact product
// resource. The workload reference is a namespace-qualified resource identity,
// not a caller-selected Account or an authorization result.
type WorkloadRoleBinding struct {
	APIVersion      string                       `json:"apiVersion"`
	Kind            string                       `json:"kind"`
	ID              WorkloadRoleBindingID        `json:"id"`
	AccountID       AccountID                    `json:"accountId"`
	RoleID          RoleID                       `json:"roleId"`
	Template        ServiceRoleTemplateReference `json:"template"`
	Workload        ResourceReference            `json:"workload"`
	Status          WorkloadRoleBindingStatus    `json:"status"`
	ResourceVersion uint64                       `json:"resourceVersion"`
	CreatedAt       time.Time                    `json:"createdAt"`
	UpdatedAt       time.Time                    `json:"updatedAt"`
	RevokedAt       *time.Time                   `json:"revokedAt,omitempty"`
}

type ServiceLinkedRoleAccess struct {
	APIVersion string                `json:"apiVersion"`
	Kind       string                `json:"kind"`
	Relation   ServiceLinkedRole     `json:"relation"`
	Bindings   []WorkloadRoleBinding `json:"bindings"`
	NextAfter  string                `json:"nextAfter,omitempty"`
}

// ServiceLinkedRoleListing is a bounded directory projection. Counts describe
// durable binding history and current ACTIVE consent; the detailed binding
// identities remain behind the separately authorized Role detail route.
type ServiceLinkedRoleListing struct {
	Relation           ServiceLinkedRole `json:"relation"`
	BindingCount       uint64            `json:"bindingCount"`
	ActiveBindingCount uint64            `json:"activeBindingCount"`
}

type ServiceLinkedRoleList struct {
	APIVersion string                     `json:"apiVersion"`
	Kind       string                     `json:"kind"`
	AccountID  AccountID                  `json:"accountId"`
	Items      []ServiceLinkedRoleListing `json:"items"`
	NextAfter  string                     `json:"nextAfter,omitempty"`
}

// CreateWorkloadRoleBindingRequest carries one product PEP decision input and
// one exact release-owned template reference. The authorization request is the
// command identity and workload reference; duplicating Account, Role, service
// principal or request selectors here would let the caller make them disagree.
type CreateWorkloadRoleBindingRequest struct {
	Template      ServiceRoleTemplateReference `json:"template"`
	Authorization AuthorizationRequest         `json:"authorization"`
}

// RevokeWorkloadRoleBindingRequest carries only the product PEP decision for
// the binding's already-recorded workload and its expected current revision.
// The path binding is authoritative for Account, Role, template, service
// principal and workload; none of those identities may be selected again.
type RevokeWorkloadRoleBindingRequest struct {
	Authorization   AuthorizationRequest `json:"authorization"`
	ResourceVersion uint64               `json:"resourceVersion"`
}

// AssumeServiceRoleRequest is a service-authenticated intent. The binding is
// the sole customer-side selector; IAM resolves its Account, Role, template,
// workload, installation, principal and purpose from current authority.
type AssumeServiceRoleRequest struct {
	BindingID       WorkloadRoleBindingID `json:"bindingId"`
	DurationSeconds *uint32               `json:"durationSeconds,omitempty"`
	RequestID       string                `json:"requestId"`
}

func ValidateServicePrincipalReference(value ServicePrincipalReference) error {
	if !knownServicePurpose(value.Purpose) {
		return errors.New("service principal reference is invalid")
	}
	return errors.Join(ValidateID("servicePrincipal.installationId", value.InstallationID),
		ValidateID("servicePrincipal.principalId", string(value.PrincipalID)))
}

func ValidateAssumeServiceRoleRequest(value AssumeServiceRoleRequest) error {
	if value.DurationSeconds != nil && (*value.DurationSeconds < MinRoleSessionDurationSeconds ||
		*value.DurationSeconds > MaxRoleSessionDurationSeconds) {
		return errors.New("service role session duration is invalid")
	}
	return errors.Join(ValidateID("bindingId", string(value.BindingID)), ValidateID("requestId", value.RequestID))
}

func ValidateServiceLinkedRole(value ServiceLinkedRole) error {
	if value.APIVersion != APIVersion || value.Kind != "ServiceLinkedRole" ||
		ValidateRole(value.Role) != nil || value.Role.Management != RoleServiceLinked ||
		ValidateServiceRoleTemplateReference(value.Template) != nil ||
		ValidateServicePrincipalReference(value.ServicePrincipal) != nil ||
		ValidateID("permissionCeiling.policyId", string(value.PermissionCeiling.PolicyID)) != nil ||
		ValidateID("permissionCeiling.versionId", string(value.PermissionCeiling.VersionID)) != nil ||
		ValidateDigest("permissionCeiling.contentDigest", value.PermissionCeiling.ContentDigest) != nil {
		return errors.New("service-linked role is invalid")
	}
	return nil
}

func ValidateWorkloadRoleBinding(value WorkloadRoleBinding) error {
	terminal := value.Status == WorkloadRoleBindingRevoked && value.ResourceVersion == 2 && value.RevokedAt != nil &&
		value.UpdatedAt.Equal(*value.RevokedAt) && !value.RevokedAt.Before(value.CreatedAt)
	active := value.Status == WorkloadRoleBindingActive && value.ResourceVersion == 1 && value.RevokedAt == nil &&
		value.UpdatedAt.Equal(value.CreatedAt)
	if value.APIVersion != APIVersion || value.Kind != "WorkloadRoleBinding" || (!active && !terminal) ||
		!profileIdentifier(string(value.Workload.Kind), true) ||
		ValidateServiceRoleTemplateReference(value.Template) != nil {
		return errors.New("workload role binding is invalid")
	}
	return errors.Join(ValidateID("workloadRoleBinding.id", string(value.ID)),
		ValidateID("workloadRoleBinding.accountId", string(value.AccountID)),
		ValidateID("workloadRoleBinding.roleId", string(value.RoleID)),
		ValidateID("workloadRoleBinding.workload.id", value.Workload.ID),
		validateChronology(value.CreatedAt, value.UpdatedAt))
}

func ValidateServiceLinkedRoleAccess(value ServiceLinkedRoleAccess) error {
	if value.APIVersion != APIVersion || value.Kind != "ServiceLinkedRoleAccess" ||
		ValidateServiceLinkedRole(value.Relation) != nil || value.Bindings == nil || len(value.Bindings) > DirectoryPageSize {
		return errors.New("service-linked role access is invalid")
	}
	var previous WorkloadRoleBindingID
	for _, binding := range value.Bindings {
		if ValidateWorkloadRoleBinding(binding) != nil || binding.AccountID != value.Relation.Role.AccountID ||
			binding.RoleID != value.Relation.Role.ID || binding.Template != value.Relation.Template || binding.ID <= previous {
			return errors.New("service-linked role binding is invalid")
		}
		previous = binding.ID
	}
	if value.NextAfter != "" && (len(value.Bindings) != DirectoryPageSize || ValidatePageCursor(value.NextAfter) != nil) {
		return errors.New("service-linked role page boundary is invalid")
	}
	encoded, err := json.Marshal(value)
	if err != nil || int64(len(encoded)) > MaxRoleAccessBytes {
		return errors.New("service-linked role access exceeds its byte budget")
	}
	return nil
}

func ValidateServiceLinkedRoleList(value ServiceLinkedRoleList) error {
	if value.APIVersion != APIVersion || value.Kind != "ServiceLinkedRoleList" ||
		ValidateID("accountId", string(value.AccountID)) != nil || value.Items == nil || len(value.Items) > DirectoryPageSize {
		return errors.New("service-linked role list is invalid")
	}
	var previous RoleID
	for _, item := range value.Items {
		if ValidateServiceLinkedRole(item.Relation) != nil || item.Relation.Role.AccountID != value.AccountID ||
			item.Relation.Role.ID <= previous || item.BindingCount == 0 || item.BindingCount > 9007199254740991 ||
			item.ActiveBindingCount > item.BindingCount {
			return errors.New("service-linked role list item is invalid")
		}
		previous = item.Relation.Role.ID
	}
	if value.NextAfter != "" && (len(value.Items) != DirectoryPageSize || ValidatePageCursor(value.NextAfter) != nil) {
		return errors.New("service-linked role list page boundary is invalid")
	}
	encoded, err := json.Marshal(value)
	if err != nil || int64(len(encoded)) > MaxServiceLinkedRoleListBytes {
		return errors.New("service-linked role list exceeds its byte budget")
	}
	return nil
}

func ValidateCreateWorkloadRoleBindingRequest(value CreateWorkloadRoleBindingRequest) error {
	if ValidateServiceRoleTemplateReference(value.Template) != nil ||
		validateProductAuthorizationRequestShape(value.Authorization) != nil ||
		value.Authorization.ResourceMode != AuthorizationResourceInstance ||
		value.Authorization.CollectionUsage != "" {
		return errors.New("workload role binding request is invalid")
	}
	return nil
}

func ValidateRevokeWorkloadRoleBindingRequest(value RevokeWorkloadRoleBindingRequest) error {
	if validateProductAuthorizationRequestShape(value.Authorization) != nil ||
		value.Authorization.ResourceMode != AuthorizationResourceInstance ||
		value.Authorization.CollectionUsage != "" || value.ResourceVersion != 1 {
		return errors.New("workload role binding revocation request is invalid")
	}
	return nil
}

// The workload command decoder validates only the bounded product request
// envelope. Exact Action/resource/condition authority is resolved from the
// authenticated current Profile inside the IAM transaction; consulting the
// executable-only catalog here would make signed products impossible to use.
func validateProductAuthorizationRequestShape(value AuthorizationRequest) error {
	if !profileIdentifier(string(value.Profile.Product), false) || validatePositiveVersion(value.Profile.Revision) != nil ||
		ValidateDigest("authorization.profile.contentDigest", value.Profile.ContentDigest) != nil ||
		!authorizationActionIdentifier(value.Action) || !profileIdentifier(string(value.Resource.Kind), true) ||
		ValidateID("authorization.resource.id", value.Resource.ID) != nil ||
		value.NetworkContext != nil && ValidateAuthorizationNetworkContext(*value.NetworkContext) != nil ||
		ValidateID("authorization.requestId", value.RequestID) != nil ||
		ValidateID("authorization.correlationId", value.CorrelationID) != nil ||
		validateAuthorizationTagShape(value.RequestTags) != nil || validateAuthorizationTagShape(value.ResourceTags) != nil {
		return errors.New("product authorization request is invalid")
	}
	return nil
}

func validateAuthorizationTagShape(values []AuthorizationTag) error {
	if values != nil && (len(values) == 0 || len(values) > MaxAuthorizationTags) {
		return errors.New("authorization tags are invalid")
	}
	previous := ""
	for _, value := range values {
		if ValidateAuthorizationTag(value) != nil || value.Key <= previous {
			return errors.New("authorization tags are invalid")
		}
		previous = value.Key
	}
	return nil
}

func ValidateServiceRoleTemplateSpec(value ServiceRoleTemplateSpec) error {
	if !profileIdentifier(string(value.Product), false) || !knownServicePurpose(value.ServicePurpose) ||
		ValidateID("policyVersion.policyId", string(value.PolicyVersion.PolicyID)) != nil ||
		ValidateID("policyVersion.versionId", string(value.PolicyVersion.VersionID)) != nil ||
		ValidateDigest("policyVersion.contentDigest", value.PolicyVersion.ContentDigest) != nil ||
		validateRoleMetadata(value.RoleName, value.RoleDescription, []RoleTag{}, value.MaxSessionDurationSeconds) != nil ||
		value.Workloads == nil || len(value.Workloads) == 0 ||
		len(value.Workloads) > MaxServiceRoleTemplateWorkloads ||
		value.MaxSessionDurationSeconds < MinRoleSessionDurationSeconds ||
		value.MaxSessionDurationSeconds > MaxRoleSessionDurationSeconds {
		return errors.New("service role template spec is invalid")
	}
	seen := make(map[ResourceKind]bool, len(value.Workloads))
	for _, workload := range value.Workloads {
		if !profileIdentifier(string(workload.ResourceKind), true) || seen[workload.ResourceKind] ||
			!authorizationActionIdentifier(workload.BindAction) || !authorizationActionIdentifier(workload.UnbindAction) ||
			workload.BindAction == workload.UnbindAction {
			return errors.New("service role template workload kind is invalid")
		}
		seen[workload.ResourceKind] = true
	}
	return nil
}

// CheckServiceRoleTemplateSpec resolves the structurally valid template only
// against declarations authenticated by its caller. Transport decoding cannot
// substitute the executable's built-in product catalog for a signed release
// catalog or a database registry snapshot.
func CheckServiceRoleTemplateSpec(value ServiceRoleTemplateSpec, profiles []AuthorizationProfile) error {
	if ValidateServiceRoleTemplateSpec(value) != nil || len(profiles) == 0 || len(profiles) > MaxAuthorizationProfileRegistryItems {
		return errors.New("service role template spec is invalid")
	}
	var profile AuthorizationProfile
	found := false
	for _, candidate := range profiles {
		if candidate.Product != value.Product {
			continue
		}
		if found || ValidateAuthorizationProfile(candidate) != nil {
			return errors.New("service role template product is ambiguous")
		}
		profile, found = CloneAuthorizationProfile(candidate), true
	}
	if !found || profile.CallingService != value.ServicePurpose {
		return errors.New("service role template product is not registered")
	}
	_, profileDigest, err := CanonicalizeAuthorizationProfile(profile)
	if err != nil {
		return errors.New("service role template product is invalid")
	}
	profileReference := AuthorizationProfileReference{Product: profile.Product, Revision: profile.Revision, ContentDigest: profileDigest}
	for _, workload := range value.Workloads {
		bind, bindFound := LookupAuthorizationProfileActionDefinition(profile, workload.BindAction)
		unbind, unbindFound := LookupAuthorizationProfileActionDefinition(profile, workload.UnbindAction)
		if !bindFound || !unbindFound || bind.Product != value.Product || unbind.Product != value.Product ||
			bind.CallingService != value.ServicePurpose || unbind.CallingService != value.ServicePurpose ||
			bind.ResourceKind != workload.ResourceKind || unbind.ResourceKind != workload.ResourceKind ||
			bind.AuthorityScope != AuthorityScopeTenant || unbind.AuthorityScope != AuthorityScopeTenant ||
			CheckAuthorizationProfileSubject(profile, profileReference, workload.BindAction, SubjectUser) != nil ||
			CheckAuthorizationProfileSubject(profile, profileReference, workload.UnbindAction, SubjectUser) != nil ||
			CheckAuthorizationProfileTarget(profile, profileReference, workload.BindAction,
				ResourceReference{Kind: workload.ResourceKind, ID: "registered-workload"}, AuthorizationResourceInstance, "") != nil ||
			CheckAuthorizationProfileTarget(profile, profileReference, workload.UnbindAction,
				ResourceReference{Kind: workload.ResourceKind, ID: "registered-workload"}, AuthorizationResourceInstance, "") != nil {
			return errors.New("service role template workload kind is invalid")
		}
	}
	return nil
}

// CheckServiceRoleTemplate validates the immutable commitment and then binds
// its product/action semantics to an explicit trusted declaration set.
func CheckServiceRoleTemplate(value ServiceRoleTemplate, profiles []AuthorizationProfile) error {
	if ValidateServiceRoleTemplate(value) != nil || CheckServiceRoleTemplateSpec(value.Spec, profiles) != nil {
		return errors.New("service role template is invalid")
	}
	return nil
}

// CanonicalizeServiceRoleTemplateSpec is the single content encoder for a
// template version. Array order is not authority and is normalized before the
// domain-separated digest is calculated.
func CanonicalizeServiceRoleTemplateSpec(value ServiceRoleTemplateSpec) (string, string, error) {
	if ValidateServiceRoleTemplateSpec(value) != nil {
		return "", "", errors.New("service role template spec is invalid")
	}
	value.Workloads = slices.Clone(value.Workloads)
	slices.SortFunc(value.Workloads, func(left, right ServiceRoleWorkloadSpec) int {
		if order := cmp.Compare(left.ResourceKind, right.ResourceKind); order != 0 {
			return order
		}
		if order := cmp.Compare(left.BindAction, right.BindAction); order != 0 {
			return order
		}
		return cmp.Compare(left.UnbindAction, right.UnbindAction)
	})
	document, err := json.Marshal(value)
	if err != nil {
		return "", "", errors.New("service role template spec is invalid")
	}
	digest := sha256.Sum256(append([]byte("matrix.iam.service-role-template.v1\x00"), document...))
	return string(document), "sha256:" + hex.EncodeToString(digest[:]), nil
}

func ValidateServiceRoleTemplateReference(value ServiceRoleTemplateReference) error {
	return errors.Join(ValidateID("serviceRoleTemplate.id", string(value.ID)), validatePositiveVersion(value.Version),
		ValidateDigest("serviceRoleTemplate.contentDigest", value.ContentDigest))
}

func ValidateServiceRoleTemplate(value ServiceRoleTemplate) error {
	if value.APIVersion != APIVersion || value.Kind != "ServiceRoleTemplate" ||
		(value.Status != ServiceRoleTemplateActive && value.Status != ServiceRoleTemplateRetired) {
		return errors.New("service role template is invalid")
	}
	_, digest, err := CanonicalizeServiceRoleTemplateSpec(value.Spec)
	if err != nil || digest != value.ContentDigest {
		return errors.New("service role template is invalid")
	}
	return errors.Join(ValidateID("serviceRoleTemplate.id", string(value.ID)), validatePositiveVersion(value.Version))
}

func (value ServiceRoleTemplate) Reference() ServiceRoleTemplateReference {
	return ServiceRoleTemplateReference{ID: value.ID, Version: value.Version, ContentDigest: value.ContentDigest}
}

func ValidateServiceRoleTemplateList(value ServiceRoleTemplateList) error {
	if value.APIVersion != APIVersion || value.Kind != "ServiceRoleTemplateList" || value.Items == nil ||
		len(value.Items) > DirectoryPageSize {
		return errors.New("service role template list is invalid")
	}
	var previous ServiceRoleTemplateID
	for _, item := range value.Items {
		if ValidateServiceRoleTemplate(item) != nil || item.ID <= previous {
			return errors.New("service role template list item is invalid")
		}
		previous = item.ID
	}
	encoded, err := json.Marshal(value)
	if err != nil || int64(len(encoded)) > MaxServiceRoleTemplateListBytes {
		return errors.New("service role template list exceeds its byte budget")
	}
	return nil
}

func (value *ServiceRoleTemplateSpec) UnmarshalJSON(source []byte) error {
	type wire ServiceRoleTemplateSpec
	var decoded wire
	if contractjson.DecodeObjectBytes(source, MaxRequestBytes, &decoded) != nil ||
		ValidateServiceRoleTemplateSpec(ServiceRoleTemplateSpec(decoded)) != nil {
		return contractjson.ErrInvalidDocument
	}
	*value = ServiceRoleTemplateSpec(decoded)
	return nil
}

func (value *ServiceRoleTemplate) UnmarshalJSON(source []byte) error {
	type wire ServiceRoleTemplate
	var decoded wire
	if contractjson.DecodeObjectBytes(source, MaxRequestBytes, &decoded) != nil ||
		ValidateServiceRoleTemplate(ServiceRoleTemplate(decoded)) != nil {
		return contractjson.ErrInvalidDocument
	}
	*value = ServiceRoleTemplate(decoded)
	return nil
}

func (value *ServiceRoleTemplateReference) UnmarshalJSON(source []byte) error {
	type wire ServiceRoleTemplateReference
	var decoded wire
	if contractjson.DecodeObjectBytes(source, MaxRequestBytes, &decoded) != nil ||
		ValidateServiceRoleTemplateReference(ServiceRoleTemplateReference(decoded)) != nil {
		return contractjson.ErrInvalidDocument
	}
	*value = ServiceRoleTemplateReference(decoded)
	return nil
}

func (value *ServiceRoleTemplateList) UnmarshalJSON(source []byte) error {
	type wire ServiceRoleTemplateList
	var decoded wire
	if contractjson.DecodeObjectBytes(source, MaxServiceRoleTemplateListBytes, &decoded) != nil ||
		ValidateServiceRoleTemplateList(ServiceRoleTemplateList(decoded)) != nil {
		return contractjson.ErrInvalidDocument
	}
	*value = ServiceRoleTemplateList(decoded)
	return nil
}

func (value *ServiceLinkedRole) UnmarshalJSON(source []byte) error {
	type wire ServiceLinkedRole
	var decoded wire
	if contractjson.DecodeObjectBytes(source, MaxRequestBytes, &decoded) != nil ||
		ValidateServiceLinkedRole(ServiceLinkedRole(decoded)) != nil {
		return contractjson.ErrInvalidDocument
	}
	*value = ServiceLinkedRole(decoded)
	return nil
}

func (value *WorkloadRoleBinding) UnmarshalJSON(source []byte) error {
	type wire WorkloadRoleBinding
	var decoded wire
	if contractjson.DecodeObjectBytes(source, MaxRequestBytes, &decoded) != nil ||
		ValidateWorkloadRoleBinding(WorkloadRoleBinding(decoded)) != nil {
		return contractjson.ErrInvalidDocument
	}
	*value = WorkloadRoleBinding(decoded)
	return nil
}

func (value *ServiceLinkedRoleAccess) UnmarshalJSON(source []byte) error {
	type wire ServiceLinkedRoleAccess
	var decoded wire
	if contractjson.DecodeObjectBytes(source, MaxRoleAccessBytes, &decoded) != nil ||
		ValidateServiceLinkedRoleAccess(ServiceLinkedRoleAccess(decoded)) != nil {
		return contractjson.ErrInvalidDocument
	}
	*value = ServiceLinkedRoleAccess(decoded)
	return nil
}

func (value *ServiceLinkedRoleList) UnmarshalJSON(source []byte) error {
	type wire ServiceLinkedRoleList
	var decoded wire
	if contractjson.DecodeObjectBytes(source, MaxServiceLinkedRoleListBytes, &decoded) != nil ||
		ValidateServiceLinkedRoleList(ServiceLinkedRoleList(decoded)) != nil {
		return contractjson.ErrInvalidDocument
	}
	*value = ServiceLinkedRoleList(decoded)
	return nil
}

func (value *CreateWorkloadRoleBindingRequest) UnmarshalJSON(source []byte) error {
	type wire CreateWorkloadRoleBindingRequest
	var decoded wire
	if contractjson.DecodeObjectBytes(source, MaxRequestBytes, &decoded) != nil ||
		ValidateCreateWorkloadRoleBindingRequest(CreateWorkloadRoleBindingRequest(decoded)) != nil {
		return contractjson.ErrInvalidDocument
	}
	*value = CreateWorkloadRoleBindingRequest(decoded)
	return nil
}

func (value *RevokeWorkloadRoleBindingRequest) UnmarshalJSON(source []byte) error {
	type wire RevokeWorkloadRoleBindingRequest
	var decoded wire
	if contractjson.DecodeObjectBytes(source, MaxRequestBytes, &decoded) != nil ||
		ValidateRevokeWorkloadRoleBindingRequest(RevokeWorkloadRoleBindingRequest(decoded)) != nil {
		return contractjson.ErrInvalidDocument
	}
	*value = RevokeWorkloadRoleBindingRequest(decoded)
	return nil
}

func (value *AssumeServiceRoleRequest) UnmarshalJSON(source []byte) error {
	type wire AssumeServiceRoleRequest
	var decoded wire
	if contractjson.DecodeObjectBytes(source, MaxRequestBytes, &decoded) != nil ||
		ValidateAssumeServiceRoleRequest(AssumeServiceRoleRequest(decoded)) != nil {
		return contractjson.ErrInvalidDocument
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(source, &fields) != nil || bytes.Equal(bytes.TrimSpace(fields["durationSeconds"]), []byte("null")) {
		return contractjson.ErrInvalidDocument
	}
	*value = AssumeServiceRoleRequest(decoded)
	return nil
}
