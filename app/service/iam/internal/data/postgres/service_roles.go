package postgres

import (
	"context"
	"encoding/json"
	"reflect"
	"time"

	iamv1 "github.com/xiak/matrix/api/iam/v1"
	"github.com/xiak/matrix/app/service/iam/internal/usecase/identityaccess"
)

func (value *transaction) ReadServiceRoleAssumption(
	ctx context.Context,
	read identityaccess.ServiceRoleAssumptionRead,
) (identityaccess.ServiceRoleAssumption, error) {
	if iamv1.ValidateDigest("serviceLookupDigest", read.ServiceLookupDigest) != nil ||
		iamv1.ValidateServiceIdentity(read.Identity) != nil ||
		iamv1.ValidateID("bindingId", string(read.BindingID)) != nil ||
		iamv1.ValidateID("requestId", read.RequestID) != nil {
		return identityaccess.ServiceRoleAssumption{}, identityaccess.ErrInvalidArgument
	}
	var encoded []byte
	if err := value.tx.QueryRow(ctx, `SELECT iam.read_service_role_assumption($1,$2,$3)`,
		read.ServiceLookupDigest, read.BindingID, read.RequestID).Scan(&encoded); err != nil {
		return identityaccess.ServiceRoleAssumption{}, mapAuthorizationDatabaseError("read IAM service role assumption", err)
	}
	defer clear(encoded)
	type serviceLinkedRoleWire iamv1.ServiceLinkedRole
	type workloadRoleBindingWire iamv1.WorkloadRoleBinding
	var stored struct {
		Relation           serviceLinkedRoleWire                     `json:"relation"`
		Binding            workloadRoleBindingWire                   `json:"binding"`
		Template           iamv1.ServiceRoleTemplate                 `json:"template"`
		SecurityGeneration uint64                                    `json:"securityGeneration"`
		Existing           *identityaccess.ServiceRoleSessionReceipt `json:"existing,omitempty"`
	}
	if json.Unmarshal(encoded, &stored) != nil {
		return identityaccess.ServiceRoleAssumption{}, identityaccess.ErrUnavailable
	}
	relation := iamv1.ServiceLinkedRole(stored.Relation)
	binding := iamv1.WorkloadRoleBinding(stored.Binding)
	normalizeRole(&relation.Role)
	binding.CreatedAt, binding.UpdatedAt = binding.CreatedAt.UTC(), binding.UpdatedAt.UTC()
	if binding.RevokedAt != nil {
		revoked := binding.RevokedAt.UTC()
		binding.RevokedAt = &revoked
	}
	if stored.Existing != nil {
		normalizeRoleSession(&stored.Existing.Session)
	}
	result := identityaccess.ServiceRoleAssumption{Relation: relation, Binding: binding,
		Template: stored.Template, SecurityGeneration: stored.SecurityGeneration, Existing: stored.Existing}
	if iamv1.ValidateServiceLinkedRole(result.Relation) != nil || iamv1.ValidateWorkloadRoleBinding(result.Binding) != nil ||
		iamv1.ValidateServiceRoleTemplate(result.Template) != nil || result.SecurityGeneration == 0 || result.SecurityGeneration > 9007199254740991 ||
		result.Relation.ServicePrincipal != (iamv1.ServicePrincipalReference{InstallationID: read.Identity.InstallationID,
			PrincipalID: read.Identity.PrincipalID, Purpose: read.Identity.Purpose}) || result.Binding.ID != read.BindingID ||
		result.Binding.AccountID != result.Relation.Role.AccountID || result.Binding.RoleID != result.Relation.Role.ID ||
		result.Binding.Template != result.Relation.Template || result.Template.Reference() != result.Relation.Template {
		return identityaccess.ServiceRoleAssumption{}, identityaccess.ErrUnavailable
	}
	if result.Existing != nil && (iamv1.ValidateRoleSession(result.Existing.Session) != nil ||
		result.Existing.Session.SourceServicePrincipalID != read.Identity.PrincipalID ||
		result.Existing.BindingID != read.BindingID || iamv1.ValidateDigest("requestDigest", result.Existing.RequestDigest) != nil) {
		return identityaccess.ServiceRoleAssumption{}, identityaccess.ErrUnavailable
	}
	return result, nil
}

func (value *transaction) IssueServiceRoleSession(
	ctx context.Context,
	mutation identityaccess.ServiceRoleSessionIssuance,
) (iamv1.RoleSession, error) {
	if iamv1.ValidateServiceIdentity(mutation.Identity) != nil || iamv1.ValidateRoleSession(mutation.Session) != nil ||
		iamv1.ValidateAssumeServiceRoleRequest(mutation.Request) != nil || mutation.Request.BindingID != mutation.BindingID ||
		mutation.Request.RequestID != mutation.RequestID ||
		mutation.Session.Status != iamv1.SessionActive || mutation.Session.SourceServicePrincipalID != mutation.Identity.PrincipalID ||
		mutation.Session.SourceUserID != "" || iamv1.ValidateDigest("serviceLookupDigest", mutation.ServiceLookupDigest) != nil ||
		iamv1.ValidateDigest("requestDigest", mutation.RequestDigest) != nil || iamv1.ValidateDigest("lookupDigest", mutation.LookupDigest) != nil ||
		iamv1.ValidateDigest("verificationDigest", mutation.VerificationDigest) != nil || mutation.DurationSeconds < iamv1.MinRoleSessionDurationSeconds ||
		mutation.DurationSeconds > iamv1.MaxRoleSessionDurationSeconds || mutation.ExpectedBindingVersion == 0 ||
		mutation.ExpectedSecurityGeneration == 0 || mutation.ExpectedSecurityGeneration > 9007199254740991 {
		return iamv1.RoleSession{}, identityaccess.ErrInvalidArgument
	}
	requestDocument, err := json.Marshal(mutation.Request)
	if err != nil {
		return iamv1.RoleSession{}, identityaccess.ErrInvalidArgument
	}
	defer clear(requestDocument)
	intent, err := json.Marshal(struct {
		SessionID                  iamv1.RoleSessionID `json:"sessionId"`
		RequestID                  string              `json:"requestId"`
		RequestDigest              string              `json:"requestDigest"`
		ExpectedBindingVersion     uint64              `json:"expectedBindingVersion"`
		ExpectedSecurityGeneration uint64              `json:"expectedSecurityGeneration"`
		DurationSeconds            uint32              `json:"durationSeconds"`
		IssuedAt                   time.Time           `json:"issuedAt"`
		ExpiresAt                  time.Time           `json:"expiresAt"`
	}{mutation.Session.ID, mutation.RequestID, mutation.RequestDigest, mutation.ExpectedBindingVersion,
		mutation.ExpectedSecurityGeneration, mutation.DurationSeconds, mutation.Session.IssuedAt, mutation.Session.ExpiresAt})
	if err != nil {
		return iamv1.RoleSession{}, identityaccess.ErrInvalidArgument
	}
	defer clear(intent)
	event, err := marshalManagementEvent(mutation.AuditEvent)
	if err != nil {
		return iamv1.RoleSession{}, err
	}
	defer clear(event)
	var encoded []byte
	err = value.tx.QueryRow(ctx, `SELECT iam.issue_service_role_session($1,$2,$3,$4::jsonb,$5,$6,$7::jsonb)`,
		mutation.ServiceLookupDigest, mutation.BindingID, string(requestDocument), intent,
		mutation.LookupDigest, mutation.VerificationDigest, event).Scan(&encoded)
	if err != nil {
		return iamv1.RoleSession{}, mapAuthorizationDatabaseError("issue IAM service role session", err)
	}
	result, err := decodeServiceRoleSession(encoded, mutation.Identity.PrincipalID)
	if err != nil || !reflect.DeepEqual(result, mutation.Session) {
		return iamv1.RoleSession{}, identityaccess.ErrUnavailable
	}
	return result, nil
}

func (value *transaction) ReadServiceRoleSessionByRequest(
	ctx context.Context,
	read identityaccess.ServiceRoleSessionRead,
) (iamv1.RoleSession, bool, error) {
	if iamv1.ValidateDigest("serviceLookupDigest", read.ServiceLookupDigest) != nil ||
		iamv1.ValidateServiceIdentity(read.Identity) != nil || iamv1.ValidateID("requestId", read.RequestID) != nil {
		return iamv1.RoleSession{}, false, identityaccess.ErrInvalidArgument
	}
	var encoded []byte
	if err := value.tx.QueryRow(ctx, `SELECT iam.read_service_role_session_by_request($1,$2)`,
		read.ServiceLookupDigest, read.RequestID).Scan(&encoded); err != nil {
		return iamv1.RoleSession{}, false, mapAuthorizationDatabaseError("read IAM service role issuance", err)
	}
	if encoded == nil {
		return iamv1.RoleSession{}, false, nil
	}
	result, err := decodeServiceRoleSession(encoded, read.Identity.PrincipalID)
	return result, err == nil, err
}

func decodeServiceRoleSession(encoded []byte, principal iamv1.PrincipalID) (iamv1.RoleSession, error) {
	defer clear(encoded)
	var result iamv1.RoleSession
	if json.Unmarshal(encoded, &result) != nil {
		return iamv1.RoleSession{}, identityaccess.ErrUnavailable
	}
	normalizeRoleSession(&result)
	if iamv1.ValidateRoleSession(result) != nil || result.SourceServicePrincipalID != principal || result.SourceUserID != "" {
		return iamv1.RoleSession{}, identityaccess.ErrUnavailable
	}
	return result, nil
}

func (value *transaction) LockWorkloadRoleBindingSources(ctx context.Context, accountID iamv1.AccountID,
	actor iamv1.PrincipalID, session iamv1.SessionID, serviceLookupDigest string, purpose iamv1.ServicePurpose,
) error {
	if iamv1.ValidateID("accountId", string(accountID)) != nil ||
		iamv1.ValidateID("actorPrincipalId", string(actor)) != nil ||
		iamv1.ValidateID("actorSessionId", string(session)) != nil ||
		iamv1.ValidateDigest("serviceLookupDigest", serviceLookupDigest) != nil {
		return identityaccess.ErrInvalidArgument
	}
	var locked bool
	if err := value.tx.QueryRow(ctx, `SELECT iam.lock_workload_role_binding_sources($1,$2,$3,$4,$5)`,
		accountID, actor, session, serviceLookupDigest, purpose).Scan(&locked); err != nil {
		return mapAuthorizationDatabaseError("lock IAM workload role binding sources", err)
	}
	if !locked {
		return identityaccess.ErrUnavailable
	}
	return nil
}

// CreateWorkloadRoleBinding crosses one deliberately narrow database
// boundary. The database re-derives every identity from the request document,
// the current USER Session, the service credential and the release template;
// these encoded values are commitments, not caller selectors.
func (value *transaction) CreateWorkloadRoleBinding(
	ctx context.Context,
	mutation identityaccess.WorkloadRoleBindingCreation,
) (iamv1.ServiceLinkedRoleAccess, error) {
	if iamv1.ValidateID("actorPrincipalId", string(mutation.ActorPrincipalID)) != nil ||
		iamv1.ValidateID("actorSessionId", string(mutation.ActorSessionID)) != nil ||
		iamv1.ValidateDigest("serviceLookupDigest", mutation.ServiceLookupDigest) != nil ||
		iamv1.ValidateDigest("requestDigest", mutation.RequestDigest) != nil ||
		iamv1.ValidateCreateWorkloadRoleBindingRequest(mutation.Request) != nil ||
		mutation.Request.Template != mutation.Template.Reference() ||
		iamv1.ValidateServiceRoleTemplate(mutation.Template) != nil ||
		iamv1.ValidateRole(mutation.Role) != nil || mutation.Role.Management != iamv1.RoleServiceLinked ||
		iamv1.ValidateRoleTrustVersion(mutation.TrustVersion) != nil ||
		iamv1.ValidateWorkloadRoleBinding(mutation.Binding) != nil ||
		mutation.AccountID != mutation.Role.AccountID || mutation.Binding.AccountID != mutation.AccountID ||
		mutation.Binding.RoleID != mutation.Role.ID || mutation.Binding.Template != mutation.Template.Reference() ||
		mutation.Binding.Workload != mutation.Request.Authorization.Resource {
		return iamv1.ServiceLinkedRoleAccess{}, identityaccess.ErrInvalidArgument
	}
	requestDocument, err := json.Marshal(mutation.Request)
	if err != nil {
		return iamv1.ServiceLinkedRoleAccess{}, identityaccess.ErrInvalidArgument
	}
	defer clear(requestDocument)
	template, err := json.Marshal(mutation.Template)
	if err != nil {
		return iamv1.ServiceLinkedRoleAccess{}, identityaccess.ErrInvalidArgument
	}
	defer clear(template)
	role, err := json.Marshal(mutation.Role)
	if err != nil {
		return iamv1.ServiceLinkedRoleAccess{}, identityaccess.ErrInvalidArgument
	}
	defer clear(role)
	trust, err := encodeRoleTrust(mutation.TrustVersion)
	if err != nil {
		return iamv1.ServiceLinkedRoleAccess{}, err
	}
	defer clear(trust)
	binding, err := json.Marshal(mutation.Binding)
	if err != nil {
		return iamv1.ServiceLinkedRoleAccess{}, identityaccess.ErrInvalidArgument
	}
	defer clear(binding)
	roleEvent, err := marshalManagementEvent(mutation.RoleCreatedAuditEvent)
	if err != nil {
		return iamv1.ServiceLinkedRoleAccess{}, err
	}
	defer clear(roleEvent)
	bindingEvent, err := marshalManagementEvent(mutation.BindingCreatedAuditEvent)
	if err != nil {
		return iamv1.ServiceLinkedRoleAccess{}, err
	}
	defer clear(bindingEvent)

	var encoded []byte
	err = value.tx.QueryRow(ctx, `SELECT iam.create_workload_role_binding(
        $1,$2,$3,$4,$5,$6,$7::jsonb,$8::jsonb,$9::jsonb,$10::jsonb,$11,$12,$13,$14::jsonb,$15::jsonb)`,
		mutation.AccountID, mutation.ActorPrincipalID, mutation.ActorSessionID, mutation.ServiceLookupDigest,
		string(requestDocument), mutation.RequestDigest, template, role, trust, binding,
		mutation.WorkloadDecisionID, mutation.RoleCreationDecisionID, mutation.RolePassDecisionID,
		roleEvent, bindingEvent).Scan(&encoded)
	if err != nil {
		return iamv1.ServiceLinkedRoleAccess{}, mapAuthorizationDatabaseError("create IAM workload role binding", err)
	}
	if int64(len(encoded)) > iamv1.MaxRoleAccessBytes {
		return iamv1.ServiceLinkedRoleAccess{}, identityaccess.ErrUnavailable
	}
	result, err := decodeServiceLinkedRoleAccess(encoded)
	if err != nil {
		return iamv1.ServiceLinkedRoleAccess{}, identityaccess.ErrUnavailable
	}
	if iamv1.ValidateServiceLinkedRoleAccess(result) != nil || len(result.Bindings) != 1 ||
		result.Relation.Role.ID != mutation.Role.ID || result.Relation.Role.AccountID != mutation.AccountID ||
		result.Relation.Template != mutation.Template.Reference() ||
		result.Relation.PermissionCeiling != mutation.Template.Spec.PolicyVersion ||
		result.Bindings[0].ID != mutation.Binding.ID || result.Bindings[0].Workload != mutation.Binding.Workload {
		return iamv1.ServiceLinkedRoleAccess{}, identityaccess.ErrUnavailable
	}
	return result, nil
}

// PrepareWorkloadRoleBindingRevocation locks the exact Role and binding after
// the shared source lock has authenticated the service and USER. PostgreSQL
// re-derives the service relationship, so this lookup cannot be used to probe
// another Account or another service principal.
func (value *transaction) PrepareWorkloadRoleBindingRevocation(
	ctx context.Context,
	accountID iamv1.AccountID,
	bindingID iamv1.WorkloadRoleBindingID,
	serviceLookupDigest string,
	purpose iamv1.ServicePurpose,
) (iamv1.ServiceLinkedRoleAccess, error) {
	if iamv1.ValidateID("accountId", string(accountID)) != nil ||
		iamv1.ValidateID("bindingId", string(bindingID)) != nil ||
		iamv1.ValidateDigest("serviceLookupDigest", serviceLookupDigest) != nil {
		return iamv1.ServiceLinkedRoleAccess{}, identityaccess.ErrInvalidArgument
	}
	var encoded []byte
	if err := value.tx.QueryRow(ctx, `SELECT iam.prepare_workload_role_binding_revocation($1,$2,$3,$4)`,
		accountID, bindingID, serviceLookupDigest, purpose).Scan(&encoded); err != nil {
		return iamv1.ServiceLinkedRoleAccess{}, mapAuthorizationDatabaseError("prepare IAM workload role binding revocation", err)
	}
	if int64(len(encoded)) > iamv1.MaxRoleAccessBytes {
		return iamv1.ServiceLinkedRoleAccess{}, identityaccess.ErrUnavailable
	}
	result, err := decodeServiceLinkedRoleAccess(encoded)
	if err != nil || iamv1.ValidateServiceLinkedRoleAccess(result) != nil || len(result.Bindings) != 1 ||
		result.Bindings[0].ID != bindingID || result.Bindings[0].AccountID != accountID ||
		result.Bindings[0].RoleID != result.Relation.Role.ID {
		return iamv1.ServiceLinkedRoleAccess{}, identityaccess.ErrUnavailable
	}
	return result, nil
}

func (value *transaction) RevokeWorkloadRoleBinding(
	ctx context.Context,
	mutation identityaccess.WorkloadRoleBindingRevocation,
) (iamv1.WorkloadRoleBinding, error) {
	if iamv1.ValidateID("accountId", string(mutation.AccountID)) != nil ||
		iamv1.ValidateID("bindingId", string(mutation.BindingID)) != nil ||
		iamv1.ValidateID("actorPrincipalId", string(mutation.ActorPrincipalID)) != nil ||
		iamv1.ValidateID("actorSessionId", string(mutation.ActorSessionID)) != nil ||
		iamv1.ValidateDigest("serviceLookupDigest", mutation.ServiceLookupDigest) != nil ||
		iamv1.ValidateDigest("requestDigest", mutation.RequestDigest) != nil ||
		iamv1.ValidateRevokeWorkloadRoleBindingRequest(mutation.Request) != nil {
		return iamv1.WorkloadRoleBinding{}, identityaccess.ErrInvalidArgument
	}
	requestDocument, err := json.Marshal(mutation.Request)
	if err != nil {
		return iamv1.WorkloadRoleBinding{}, identityaccess.ErrInvalidArgument
	}
	defer clear(requestDocument)
	event, err := marshalManagementEvent(mutation.AuditEvent)
	if err != nil {
		return iamv1.WorkloadRoleBinding{}, err
	}
	defer clear(event)
	var encoded []byte
	err = value.tx.QueryRow(ctx, `SELECT iam.revoke_workload_role_binding(
        $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12::jsonb)`,
		mutation.AccountID, mutation.ActorPrincipalID, mutation.ActorSessionID,
		mutation.ServiceLookupDigest, mutation.ServicePurpose, mutation.BindingID,
		string(requestDocument), mutation.RequestDigest, mutation.WorkloadDecisionID,
		mutation.BindingRevokeDecisionID, mutation.RolePassDecisionID, event).Scan(&encoded)
	if err != nil {
		return iamv1.WorkloadRoleBinding{}, mapAuthorizationDatabaseError("revoke IAM workload role binding", err)
	}
	if int64(len(encoded)) > iamv1.MaxRequestBytes {
		return iamv1.WorkloadRoleBinding{}, identityaccess.ErrUnavailable
	}
	result, err := decodeWorkloadRoleBinding(encoded)
	if err != nil || iamv1.ValidateWorkloadRoleBinding(result) != nil || result.ID != mutation.BindingID ||
		result.AccountID != mutation.AccountID || result.Status != iamv1.WorkloadRoleBindingRevoked ||
		result.ResourceVersion != mutation.Request.ResourceVersion+1 ||
		result.Workload != mutation.Request.Authorization.Resource {
		return iamv1.WorkloadRoleBinding{}, identityaccess.ErrUnavailable
	}
	return result, nil
}

// ListServiceLinkedRoles reads the bounded Account-owned relation directory.
// PostgreSQL returns one look-ahead row so this adapter, rather than SQL or a
// caller, remains the owner of public page boundaries.
func (value *transaction) ListServiceLinkedRoles(
	ctx context.Context,
	read identityaccess.AccountRead,
) (iamv1.ServiceLinkedRoleList, error) {
	var encoded []byte
	if err := value.tx.QueryRow(ctx, `SELECT iam.list_service_linked_roles($1,$2,$3,$4)`,
		read.AccountID, read.ActorPrincipalID, read.DecisionID, read.After).Scan(&encoded); err != nil {
		return iamv1.ServiceLinkedRoleList{}, mapAuthorizationDatabaseError("list IAM service-linked roles", err)
	}
	type serviceLinkedRoleWire iamv1.ServiceLinkedRole
	type listingWire struct {
		Relation           serviceLinkedRoleWire `json:"relation"`
		BindingCount       uint64                `json:"bindingCount"`
		ActiveBindingCount uint64                `json:"activeBindingCount"`
	}
	var wire []listingWire
	if int64(len(encoded)) > iamv1.MaxServiceLinkedRoleListBytes || json.Unmarshal(encoded, &wire) != nil ||
		wire == nil || len(wire) > iamv1.DirectoryPageSize+1 {
		return iamv1.ServiceLinkedRoleList{}, identityaccess.ErrUnavailable
	}
	result := iamv1.ServiceLinkedRoleList{
		APIVersion: iamv1.APIVersion,
		Kind:       "ServiceLinkedRoleList",
		AccountID:  read.AccountID,
		Items:      make([]iamv1.ServiceLinkedRoleListing, len(wire)),
	}
	previous := iamv1.RoleID(read.After)
	for index := range wire {
		item := iamv1.ServiceLinkedRoleListing{
			Relation:           iamv1.ServiceLinkedRole(wire[index].Relation),
			BindingCount:       wire[index].BindingCount,
			ActiveBindingCount: wire[index].ActiveBindingCount,
		}
		normalizeRole(&item.Relation.Role)
		if iamv1.ValidateServiceLinkedRole(item.Relation) != nil || item.Relation.Role.AccountID != read.AccountID ||
			item.Relation.Role.ID <= previous || item.BindingCount == 0 || item.BindingCount > 9007199254740991 ||
			item.ActiveBindingCount > item.BindingCount {
			return iamv1.ServiceLinkedRoleList{}, identityaccess.ErrUnavailable
		}
		result.Items[index] = item
		previous = item.Relation.Role.ID
	}
	if len(result.Items) > iamv1.DirectoryPageSize {
		result.Items = result.Items[:iamv1.DirectoryPageSize]
		result.NextAfter = string(result.Items[iamv1.DirectoryPageSize-1].Relation.Role.ID)
	}
	return result, nil
}

// ReadServiceLinkedRole returns one relation and a bounded page of its durable
// workload-binding history. Revoked history is never filtered from this
// management projection; current authority remains a separately evaluated
// fact.
func (value *transaction) ReadServiceLinkedRole(
	ctx context.Context,
	read identityaccess.ServiceLinkedRoleRead,
) (iamv1.ServiceLinkedRoleAccess, error) {
	var encoded []byte
	if err := value.tx.QueryRow(ctx, `SELECT iam.read_service_linked_role($1,$2,$3,$4,$5)`,
		read.AccountID, read.ActorPrincipalID, read.DecisionID, read.RoleID, read.After).Scan(&encoded); err != nil {
		return iamv1.ServiceLinkedRoleAccess{}, mapAuthorizationDatabaseError("read IAM service-linked role", err)
	}
	if int64(len(encoded)) > iamv1.MaxRoleAccessBytes {
		return iamv1.ServiceLinkedRoleAccess{}, identityaccess.ErrUnavailable
	}
	result, err := decodeServiceLinkedRoleAccess(encoded)
	if err != nil || len(result.Bindings) > iamv1.DirectoryPageSize+1 ||
		iamv1.ValidateServiceLinkedRole(result.Relation) != nil || result.Relation.Role.AccountID != read.AccountID ||
		result.Relation.Role.ID != read.RoleID {
		return iamv1.ServiceLinkedRoleAccess{}, identityaccess.ErrUnavailable
	}
	previous := iamv1.WorkloadRoleBindingID(read.After)
	for index := range result.Bindings {
		binding := result.Bindings[index]
		if iamv1.ValidateWorkloadRoleBinding(binding) != nil || binding.AccountID != read.AccountID ||
			binding.RoleID != read.RoleID || binding.Template != result.Relation.Template || binding.ID <= previous {
			return iamv1.ServiceLinkedRoleAccess{}, identityaccess.ErrUnavailable
		}
		previous = binding.ID
	}
	if len(result.Bindings) > iamv1.DirectoryPageSize {
		result.Bindings = result.Bindings[:iamv1.DirectoryPageSize]
		result.NextAfter = string(result.Bindings[iamv1.DirectoryPageSize-1].ID)
	}
	return result, nil
}

// PostgreSQL renders timestamptz values with an explicit +00:00 suffix. That
// storage representation is normalized only inside this adapter; public IAM
// JSON remains canonical UTC and therefore continues to reject non-Z inputs.
func decodeServiceLinkedRoleAccess(encoded []byte) (iamv1.ServiceLinkedRoleAccess, error) {
	type serviceLinkedRoleWire iamv1.ServiceLinkedRole
	type workloadRoleBindingWire iamv1.WorkloadRoleBinding
	type accessWire struct {
		APIVersion string                    `json:"apiVersion"`
		Kind       string                    `json:"kind"`
		Relation   serviceLinkedRoleWire     `json:"relation"`
		Bindings   []workloadRoleBindingWire `json:"bindings"`
	}
	var wire accessWire
	if err := json.Unmarshal(encoded, &wire); err != nil {
		return iamv1.ServiceLinkedRoleAccess{}, err
	}
	result := iamv1.ServiceLinkedRoleAccess{
		APIVersion: wire.APIVersion,
		Kind:       wire.Kind,
		Relation:   iamv1.ServiceLinkedRole(wire.Relation),
		Bindings:   make([]iamv1.WorkloadRoleBinding, len(wire.Bindings)),
	}
	normalizeRole(&result.Relation.Role)
	for index := range wire.Bindings {
		result.Bindings[index] = iamv1.WorkloadRoleBinding(wire.Bindings[index])
		result.Bindings[index].CreatedAt = result.Bindings[index].CreatedAt.UTC()
		result.Bindings[index].UpdatedAt = result.Bindings[index].UpdatedAt.UTC()
		if result.Bindings[index].RevokedAt != nil {
			revoked := result.Bindings[index].RevokedAt.UTC()
			result.Bindings[index].RevokedAt = &revoked
		}
	}
	return result, nil
}

func decodeWorkloadRoleBinding(encoded []byte) (iamv1.WorkloadRoleBinding, error) {
	type workloadRoleBindingWire iamv1.WorkloadRoleBinding
	var wire workloadRoleBindingWire
	if err := json.Unmarshal(encoded, &wire); err != nil {
		return iamv1.WorkloadRoleBinding{}, err
	}
	result := iamv1.WorkloadRoleBinding(wire)
	result.CreatedAt = result.CreatedAt.UTC()
	result.UpdatedAt = result.UpdatedAt.UTC()
	if result.RevokedAt != nil {
		revoked := result.RevokedAt.UTC()
		result.RevokedAt = &revoked
	}
	return result, nil
}
