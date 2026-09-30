package postgres

import (
	"context"
	"encoding/json"

	iamv1 "github.com/xiak/matrix/api/iam/v1"
	"github.com/xiak/matrix/app/service/iam/internal/usecase/identityaccess"
)

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
