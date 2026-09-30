package identityaccess

import (
	"cmp"
	"context"
	"slices"
	"time"

	auditv1 "github.com/xiak/matrix/api/audit/v1"
	iamv1 "github.com/xiak/matrix/api/iam/v1"
	"github.com/xiak/matrix/app/service/iam/internal/authority"
)

// ListServiceRoleTemplates returns release-owned template metadata only after
// the current user is authorized in their authenticated account. An ACTIVE
// template is not account consent and this projection contains no service
// credential or account-selected authority.
func (service *Authority) ListServiceRoleTemplates(ctx context.Context, credential iamv1.Secret, requestID string) (iamv1.ServiceRoleTemplateList, error) {
	if iamv1.ValidateID("requestId", requestID) != nil {
		return iamv1.ServiceRoleTemplateList{}, ErrInvalidArgument
	}
	return withAccountAuthorization(service, ctx, credential, iamv1.ActionIAMServiceRoleTemplateList,
		iamv1.AuthorizationResourceInstance, "", iamv1.ResourceReference{Kind: iamv1.ResourceAccount}, requestID,
		func(_ context.Context, _ Transaction, _ SessionCredential, _ iamv1.AuthorizationDecision, _ time.Time) (iamv1.ServiceRoleTemplateList, error) {
			templates, err := authority.ServiceRoleTemplates()
			if err != nil {
				return iamv1.ServiceRoleTemplateList{}, ErrUnavailable
			}
			slices.SortFunc(templates, func(left, right iamv1.ServiceRoleTemplate) int {
				return cmp.Compare(left.ID, right.ID)
			})
			result := iamv1.ServiceRoleTemplateList{
				APIVersion: iamv1.APIVersion,
				Kind:       "ServiceRoleTemplateList",
				Items:      templates,
			}
			if iamv1.ValidateServiceRoleTemplateList(result) != nil {
				return iamv1.ServiceRoleTemplateList{}, ErrUnavailable
			}
			return result, nil
		})
}

// ListServiceLinkedRoles observes only consent owned by the authenticated
// Account. Template publication is deliberately separate, and binding counts
// are observations rather than cached authorization results.
func (service *Authority) ListServiceLinkedRoles(ctx context.Context, credential iamv1.Secret, after, requestID string) (iamv1.ServiceLinkedRoleList, error) {
	if iamv1.ValidateID("requestId", requestID) != nil || (after != "" && iamv1.ValidatePageCursor(after) != nil) {
		return iamv1.ServiceLinkedRoleList{}, ErrInvalidArgument
	}
	return withAccountAuthorization(service, ctx, credential, iamv1.ActionIAMServiceLinkedRoleList,
		iamv1.AuthorizationResourceInstance, "", iamv1.ResourceReference{Kind: iamv1.ResourceAccount}, requestID,
		func(ctx context.Context, tx Transaction, subject SessionCredential, decision iamv1.AuthorizationDecision, now time.Time) (iamv1.ServiceLinkedRoleList, error) {
			position, query, err := service.directoryPosition(ctx, tx, subject, decision, after, now)
			if err != nil {
				return iamv1.ServiceLinkedRoleList{}, err
			}
			result, err := tx.ListServiceLinkedRoles(ctx, AccountRead{AccountID: subject.Subject.Organization.ID,
				ActorPrincipalID: subject.Subject.Principal.ID, DecisionID: decision.ID, After: position})
			if err != nil {
				return iamv1.ServiceLinkedRoleList{}, err
			}
			result.NextAfter, err = service.sealDirectoryPage(subject, query, result.NextAfter, now)
			if err != nil || iamv1.ValidateServiceLinkedRoleList(result) != nil {
				return iamv1.ServiceLinkedRoleList{}, ErrUnavailable
			}
			return result, nil
		})
}

// GetServiceLinkedRole authorizes the exact SERVICE_LINKED Role on every page.
// The route never falls back to the ordinary customer Role projection.
func (service *Authority) GetServiceLinkedRole(ctx context.Context, credential iamv1.Secret, id iamv1.RoleID, after, requestID string) (iamv1.ServiceLinkedRoleAccess, error) {
	if iamv1.ValidateID("roleId", string(id)) != nil || iamv1.ValidateID("requestId", requestID) != nil ||
		(after != "" && iamv1.ValidatePageCursor(after) != nil) {
		return iamv1.ServiceLinkedRoleAccess{}, ErrInvalidArgument
	}
	return withAccountAuthorization(service, ctx, credential, iamv1.ActionIAMServiceLinkedRoleRead,
		iamv1.AuthorizationResourceInstance, "", iamv1.ResourceReference{Kind: iamv1.ResourceRole, ID: string(id)}, requestID,
		func(ctx context.Context, tx Transaction, subject SessionCredential, decision iamv1.AuthorizationDecision, now time.Time) (iamv1.ServiceLinkedRoleAccess, error) {
			position, query, err := service.directoryPosition(ctx, tx, subject, decision, after, now)
			if err != nil {
				return iamv1.ServiceLinkedRoleAccess{}, err
			}
			result, err := tx.ReadServiceLinkedRole(ctx, ServiceLinkedRoleRead{AccountRead: AccountRead{
				AccountID: subject.Subject.Organization.ID, ActorPrincipalID: subject.Subject.Principal.ID,
				DecisionID: decision.ID, After: position}, RoleID: id})
			if err != nil {
				return iamv1.ServiceLinkedRoleAccess{}, err
			}
			result.NextAfter, err = service.sealDirectoryPage(subject, query, result.NextAfter, now)
			if err != nil || iamv1.ValidateServiceLinkedRoleAccess(result) != nil || result.Relation.Role.ID != id {
				return iamv1.ServiceLinkedRoleAccess{}, ErrUnavailable
			}
			return result, nil
		})
}

// CreateWorkloadRoleBinding consumes one product-owned workload admission and
// the current USER's IAM management authority in one serializable transaction.
// The service and USER credentials derive every identity; the command contains
// no Account, Role, installation, principal or purpose selector.
func (service *Authority) CreateWorkloadRoleBinding(
	ctx context.Context,
	serviceCredential iamv1.Secret,
	subjectCredential iamv1.Secret,
	request iamv1.CreateWorkloadRoleBindingRequest,
) (iamv1.ServiceLinkedRoleAccess, error) {
	if iamv1.ValidateCreateWorkloadRoleBindingRequest(request) != nil {
		return iamv1.ServiceLinkedRoleAccess{}, ErrInvalidArgument
	}
	template, found, err := authority.LookupServiceRoleTemplate(request.Template)
	if err != nil {
		return iamv1.ServiceLinkedRoleAccess{}, ErrUnavailable
	}
	if !found || template.Status != iamv1.ServiceRoleTemplateActive {
		return iamv1.ServiceLinkedRoleAccess{}, ErrConflict
	}
	workloadRegistered := false
	for _, workload := range template.Spec.Workloads {
		if workload.ResourceKind == request.Authorization.Resource.Kind && workload.BindAction == request.Authorization.Action {
			workloadRegistered = true
			break
		}
	}
	if !workloadRegistered || request.Authorization.Profile.Product != template.Spec.Product {
		return iamv1.ServiceLinkedRoleAccess{}, ErrInvalidArgument
	}
	requestDigest, err := digestSanitized("workload-role-binding-create", request)
	if err != nil {
		return iamv1.ServiceLinkedRoleAccess{}, err
	}
	var result iamv1.ServiceLinkedRoleAccess
	denied := false
	err = service.withinTransaction(ctx, func(transactionContext context.Context, transaction Transaction) error {
		denied = false
		now, err := transactionTime(transactionContext, transaction)
		if err != nil {
			return err
		}
		caller, err := service.authenticateService(transactionContext, transaction, serviceCredential)
		if err != nil {
			return err
		}
		if caller.Identity.Purpose != template.Spec.ServicePurpose {
			denied = true
			return nil
		}
		subject, err := service.authenticateSession(transactionContext, transaction, subjectCredential, now)
		if err != nil {
			return err
		}
		if err := transaction.LockWorkloadRoleBindingSources(transactionContext,
			subject.Subject.Organization.ID, subject.Subject.Principal.ID, subject.Subject.Session.ID,
			caller.LookupDigest, template.Spec.ServicePurpose); err != nil {
			return err
		}
		authorizationDigest, err := digestSanitized("authorization", request.Authorization)
		if err != nil {
			return err
		}
		workloadDecision, err := service.decideAndRecord(transactionContext, transaction, request.Authorization, authorizationDigest, now,
			authorizationActor{organizationID: subject.Subject.Organization.ID,
				subject: iamv1.Subject{Type: iamv1.SubjectUser, ID: string(subject.Subject.Principal.ID)}},
			func(decisionID iamv1.DecisionID) (authority.AuthorizationEvaluation, error) {
				return authority.Decide(subject.Subject, caller.Identity.Purpose, request.Authorization, decisionID, now)
			})
		if err != nil {
			return err
		}
		if !workloadDecision.Allowed {
			denied = true
			return nil
		}

		roleID, trustID, bindingID, err := serviceRoleConsentIdentities(subject, caller, request)
		if err != nil {
			return err
		}
		roleCreationDecision, err := service.managementDecision(transactionContext, transaction, subject,
			iamv1.ActionIAMServiceLinkedRoleCreate,
			iamv1.ResourceReference{Kind: iamv1.ResourceAccount, ID: string(subject.Subject.Organization.ID)},
			iamv1.AuthorizationResourceInstance, "", request.Authorization.RequestID, now)
		if err != nil {
			return err
		}
		if !roleCreationDecision.Allowed {
			denied = true
			return nil
		}
		rolePassDecision, err := service.managementDecision(transactionContext, transaction, subject,
			iamv1.ActionIAMRolePass, iamv1.ResourceReference{Kind: iamv1.ResourceRole, ID: string(roleID)},
			iamv1.AuthorizationResourceInstance, "", request.Authorization.RequestID, now)
		if err != nil {
			return err
		}
		if !rolePassDecision.Allowed {
			denied = true
			return nil
		}

		emptyTrust := iamv1.TrustPolicyDocument{LanguageVersion: iamv1.TrustPolicyLanguageVersion, Statements: []iamv1.TrustPolicyStatement{}}
		_, trustDigest, err := iamv1.CanonicalizeTrustPolicyDocument(emptyTrust)
		if err != nil {
			return ErrUnavailable
		}
		role := iamv1.Role{APIVersion: iamv1.APIVersion, Kind: "Role", ID: roleID,
			AccountID: subject.Subject.Organization.ID, Name: template.Spec.RoleName, Description: template.Spec.RoleDescription,
			Tags: []iamv1.RoleTag{}, Management: iamv1.RoleServiceLinked, Status: iamv1.RoleActive,
			MaxSessionDurationSeconds: template.Spec.MaxSessionDurationSeconds, ResourceVersion: 1,
			CurrentTrustVersionID: trustID, CreatedAt: now, UpdatedAt: now}
		trust := iamv1.RoleTrustVersion{APIVersion: iamv1.APIVersion, Kind: "RoleTrustVersion", ID: trustID,
			AccountID: role.AccountID, RoleID: role.ID, Document: emptyTrust, ContentDigest: trustDigest, CreatedAt: now}
		binding := iamv1.WorkloadRoleBinding{APIVersion: iamv1.APIVersion, Kind: "WorkloadRoleBinding", ID: bindingID,
			AccountID: role.AccountID, RoleID: role.ID, Template: template.Reference(), Workload: request.Authorization.Resource,
			Status: iamv1.WorkloadRoleBindingActive, ResourceVersion: 1, CreatedAt: now, UpdatedAt: now}
		roleEvent, err := service.newManagementEvent(subject, auditv1.ActionIAMServiceLinkedRoleCreated,
			auditv1.TargetRole, string(role.ID), roleCreationDecision.ID, requestDigest, request.Authorization.RequestID, now)
		if err != nil {
			return err
		}
		bindingEvent, err := service.newManagementEvent(subject, auditv1.ActionIAMWorkloadRoleBindingCreated,
			auditv1.TargetWorkloadRoleBinding, string(binding.ID), workloadDecision.ID, requestDigest, request.Authorization.RequestID, now)
		if err != nil {
			return err
		}
		result, err = transaction.CreateWorkloadRoleBinding(transactionContext, WorkloadRoleBindingCreation{
			AccountID: role.AccountID, ActorPrincipalID: subject.Subject.Principal.ID, ActorSessionID: subject.Subject.Session.ID,
			ServiceLookupDigest: caller.LookupDigest, Request: request, Template: template, Role: role, TrustVersion: trust, Binding: binding,
			WorkloadDecisionID: workloadDecision.ID, RoleCreationDecisionID: roleCreationDecision.ID,
			RolePassDecisionID: rolePassDecision.ID, RequestDigest: requestDigest,
			RoleCreatedAuditEvent: roleEvent, BindingCreatedAuditEvent: bindingEvent,
		})
		return err
	})
	if err != nil {
		return iamv1.ServiceLinkedRoleAccess{}, err
	}
	if denied {
		return iamv1.ServiceLinkedRoleAccess{}, ErrForbidden
	}
	if iamv1.ValidateServiceLinkedRoleAccess(result) != nil || len(result.Bindings) != 1 ||
		result.Relation.Template != request.Template || result.Bindings[0].Workload != request.Authorization.Resource {
		return iamv1.ServiceLinkedRoleAccess{}, ErrUnavailable
	}
	return result, nil
}

func serviceRoleConsentIdentities(subject SessionCredential, caller ServiceCredential,
	request iamv1.CreateWorkloadRoleBindingRequest) (iamv1.RoleID, iamv1.RoleTrustVersionID, iamv1.WorkloadRoleBindingID, error) {
	roleDigest, err := digestSanitized("service-linked-role-identity", struct {
		AccountID        iamv1.AccountID                    `json:"accountId"`
		Template         iamv1.ServiceRoleTemplateReference `json:"template"`
		ServicePrincipal iamv1.ServicePrincipalReference    `json:"servicePrincipal"`
	}{subject.Subject.Organization.ID, request.Template, iamv1.ServicePrincipalReference{
		InstallationID: caller.Identity.InstallationID, PrincipalID: caller.Identity.PrincipalID, Purpose: caller.Identity.Purpose,
	}})
	if err != nil {
		return "", "", "", err
	}
	roleID := iamv1.RoleID("slr-" + roleDigest[len("sha256:"):])
	trustDigest, err := digestSanitized("service-linked-role-trust-identity", struct {
		RoleID   iamv1.RoleID                       `json:"roleId"`
		Template iamv1.ServiceRoleTemplateReference `json:"template"`
	}{roleID, request.Template})
	if err != nil {
		return "", "", "", err
	}
	bindingDigest, err := digestSanitized("workload-role-binding-identity", struct {
		AccountID iamv1.AccountID                    `json:"accountId"`
		Template  iamv1.ServiceRoleTemplateReference `json:"template"`
		Workload  iamv1.ResourceReference            `json:"workload"`
		RequestID string                             `json:"requestId"`
	}{subject.Subject.Organization.ID, request.Template,
		request.Authorization.Resource, request.Authorization.RequestID})
	if err != nil {
		return "", "", "", err
	}
	return roleID, iamv1.RoleTrustVersionID("trust-" + trustDigest[len("sha256:"):]),
		iamv1.WorkloadRoleBindingID("wrb-" + bindingDigest[len("sha256:"):]), nil
}
