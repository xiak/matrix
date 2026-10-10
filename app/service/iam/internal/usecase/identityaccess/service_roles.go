package identityaccess

import (
	"context"
	"reflect"
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
		func(ctx context.Context, tx Transaction, subject SessionCredential, decision iamv1.AuthorizationDecision, _ time.Time) (iamv1.ServiceRoleTemplateList, error) {
			result, err := tx.ListServiceRoleTemplates(ctx, AccountRead{AccountID: subject.Subject.Organization.ID,
				ActorPrincipalID: subject.Subject.Principal.ID, DecisionID: decision.ID})
			if err != nil {
				return iamv1.ServiceRoleTemplateList{}, err
			}
			profiles, err := tx.CurrentAuthorizationProfiles(ctx)
			if err != nil {
				return iamv1.ServiceRoleTemplateList{}, err
			}
			for _, template := range result.Items {
				if template.Status != iamv1.ServiceRoleTemplateActive || iamv1.CheckServiceRoleTemplate(template, profiles) != nil {
					return iamv1.ServiceRoleTemplateList{}, ErrUnavailable
				}
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

// AssumeServiceRole exchanges one current service credential and one active
// workload binding for a short-lived Role credential. Binding is the only
// customer-side selector; every Account, Role, template and service-principal
// fact is resolved again under the transaction locks.
func (service *Authority) AssumeServiceRole(
	ctx context.Context,
	credential iamv1.Secret,
	request iamv1.AssumeServiceRoleRequest,
) (iamv1.AssumeRoleResponse, error) {
	if iamv1.ValidateAssumeServiceRoleRequest(request) != nil {
		return iamv1.AssumeRoleResponse{}, ErrInvalidArgument
	}
	requestDigest, err := digestSanitized("service-role-session-assume", request)
	if err != nil {
		return iamv1.AssumeRoleResponse{}, err
	}
	var response iamv1.AssumeRoleResponse
	err = service.withinTransaction(ctx, func(transactionContext context.Context, transaction Transaction) error {
		response = iamv1.AssumeRoleResponse{}
		now, err := transactionTime(transactionContext, transaction)
		if err != nil {
			return err
		}
		caller, err := service.authenticateService(transactionContext, transaction, credential)
		if err != nil {
			return err
		}
		profiles, err := transaction.CurrentAuthorizationProfiles(transactionContext)
		if err != nil {
			return err
		}
		read := ServiceRoleAssumptionRead{ServiceRoleSessionRead: ServiceRoleSessionRead{
			ServiceLookupDigest: caller.LookupDigest, Identity: caller.Identity, RequestID: request.RequestID,
		}, BindingID: request.BindingID}
		assumption, err := transaction.ReadServiceRoleAssumption(transactionContext, read)
		if err != nil {
			return err
		}
		if validateServiceRoleAssumption(read, assumption, profiles) != nil {
			return ErrUnavailable
		}
		if assumption.Existing != nil {
			if assumption.Existing.RequestDigest != requestDigest || assumption.Existing.BindingID != request.BindingID {
				return ErrConflict
			}
			response = iamv1.AssumeRoleResponse{Outcome: "EQUAL_REPLAY", Session: assumption.Existing.Session}
			return nil
		}
		duration := iamv1.DefaultRoleSessionDurationSeconds
		if duration > assumption.Template.Spec.MaxSessionDurationSeconds {
			duration = assumption.Template.Spec.MaxSessionDurationSeconds
		}
		if request.DurationSeconds != nil {
			duration = *request.DurationSeconds
			if duration > assumption.Template.Spec.MaxSessionDurationSeconds {
				return ErrForbidden
			}
		}
		expires := now.Add(time.Duration(duration) * time.Second)
		sessionID, err := service.config.NewID("role-session")
		if err != nil {
			return ErrUnavailable
		}
		issued, err := service.credentials.Issue(authority.CredentialRoleSession, sessionID)
		if err != nil {
			return ErrUnavailable
		}
		session := iamv1.RoleSession{APIVersion: iamv1.APIVersion, Kind: "RoleSession", ID: iamv1.RoleSessionID(sessionID),
			AccountID: assumption.Binding.AccountID, RoleID: assumption.Binding.RoleID,
			SourceServicePrincipalID: caller.Identity.PrincipalID, Status: iamv1.SessionActive, IssuedAt: now, ExpiresAt: expires}
		if iamv1.ValidateRoleSession(session) != nil {
			return ErrUnavailable
		}
		eventID, err := service.config.NewID("event")
		if err != nil {
			return ErrUnavailable
		}
		event, err := newAuditEvent(eventID, session.AccountID, "",
			auditv1.ActorReference{Type: auditv1.ActorServiceAccount, ID: auditv1.ActorID(caller.Identity.PrincipalID)},
			auditv1.ActionIAMServiceRoleSessionIssued,
			auditv1.TargetReference{Kind: auditv1.TargetRoleSession, ID: sessionID}, auditv1.ResultSucceeded, "",
			requestDigest, request.RequestID, request.RequestID, now)
		if err != nil {
			return err
		}
		stored, err := transaction.IssueServiceRoleSession(transactionContext, ServiceRoleSessionIssuance{
			ServiceRoleAssumptionRead: read, Session: session, Request: request,
			ExpectedBindingVersion: assumption.Binding.ResourceVersion, ExpectedSecurityGeneration: assumption.SecurityGeneration,
			DurationSeconds: duration, RequestDigest: requestDigest, LookupDigest: issued.LookupDigest,
			VerificationDigest: issued.VerificationDigest, AuditEvent: event,
		})
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(stored, session) {
			return ErrUnavailable
		}
		response = iamv1.AssumeRoleResponse{Outcome: "APPLIED", Session: stored, Credential: issued.Credential}
		return nil
	})
	if err != nil {
		return iamv1.AssumeRoleResponse{}, err
	}
	if iamv1.ValidateAssumeRoleResponse(response) != nil {
		return iamv1.AssumeRoleResponse{}, ErrUnavailable
	}
	return response, nil
}

func validateServiceRoleAssumption(read ServiceRoleAssumptionRead, value ServiceRoleAssumption,
	profiles []iamv1.AuthorizationProfile,
) error {
	if iamv1.ValidateServiceIdentity(read.Identity) != nil || iamv1.ValidateDigest("serviceLookupDigest", read.ServiceLookupDigest) != nil ||
		iamv1.ValidateServiceLinkedRole(value.Relation) != nil || iamv1.ValidateWorkloadRoleBinding(value.Binding) != nil ||
		iamv1.CheckServiceRoleTemplate(value.Template, profiles) != nil || value.Template.Status != iamv1.ServiceRoleTemplateActive ||
		value.SecurityGeneration == 0 || value.SecurityGeneration > 9007199254740991 ||
		value.Relation.Role.Management != iamv1.RoleServiceLinked || value.Relation.Role.Status != iamv1.RoleActive ||
		value.Relation.ServicePrincipal != (iamv1.ServicePrincipalReference{InstallationID: read.Identity.InstallationID,
			PrincipalID: read.Identity.PrincipalID, Purpose: read.Identity.Purpose}) ||
		value.Relation.Template != value.Template.Reference() || value.Relation.PermissionCeiling != value.Template.Spec.PolicyVersion ||
		value.Binding.ID != read.BindingID || value.Binding.AccountID != value.Relation.Role.AccountID ||
		value.Binding.RoleID != value.Relation.Role.ID || value.Binding.Template != value.Relation.Template ||
		value.Binding.Status != iamv1.WorkloadRoleBindingActive ||
		value.Relation.Role.MaxSessionDurationSeconds != value.Template.Spec.MaxSessionDurationSeconds {
		return ErrUnavailable
	}
	if value.Existing != nil {
		if iamv1.ValidateRoleSession(value.Existing.Session) != nil || value.Existing.Session.AccountID != value.Binding.AccountID ||
			value.Existing.Session.RoleID != value.Binding.RoleID || value.Existing.Session.SourceServicePrincipalID != read.Identity.PrincipalID ||
			value.Existing.BindingID != value.Binding.ID || iamv1.ValidateDigest("requestDigest", value.Existing.RequestDigest) != nil {
			return ErrUnavailable
		}
	}
	return nil
}

// GetServiceRoleSessionByRequest returns only the original non-secret result.
// It never replays a credential and the authenticated service principal is the
// sole namespace for the request identity.
func (service *Authority) GetServiceRoleSessionByRequest(ctx context.Context, credential iamv1.Secret, requestID string) (iamv1.RoleSession, bool, error) {
	if iamv1.ValidateID("requestId", requestID) != nil {
		return iamv1.RoleSession{}, false, ErrInvalidArgument
	}
	var result iamv1.RoleSession
	var found bool
	err := service.withinTransaction(ctx, func(transactionContext context.Context, transaction Transaction) error {
		caller, err := service.authenticateService(transactionContext, transaction, credential)
		if err != nil {
			return err
		}
		result, found, err = transaction.ReadServiceRoleSessionByRequest(transactionContext, ServiceRoleSessionRead{
			ServiceLookupDigest: caller.LookupDigest, Identity: caller.Identity, RequestID: requestID,
		})
		if err != nil || !found {
			return err
		}
		if iamv1.ValidateRoleSession(result) != nil || result.SourceServicePrincipalID != caller.Identity.PrincipalID {
			return ErrUnavailable
		}
		return nil
	})
	if err != nil {
		return iamv1.RoleSession{}, false, err
	}
	return result, found, nil
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
		subject, err := service.authenticateSession(transactionContext, transaction, subjectCredential, now)
		if err != nil {
			return err
		}
		template, found, err := transaction.ReadServiceRoleTemplate(transactionContext, request.Template)
		if err != nil {
			return err
		}
		if !found {
			return ErrConflict
		}
		profiles, err := transaction.CurrentAuthorizationProfiles(transactionContext)
		if err != nil || iamv1.CheckServiceRoleTemplate(template, profiles) != nil {
			return ErrUnavailable
		}
		profile, found, err := transaction.LookupCurrentAuthorizationProfile(transactionContext, request.Authorization.Profile)
		if err != nil {
			return err
		}
		if !found || profile.Product != template.Spec.Product ||
			iamv1.ValidateAuthorizationRequestForProfile(request.Authorization, profile) != nil {
			return ErrInvalidArgument
		}
		if caller.Identity.Purpose != template.Spec.ServicePurpose {
			denied = true
			return nil
		}
		workloadRegistered := false
		for _, workload := range template.Spec.Workloads {
			if workload.ResourceKind == request.Authorization.Resource.Kind && workload.BindAction == request.Authorization.Action {
				workloadRegistered = true
				break
			}
		}
		if !workloadRegistered || request.Authorization.Profile.Product != template.Spec.Product {
			return ErrInvalidArgument
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
				return authority.DecideWithProfile(subject.Subject, caller.Identity.Purpose, request.Authorization, profile, decisionID, now)
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
		// A known retired template is still immutable authorization context,
		// but it cannot admit a new workload. Check current caller authority
		// first so retirement cannot turn a revoked administrator's retry into
		// a template-state oracle. Returning this error rolls back the allowed
		// decisions recorded above together with the rest of the transaction.
		if template.Status != iamv1.ServiceRoleTemplateActive {
			return ErrConflict
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

// RevokeWorkloadRoleBinding performs the one terminal consent transition. The
// binding is loaded under the authenticated service and USER sources before
// decisions are made, so a path ID cannot select another Account, Role,
// template, workload or service principal.
func (service *Authority) RevokeWorkloadRoleBinding(
	ctx context.Context,
	serviceCredential iamv1.Secret,
	subjectCredential iamv1.Secret,
	id iamv1.WorkloadRoleBindingID,
	request iamv1.RevokeWorkloadRoleBindingRequest,
) (iamv1.WorkloadRoleBinding, error) {
	if iamv1.ValidateID("bindingId", string(id)) != nil ||
		iamv1.ValidateRevokeWorkloadRoleBindingRequest(request) != nil {
		return iamv1.WorkloadRoleBinding{}, ErrInvalidArgument
	}
	requestDigest, err := digestSanitized("workload-role-binding-revoke:"+string(id), request)
	if err != nil {
		return iamv1.WorkloadRoleBinding{}, err
	}
	var result iamv1.WorkloadRoleBinding
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
		subject, err := service.authenticateSession(transactionContext, transaction, subjectCredential, now)
		if err != nil {
			return err
		}
		if err := transaction.LockWorkloadRoleBindingSources(transactionContext,
			subject.Subject.Organization.ID, subject.Subject.Principal.ID, subject.Subject.Session.ID,
			caller.LookupDigest, caller.Identity.Purpose); err != nil {
			return err
		}
		target, err := transaction.PrepareWorkloadRoleBindingRevocation(transactionContext,
			subject.Subject.Organization.ID, id, caller.LookupDigest, caller.Identity.Purpose)
		if err != nil {
			return err
		}
		if iamv1.ValidateServiceLinkedRoleAccess(target) != nil || len(target.Bindings) != 1 {
			return ErrUnavailable
		}
		binding, relation := target.Bindings[0], target.Relation
		if binding.ID != id || binding.AccountID != subject.Subject.Organization.ID ||
			binding.RoleID != relation.Role.ID || binding.Template != relation.Template ||
			relation.Role.AccountID != subject.Subject.Organization.ID ||
			relation.ServicePrincipal != (iamv1.ServicePrincipalReference{
				InstallationID: caller.Identity.InstallationID,
				PrincipalID:    caller.Identity.PrincipalID,
				Purpose:        caller.Identity.Purpose,
			}) {
			return ErrForbidden
		}
		template, found, err := transaction.ReadServiceRoleTemplate(transactionContext, binding.Template)
		if err != nil || !found {
			return ErrUnavailable
		}
		profiles, err := transaction.CurrentAuthorizationProfiles(transactionContext)
		if err != nil || iamv1.CheckServiceRoleTemplate(template, profiles) != nil {
			return ErrUnavailable
		}
		profile, found, err := transaction.LookupCurrentAuthorizationProfile(transactionContext, request.Authorization.Profile)
		if err != nil {
			return err
		}
		if !found || profile.Product != template.Spec.Product ||
			iamv1.ValidateAuthorizationRequestForProfile(request.Authorization, profile) != nil {
			return ErrInvalidArgument
		}
		workloadRegistered := false
		for _, workload := range template.Spec.Workloads {
			if workload.ResourceKind == binding.Workload.Kind &&
				workload.UnbindAction == request.Authorization.Action {
				workloadRegistered = true
				break
			}
		}
		if !workloadRegistered || request.Authorization.Profile.Product != template.Spec.Product ||
			request.Authorization.Resource != binding.Workload || caller.Identity.Purpose != template.Spec.ServicePurpose {
			return ErrInvalidArgument
		}
		authorizationDigest, err := digestSanitized("authorization", request.Authorization)
		if err != nil {
			return err
		}
		workloadDecision, err := service.decideAndRecord(transactionContext, transaction, request.Authorization,
			authorizationDigest, now,
			authorizationActor{organizationID: subject.Subject.Organization.ID,
				subject: iamv1.Subject{Type: iamv1.SubjectUser, ID: string(subject.Subject.Principal.ID)}},
			func(decisionID iamv1.DecisionID) (authority.AuthorizationEvaluation, error) {
				return authority.DecideWithProfile(subject.Subject, caller.Identity.Purpose, request.Authorization, profile, decisionID, now)
			})
		if err != nil {
			return err
		}
		if !workloadDecision.Allowed {
			denied = true
			return nil
		}
		bindingRevokeDecision, err := service.managementDecision(transactionContext, transaction, subject,
			iamv1.ActionIAMWorkloadRoleBindingRevoke,
			iamv1.ResourceReference{Kind: iamv1.ResourceWorkloadRoleBinding, ID: string(id)},
			iamv1.AuthorizationResourceInstance, "", request.Authorization.RequestID, now)
		if err != nil {
			return err
		}
		if !bindingRevokeDecision.Allowed {
			denied = true
			return nil
		}
		rolePassDecision, err := service.managementDecision(transactionContext, transaction, subject,
			iamv1.ActionIAMRolePass,
			iamv1.ResourceReference{Kind: iamv1.ResourceRole, ID: string(binding.RoleID)},
			iamv1.AuthorizationResourceInstance, "", request.Authorization.RequestID, now)
		if err != nil {
			return err
		}
		if !rolePassDecision.Allowed {
			denied = true
			return nil
		}
		event, err := service.newManagementEvent(subject, auditv1.ActionIAMWorkloadRoleBindingRevoked,
			auditv1.TargetWorkloadRoleBinding, string(id), bindingRevokeDecision.ID,
			requestDigest, request.Authorization.RequestID, now)
		if err != nil {
			return err
		}
		result, err = transaction.RevokeWorkloadRoleBinding(transactionContext, WorkloadRoleBindingRevocation{
			AccountID: subject.Subject.Organization.ID, BindingID: id,
			ActorPrincipalID: subject.Subject.Principal.ID, ActorSessionID: subject.Subject.Session.ID,
			ServiceLookupDigest: caller.LookupDigest, ServicePurpose: caller.Identity.Purpose,
			Request: request, RequestDigest: requestDigest,
			WorkloadDecisionID: workloadDecision.ID, BindingRevokeDecisionID: bindingRevokeDecision.ID,
			RolePassDecisionID: rolePassDecision.ID, AuditEvent: event,
		})
		return err
	})
	if err != nil {
		return iamv1.WorkloadRoleBinding{}, err
	}
	if denied {
		return iamv1.WorkloadRoleBinding{}, ErrForbidden
	}
	if iamv1.ValidateWorkloadRoleBinding(result) != nil || result.ID != id ||
		result.Status != iamv1.WorkloadRoleBindingRevoked || result.ResourceVersion != request.ResourceVersion+1 ||
		result.Workload != request.Authorization.Resource {
		return iamv1.WorkloadRoleBinding{}, ErrUnavailable
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
