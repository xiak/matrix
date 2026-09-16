package authority

import (
	"errors"
	"time"

	iamv1 "github.com/xiak/matrix/api/iam/v1"
)

var (
	ErrUnauthenticated             = errors.New("IAM authentication failed")
	ErrInvalidAuthorizationRequest = errors.New("IAM authorization request is invalid")
	ErrAuthorityUnavailable        = errors.New("IAM authority state is unavailable")
	ErrInvalidRoleSessionRequest   = errors.New("IAM role session request is invalid")
)

// RoleTrustAllowsUser checks only the selected carrier trust. The issuance
// use case must separately authenticate the exact bearer/generation and obtain
// a current AssumeRole decision inside its transaction. This is not a permit.
func RoleTrustAllowsUser(source SubjectContext, role iamv1.Role, version iamv1.RoleTrustVersion, databaseTime time.Time) (bool, error) {
	if err := validateSubjectContext(source, databaseTime); err != nil {
		return false, err
	}
	if iamv1.ValidateRole(role) != nil || iamv1.ValidateRoleTrustVersion(version) != nil ||
		role.AccountID != source.Organization.ID || version.AccountID != role.AccountID || version.RoleID != role.ID ||
		version.ID != role.CurrentTrustVersionID || version.CreatedAt.Before(role.CreatedAt) ||
		version.CreatedAt.After(role.UpdatedAt) || role.UpdatedAt.After(databaseTime) {
		return false, ErrAuthorityUnavailable
	}
	if source.Principal.Type != iamv1.PrincipalUser || source.Principal.MustChangePassword || role.Status != iamv1.RoleActive {
		return false, nil
	}
	allowed, denied := false, false
	for _, statement := range version.Document.Statements {
		for _, principal := range statement.Principals {
			if principal.ID == source.Principal.ID {
				allowed = allowed || statement.Effect == iamv1.PolicyAllow
				denied = denied || statement.Effect == iamv1.PolicyDeny
			}
		}
	}
	return allowed && !denied, nil
}

// RoleSessionDeadline uses one authoritative instant. Short source lifetimes
// are clipped, not renewed to the requested minimum; equality means expired.
func RoleSessionDeadline(databaseTime time.Time, requestedSeconds, maximumSeconds uint32, sourceExpiresAt time.Time) (time.Time, error) {
	if validateAuthorityTime(databaseTime) != nil || validateAuthorityTime(sourceExpiresAt) != nil ||
		maximumSeconds < iamv1.MinRoleSessionDurationSeconds || maximumSeconds > iamv1.MaxRoleSessionDurationSeconds {
		return time.Time{}, ErrAuthorityUnavailable
	}
	if requestedSeconds < iamv1.MinRoleSessionDurationSeconds || requestedSeconds > iamv1.MaxRoleSessionDurationSeconds {
		return time.Time{}, ErrInvalidRoleSessionRequest
	}
	if !databaseTime.Before(sourceExpiresAt) {
		return time.Time{}, ErrUnauthenticated
	}
	deadline := databaseTime.Add(time.Duration(min(requestedSeconds, maximumSeconds)) * time.Second)
	if sourceExpiresAt.Before(deadline) {
		deadline = sourceExpiresAt
	}
	return deadline, nil
}

type SubjectContext struct {
	Organization iamv1.Organization
	Principal    iamv1.Principal
	Session      iamv1.Session
	Policies     []AttachedPolicy
	Boundary     *ResolvedUserBoundary
	// InstallationID is read from the sealed IAM bootstrap receipt, not a
	// request field or an organization ID. Empty context cannot grant platform
	// authority even when an attachment has been supplied.
	InstallationID string
}

// AuthorizationEvaluation keeps private policy provenance alongside the
// sanitized public decision. Only the decision is returned to a caller.
type AuthorizationEvaluation struct {
	iamv1.AuthorizationDecision
	PolicyEvidence   []PolicyAttachmentEvidence `json:"-"`
	BoundaryEvidence UserBoundaryEvidence       `json:"-"`
}

func AuthenticateSession(
	session iamv1.Session,
	storedDigest string,
	credential iamv1.Secret,
	databaseTime time.Time,
) error {
	if validateAuthorityTime(databaseTime) != nil || iamv1.ValidateSession(session) != nil {
		return ErrAuthorityUnavailable
	}
	if session.Status != iamv1.SessionActive || !databaseTime.Before(session.ExpiresAt) {
		return ErrUnauthenticated
	}
	verified, err := VerifyCredential(
		CredentialSession,
		string(session.ID),
		credential,
		storedDigest,
	)
	if err != nil {
		return ErrAuthorityUnavailable
	}
	if !verified {
		return ErrUnauthenticated
	}
	return nil
}

func Decide(
	context SubjectContext,
	callingService iamv1.ServicePurpose,
	request iamv1.AuthorizationRequest,
	decisionID iamv1.DecisionID,
	databaseTime time.Time,
) (AuthorizationEvaluation, error) {
	if err := validateSubjectContext(context, databaseTime); err != nil {
		return AuthorizationEvaluation{}, err
	}
	return decide(
		context.Organization.ID,
		context.InstallationID,
		iamv1.Subject{Type: context.Principal.Type, ID: context.Principal.ID},
		context.Principal.MustChangePassword,
		context.Policies,
		context.Boundary,
		callingService,
		request,
		decisionID,
		databaseTime,
	)
}

// DecideService authorizes the credential-bound service as its own subject.
// The installation verification endpoint is its only Phase 1 consumer.
func DecideService(
	identity iamv1.ServiceIdentity,
	policies []AttachedPolicy,
	request iamv1.AuthorizationRequest,
	decisionID iamv1.DecisionID,
	databaseTime time.Time,
) (AuthorizationEvaluation, error) {
	if iamv1.ValidateServiceIdentity(identity) != nil ||
		validateAuthorityTime(databaseTime) != nil {
		return AuthorizationEvaluation{}, ErrAuthorityUnavailable
	}
	return decide(
		identity.AccountID,
		identity.InstallationID,
		iamv1.Subject{Type: iamv1.PrincipalServiceAccount, ID: identity.PrincipalID},
		false,
		policies,
		nil,
		identity.Purpose,
		request,
		decisionID,
		databaseTime,
	)
}

func decide(
	tenantID iamv1.AccountID,
	installationID string,
	subject iamv1.Subject,
	mustChangePassword bool,
	policies []AttachedPolicy,
	boundary *ResolvedUserBoundary,
	callingService iamv1.ServicePurpose,
	request iamv1.AuthorizationRequest,
	decisionID iamv1.DecisionID,
	databaseTime time.Time,
) (AuthorizationEvaluation, error) {
	if iamv1.ValidateAuthorizationRequest(request) != nil {
		return AuthorizationEvaluation{}, ErrInvalidAuthorizationRequest
	}
	if iamv1.ValidateID("decisionId", string(decisionID)) != nil {
		return AuthorizationEvaluation{}, ErrAuthorityUnavailable
	}
	if !knownServicePurpose(callingService) {
		return AuthorizationEvaluation{}, ErrAuthorityUnavailable
	}
	evaluation, evidence, err := EvaluateAttachedPolicies(databaseTime, tenantID, installationID, subject, policies, request)
	subjectSupported := !errors.Is(err, errUnsupportedPolicySubject)
	if err != nil && subjectSupported {
		return AuthorizationEvaluation{}, ErrAuthorityUnavailable
	}
	boundaryEvidence := UserBoundaryEvidence{State: "NOT_APPLICABLE"}
	definition, _ := iamv1.LookupActionDefinition(request.Action)
	if subject.Type == iamv1.PrincipalUser && definition.AuthorityScope == iamv1.AuthorityScopeTenant {
		limit, proof, err := evaluateUserBoundary(boundary, policyEvaluationContext{databaseTime: databaseTime, accountID: tenantID, subject: subject}, request)
		if err != nil {
			return AuthorizationEvaluation{}, ErrAuthorityUnavailable
		}
		evaluation.Allowed = evaluation.Allowed && limit.Allowed
		boundaryEvidence = proof
	}
	platform := iamv1.IsPlatformAction(request.Action)
	platformContext := !platform || subject.Type == iamv1.PrincipalUser && iamv1.ValidateID("installationId", installationID) == nil
	probeContext := request.Action != iamv1.ActionInstallationVerify ||
		subject.Type == iamv1.PrincipalServiceAccount && request.Resource.ID == installationID
	allowed := subjectSupported && evaluation.Allowed && !mustChangePassword && platformContext && probeContext && ServiceCanRequest(callingService, request.Action)
	profile := request.Profile
	decision := iamv1.AuthorizationDecision{
		APIVersion:      iamv1.APIVersion,
		Kind:            "AuthorizationDecision",
		ID:              decisionID,
		Allowed:         allowed,
		Reason:          iamv1.DecisionDenied,
		Action:          request.Action,
		Resource:        request.Resource,
		RequestID:       request.RequestID,
		DecidedAt:       databaseTime,
		Profile:         &profile,
		ResourceMode:    request.ResourceMode,
		CollectionUsage: request.CollectionUsage,
		CorrelationID:   request.CorrelationID,
	}
	if allowed {
		decision.Reason = iamv1.DecisionAllowed
		if platform {
			decision.InstallationID = installationID
		} else {
			decision.TenantID = tenantID
		}
		decision.Subject = &subject
	}
	if err := iamv1.CheckAuthorizationDecisionForRequest(decision, request); err != nil {
		return AuthorizationEvaluation{}, ErrAuthorityUnavailable
	}
	return AuthorizationEvaluation{AuthorizationDecision: decision, PolicyEvidence: evidence, BoundaryEvidence: boundaryEvidence}, nil
}

// ServiceCanRequest confines each authorization action to the service that
// owns its product boundary. APISIX forwards credentials but never asks IAM
// for product authorization on another service's behalf.
func ServiceCanRequest(purpose iamv1.ServicePurpose, action iamv1.Action) bool {
	definition, known := iamv1.LookupActionDefinition(action)
	return known && definition.CallingService == purpose
}

func validateSubjectContext(context SubjectContext, databaseTime time.Time) error {
	if validateAuthorityTime(databaseTime) != nil ||
		iamv1.ValidateOrganization(context.Organization) != nil ||
		iamv1.ValidatePrincipal(context.Principal) != nil ||
		iamv1.ValidateSession(context.Session) != nil {
		return ErrAuthorityUnavailable
	}
	if context.Principal.AccountID != context.Organization.ID ||
		context.Session.AccountID != context.Organization.ID ||
		context.Session.PrincipalID != context.Principal.ID {
		return ErrAuthorityUnavailable
	}
	if ValidateUserBoundary(context.Boundary, context.Organization.ID, context.Principal.ID, context.Principal.ResourceVersion) != nil {
		return ErrAuthorityUnavailable
	}
	if context.Organization.Status != iamv1.AccountActive ||
		context.Principal.Status != iamv1.PrincipalActive ||
		context.Session.Status != iamv1.SessionActive ||
		!databaseTime.Before(context.Session.ExpiresAt) {
		return ErrUnauthenticated
	}
	return nil
}

func knownServicePurpose(purpose iamv1.ServicePurpose) bool {
	for _, candidate := range iamv1.AllServicePurposes() {
		if purpose == candidate {
			return true
		}
	}
	return false
}

func validateAuthorityTime(value time.Time) error {
	if value.IsZero() || value.Location() != time.UTC || value != value.Round(0) || value.Nanosecond()%1_000 != 0 {
		return ErrAuthorityUnavailable
	}
	return nil
}
