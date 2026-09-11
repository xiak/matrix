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
)

type SubjectContext struct {
	Organization iamv1.Organization
	Principal    iamv1.Principal
	Session      iamv1.Session
	Policies     []AttachedPolicy
	// InstallationID is read from the sealed IAM bootstrap receipt, not a
	// request field or an organization ID. Empty context cannot grant platform
	// authority even when an attachment has been supplied.
	InstallationID string
}

// AuthorizationEvaluation keeps private policy provenance alongside the
// sanitized public decision. Only the decision is returned to a caller.
type AuthorizationEvaluation struct {
	iamv1.AuthorizationDecision
	PolicyEvidence []PolicyAttachmentEvidence `json:"-"`
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
		identity.OrganizationID,
		identity.InstallationID,
		iamv1.Subject{Type: iamv1.PrincipalServiceAccount, ID: identity.PrincipalID},
		false,
		policies,
		identity.Purpose,
		request,
		decisionID,
		databaseTime,
	)
}

func decide(
	tenantID iamv1.OrganizationID,
	installationID string,
	subject iamv1.Subject,
	mustChangePassword bool,
	policies []AttachedPolicy,
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
	evaluation, evidence, err := EvaluateAttachedPolicies(tenantID, installationID, subject, policies, request.Action, request.Resource)
	if err != nil {
		return AuthorizationEvaluation{}, ErrAuthorityUnavailable
	}
	platform := iamv1.IsPlatformAction(request.Action)
	platformContext := !platform || subject.Type == iamv1.PrincipalUser && iamv1.ValidateID("installationId", installationID) == nil
	probeContext := request.Action != iamv1.ActionInstallationVerify ||
		subject.Type == iamv1.PrincipalServiceAccount && request.Resource.ID == installationID
	allowed := evaluation.Allowed && !mustChangePassword && platformContext && probeContext && ServiceCanRequest(callingService, request.Action)
	decision := iamv1.AuthorizationDecision{
		APIVersion: iamv1.APIVersion,
		Kind:       "AuthorizationDecision",
		ID:         decisionID,
		Allowed:    allowed,
		Reason:     iamv1.DecisionDenied,
		Action:     request.Action,
		Resource:   request.Resource,
		RequestID:  request.RequestID,
		DecidedAt:  databaseTime,
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
	if err := iamv1.ValidateAuthorizationDecision(decision); err != nil {
		return AuthorizationEvaluation{}, ErrAuthorityUnavailable
	}
	return AuthorizationEvaluation{AuthorizationDecision: decision, PolicyEvidence: evidence}, nil
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
	if context.Principal.OrganizationID != context.Organization.ID ||
		context.Session.OrganizationID != context.Organization.ID ||
		context.Session.PrincipalID != context.Principal.ID {
		return ErrAuthorityUnavailable
	}
	if context.Organization.Status != iamv1.OrganizationActive ||
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
