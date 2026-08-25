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
	Roles        []iamv1.BuiltinRole
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
	request iamv1.AuthorizationRequest,
	decisionID iamv1.DecisionID,
	databaseTime time.Time,
) (iamv1.AuthorizationDecision, error) {
	if err := validateSubjectContext(context, databaseTime); err != nil {
		return iamv1.AuthorizationDecision{}, err
	}
	if iamv1.ValidateAuthorizationRequest(request) != nil {
		return iamv1.AuthorizationDecision{}, ErrInvalidAuthorizationRequest
	}
	if iamv1.ValidateID("decisionId", string(decisionID)) != nil {
		return iamv1.AuthorizationDecision{}, ErrAuthorityUnavailable
	}
	allowed := false
	if !context.Principal.MustChangePassword {
		for _, role := range context.Roles {
			if RoleAllows(role, request.Action) {
				allowed = true
				break
			}
		}
	}
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
		decision.TenantID = context.Organization.ID
		decision.Subject = &iamv1.Subject{Type: context.Principal.Type, ID: context.Principal.ID}
	}
	if err := iamv1.ValidateAuthorizationDecision(decision); err != nil {
		return iamv1.AuthorizationDecision{}, ErrAuthorityUnavailable
	}
	return decision, nil
}

func RoleAllows(role iamv1.BuiltinRole, action iamv1.Action) bool {
	switch role {
	case iamv1.RoleOrganizationAdmin:
		return action != iamv1.ActionInstallationVerify && knownAction(action)
	case iamv1.RolePaaSDeveloper:
		switch action {
		case iamv1.ActionPaaSApplicationCreate,
			iamv1.ActionPaaSApplicationRead,
			iamv1.ActionPaaSConfigurationCreate,
			iamv1.ActionPaaSConfigurationRead,
			iamv1.ActionPaaSConfigurationRevisionCreate,
			iamv1.ActionPaaSConfigurationRevisionRead,
			iamv1.ActionPaaSApplicationRevisionCreate,
			iamv1.ActionPaaSApplicationRevisionRead,
			iamv1.ActionPaaSDeploymentCreate,
			iamv1.ActionPaaSDeploymentUpdate,
			iamv1.ActionPaaSDeploymentRollback,
			iamv1.ActionPaaSDeploymentStop,
			iamv1.ActionPaaSDeploymentRead,
			iamv1.ActionPaaSOperationRead:
			return true
		}
	case iamv1.RolePaaSViewer:
		switch action {
		case iamv1.ActionPaaSApplicationRead,
			iamv1.ActionPaaSConfigurationRead,
			iamv1.ActionPaaSConfigurationRevisionRead,
			iamv1.ActionPaaSApplicationRevisionRead,
			iamv1.ActionPaaSDeploymentRead,
			iamv1.ActionPaaSOperationRead:
			return true
		}
	case iamv1.RoleAuditReader:
		return action == iamv1.ActionAuditRecordRead || action == iamv1.ActionAuditIntegrityVerify
	case iamv1.RoleInstallationVerifier:
		return action == iamv1.ActionInstallationVerify
	}
	return false
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
	seen := map[iamv1.BuiltinRole]struct{}{}
	for _, role := range context.Roles {
		if _, duplicate := seen[role]; duplicate || !knownRole(role) {
			return ErrAuthorityUnavailable
		}
		seen[role] = struct{}{}
	}
	return nil
}

func knownAction(action iamv1.Action) bool {
	for _, candidate := range iamv1.AllActions() {
		if action == candidate {
			return true
		}
	}
	return false
}

func knownRole(role iamv1.BuiltinRole) bool {
	for _, candidate := range iamv1.AllBuiltinRoles() {
		if role == candidate {
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
