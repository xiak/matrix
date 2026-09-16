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

// RoleSessionContext is a separate credential-bound identity. The adapter
// checks the issued credential/security generations and complete revision
// vectors; this context does not promote its source USER into a ROLE principal.
type RoleSessionContext struct {
	AuthorityContractVersion      uint64
	SourceAuthorizationGeneration uint64
	SourceGroupGenerations        []RoleSourceGroupGeneration
	Session                       iamv1.RoleSession
	Source                        SubjectContext
	SourceSessionID               iamv1.SessionID
	CredentialGeneration          uint64
	SecurityGeneration            uint64
	AssumeDecisionID              iamv1.DecisionID
	Role                          iamv1.Role
	Trust                         iamv1.RoleTrustVersion
	Policies                      []AttachedPolicy
	Boundary                      *ResolvedRoleBoundary
	SessionPolicy                 *ResolvedSessionPolicy
}

// Private issuance evidence, not public group metadata or current permissions.
type RoleSourceGroupGeneration struct {
	GroupID                   iamv1.GroupID           `json:"groupId"`
	MembershipID              iamv1.GroupMembershipID `json:"membershipId"`
	MembershipResourceVersion uint64                  `json:"membershipResourceVersion"`
	AuthorizationGeneration   uint64                  `json:"authorizationGeneration"`
}

func ValidateRoleSourceAuthority(contract, generation uint64, groups []RoleSourceGroupGeneration) error {
	if contract != 2 || generation == 0 || generation > 9007199254740991 || groups == nil || len(groups) > 100 {
		return ErrAuthorityUnavailable
	}
	var previous iamv1.GroupID
	for _, group := range groups {
		if iamv1.ValidateID("groupId", string(group.GroupID)) != nil || group.GroupID <= previous ||
			iamv1.ValidateID("membershipId", string(group.MembershipID)) != nil || group.MembershipResourceVersion != 1 ||
			group.AuthorizationGeneration == 0 || group.AuthorizationGeneration > 9007199254740991 {
			return ErrAuthorityUnavailable
		}
		previous = group.GroupID
	}
	return nil
}

func AuthenticateRoleSession(value RoleSessionContext, storedDigest string, credential iamv1.Secret, now time.Time) error {
	if err := validateRoleSessionContext(value, now); err != nil {
		return err
	}
	verified, err := VerifyCredential(CredentialRoleSession, string(value.Session.ID), credential, storedDigest)
	if err != nil {
		return ErrAuthorityUnavailable
	}
	if !verified {
		return ErrUnauthenticated
	}
	return nil
}

func validateRoleSessionContext(value RoleSessionContext, now time.Time) error {
	if ValidateRoleSourceAuthority(value.AuthorityContractVersion, value.SourceAuthorizationGeneration, value.SourceGroupGenerations) != nil ||
		iamv1.ValidateRoleSession(value.Session) != nil || validateAuthorityTime(now) != nil ||
		value.Session.AccountID != value.Source.Organization.ID || value.Session.SourceUserID != value.Source.Principal.ID ||
		value.Session.RoleID != value.Role.ID || value.SourceSessionID != value.Source.Session.ID ||
		value.Session.ExpiresAt.After(value.Source.Session.ExpiresAt) || value.Session.IssuedAt.After(now) ||
		value.CredentialGeneration == 0 || value.CredentialGeneration > 9007199254740991 ||
		value.SecurityGeneration == 0 || value.SecurityGeneration > 9007199254740991 ||
		iamv1.ValidateID("assumeDecisionId", string(value.AssumeDecisionID)) != nil {
		return ErrAuthorityUnavailable
	}
	if value.Session.Status != iamv1.SessionActive || !now.Before(value.Session.ExpiresAt) {
		return ErrUnauthenticated
	}
	if ValidateRoleBoundary(value.Boundary, value.Session.AccountID) != nil ||
		ValidateSessionPolicy(value.SessionPolicy) != nil {
		return ErrAuthorityUnavailable
	}
	trusted, err := RoleTrustAllowsUser(value.Source, value.Role, value.Trust, now)
	if err != nil {
		return err
	}
	if !trusted {
		return ErrUnauthenticated
	}
	// Re-evaluate time-dependent source conditions, not just a revision digest.
	// This internal eligibility evaluation is not recorded as a fabricated
	// business decision and never contributes source grants to role permissions.
	request, err := iamv1.NewAuthorizationRequest(iamv1.ActionIAMRoleAssume,
		iamv1.ResourceReference{Kind: iamv1.ResourceRole, ID: string(value.Role.ID)}, iamv1.AuthorizationResourceInstance, "",
		string(value.Session.ID), string(value.Session.ID))
	if err != nil {
		return ErrAuthorityUnavailable
	}
	result, err := Decide(value.Source, iamv1.ServiceIAM, request, iamv1.DecisionID(value.Session.ID), now)
	if err != nil {
		return err
	}
	if !result.Allowed {
		return ErrUnauthenticated
	}
	return nil
}

// AuthorizationEvaluation keeps private policy provenance alongside the
// sanitized public decision. Only the decision is returned to a caller.
type AuthorizationEvaluation struct {
	iamv1.AuthorizationDecision
	PolicyEvidence   []PolicyAttachmentEvidence `json:"-"`
	BoundaryEvidence UserBoundaryEvidence       `json:"-"`
	RoleEvidence     *RoleAuthorizationEvidence `json:"-"`
}

// This reference resolves to the immutable issuance ledger, which owns the
// full source and role authority vectors. The SQL recorder checks each field;
// delivery checks the original vectors, never a current login or policy head.
type RoleAuthorizationEvidence struct {
	AuthorityContractVersion      uint64                      `json:"authorityContractVersion"`
	SourceAuthorizationGeneration uint64                      `json:"sourceAuthorizationGeneration"`
	SourceGroupGenerations        []RoleSourceGroupGeneration `json:"sourceGroupGenerations"`
	SessionID                     iamv1.RoleSessionID         `json:"sessionId"`
	RoleID                        iamv1.RoleID                `json:"roleId"`
	SourceUserID                  iamv1.PrincipalID           `json:"sourceUserId"`
	SourceSessionID               iamv1.SessionID             `json:"sourceSessionId"`
	CredentialGeneration          uint64                      `json:"credentialGeneration"`
	SecurityGeneration            uint64                      `json:"securityGeneration"`
	TrustVersionID                iamv1.RoleTrustVersionID    `json:"trustVersionId"`
	TrustDigest                   string                      `json:"trustDigest"`
	AssumeDecisionID              iamv1.DecisionID            `json:"assumeDecisionId"`
	Boundary                      RoleBoundaryEvidence        `json:"boundary"`
	SessionPolicy                 *RoleSessionPolicyEvidence  `json:"sessionPolicy"`
}

type RoleBoundaryEvidence struct {
	BoundaryID      string                       `json:"boundaryId"`
	ResourceVersion uint64                       `json:"resourceVersion"`
	Version         iamv1.PolicyVersionReference `json:"version"`
	ContractVersion uint64                       `json:"contractVersion"`
	Compilation     *iamv1.PolicyCompilation     `json:"compilation,omitempty"`
}

type RoleSessionPolicyEvidence struct {
	ContentDigest string                  `json:"contentDigest"`
	Compilation   iamv1.PolicyCompilation `json:"compilation"`
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
		iamv1.Subject{Type: iamv1.SubjectType(context.Principal.Type), ID: string(context.Principal.ID)},
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
		iamv1.Subject{Type: iamv1.SubjectServiceAccount, ID: string(identity.PrincipalID)},
		false,
		policies,
		nil,
		identity.Purpose,
		request,
		decisionID,
		databaseTime,
	)
}

func DecideRole(value RoleSessionContext, callingService iamv1.ServicePurpose, request iamv1.AuthorizationRequest, decisionID iamv1.DecisionID, now time.Time) (AuthorizationEvaluation, error) {
	if err := validateRoleSessionContext(value, now); err != nil {
		return AuthorizationEvaluation{}, err
	}
	if iamv1.ValidateAuthorizationRequest(request) != nil {
		return AuthorizationEvaluation{}, ErrInvalidAuthorizationRequest
	}
	if iamv1.ValidateID("decisionId", string(decisionID)) != nil || !knownServicePurpose(callingService) {
		return AuthorizationEvaluation{}, ErrAuthorityUnavailable
	}
	subject := iamv1.Subject{Type: iamv1.SubjectRole, ID: string(value.Role.ID), RoleSession: &iamv1.RoleSessionReference{SessionID: value.Session.ID, SourceUserID: value.Session.SourceUserID}}
	grant, policies, err := EvaluateAttachedPolicies(now, value.Session.AccountID, "", subject, value.Policies, request)
	supported := !errors.Is(err, errUnsupportedPolicySubject)
	if err != nil && supported {
		return AuthorizationEvaluation{}, ErrAuthorityUnavailable
	}
	if policies == nil {
		policies = []PolicyAttachmentEvidence{}
	}
	if supported {
		context := policyEvaluationContext{databaseTime: now, accountID: value.Session.AccountID, subject: subject,
			profiles: make(map[iamv1.AuthorizationProfileReference]iamv1.AuthorizationProfile)}
		if context.includeProfiles(value.Boundary.Profiles) != nil {
			return AuthorizationEvaluation{}, ErrAuthorityUnavailable
		}
		boundary, err := evaluatePolicies(context, []iamv1.PolicyVersion{value.Boundary.Version}, request)
		if err != nil {
			return AuthorizationEvaluation{}, ErrAuthorityUnavailable
		}
		session, err := evaluateSessionPolicy(value.SessionPolicy, context, request)
		if err != nil {
			return AuthorizationEvaluation{}, ErrAuthorityUnavailable
		}
		grant.Allowed = grant.Allowed && boundary.Allowed && session.Allowed
	}
	proof := &RoleAuthorizationEvidence{AuthorityContractVersion: value.AuthorityContractVersion,
		SourceAuthorizationGeneration: value.SourceAuthorizationGeneration, SourceGroupGenerations: append([]RoleSourceGroupGeneration{}, value.SourceGroupGenerations...),
		SessionID: value.Session.ID, RoleID: value.Role.ID, SourceUserID: value.Session.SourceUserID,
		SourceSessionID: value.SourceSessionID, CredentialGeneration: value.CredentialGeneration, SecurityGeneration: value.SecurityGeneration,
		TrustVersionID: value.Trust.ID, TrustDigest: value.Trust.ContentDigest, AssumeDecisionID: value.AssumeDecisionID,
		Boundary: RoleBoundaryEvidence{BoundaryID: value.Boundary.BoundaryID, ResourceVersion: value.Boundary.ResourceVersion,
			Version:         iamv1.PolicyVersionReference{PolicyID: value.Boundary.Policy.ID, VersionID: value.Boundary.Version.ID, ContentDigest: value.Boundary.Version.ContentDigest},
			ContractVersion: value.Boundary.Version.ContractVersion, Compilation: value.Boundary.Version.Compilation}}
	if value.SessionPolicy != nil {
		proof.SessionPolicy = &RoleSessionPolicyEvidence{ContentDigest: value.SessionPolicy.ContentDigest, Compilation: value.SessionPolicy.Compilation}
	}
	allowed := supported && grant.Allowed && ServiceCanRequest(callingService, request.Action)
	decision, err := authorizationDecision(value.Session.AccountID, "", subject, request, decisionID, now, allowed)
	if err != nil {
		return AuthorizationEvaluation{}, err
	}
	return AuthorizationEvaluation{AuthorizationDecision: decision, PolicyEvidence: policies, BoundaryEvidence: UserBoundaryEvidence{State: "NOT_APPLICABLE"}, RoleEvidence: proof}, nil
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
	if subject.Type == iamv1.SubjectUser && definition.AuthorityScope == iamv1.AuthorityScopeTenant {
		limit, proof, err := evaluateUserBoundary(boundary, policyEvaluationContext{databaseTime: databaseTime, accountID: tenantID, subject: subject}, request)
		if err != nil {
			return AuthorizationEvaluation{}, ErrAuthorityUnavailable
		}
		evaluation.Allowed = evaluation.Allowed && limit.Allowed
		boundaryEvidence = proof
	}
	platform := iamv1.IsPlatformAction(request.Action)
	platformContext := !platform || subject.Type == iamv1.SubjectUser && iamv1.ValidateID("installationId", installationID) == nil
	probeContext := request.Action != iamv1.ActionInstallationVerify ||
		subject.Type == iamv1.SubjectServiceAccount && request.Resource.ID == installationID
	allowed := subjectSupported && evaluation.Allowed && !mustChangePassword && platformContext && probeContext && ServiceCanRequest(callingService, request.Action)
	decision, err := authorizationDecision(tenantID, installationID, subject, request, decisionID, databaseTime, allowed)
	if err != nil {
		return AuthorizationEvaluation{}, err
	}
	return AuthorizationEvaluation{AuthorizationDecision: decision, PolicyEvidence: evidence, BoundaryEvidence: boundaryEvidence}, nil
}

func authorizationDecision(tenantID iamv1.AccountID, installationID string, subject iamv1.Subject, request iamv1.AuthorizationRequest, decisionID iamv1.DecisionID, databaseTime time.Time, allowed bool) (iamv1.AuthorizationDecision, error) {
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
		if iamv1.IsPlatformAction(request.Action) {
			decision.InstallationID = installationID
		} else {
			decision.TenantID = tenantID
		}
		decision.Subject = &subject
	}
	if err := iamv1.CheckAuthorizationDecisionForRequest(decision, request); err != nil {
		return iamv1.AuthorizationDecision{}, ErrAuthorityUnavailable
	}
	return decision, nil
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
