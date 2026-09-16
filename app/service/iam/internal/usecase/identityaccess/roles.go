package identityaccess

import (
	"context"
	"errors"
	"time"

	auditv1 "github.com/xiak/matrix/api/audit/v1"
	iamv1 "github.com/xiak/matrix/api/iam/v1"
	"github.com/xiak/matrix/app/service/iam/internal/authority"
)

func (service *Authority) authenticateRoleSession(ctx context.Context, tx Transaction, credential iamv1.Secret, now time.Time) (RoleSessionCredential, error) {
	digest, err := authority.LookupCredentialDigest(authority.CredentialRoleSession, credential)
	if err != nil {
		return RoleSessionCredential{}, ErrUnauthenticated
	}
	binding, found, err := tx.LookupRoleSession(ctx, digest)
	if err != nil {
		return RoleSessionCredential{}, err
	}
	if !found {
		return RoleSessionCredential{}, ErrUnauthenticated
	}
	if err := service.resolveSubjectInstallation(ctx, tx, &binding.Subject.Source); err != nil {
		return RoleSessionCredential{}, err
	}
	if err := tx.CheckCurrentAuthorizationProfiles(ctx); err != nil {
		return RoleSessionCredential{}, err
	}
	if err := authority.AuthenticateRoleSession(binding.Subject, binding.VerificationDigest, credential, now); err != nil {
		if errors.Is(err, authority.ErrUnauthenticated) {
			return RoleSessionCredential{}, ErrUnauthenticated
		}
		return RoleSessionCredential{}, ErrUnavailable
	}
	return binding, nil
}

func (service *Authority) CurrentRoleIdentity(ctx context.Context, credential iamv1.Secret) (iamv1.CurrentRoleIdentity, error) {
	var result iamv1.CurrentRoleIdentity
	err := service.withinTransaction(ctx, func(ctx context.Context, tx Transaction) error {
		now, err := transactionTime(ctx, tx)
		if err != nil {
			return err
		}
		binding, err := service.authenticateRoleSession(ctx, tx, credential, now)
		if err != nil {
			return err
		}
		result = iamv1.CurrentRoleIdentity{APIVersion: iamv1.APIVersion, Kind: "CurrentRoleIdentity", Session: binding.Subject.Session,
			Account: iamv1.RoleAccountDisplay{ID: binding.Subject.Source.Organization.ID, DisplayName: binding.Subject.Source.Organization.DisplayName},
			Role:    iamv1.RoleDisplay{ID: binding.Subject.Role.ID, Name: binding.Subject.Role.Name},
			SourceUser: iamv1.RoleSourceUserDisplay{ID: binding.Subject.Source.Principal.ID, LoginName: binding.Subject.Source.Principal.LoginName,
				DisplayName: binding.Subject.Source.Principal.DisplayName}}
		if iamv1.ValidateCurrentRoleIdentity(result) != nil {
			return ErrUnavailable
		}
		return nil
	})
	if err != nil {
		return iamv1.CurrentRoleIdentity{}, err
	}
	return result, nil
}

func (service *Authority) LogoutRoleSession(ctx context.Context, credential iamv1.Secret, request iamv1.LogoutRequest) (iamv1.RoleSession, error) {
	if iamv1.ValidateID("requestId", request.RequestID) != nil {
		return iamv1.RoleSession{}, ErrInvalidArgument
	}
	lookup, err := authority.LookupCredentialDigest(authority.CredentialRoleSession, credential)
	if err != nil {
		return iamv1.RoleSession{}, ErrUnauthenticated
	}
	var result iamv1.RoleSession
	err = service.withinTransaction(ctx, func(ctx context.Context, tx Transaction) error {
		now, err := transactionTime(ctx, tx)
		if err != nil {
			return err
		}
		binding, found, err := tx.LookupRoleSessionForExit(ctx, lookup)
		if err != nil {
			return err
		}
		if !found {
			return ErrUnauthenticated
		}
		session := binding.Session
		if iamv1.ValidateRoleSession(session) != nil {
			return ErrUnavailable
		}
		verified, err := authority.VerifyCredential(authority.CredentialRoleSession, string(session.ID), credential, binding.VerificationDigest)
		if err != nil {
			return ErrUnavailable
		}
		if !verified {
			return ErrUnauthenticated
		}
		digest, err := digestSanitized("role-session-exit", struct {
			SessionID iamv1.RoleSessionID `json:"sessionId"`
			Request   iamv1.LogoutRequest `json:"request"`
		}{session.ID, request})
		if err != nil {
			return err
		}
		eventID, err := service.config.NewID("event")
		if err != nil {
			return ErrUnavailable
		}
		event, err := newAuditEvent(eventID, session.AccountID, "", auditv1.ActorReference{
			Type: auditv1.ActorRole, ID: auditv1.ActorID(session.RoleID),
			RoleSession: &auditv1.RoleSessionReference{SessionID: string(session.ID), SourceUserID: auditv1.ActorID(session.SourceUserID)},
		}, auditv1.ActionIAMRoleSessionExited, auditv1.TargetReference{Kind: auditv1.TargetRoleSession, ID: string(session.ID)},
			auditv1.ResultSucceeded, "", digest, request.RequestID, request.RequestID, now)
		if err != nil {
			return err
		}
		result, err = tx.ExitRoleSession(ctx, lookup, event)
		if err != nil {
			return err
		}
		if iamv1.ValidateRoleSession(result) != nil || result.Status != iamv1.SessionRevoked || result.ID != session.ID ||
			result.RoleID != session.RoleID || result.AccountID != session.AccountID || result.SourceUserID != session.SourceUserID ||
			!result.IssuedAt.Equal(session.IssuedAt) || !result.ExpiresAt.Equal(session.ExpiresAt) {
			return ErrUnavailable
		}
		return nil
	})
	if err != nil {
		return iamv1.RoleSession{}, err
	}
	return result, nil
}

func (service *Authority) AssumeRole(ctx context.Context, credential iamv1.Secret, id iamv1.RoleID, request iamv1.AssumeRoleRequest) (iamv1.AssumeRoleResponse, error) {
	if iamv1.ValidateID("roleId", string(id)) != nil || iamv1.ValidateAssumeRoleRequest(request) != nil {
		return iamv1.AssumeRoleResponse{}, ErrInvalidArgument
	}
	digest, err := digestSanitized("role-assume", struct {
		RoleID  iamv1.RoleID            `json:"roleId"`
		Request iamv1.AssumeRoleRequest `json:"request"`
	}{id, request})
	if err != nil {
		return iamv1.AssumeRoleResponse{}, err
	}
	var response iamv1.AssumeRoleResponse
	denied := false
	err = service.withinTransaction(ctx, func(ctx context.Context, tx Transaction) error {
		response, denied = iamv1.AssumeRoleResponse{}, false
		now, err := transactionTime(ctx, tx)
		if err != nil {
			return err
		}
		source, err := service.authenticateSession(ctx, tx, credential, now)
		if err != nil {
			return err
		}
		if source.Subject.Principal.Type != iamv1.PrincipalUser || source.Subject.Principal.MustChangePassword {
			return ErrForbidden
		}
		read := RoleAssumptionRead{AccountID: source.Subject.Organization.ID, ActorPrincipalID: source.Subject.Principal.ID,
			ActorSessionID: source.Subject.Session.ID, RoleID: id, RequestID: request.RequestID}
		assumption, err := tx.ReadRoleAssumption(ctx, read)
		if err != nil {
			return err
		}
		if previous := assumption.Existing; previous != nil {
			if previous.RequestDigest != digest || previous.SourceSessionID != read.ActorSessionID ||
				previous.CredentialGeneration != assumption.CredentialGeneration {
				return ErrConflict
			}
			response = iamv1.AssumeRoleResponse{Outcome: "EQUAL_REPLAY", Session: previous.Session}
			return nil
		}
		if assumption.Role.ResourceVersion != request.ResourceVersion {
			return ErrConflict
		}
		trusted, err := authority.RoleTrustAllowsUser(source.Subject, assumption.Role, assumption.Trust, now)
		if err != nil {
			return ErrUnavailable
		}
		if !trusted {
			return ErrForbidden
		}
		decision, err := service.managementDecision(ctx, tx, source, iamv1.ActionIAMRoleAssume,
			iamv1.ResourceReference{Kind: iamv1.ResourceRole, ID: string(id)}, iamv1.AuthorizationResourceInstance, "", request.RequestID, now)
		if err != nil {
			return err
		}
		if !decision.Allowed {
			denied = true
			return nil
		}
		duration := iamv1.DefaultRoleSessionDurationSeconds
		if request.DurationSeconds != nil {
			duration = *request.DurationSeconds
		}
		expires, err := authority.RoleSessionDeadline(now, duration, assumption.Role.MaxSessionDurationSeconds, source.Subject.Session.ExpiresAt)
		if err != nil {
			return ErrUnavailable
		}
		canonical, policyDigest := "", ""
		if request.SessionPolicy != nil {
			compilation, err := iamv1.CompilePolicyDocument(*request.SessionPolicy, iamv1.AllAuthorizationProfiles())
			if err != nil {
				return ErrInvalidArgument
			}
			canonical, policyDigest, err = iamv1.CanonicalizePolicyCompilation(*request.SessionPolicy, compilation, iamv1.AllAuthorizationProfiles())
			if err != nil {
				return ErrInvalidArgument
			}
		}
		sessionID, err := service.config.NewID("role-session")
		if err != nil {
			return ErrUnavailable
		}
		issued, err := service.credentials.Issue(authority.CredentialRoleSession, sessionID)
		if err != nil {
			return ErrUnavailable
		}
		session := iamv1.RoleSession{APIVersion: iamv1.APIVersion, Kind: "RoleSession", ID: iamv1.RoleSessionID(sessionID),
			AccountID: read.AccountID, RoleID: id, SourceUserID: read.ActorPrincipalID, Status: iamv1.SessionActive, IssuedAt: now, ExpiresAt: expires}
		event, err := service.newManagementEvent(source, auditv1.ActionIAMRoleSessionIssued, auditv1.TargetRoleSession, sessionID,
			decision.ID, digest, request.RequestID, now)
		if err != nil {
			return err
		}
		stored, err := tx.IssueRoleSession(ctx, RoleSessionIssuance{RoleAssumptionRead: read, Session: session, ExpectedRoleVersion: request.ResourceVersion,
			CredentialGeneration: assumption.CredentialGeneration, SecurityGeneration: assumption.SecurityGeneration, DurationSeconds: duration,
			RequestDigest: digest, SessionPolicyCanonical: canonical, SessionPolicyDigest: policyDigest, LookupDigest: issued.LookupDigest,
			VerificationDigest: issued.VerificationDigest, DecisionID: decision.ID, AuditEvent: event})
		if err != nil {
			return err
		}
		response = iamv1.AssumeRoleResponse{Outcome: "APPLIED", Session: stored, Credential: issued.Credential}
		return nil
	})
	if err != nil {
		return iamv1.AssumeRoleResponse{}, err
	}
	if denied {
		return iamv1.AssumeRoleResponse{}, ErrForbidden
	}
	if iamv1.ValidateAssumeRoleResponse(response) != nil {
		return iamv1.AssumeRoleResponse{}, ErrUnavailable
	}
	return response, nil
}

func (service *Authority) GetRoleSessionByRequest(ctx context.Context, credential iamv1.Secret, requestID string) (iamv1.RoleSession, bool, error) {
	if iamv1.ValidateID("requestId", requestID) != nil {
		return iamv1.RoleSession{}, false, ErrInvalidArgument
	}
	var result iamv1.RoleSession
	var found bool
	err := service.withinTransaction(ctx, func(ctx context.Context, tx Transaction) error {
		now, err := transactionTime(ctx, tx)
		if err != nil {
			return err
		}
		source, err := service.authenticateSession(ctx, tx, credential, now)
		if err != nil {
			return err
		}
		if source.Subject.Principal.MustChangePassword {
			return ErrForbidden
		}
		result, found, err = tx.ReadRoleSessionByRequest(ctx, RoleAssumptionRead{AccountID: source.Subject.Organization.ID,
			ActorPrincipalID: source.Subject.Principal.ID, ActorSessionID: source.Subject.Session.ID, RequestID: requestID})
		return err
	})
	if err != nil {
		return iamv1.RoleSession{}, false, err
	}
	return result, found, nil
}

func (service *Authority) RevokeRoleSessionByRequest(ctx context.Context, credential iamv1.Secret, issuanceRequestID string, request iamv1.RevokeRoleSessionRequest) (iamv1.RoleSession, error) {
	if iamv1.ValidateID("issuanceRequestId", issuanceRequestID) != nil || iamv1.ValidateID("requestId", request.RequestID) != nil {
		return iamv1.RoleSession{}, ErrInvalidArgument
	}
	digest, err := digestSanitized("role-session-revoke", struct {
		IssuanceRequestID string
		Request           iamv1.RevokeRoleSessionRequest
	}{issuanceRequestID, request})
	if err != nil {
		return iamv1.RoleSession{}, err
	}
	var result iamv1.RoleSession
	err = service.withinTransaction(ctx, func(ctx context.Context, tx Transaction) error {
		now, err := transactionTime(ctx, tx)
		if err != nil {
			return err
		}
		source, err := service.authenticateSession(ctx, tx, credential, now)
		if err != nil {
			return err
		}
		if source.Subject.Principal.MustChangePassword {
			return ErrForbidden
		}
		read := RoleAssumptionRead{AccountID: source.Subject.Organization.ID, ActorPrincipalID: source.Subject.Principal.ID,
			ActorSessionID: source.Subject.Session.ID, RequestID: issuanceRequestID}
		previous, found, err := tx.ReadRoleSessionByRequest(ctx, read)
		if err != nil {
			return err
		}
		if !found {
			return ErrForbidden
		}
		event, err := service.newManagementEvent(source, auditv1.ActionIAMRoleSessionRevoked, auditv1.TargetRoleSession, string(previous.ID), "", digest, request.RequestID, now)
		if err != nil {
			return err
		}
		result, err = tx.RevokeRoleSessionByRequest(ctx, RoleSessionRevocation{RoleAssumptionRead: read, AuditEvent: event})
		return err
	})
	if err != nil {
		return iamv1.RoleSession{}, err
	}
	return result, nil
}

func roleRoot(ctx context.Context, tx Transaction, subject SessionCredential) (bool, error) {
	account, err := tx.ReadAccount(ctx, subject.Subject.Organization.ID, subject.Subject.Principal.ID)
	if err != nil {
		return false, err
	}
	if iamv1.ValidateAccount(account) != nil || account.ID != subject.Subject.Organization.ID {
		return false, ErrUnavailable
	}
	return account.RootIdentity.PrincipalID == subject.Subject.Principal.ID, nil
}

func roleCapabilities(subject SessionCredential, role iamv1.Role, attachments []iamv1.PolicyAttachment, root bool, now time.Time) ([]iamv1.ActionCapability, error) {
	result := make([]iamv1.ActionCapability, 0, 8+len(attachments))
	for _, action := range []iamv1.Action{iamv1.ActionIAMRoleRead, iamv1.ActionIAMRoleUpdate, iamv1.ActionIAMRoleSetStatus,
		iamv1.ActionIAMRoleDelete, iamv1.ActionIAMRoleTrustSet, iamv1.ActionIAMRolePolicyAttachmentCreate,
		iamv1.ActionIAMRolePermissionBoundarySet, iamv1.ActionIAMRolePermissionBoundaryRemove} {
		capability, err := projectCapability(subject, action, iamv1.ResourceReference{Kind: iamv1.ResourceRole, ID: string(role.ID)}, iamv1.AuthorizationResourceInstance, "", now)
		if err != nil {
			return nil, err
		}
		if action != iamv1.ActionIAMRoleRead && !root {
			restrictCapability(&capability, iamv1.CapabilityAuthorityRequired)
		}
		result = append(result, capability)
	}
	for _, attachment := range attachments {
		capability, err := projectCapability(subject, iamv1.ActionIAMRolePolicyAttachmentRevoke,
			iamv1.ResourceReference{Kind: iamv1.ResourcePolicyAttachment, ID: string(attachment.ID)}, iamv1.AuthorizationResourceInstance, "", now)
		if err != nil {
			return nil, err
		}
		if !root {
			restrictCapability(&capability, iamv1.CapabilityAuthorityRequired)
		}
		result = append(result, capability)
	}
	return result, nil
}

// Shared by self discovery and management detail. It does not issue a session
// or record a fabricated decision, and root-only management protection must
// never be used as the rule for an ordinary USER assuming a role.
func roleAssumeCapability(subject SessionCredential, candidate RoleCandidate, now time.Time) (iamv1.ActionCapability, error) {
	trusted, err := authority.RoleTrustAllowsUser(subject.Subject, candidate.Role, candidate.Trust, now)
	if err != nil || (candidate.Boundary != nil && authority.ValidateRoleBoundary(candidate.Boundary, candidate.Role.AccountID) != nil) {
		return iamv1.ActionCapability{}, ErrUnavailable
	}
	capability, err := projectCapability(subject, iamv1.ActionIAMRoleAssume,
		iamv1.ResourceReference{Kind: iamv1.ResourceRole, ID: string(candidate.Role.ID)}, iamv1.AuthorizationResourceInstance, "", now)
	if err != nil {
		return iamv1.ActionCapability{}, err
	}
	if candidate.Role.Status != iamv1.RoleActive {
		restrictCapability(&capability, iamv1.CapabilityTargetDisabled)
	} else if !trusted || candidate.Boundary == nil {
		restrictCapability(&capability, iamv1.CapabilityAuthorityRequired)
	}
	return capability, nil
}

func (service *Authority) ListAssumableRoles(ctx context.Context, credential iamv1.Secret, after string) (iamv1.AssumableRoleList, error) {
	if after != "" && iamv1.ValidateRoleDiscoveryCursor(after) != nil {
		return iamv1.AssumableRoleList{}, ErrInvalidArgument
	}
	if service.cursors == nil {
		return iamv1.AssumableRoleList{}, ErrUnavailable
	}
	var result iamv1.AssumableRoleList
	err := service.withinTransaction(ctx, func(ctx context.Context, tx Transaction) error {
		now, err := transactionTime(ctx, tx)
		if err != nil {
			return err
		}
		source, err := service.authenticateSession(ctx, tx, credential, now)
		if err != nil {
			return err
		}
		if source.Subject.Principal.Type != iamv1.PrincipalUser || source.Subject.Principal.MustChangePassword {
			return ErrForbidden
		}
		if err := tx.CheckCurrentAuthorizationProfiles(ctx); err != nil {
			return err
		}
		read := RoleDiscoveryRead{AccountID: source.Subject.Organization.ID, ActorPrincipalID: source.Subject.Principal.ID, ActorSessionID: source.Subject.Session.ID}
		revision, err := tx.ReadRoleDiscoveryRevision(ctx, read)
		if err != nil {
			return err
		}
		bootstrap, err := tx.BootstrapStatus(ctx)
		if err != nil || iamv1.ValidateBootstrapStatus(bootstrap) != nil || bootstrap.State != iamv1.BootstrapReady {
			return ErrUnavailable
		}
		query := authority.DirectoryQuery{InstallationID: bootstrap.InstallationID, AssumableRoles: &revision}
		if after != "" {
			read.After, err = service.cursors.Decode(after, source.Subject, query, now)
			if err != nil {
				return ErrInvalidArgument
			}
		}
		candidates, err := tx.ReadRoleCandidates(ctx, read)
		if err != nil {
			return err
		}
		if candidates.Revision != revision {
			return ErrUnavailable
		}
		result = iamv1.AssumableRoleList{APIVersion: iamv1.APIVersion, Kind: "AssumableRoleList", AccountID: read.AccountID,
			SourceUserID: read.ActorPrincipalID, Items: make([]iamv1.AssumableRole, 0, len(candidates.Items))}
		for _, candidate := range candidates.Items {
			capability, err := roleAssumeCapability(source, candidate, now)
			if err != nil {
				return err
			}
			if capability.Available {
				role := candidate.Role
				result.Items = append(result.Items, iamv1.AssumableRole{RoleID: role.ID, AccountID: role.AccountID, Name: role.Name,
					Status: role.Status, MaxSessionDurationSeconds: role.MaxSessionDurationSeconds, ResourceVersion: role.ResourceVersion, Capability: capability})
			}
		}
		result.NextAfter, err = service.sealDirectoryPage(source, query, candidates.NextAfter, now)
		if err != nil || iamv1.ValidateAssumableRoleList(result) != nil {
			return ErrUnavailable
		}
		return nil
	})
	if err != nil {
		return iamv1.AssumableRoleList{}, err
	}
	return result, nil
}

func (service *Authority) ListRoles(ctx context.Context, credential iamv1.Secret, after, requestID string) (iamv1.RoleList, error) {
	if iamv1.ValidateID("requestId", requestID) != nil || (after != "" && iamv1.ValidatePageCursor(after) != nil) {
		return iamv1.RoleList{}, ErrInvalidArgument
	}
	return withAccountAuthorization(service, ctx, credential, iamv1.ActionIAMRoleList, iamv1.AuthorizationResourceInstance, "",
		iamv1.ResourceReference{Kind: iamv1.ResourceAccount}, requestID,
		func(ctx context.Context, tx Transaction, subject SessionCredential, decision iamv1.AuthorizationDecision, now time.Time) (iamv1.RoleList, error) {
			position, query, err := service.directoryPosition(ctx, tx, subject, decision, after, now)
			if err != nil {
				return iamv1.RoleList{}, err
			}
			root, err := roleRoot(ctx, tx, subject)
			if err != nil {
				return iamv1.RoleList{}, err
			}
			result, err := tx.ListRoles(ctx, AccountRead{AccountID: subject.Subject.Organization.ID, ActorPrincipalID: subject.Subject.Principal.ID, DecisionID: decision.ID, After: position})
			if err != nil {
				return iamv1.RoleList{}, err
			}
			for index := range result.Items {
				result.Items[index].Capabilities, err = roleCapabilities(subject, result.Items[index].Role, nil, root, now)
				if err != nil {
					return iamv1.RoleList{}, err
				}
			}
			result.NextAfter, err = service.sealDirectoryPage(subject, query, result.NextAfter, now)
			if err != nil || iamv1.ValidateRoleList(result) != nil {
				return iamv1.RoleList{}, ErrUnavailable
			}
			return result, nil
		})
}

func withRoleRead[T any](service *Authority, ctx context.Context, credential iamv1.Secret, id iamv1.RoleID, requestID string,
	read func(context.Context, Transaction, SessionCredential, iamv1.AuthorizationDecision, time.Time) (T, error)) (T, error) {
	if iamv1.ValidateID("roleId", string(id)) != nil || iamv1.ValidateID("requestId", requestID) != nil {
		var zero T
		return zero, ErrInvalidArgument
	}
	return withAccountAuthorization(service, ctx, credential, iamv1.ActionIAMRoleRead, iamv1.AuthorizationResourceInstance, "",
		iamv1.ResourceReference{Kind: iamv1.ResourceRole, ID: string(id)}, requestID, read)
}

func (service *Authority) GetRole(ctx context.Context, credential iamv1.Secret, id iamv1.RoleID, requestID string) (iamv1.RoleAccess, error) {
	return withRoleRead(service, ctx, credential, id, requestID,
		func(ctx context.Context, tx Transaction, subject SessionCredential, decision iamv1.AuthorizationDecision, now time.Time) (iamv1.RoleAccess, error) {
			root, err := roleRoot(ctx, tx, subject)
			if err != nil {
				return iamv1.RoleAccess{}, err
			}
			result, err := tx.ReadRole(ctx, RoleRead{AccountRead: AccountRead{AccountID: subject.Subject.Organization.ID, ActorPrincipalID: subject.Subject.Principal.ID, DecisionID: decision.ID}, RoleID: id})
			if err != nil {
				return iamv1.RoleAccess{}, err
			}
			result.Capabilities, err = roleCapabilities(subject, result.Role, result.PolicyAttachments, root, now)
			if err != nil {
				return iamv1.RoleAccess{}, err
			}
			candidates, err := tx.ReadRoleCandidates(ctx, RoleDiscoveryRead{AccountID: subject.Subject.Organization.ID,
				ActorPrincipalID: subject.Subject.Principal.ID, ActorSessionID: subject.Subject.Session.ID, RoleID: id})
			if err != nil {
				return iamv1.RoleAccess{}, err
			}
			if len(candidates.Items) != 1 || candidates.Items[0].Role.ID != result.Role.ID || candidates.Items[0].Role.ResourceVersion != result.Role.ResourceVersion {
				return iamv1.RoleAccess{}, ErrUnavailable
			}
			assume, err := roleAssumeCapability(subject, candidates.Items[0], now)
			if err != nil {
				return iamv1.RoleAccess{}, err
			}
			result.Capabilities = append(result.Capabilities, assume)
			if iamv1.ValidateRoleAccess(result) != nil {
				return iamv1.RoleAccess{}, ErrUnavailable
			}
			return result, nil
		})
}

func (service *Authority) GetRolePermissionBoundary(ctx context.Context, credential iamv1.Secret, id iamv1.RoleID, requestID string) (iamv1.RolePermissionBoundary, error) {
	return withRoleRead(service, ctx, credential, id, requestID,
		func(ctx context.Context, tx Transaction, subject SessionCredential, decision iamv1.AuthorizationDecision, _ time.Time) (iamv1.RolePermissionBoundary, error) {
			return tx.ReadRolePermissionBoundary(ctx, RoleRead{AccountRead: AccountRead{AccountID: subject.Subject.Organization.ID,
				ActorPrincipalID: subject.Subject.Principal.ID, DecisionID: decision.ID}, RoleID: id})
		})
}

func (service *Authority) SetRolePermissionBoundary(ctx context.Context, credential iamv1.Secret, id iamv1.RoleID, request iamv1.SetRolePermissionBoundaryRequest) (iamv1.RolePermissionBoundary, error) {
	if iamv1.ValidateSetRolePermissionBoundaryRequest(request) != nil {
		return iamv1.RolePermissionBoundary{}, ErrInvalidArgument
	}
	return service.changeRolePermissionBoundary(ctx, credential, id, request)
}

func (service *Authority) RemoveRolePermissionBoundary(ctx context.Context, credential iamv1.Secret, id iamv1.RoleID, request iamv1.RemoveRolePermissionBoundaryRequest) (iamv1.RolePermissionBoundary, error) {
	if iamv1.ValidateRemoveRolePermissionBoundaryRequest(request) != nil {
		return iamv1.RolePermissionBoundary{}, ErrInvalidArgument
	}
	return service.changeRolePermissionBoundary(ctx, credential, id, iamv1.SetRolePermissionBoundaryRequest{ResourceVersion: request.ResourceVersion, RequestID: request.RequestID})
}

func (service *Authority) changeRolePermissionBoundary(ctx context.Context, credential iamv1.Secret, id iamv1.RoleID, request iamv1.SetRolePermissionBoundaryRequest) (iamv1.RolePermissionBoundary, error) {
	if iamv1.ValidateID("roleId", string(id)) != nil {
		return iamv1.RolePermissionBoundary{}, ErrInvalidArgument
	}
	action, fact := iamv1.ActionIAMRolePermissionBoundarySet, auditv1.ActionIAMRolePermissionBoundarySet
	if request.PolicyID == "" {
		action, fact = iamv1.ActionIAMRolePermissionBoundaryRemove, auditv1.ActionIAMRolePermissionBoundaryRemoved
	}
	digest, err := digestSanitized(string(action), struct {
		RoleID  iamv1.RoleID                           `json:"roleId"`
		Request iamv1.SetRolePermissionBoundaryRequest `json:"request"`
	}{id, request})
	if err != nil {
		return iamv1.RolePermissionBoundary{}, err
	}
	return withRoleMutation(service, ctx, credential, id, request.ResourceVersion, action, fact, request.RequestID, digest,
		func(ctx context.Context, tx Transaction, subject SessionCredential, mutation RoleMutation, _ time.Time) (iamv1.RolePermissionBoundary, error) {
			boundaryID := ""
			if request.PolicyID != "" {
				identity, err := digestSanitized("role-boundary-identity", struct {
					AccountID iamv1.AccountID   `json:"accountId"`
					ActorID   iamv1.PrincipalID `json:"actorId"`
					RoleID    iamv1.RoleID      `json:"roleId"`
					RequestID string            `json:"requestId"`
				}{subject.Subject.Organization.ID, subject.Subject.Principal.ID, id, request.RequestID})
				if err != nil {
					return iamv1.RolePermissionBoundary{}, err
				}
				boundaryID = "role-boundary-" + identity[len("sha256:"):]
			}
			return tx.ChangeRolePermissionBoundary(ctx, RoleBoundaryMutation{RoleMutation: mutation, PolicyID: request.PolicyID,
				PolicyResourceVersion: request.PolicyResourceVersion, BoundaryID: boundaryID})
		})
}

func roleTrustIdentity(subject SessionCredential, role iamv1.RoleID, requestID string) (iamv1.RoleTrustVersionID, error) {
	digest, err := digestSanitized("role-trust-identity", struct {
		AccountID iamv1.AccountID   `json:"accountId"`
		ActorID   iamv1.PrincipalID `json:"actorId"`
		RoleID    iamv1.RoleID      `json:"roleId"`
		RequestID string            `json:"requestId"`
	}{subject.Subject.Organization.ID, subject.Subject.Principal.ID, role, requestID})
	if err != nil {
		return "", err
	}
	return iamv1.RoleTrustVersionID("trust-" + digest[len("sha256:"):]), nil
}

func (service *Authority) CreateRole(ctx context.Context, credential iamv1.Secret, request iamv1.CreateRoleRequest) (iamv1.Role, error) {
	if iamv1.ValidateCreateRoleRequest(request) != nil {
		return iamv1.Role{}, ErrInvalidArgument
	}
	digest, err := digestSanitized("role-create", request)
	if err != nil {
		return iamv1.Role{}, err
	}
	return withAccountAuthorization(service, ctx, credential, iamv1.ActionIAMRoleCreate, iamv1.AuthorizationResourceInstance, "",
		iamv1.ResourceReference{Kind: iamv1.ResourceAccount}, request.RequestID,
		func(ctx context.Context, tx Transaction, subject SessionCredential, decision iamv1.AuthorizationDecision, now time.Time) (iamv1.Role, error) {
			root, err := roleRoot(ctx, tx, subject)
			if err != nil {
				return iamv1.Role{}, err
			}
			if !root {
				return iamv1.Role{}, ErrForbidden
			}
			identityDigest, err := digestSanitized("role-identity", struct {
				AccountID iamv1.AccountID   `json:"accountId"`
				ActorID   iamv1.PrincipalID `json:"actorId"`
				RequestID string            `json:"requestId"`
			}{subject.Subject.Organization.ID, subject.Subject.Principal.ID, request.RequestID})
			if err != nil {
				return iamv1.Role{}, err
			}
			id := iamv1.RoleID("role-" + identityDigest[len("sha256:"):])
			trustID, err := roleTrustIdentity(subject, id, request.RequestID)
			if err != nil {
				return iamv1.Role{}, err
			}
			_, trustDigest, err := iamv1.CanonicalizeTrustPolicyDocument(request.TrustPolicy)
			if err != nil {
				return iamv1.Role{}, ErrInvalidArgument
			}
			duration := iamv1.DefaultRoleSessionDurationSeconds
			if request.MaxSessionDurationSeconds != nil {
				duration = *request.MaxSessionDurationSeconds
			}
			role := iamv1.Role{APIVersion: iamv1.APIVersion, Kind: "Role", ID: id, AccountID: subject.Subject.Organization.ID,
				Name: request.Name, Description: request.Description, Tags: request.Tags, Management: iamv1.RoleCustomerManaged,
				Status: iamv1.RoleActive, MaxSessionDurationSeconds: duration, ResourceVersion: 1, CurrentTrustVersionID: trustID, CreatedAt: now, UpdatedAt: now}
			trust := iamv1.RoleTrustVersion{APIVersion: iamv1.APIVersion, Kind: "RoleTrustVersion", ID: trustID, AccountID: role.AccountID,
				RoleID: id, Document: request.TrustPolicy, ContentDigest: trustDigest, CreatedAt: now}
			event, err := service.newManagementEvent(subject, auditv1.ActionIAMRoleCreated, auditv1.TargetRole, string(id), decision.ID, digest, request.RequestID, now)
			if err != nil {
				return iamv1.Role{}, err
			}
			return tx.CreateRole(ctx, RoleCreation{Role: role, TrustVersion: trust, ActorPrincipalID: subject.Subject.Principal.ID,
				ActorSessionID: subject.Subject.Session.ID, DecisionID: decision.ID, AuditEvent: event})
		})
}

// Every Role write passes the same current PDP plus original-root boundary.
// The adapter rechecks that writer's exact session under the database locks.
func withRoleMutation[T any](service *Authority, ctx context.Context, credential iamv1.Secret, id iamv1.RoleID, revision uint64,
	action iamv1.Action, fact auditv1.Action, requestID, digest string,
	apply func(context.Context, Transaction, SessionCredential, RoleMutation, time.Time) (T, error)) (T, error) {
	return withAccountAuthorization(service, ctx, credential, action, iamv1.AuthorizationResourceInstance, "",
		iamv1.ResourceReference{Kind: iamv1.ResourceRole, ID: string(id)}, requestID,
		func(ctx context.Context, tx Transaction, subject SessionCredential, decision iamv1.AuthorizationDecision, now time.Time) (T, error) {
			var zero T
			root, err := roleRoot(ctx, tx, subject)
			if err != nil {
				return zero, err
			}
			if !root {
				return zero, ErrForbidden
			}
			event, err := service.newManagementEvent(subject, fact, auditv1.TargetRole, string(id), decision.ID, digest, requestID, now)
			if err != nil {
				return zero, err
			}
			return apply(ctx, tx, subject, RoleMutation{AccountID: subject.Subject.Organization.ID, RoleID: id,
				ActorPrincipalID: subject.Subject.Principal.ID, ActorSessionID: subject.Subject.Session.ID,
				DecisionID: decision.ID, ResourceVersion: revision, AuditEvent: event}, now)
		})
}

func (service *Authority) UpdateRole(ctx context.Context, credential iamv1.Secret, id iamv1.RoleID, request iamv1.UpdateRoleRequest) (iamv1.Role, error) {
	if iamv1.ValidateID("roleId", string(id)) != nil || iamv1.ValidateUpdateRoleRequest(request) != nil {
		return iamv1.Role{}, ErrInvalidArgument
	}
	digest, err := digestSanitized("role-update", struct {
		ID      iamv1.RoleID
		Request iamv1.UpdateRoleRequest
	}{id, request})
	if err != nil {
		return iamv1.Role{}, err
	}
	return withRoleMutation(service, ctx, credential, id, request.ResourceVersion, iamv1.ActionIAMRoleUpdate, auditv1.ActionIAMRoleUpdated, request.RequestID, digest,
		func(ctx context.Context, tx Transaction, _ SessionCredential, mutation RoleMutation, _ time.Time) (iamv1.Role, error) {
			return tx.UpdateRole(ctx, RoleProfileMutation{RoleMutation: mutation, Name: request.Name, Description: request.Description,
				Tags: request.Tags, MaxSessionDurationSeconds: request.MaxSessionDurationSeconds})
		})
}

func (service *Authority) SetRoleStatus(ctx context.Context, credential iamv1.Secret, id iamv1.RoleID, request iamv1.SetRoleStatusRequest) (iamv1.Role, error) {
	if iamv1.ValidateID("roleId", string(id)) != nil || iamv1.ValidateSetRoleStatusRequest(request) != nil {
		return iamv1.Role{}, ErrInvalidArgument
	}
	digest, err := digestSanitized("role-status", struct {
		ID      iamv1.RoleID
		Request iamv1.SetRoleStatusRequest
	}{id, request})
	if err != nil {
		return iamv1.Role{}, err
	}
	fact := auditv1.ActionIAMRoleDisabled
	if request.Status == iamv1.RoleActive {
		fact = auditv1.ActionIAMRoleEnabled
	}
	return withRoleMutation(service, ctx, credential, id, request.ResourceVersion, iamv1.ActionIAMRoleSetStatus, fact, request.RequestID, digest,
		func(ctx context.Context, tx Transaction, _ SessionCredential, mutation RoleMutation, _ time.Time) (iamv1.Role, error) {
			return tx.SetRoleStatus(ctx, RoleStatusMutation{RoleMutation: mutation, Status: request.Status})
		})
}

func (service *Authority) SetRoleTrustPolicy(ctx context.Context, credential iamv1.Secret, id iamv1.RoleID, request iamv1.SetRoleTrustPolicyRequest) (iamv1.Role, error) {
	if iamv1.ValidateID("roleId", string(id)) != nil || iamv1.ValidateSetRoleTrustPolicyRequest(request) != nil {
		return iamv1.Role{}, ErrInvalidArgument
	}
	digest, err := digestSanitized("role-trust-set", struct {
		ID      iamv1.RoleID
		Request iamv1.SetRoleTrustPolicyRequest
	}{id, request})
	if err != nil {
		return iamv1.Role{}, err
	}
	return withRoleMutation(service, ctx, credential, id, request.ResourceVersion, iamv1.ActionIAMRoleTrustSet, auditv1.ActionIAMRoleTrustSet, request.RequestID, digest,
		func(ctx context.Context, tx Transaction, subject SessionCredential, mutation RoleMutation, now time.Time) (iamv1.Role, error) {
			trustID, err := roleTrustIdentity(subject, id, request.RequestID)
			if err != nil {
				return iamv1.Role{}, err
			}
			_, digest, err := iamv1.CanonicalizeTrustPolicyDocument(request.Document)
			if err != nil {
				return iamv1.Role{}, ErrInvalidArgument
			}
			return tx.SetRoleTrustPolicy(ctx, RoleTrustMutation{RoleMutation: mutation, TrustVersion: iamv1.RoleTrustVersion{
				APIVersion: iamv1.APIVersion, Kind: "RoleTrustVersion", ID: trustID, AccountID: mutation.AccountID,
				RoleID: id, Document: request.Document, ContentDigest: digest, CreatedAt: now}})
		})
}

func (service *Authority) DeleteRole(ctx context.Context, credential iamv1.Secret, id iamv1.RoleID, request iamv1.DeleteRoleRequest) (iamv1.RoleDeletion, error) {
	if iamv1.ValidateID("roleId", string(id)) != nil || iamv1.ValidateDeleteRoleRequest(request) != nil {
		return iamv1.RoleDeletion{}, ErrInvalidArgument
	}
	digest, err := digestSanitized("role-delete", struct {
		ID      iamv1.RoleID
		Request iamv1.DeleteRoleRequest
	}{id, request})
	if err != nil {
		return iamv1.RoleDeletion{}, err
	}
	return withRoleMutation(service, ctx, credential, id, request.ResourceVersion, iamv1.ActionIAMRoleDelete, auditv1.ActionIAMRoleDeleted, request.RequestID, digest,
		func(ctx context.Context, tx Transaction, _ SessionCredential, mutation RoleMutation, _ time.Time) (iamv1.RoleDeletion, error) {
			return tx.DeleteRole(ctx, mutation)
		})
}

func (service *Authority) ListRoleTrustVersions(ctx context.Context, credential iamv1.Secret, id iamv1.RoleID, after, requestID string) (iamv1.RoleTrustVersionList, error) {
	if after != "" && iamv1.ValidatePageCursor(after) != nil {
		return iamv1.RoleTrustVersionList{}, ErrInvalidArgument
	}
	return withRoleRead(service, ctx, credential, id, requestID,
		func(ctx context.Context, tx Transaction, subject SessionCredential, decision iamv1.AuthorizationDecision, now time.Time) (iamv1.RoleTrustVersionList, error) {
			position, query, err := service.directoryPosition(ctx, tx, subject, decision, after, now)
			if err != nil {
				return iamv1.RoleTrustVersionList{}, err
			}
			result, err := tx.ListRoleTrustVersions(ctx, RoleRead{AccountRead: AccountRead{AccountID: subject.Subject.Organization.ID, ActorPrincipalID: subject.Subject.Principal.ID, DecisionID: decision.ID, After: position}, RoleID: id})
			if err != nil {
				return iamv1.RoleTrustVersionList{}, err
			}
			result.NextAfter, err = service.sealDirectoryPage(subject, query, result.NextAfter, now)
			if err != nil || iamv1.ValidateRoleTrustVersionList(result) != nil {
				return iamv1.RoleTrustVersionList{}, ErrUnavailable
			}
			return result, nil
		})
}

func (service *Authority) GetRoleTrustVersion(ctx context.Context, credential iamv1.Secret, id iamv1.RoleID, versionID iamv1.RoleTrustVersionID, requestID string) (iamv1.RoleTrustVersion, error) {
	if iamv1.ValidateID("trustVersionId", string(versionID)) != nil {
		return iamv1.RoleTrustVersion{}, ErrInvalidArgument
	}
	return withRoleRead(service, ctx, credential, id, requestID,
		func(ctx context.Context, tx Transaction, subject SessionCredential, decision iamv1.AuthorizationDecision, _ time.Time) (iamv1.RoleTrustVersion, error) {
			return tx.ReadRoleTrustVersion(ctx, RoleRead{AccountRead: AccountRead{AccountID: subject.Subject.Organization.ID, ActorPrincipalID: subject.Subject.Principal.ID, DecisionID: decision.ID}, RoleID: id}, versionID)
		})
}
