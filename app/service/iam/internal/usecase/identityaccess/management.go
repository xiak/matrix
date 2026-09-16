package identityaccess

import (
	"context"
	"errors"
	"time"

	auditv1 "github.com/xiak/matrix/api/audit/v1"
	iamv1 "github.com/xiak/matrix/api/iam/v1"
	"github.com/xiak/matrix/app/service/iam/internal/authority"
)

type passwordDigestInput struct {
	RequestID           string          `json:"requestId"`
	SessionID           iamv1.SessionID `json:"sessionId"`
	RevokeOtherSessions bool            `json:"revokeOtherSessions"`
}

type createUserDigestInput struct {
	LoginName   string `json:"loginName"`
	DisplayName string `json:"displayName"`
	RequestID   string `json:"requestId"`
}

type revokeDigestInput struct {
	ID        string `json:"id"`
	RequestID string `json:"requestId"`
}

func (service *Authority) Logout(
	ctx context.Context,
	credential iamv1.Secret,
	request iamv1.LogoutRequest,
) (iamv1.LogoutResponse, error) {
	if iamv1.ValidateLogoutRequest(request) != nil {
		return iamv1.LogoutResponse{}, ErrInvalidArgument
	}
	requestDigest, err := digestSanitized("logout", request)
	if err != nil {
		return iamv1.LogoutResponse{}, err
	}
	var response iamv1.LogoutResponse
	err = service.withinTransaction(ctx, func(transactionContext context.Context, transaction Transaction) error {
		now, err := transactionTime(transactionContext, transaction)
		if err != nil {
			return err
		}
		subject, err := service.authenticateSession(transactionContext, transaction, credential, now)
		if err != nil {
			return err
		}
		event, err := service.newManagementEvent(
			subject,
			auditv1.ActionIAMSessionRevoked,
			auditv1.TargetSession,
			string(subject.Subject.Session.ID),
			"",
			requestDigest,
			request.RequestID,
			now,
		)
		if err != nil {
			return err
		}
		revocation, applied, err := transaction.RevokeSession(transactionContext, SessionRevocationMutation{
			AccountID:        subject.Subject.Organization.ID,
			SessionID:        subject.Subject.Session.ID,
			ActorPrincipalID: subject.Subject.Principal.ID,
			AuditEvent:       event,
		})
		if err != nil {
			return err
		}
		if !applied {
			return ErrUnavailable
		}
		response = iamv1.LogoutResponse{RevokedAt: revocation.RevokedAt}
		return nil
	})
	if err != nil {
		return iamv1.LogoutResponse{}, err
	}
	if iamv1.ValidateLogoutResponse(response) != nil {
		return iamv1.LogoutResponse{}, ErrUnavailable
	}
	return response, nil
}

func (service *Authority) ChangePassword(
	ctx context.Context,
	credential iamv1.Secret,
	request iamv1.ChangePasswordRequest,
) (iamv1.ChangePasswordResponse, error) {
	if iamv1.ValidateChangePasswordRequest(request) != nil ||
		authority.ValidatePassword(request.NewPassword) != nil {
		return iamv1.ChangePasswordResponse{}, ErrInvalidArgument
	}
	var response iamv1.ChangePasswordResponse
	err := service.withinTransaction(ctx, func(transactionContext context.Context, transaction Transaction) error {
		now, err := transactionTime(transactionContext, transaction)
		if err != nil {
			return err
		}
		subject, err := service.authenticateSession(transactionContext, transaction, credential, now)
		if err != nil {
			return err
		}
		stored, found, err := transaction.LookupPassword(
			transactionContext,
			subject.Subject.Organization.ID,
			subject.Subject.Principal.ID,
		)
		if err != nil {
			return err
		}
		if !found {
			return ErrUnavailable
		}
		verified, err := service.passwords.Verify(request.CurrentPassword, stored)
		if err != nil {
			return ErrUnavailable
		}
		if !verified {
			return ErrUnauthenticated
		}
		replacement, err := service.passwords.Hash(request.NewPassword)
		if err != nil {
			if errors.Is(err, authority.ErrWeakPassword) {
				return ErrInvalidArgument
			}
			return ErrUnavailable
		}
		revokeOthers := subject.Subject.Principal.MustChangePassword || request.RevokeOtherSessions == nil || *request.RevokeOtherSessions
		requestDigest, err := digestSanitized("password-change", passwordDigestInput{
			RequestID: request.RequestID, SessionID: subject.Subject.Session.ID, RevokeOtherSessions: revokeOthers,
		})
		if err != nil {
			return err
		}
		event, err := service.newManagementEvent(
			subject,
			auditv1.ActionIAMUserPasswordChanged,
			auditv1.TargetUser,
			string(subject.Subject.Principal.ID),
			"",
			requestDigest,
			request.RequestID,
			now,
		)
		if err != nil {
			return err
		}
		response, err = transaction.ChangePassword(transactionContext, PasswordMutation{
			AccountID:            subject.Subject.Organization.ID,
			PrincipalID:          subject.Subject.Principal.ID,
			SessionID:            subject.Subject.Session.ID,
			RevokeOtherSessions:  revokeOthers,
			ExpectedPasswordHash: stored,
			NewPasswordHash:      replacement,
			AuditEvent:           event,
		})
		return err
	})
	if err != nil {
		return iamv1.ChangePasswordResponse{}, err
	}
	if iamv1.ValidateChangePasswordResponse(response) != nil {
		return iamv1.ChangePasswordResponse{}, ErrUnavailable
	}
	return response, nil
}

func (service *Authority) CreateUser(
	ctx context.Context,
	credential iamv1.Secret,
	request iamv1.CreateUserRequest,
) (iamv1.User, error) {
	if iamv1.ValidateCreateUserRequest(request) != nil ||
		authority.ValidatePassword(request.InitialPassword) != nil {
		return iamv1.User{}, ErrInvalidArgument
	}
	requestDigest, err := digestSanitized("user-create", createUserDigestInput{
		LoginName: request.LoginName, DisplayName: request.DisplayName, RequestID: request.RequestID,
	})
	if err != nil {
		return iamv1.User{}, err
	}
	var created iamv1.User
	denied := false
	err = service.withinTransaction(ctx, func(transactionContext context.Context, transaction Transaction) error {
		denied = false
		now, err := transactionTime(transactionContext, transaction)
		if err != nil {
			return err
		}
		subject, err := service.authenticateSession(transactionContext, transaction, credential, now)
		if err != nil {
			return err
		}
		decision, err := service.managementDecision(
			transactionContext,
			transaction,
			subject,
			iamv1.ActionIAMUserCreate,
			iamv1.ResourceReference{Kind: iamv1.ResourceAccount, ID: string(subject.Subject.Organization.ID)},
			iamv1.AuthorizationResourceInstance, "",
			request.RequestID,
			now,
		)
		if err != nil {
			return err
		}
		if !decision.Allowed {
			denied = true
			return nil
		}
		passwordHash, err := service.passwords.Hash(request.InitialPassword)
		if err != nil {
			return ErrUnavailable
		}
		principalID, err := service.config.NewID("principal")
		if err != nil {
			return ErrUnavailable
		}
		proposed := iamv1.User{
			APIVersion:         iamv1.APIVersion,
			Kind:               "User",
			ID:                 iamv1.PrincipalID(principalID),
			AccountID:          subject.Subject.Organization.ID,
			LoginName:          request.LoginName,
			DisplayName:        request.DisplayName,
			Status:             iamv1.PrincipalActive,
			MustChangePassword: true,
			ResourceVersion:    1,
			CreatedAt:          now,
			UpdatedAt:          now,
		}
		event, err := service.newManagementEvent(
			subject,
			auditv1.ActionIAMUserCreated,
			auditv1.TargetUser,
			principalID,
			decision.ID,
			requestDigest,
			request.RequestID,
			now,
		)
		if err != nil {
			return err
		}
		created, err = transaction.CreateUser(transactionContext, UserMutation{
			User:             proposed,
			PasswordHash:     passwordHash,
			ActorPrincipalID: subject.Subject.Principal.ID,
			DecisionID:       decision.ID,
			AuditEvent:       event,
		})
		return err
	})
	if err != nil {
		return iamv1.User{}, err
	}
	if denied {
		return iamv1.User{}, ErrForbidden
	}
	if iamv1.ValidateUser(created) != nil {
		return iamv1.User{}, ErrUnavailable
	}
	return created, nil
}

func (service *Authority) CreatePolicyAttachment(ctx context.Context, credential iamv1.Secret, request iamv1.CreatePolicyAttachmentRequest) (iamv1.PolicyAttachment, error) {
	if iamv1.ValidateCreatePolicyAttachmentRequest(request) != nil {
		return iamv1.PolicyAttachment{}, ErrInvalidArgument
	}
	requestDigest, err := digestSanitized("policy-attachment-create", request)
	if err != nil {
		return iamv1.PolicyAttachment{}, err
	}
	var stored iamv1.PolicyAttachment
	denied := false
	err = service.withinTransaction(ctx, func(ctx context.Context, tx Transaction) error {
		denied = false
		now, err := transactionTime(ctx, tx)
		if err != nil {
			return err
		}
		subject, err := service.authenticateSession(ctx, tx, credential, now)
		if err != nil {
			return err
		}
		policy, found, err := tx.LookupPolicy(ctx, subject.Subject.Organization.ID, request.PolicyID)
		if err != nil {
			return err
		}
		if !found || policy.Status != iamv1.PolicyActive || (policy.Scope != iamv1.AuthorityScopeTenant && policy.Scope != iamv1.AuthorityScopeInstallation) {
			return ErrForbidden
		}
		if iamv1.ValidatePolicy(policy) != nil {
			return ErrUnavailable
		}
		if policy.AccountID != "" && policy.AccountID != subject.Subject.Organization.ID {
			return ErrForbidden
		}
		action, fact := iamv1.ActionIAMPolicyAttachmentCreate, auditv1.ActionIAMPolicyAttachmentCreated
		resourceKind := iamv1.ResourceUser
		if request.Target.Kind == iamv1.PolicyTargetGroup || request.Target.Kind == iamv1.PolicyTargetRole {
			if policy.Scope != iamv1.AuthorityScopeTenant {
				return ErrForbidden
			}
			action, resourceKind = iamv1.ActionIAMGroupPolicyAttachmentCreate, iamv1.ResourceGroup
			if request.Target.Kind == iamv1.PolicyTargetRole {
				action, resourceKind = iamv1.ActionIAMRolePolicyAttachmentCreate, iamv1.ResourceRole
			}
		} else if policy.Scope == iamv1.AuthorityScopeInstallation {
			action, fact = iamv1.ActionIAMPlatformPolicyAttachmentCreate, auditv1.ActionIAMPlatformPolicyAttachmentCreated
		}
		decision, err := service.managementDecision(ctx, tx, subject, action,
			iamv1.ResourceReference{Kind: resourceKind, ID: request.Target.ID}, iamv1.AuthorizationResourceInstance, "", request.RequestID, now)
		if err != nil {
			return err
		}
		if !decision.Allowed {
			denied = true
			return nil
		}
		if policy.ResourceVersion != request.PolicyResourceVersion {
			return ErrConflict
		}
		if request.Target.Kind == iamv1.PolicyTargetRole {
			root, err := roleRoot(ctx, tx, subject)
			if err != nil {
				return err
			}
			if !root {
				return ErrForbidden
			}
		}
		identityDigest, err := digestSanitized("policy-attachment-identity", struct {
			AccountID iamv1.AccountID   `json:"accountId"`
			ActorID   iamv1.PrincipalID `json:"actorId"`
			RequestID string            `json:"requestId"`
		}{subject.Subject.Organization.ID, subject.Subject.Principal.ID, request.RequestID})
		if err != nil {
			return err
		}
		attachment := iamv1.PolicyAttachment{APIVersion: iamv1.APIVersion, Kind: "PolicyAttachment",
			ID: iamv1.PolicyAttachmentID("attachment-" + identityDigest[len("sha256:"):]), AccountID: subject.Subject.Organization.ID,
			Target: request.Target, PolicyID: policy.ID, Scope: policy.Scope, ResourceVersion: 1, CreatedAt: now, UpdatedAt: now}
		if policy.Scope == iamv1.AuthorityScopeInstallation {
			attachment.InstallationID = subject.Subject.InstallationID
		}
		event, err := service.newManagementEvent(subject, fact, auditv1.TargetPolicyAttachment, string(attachment.ID), decision.ID, requestDigest, request.RequestID, now)
		if err != nil {
			return err
		}
		stored, err = tx.CreatePolicyAttachment(ctx, PolicyAttachmentMutation{Attachment: attachment,
			PolicyResourceVersion: request.PolicyResourceVersion, ActorPrincipalID: subject.Subject.Principal.ID,
			ActorSessionID: subject.Subject.Session.ID, DecisionID: decision.ID, AuditEvent: event})
		return err
	})
	if err != nil {
		return iamv1.PolicyAttachment{}, err
	}
	if denied {
		return iamv1.PolicyAttachment{}, ErrForbidden
	}
	if iamv1.ValidatePolicyAttachment(stored) != nil {
		return iamv1.PolicyAttachment{}, ErrUnavailable
	}
	return stored, nil
}

func (service *Authority) RevokePolicyAttachment(ctx context.Context, credential iamv1.Secret, id iamv1.PolicyAttachmentID, request iamv1.RevokePolicyAttachmentRequest) (iamv1.Revocation, error) {
	if iamv1.ValidateID("attachmentId", string(id)) != nil || iamv1.ValidateRevokePolicyAttachmentRequest(request) != nil {
		return iamv1.Revocation{}, ErrInvalidArgument
	}
	digest, err := digestSanitized("policy-attachment-revoke", struct {
		ID      iamv1.PolicyAttachmentID            `json:"id"`
		Request iamv1.RevokePolicyAttachmentRequest `json:"request"`
	}{id, request})
	if err != nil {
		return iamv1.Revocation{}, err
	}
	var result iamv1.Revocation
	denied := false
	err = service.withinTransaction(ctx, func(ctx context.Context, tx Transaction) error {
		denied = false
		now, err := transactionTime(ctx, tx)
		if err != nil {
			return err
		}
		subject, err := service.authenticateSession(ctx, tx, credential, now)
		if err != nil {
			return err
		}
		attachment, found, err := tx.LookupPolicyAttachment(ctx, subject.Subject.Organization.ID, id)
		if err != nil {
			return err
		}
		if !found {
			return ErrForbidden
		}
		if iamv1.ValidatePolicyAttachment(attachment) != nil {
			return ErrUnavailable
		}
		if attachment.AccountID != subject.Subject.Organization.ID ||
			(attachment.Target.Kind != iamv1.PolicyTargetUser && attachment.Target.Kind != iamv1.PolicyTargetGroup && attachment.Target.Kind != iamv1.PolicyTargetRole) {
			return ErrForbidden
		}
		action, fact := iamv1.ActionIAMPolicyAttachmentRevoke, auditv1.ActionIAMPolicyAttachmentRevoked
		if attachment.Target.Kind == iamv1.PolicyTargetGroup || attachment.Target.Kind == iamv1.PolicyTargetRole {
			if attachment.Scope != iamv1.AuthorityScopeTenant {
				return ErrForbidden
			}
			action = iamv1.ActionIAMGroupPolicyAttachmentRevoke
			if attachment.Target.Kind == iamv1.PolicyTargetRole {
				action = iamv1.ActionIAMRolePolicyAttachmentRevoke
			}
		} else if attachment.Scope == iamv1.AuthorityScopeInstallation {
			action, fact = iamv1.ActionIAMPlatformPolicyAttachmentRevoke, auditv1.ActionIAMPlatformPolicyAttachmentRevoked
			if attachment.InstallationID != subject.Subject.InstallationID {
				return ErrForbidden
			}
		} else if attachment.Scope != iamv1.AuthorityScopeTenant {
			return ErrForbidden
		}
		decision, err := service.managementDecision(ctx, tx, subject, action,
			iamv1.ResourceReference{Kind: iamv1.ResourcePolicyAttachment, ID: string(id)}, iamv1.AuthorizationResourceInstance, "", request.RequestID, now)
		if err != nil {
			return err
		}
		if !decision.Allowed {
			denied = true
			return nil
		}
		event, err := service.newManagementEvent(subject, fact, auditv1.TargetPolicyAttachment, string(id), decision.ID, digest, request.RequestID, now)
		if attachment.Target.Kind == iamv1.PolicyTargetRole {
			root, err := roleRoot(ctx, tx, subject)
			if err != nil {
				return err
			}
			if !root {
				return ErrForbidden
			}
		}
		if err != nil {
			return err
		}
		result, _, err = tx.RevokePolicyAttachment(ctx, PolicyAttachmentRevocationMutation{AccountID: subject.Subject.Organization.ID,
			AttachmentID: id, ResourceVersion: request.ResourceVersion, ActorPrincipalID: subject.Subject.Principal.ID,
			ActorSessionID: subject.Subject.Session.ID, DecisionID: decision.ID, AuditEvent: event})
		return err
	})
	if err != nil {
		return iamv1.Revocation{}, err
	}
	if denied {
		return iamv1.Revocation{}, ErrForbidden
	}
	if iamv1.ValidateRevocation(result) != nil {
		return iamv1.Revocation{}, ErrUnavailable
	}
	return result, nil
}

func (service *Authority) RevokeSession(
	ctx context.Context,
	credential iamv1.Secret,
	sessionID iamv1.SessionID,
	request iamv1.RevokeSessionRequest,
) (iamv1.Revocation, error) {
	if iamv1.ValidateID("sessionId", string(sessionID)) != nil ||
		iamv1.ValidateRevokeSessionRequest(request) != nil {
		return iamv1.Revocation{}, ErrInvalidArgument
	}
	return service.revokeManagedResource(
		ctx,
		credential,
		request.RequestID,
		iamv1.ActionIAMSessionRevoke,
		iamv1.ResourceReference{Kind: iamv1.ResourceSession, ID: string(sessionID)},
		auditv1.ActionIAMSessionRevoked,
		auditv1.TargetSession,
		func(
			transactionContext context.Context,
			transaction Transaction,
			subject SessionCredential,
			decision iamv1.AuthorizationDecision,
			event auditv1.Event,
		) (iamv1.Revocation, bool, error) {
			return transaction.RevokeSession(transactionContext, SessionRevocationMutation{
				AccountID:        subject.Subject.Organization.ID,
				SessionID:        sessionID,
				ActorPrincipalID: subject.Subject.Principal.ID,
				DecisionID:       decision.ID,
				AuditEvent:       event,
			})
		},
	)
}

type revokeMutation func(
	context.Context,
	Transaction,
	SessionCredential,
	iamv1.AuthorizationDecision,
	auditv1.Event,
) (iamv1.Revocation, bool, error)

func (service *Authority) revokeManagedResource(
	ctx context.Context,
	credential iamv1.Secret,
	requestID string,
	action iamv1.Action,
	resource iamv1.ResourceReference,
	auditAction auditv1.Action,
	targetKind auditv1.TargetKind,
	mutate revokeMutation,
) (iamv1.Revocation, error) {
	requestDigest, err := digestSanitized("revoke", revokeDigestInput{ID: resource.ID, RequestID: requestID})
	if err != nil {
		return iamv1.Revocation{}, err
	}
	var result iamv1.Revocation
	denied := false
	err = service.withinTransaction(ctx, func(transactionContext context.Context, transaction Transaction) error {
		denied = false
		now, err := transactionTime(transactionContext, transaction)
		if err != nil {
			return err
		}
		subject, err := service.authenticateSession(transactionContext, transaction, credential, now)
		if err != nil {
			return err
		}
		decision, err := service.managementDecision(
			transactionContext,
			transaction,
			subject,
			action,
			resource,
			iamv1.AuthorizationResourceInstance, "",
			requestID,
			now,
		)
		if err != nil {
			return err
		}
		if !decision.Allowed {
			denied = true
			return nil
		}
		event, err := service.newManagementEvent(
			subject,
			auditAction,
			targetKind,
			resource.ID,
			decision.ID,
			requestDigest,
			requestID,
			now,
		)
		if err != nil {
			return err
		}
		result, _, err = mutate(transactionContext, transaction, subject, decision, event)
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return iamv1.Revocation{}, err
	}
	if denied {
		return iamv1.Revocation{}, ErrForbidden
	}
	if iamv1.ValidateRevocation(result) != nil {
		return iamv1.Revocation{}, ErrUnavailable
	}
	return result, nil
}

func (service *Authority) managementDecision(
	ctx context.Context,
	transaction Transaction,
	subject SessionCredential,
	action iamv1.Action,
	resource iamv1.ResourceReference,
	mode iamv1.AuthorizationResourceMode,
	usage iamv1.AuthorizationCollectionUsage,
	requestID string,
	now time.Time,
) (iamv1.AuthorizationDecision, error) {
	if err := transaction.CheckCurrentAuthorizationProfiles(ctx); err != nil {
		return iamv1.AuthorizationDecision{}, err
	}
	request, err := iamv1.NewAuthorizationRequest(action, resource, mode, usage, requestID, requestID)
	if err != nil {
		return iamv1.AuthorizationDecision{}, ErrUnavailable
	}
	requestDigest, err := digestSanitized("authorization", request)
	if err != nil {
		return iamv1.AuthorizationDecision{}, err
	}
	decisionID, err := service.config.NewID("decision")
	if err != nil {
		return iamv1.AuthorizationDecision{}, ErrUnavailable
	}
	decision, err := authority.Decide(
		subject.Subject,
		iamv1.ServiceIAM,
		request,
		iamv1.DecisionID(decisionID),
		now,
	)
	if err != nil {
		return iamv1.AuthorizationDecision{}, ErrUnavailable
	}
	eventID, err := service.config.NewID("event")
	if err != nil {
		return iamv1.AuthorizationDecision{}, ErrUnavailable
	}
	result := auditv1.ResultDenied
	if decision.Allowed {
		result = auditv1.ResultAllowed
	}
	event, err := newAuditEvent(
		eventID,
		subject.Subject.Organization.ID,
		"",
		auditv1.ActorReference{
			Type: auditv1.ActorType(subject.Subject.Principal.Type),
			ID:   auditv1.ActorID(subject.Subject.Principal.ID),
		},
		auditv1.ActionIAMAuthorizationDecided,
		auditv1.TargetReference{Kind: auditv1.TargetAuthorizationDecision, ID: decisionID},
		result,
		decision.ID,
		requestDigest,
		requestID,
		requestID,
		now,
	)
	if err != nil {
		return iamv1.AuthorizationDecision{}, err
	}
	if err := transaction.RecordAuthorization(ctx, AuthorizationMutation{
		AccountID:        subject.Subject.Organization.ID,
		PrincipalID:      subject.Subject.Principal.ID,
		Request:          request,
		Decision:         decision.AuthorizationDecision,
		PolicyEvidence:   decision.PolicyEvidence,
		BoundaryEvidence: decision.BoundaryEvidence,
		AuditEvent:       event,
	}); err != nil {
		return iamv1.AuthorizationDecision{}, err
	}
	return decision.AuthorizationDecision, nil
}

func (service *Authority) newManagementEvent(
	subject SessionCredential,
	action auditv1.Action,
	targetKind auditv1.TargetKind,
	targetID string,
	decisionID iamv1.DecisionID,
	requestDigest string,
	requestID string,
	now time.Time,
) (auditv1.Event, error) {
	eventID, err := service.config.NewID("event")
	if err != nil {
		return auditv1.Event{}, ErrUnavailable
	}
	tenant, installation := subject.Subject.Organization.ID, ""
	contract, known := auditv1.ContractForAction(action)
	if !known {
		return auditv1.Event{}, ErrUnavailable
	}
	if contract.PlatformOnly {
		tenant, installation = "", subject.Subject.InstallationID
	}
	return newAuditEvent(
		eventID,
		tenant,
		installation,
		auditv1.ActorReference{
			Type: auditv1.ActorType(subject.Subject.Principal.Type),
			ID:   auditv1.ActorID(subject.Subject.Principal.ID),
		},
		action,
		auditv1.TargetReference{Kind: targetKind, ID: targetID},
		auditv1.ResultSucceeded,
		decisionID,
		requestDigest,
		requestID,
		requestID,
		now,
	)
}
