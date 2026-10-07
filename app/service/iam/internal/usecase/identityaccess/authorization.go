package identityaccess

import (
	"context"
	"crypto/subtle"
	"errors"
	"time"

	auditv1 "github.com/xiak/matrix/api/audit/v1"
	iamv1 "github.com/xiak/matrix/api/iam/v1"
	"github.com/xiak/matrix/app/service/iam/internal/authority"
)

type authorizationActor struct {
	organizationID    iamv1.AccountID
	installationID    string
	subject           iamv1.Subject
	accessKeyEvidence *AccessKeyAuthorizationEvidence
}

type verifiedAccessKeyRequest struct {
	caller       ServiceCredential
	credential   AccessKeyCredential
	signedDigest string
}

// verifyAccessKeyRequest authenticates the calling service and the exact MAC
// without consuming the nonce or evaluating Policy. Callers either use the
// result for a non-authorizing Account-scoped lookup or immediately feed it to
// decideAndRecord in the same transaction.
func (service *Authority) verifyAccessKeyRequest(
	ctx context.Context,
	tx Transaction,
	serviceCredential iamv1.Secret,
	profileReference iamv1.AuthorizationProfileReference,
	signed iamv1.AccessKeySignedRequest,
) (verifiedAccessKeyRequest, error) {
	caller, err := service.authenticateService(ctx, tx, serviceCredential)
	if err != nil {
		return verifiedAccessKeyRequest{}, err
	}
	profile, known := iamv1.LookupAuthorizationProfile(profileReference.Product)
	parameters := signed.Parameters
	if !known || iamv1.CheckAuthorizationProfileReference(profile, profileReference) != nil ||
		profile.CallingService != caller.Identity.Purpose || profile.Product != parameters.Audience ||
		caller.Identity.InstallationID != parameters.InstallationID {
		return verifiedAccessKeyRequest{}, ErrUnauthenticated
	}
	if err := tx.CheckCurrentAuthorizationProfiles(ctx); err != nil {
		return verifiedAccessKeyRequest{}, err
	}
	if err := service.checkAccessKeyCustody(ctx, tx); err != nil {
		return verifiedAccessKeyRequest{}, err
	}
	if err := service.checkTOTPCustody(ctx, tx); err != nil {
		return verifiedAccessKeyRequest{}, err
	}
	credential, found, err := tx.LookupAccessKey(ctx, caller.LookupDigest, parameters.AccessKeyID, parameters.InstallationID, parameters.Audience)
	if err != nil {
		return verifiedAccessKeyRequest{}, err
	}
	if !found {
		return verifiedAccessKeyRequest{}, ErrUnauthenticated
	}
	defer clear(credential.Material.Nonce)
	defer clear(credential.Material.Ciphertext)
	wrapping := service.accessKeys
	if credential.Subject.InstallationID != wrapping.scope.InstallationID || credential.Material.WrappingKeyID != wrapping.id ||
		subtle.ConstantTimeCompare([]byte(credential.MaterialCommitment), []byte(wrapping.commitment)) != 1 {
		return verifiedAccessKeyRequest{}, ErrUnavailable
	}
	secret, err := authority.OpenAccessKeySecret(authority.AccessKeySecretScope{InstallationID: credential.Subject.InstallationID,
		AccountID: credential.Subject.Organization.ID, UserID: credential.Subject.Principal.ID, AccessKeyID: string(credential.Subject.Key.ID)},
		wrapping.id, wrapping.material, credential.Material)
	if err != nil {
		return verifiedAccessKeyRequest{}, ErrUnavailable
	}
	verified, err := authority.VerifyAccessKeyRequestSignature(secret, signed)
	if err != nil || !verified {
		return verifiedAccessKeyRequest{}, ErrUnauthenticated
	}
	signedDigest, err := iamv1.AccessKeySignedRequestDigest(signed)
	if err != nil {
		return verifiedAccessKeyRequest{}, ErrUnavailable
	}
	return verifiedAccessKeyRequest{caller: caller, credential: credential, signedDigest: signedDigest}, nil
}

func (service *Authority) AuthorizeAccessKey(ctx context.Context, serviceCredential iamv1.Secret, request iamv1.AccessKeyAuthorizationRequest) (iamv1.AccessKeyAuthorization, error) {
	if iamv1.ValidateAccessKeyAuthorizationRequest(request) != nil {
		return iamv1.AccessKeyAuthorization{}, ErrInvalidArgument
	}
	requestDigest, err := digestSanitized("authorization", request.Authorization)
	if err != nil {
		return iamv1.AccessKeyAuthorization{}, err
	}
	var result iamv1.AccessKeyAuthorization
	err = service.withinTransaction(ctx, func(ctx context.Context, tx Transaction) error {
		now, err := transactionTime(ctx, tx)
		if err != nil {
			return err
		}
		verified, err := service.verifyAccessKeyRequest(ctx, tx, serviceCredential, request.Authorization.Profile, request.SignedRequest)
		if err != nil {
			return err
		}
		caller, credential := verified.caller, verified.credential
		parameters := request.SignedRequest.Parameters
		definition, found := iamv1.LookupActionDefinition(request.Authorization.Action)
		if !found || definition.CallingService != caller.Identity.Purpose || definition.Product != parameters.Audience {
			return ErrUnauthenticated
		}
		nonceDigest, err := iamv1.AccessKeyNonceDigest(parameters)
		if err != nil {
			return ErrUnavailable
		}
		evidenceID, err := service.config.NewID("evidence")
		if err != nil || iamv1.ValidateID("requestEvidenceId", evidenceID) != nil {
			return ErrUnavailable
		}
		evidence := newAccessKeyAuthorizationEvidence(evidenceID, caller, credential, parameters, verified.signedDigest, nonceDigest)
		decision, err := service.decideAndRecord(ctx, tx, request.Authorization, requestDigest, now,
			authorizationActor{organizationID: credential.Subject.Organization.ID,
				subject: iamv1.Subject{Type: iamv1.SubjectUser, ID: string(credential.Subject.Principal.ID), AccessKeyID: credential.Subject.Key.ID}, accessKeyEvidence: evidence},
			func(id iamv1.DecisionID) (authority.AuthorizationEvaluation, error) {
				return authority.DecideAccessKey(credential.Subject, caller.Identity.Purpose, request.Authorization, id, now, parameters.SignedAt)
			})
		if err != nil {
			return err
		}
		result = iamv1.AccessKeyAuthorization{APIVersion: iamv1.APIVersion, Kind: "AccessKeyAuthorization", Decision: decision, SignedRequestDigest: verified.signedDigest}
		// Deny commits exactly like Allow. Returning an authentication error here
		// would roll back its nonce and permit the old packet after a later grant.
		return nil
	})
	if err != nil {
		return iamv1.AccessKeyAuthorization{}, err
	}
	if iamv1.CheckAccessKeyAuthorizationForRequest(result, request) != nil {
		return iamv1.AccessKeyAuthorization{}, ErrUnavailable
	}
	return result, nil
}

func (service *Authority) AuthorizeAccessKeyList(ctx context.Context, serviceCredential iamv1.Secret, request iamv1.AccessKeyListAuthorizationRequest) (iamv1.AccessKeyListAuthorization, error) {
	if iamv1.ValidateAccessKeyListAuthorizationRequest(request) != nil {
		return iamv1.AccessKeyListAuthorization{}, ErrInvalidArgument
	}
	requests := make([]iamv1.AuthorizationRequest, 1, len(request.Instances)+1)
	requests[0] = request.Collection
	requests = append(requests, request.Instances...)
	digests := make([]string, len(requests))
	for index := range requests {
		digest, err := digestSanitized("authorization", requests[index])
		if err != nil {
			return iamv1.AccessKeyListAuthorization{}, err
		}
		digests[index] = digest
	}
	var result iamv1.AccessKeyListAuthorization
	err := service.withinTransaction(ctx, func(ctx context.Context, tx Transaction) error {
		now, err := transactionTime(ctx, tx)
		if err != nil {
			return err
		}
		verified, err := service.verifyAccessKeyRequest(ctx, tx, serviceCredential, request.Collection.Profile, request.SignedRequest)
		if err != nil {
			return err
		}
		caller, credential := verified.caller, verified.credential
		parameters := request.SignedRequest.Parameters
		definition, found := iamv1.LookupActionDefinition(request.Collection.Action)
		if !found || definition.CallingService != caller.Identity.Purpose || definition.Product != parameters.Audience {
			return ErrUnauthenticated
		}
		nonceDigest, err := iamv1.AccessKeyNonceDigest(parameters)
		if err != nil {
			return ErrUnavailable
		}
		evidenceID, err := service.config.NewID("evidence")
		if err != nil || iamv1.ValidateID("requestEvidenceId", evidenceID) != nil {
			return ErrUnavailable
		}
		evidence := newAccessKeyAuthorizationEvidence(evidenceID, caller, credential, parameters, verified.signedDigest, nonceDigest)
		actor := authorizationActor{organizationID: credential.Subject.Organization.ID,
			subject:           iamv1.Subject{Type: iamv1.SubjectUser, ID: string(credential.Subject.Principal.ID), AccessKeyID: credential.Subject.Key.ID},
			accessKeyEvidence: evidence}
		decide := func(item iamv1.AuthorizationRequest, digest string) (iamv1.AuthorizationDecision, error) {
			return service.decideAndRecord(ctx, tx, item, digest, now, actor,
				func(id iamv1.DecisionID) (authority.AuthorizationEvaluation, error) {
					return authority.DecideAccessKey(credential.Subject, caller.Identity.Purpose, item, id, now, parameters.SignedAt)
				})
		}
		collection, err := decide(request.Collection, digests[0])
		if err != nil {
			return err
		}
		instances := make([]iamv1.AuthorizationDecision, 0)
		if collection.Allowed {
			instances = make([]iamv1.AuthorizationDecision, 0, len(request.Instances))
			for index, item := range request.Instances {
				decision, decisionErr := decide(item, digests[index+1])
				if decisionErr != nil {
					return decisionErr
				}
				instances = append(instances, decision)
			}
		}
		result = iamv1.AccessKeyListAuthorization{APIVersion: iamv1.APIVersion, Kind: "AccessKeyListAuthorization",
			Collection: collection, Instances: instances, SignedRequestDigest: verified.signedDigest}
		return nil
	})
	if err != nil {
		return iamv1.AccessKeyListAuthorization{}, err
	}
	if iamv1.CheckAccessKeyListAuthorizationForRequest(result, request) != nil {
		return iamv1.AccessKeyListAuthorization{}, ErrUnavailable
	}
	return result, nil
}

func newAccessKeyAuthorizationEvidence(
	requestEvidenceID string,
	caller ServiceCredential,
	credential AccessKeyCredential,
	parameters iamv1.AccessKeySignatureParameters,
	signedDigest string,
	nonceDigest string,
) *AccessKeyAuthorizationEvidence {
	return &AccessKeyAuthorizationEvidence{RequestEvidenceID: requestEvidenceID,
		AccessKeyID: credential.Subject.Key.ID, ResourceVersion: credential.Subject.Key.ResourceVersion,
		AccountSecuritySettingsVersion: credential.Subject.AccountSecuritySettingsVersion,
		FormatVersion:                  credential.Material.FormatVersion, WrappingKeyID: credential.Material.WrappingKeyID,
		MaterialCommitment: credential.MaterialCommitment, InstallationID: credential.Subject.InstallationID,
		ServiceLookupDigest: caller.LookupDigest, Audience: parameters.Audience,
		SignedRequestDigest: signedDigest, NonceDigest: nonceDigest, SignedAt: parameters.SignedAt}
}

// ResolveAccessKeySubject authenticates one fresh signed request for the
// calling product's Account-scoped resource lookup. It deliberately does not
// evaluate Policy, record a decision or consume the nonce; only the later
// AuthorizeAccessKey call can permit resource access.
func (service *Authority) ResolveAccessKeySubject(
	ctx context.Context,
	serviceCredential iamv1.Secret,
	request iamv1.ResolveAccessKeySubjectRequest,
) (iamv1.AccessKeySubjectContext, error) {
	if iamv1.ValidateResolveAccessKeySubjectRequest(request) != nil {
		return iamv1.AccessKeySubjectContext{}, ErrInvalidArgument
	}
	var result iamv1.AccessKeySubjectContext
	err := service.withinTransaction(ctx, func(transactionContext context.Context, transaction Transaction) error {
		now, err := transactionTime(transactionContext, transaction)
		if err != nil {
			return err
		}
		verified, err := service.verifyAccessKeyRequest(transactionContext, transaction, serviceCredential, request.Profile, request.SignedRequest)
		if err != nil {
			return err
		}
		if err := authority.ValidateAccessKeyLookupContext(verified.credential.Subject, now, request.SignedRequest.Parameters.SignedAt); err != nil {
			if errors.Is(err, authority.ErrUnauthenticated) {
				return ErrUnauthenticated
			}
			return ErrUnavailable
		}
		result = iamv1.AccessKeySubjectContext{
			APIVersion: iamv1.APIVersion, Kind: "AccessKeySubjectContext",
			TenantID: verified.credential.Subject.Organization.ID,
			Subject: iamv1.Subject{Type: iamv1.SubjectUser, ID: string(verified.credential.Subject.Principal.ID),
				AccessKeyID: verified.credential.Subject.Key.ID},
			Profile: request.Profile, SignedRequestDigest: verified.signedDigest,
		}
		return nil
	})
	if err != nil {
		return iamv1.AccessKeySubjectContext{}, err
	}
	if iamv1.CheckAccessKeySubjectContextForRequest(result, request) != nil {
		return iamv1.AccessKeySubjectContext{}, ErrUnavailable
	}
	return result, nil
}

func (service *Authority) Authorize(
	ctx context.Context,
	serviceCredential iamv1.Secret,
	subjectCredential iamv1.Secret,
	request iamv1.AuthorizationRequest,
) (iamv1.AuthorizationDecision, error) {
	if iamv1.ValidateAuthorizationRequest(request) != nil {
		return iamv1.AuthorizationDecision{}, ErrInvalidArgument
	}
	requestDigest, err := digestSanitized("authorization", request)
	if err != nil {
		return iamv1.AuthorizationDecision{}, err
	}
	var decision iamv1.AuthorizationDecision
	err = service.withinTransaction(ctx, func(transactionContext context.Context, transaction Transaction) error {
		now, err := transactionTime(transactionContext, transaction)
		if err != nil {
			return err
		}
		caller, err := service.authenticateService(
			transactionContext,
			transaction,
			serviceCredential,
		)
		if err != nil {
			return err
		}
		subject, err := service.authenticateSession(
			transactionContext,
			transaction,
			subjectCredential,
			now,
		)
		if err != nil {
			if errors.Is(err, ErrUnauthenticated) {
				role, roleErr := service.authenticateRoleSession(transactionContext, transaction, subjectCredential, now)
				if roleErr != nil {
					return roleErr
				}
				if role.Subject.Service != nil && role.Subject.Service.Identity != caller.Identity {
					return ErrUnauthenticated
				}
				reference, roleErr := roleSessionReference(role.Subject.Session)
				if roleErr != nil {
					return roleErr
				}
				decision, roleErr = service.decideAndRecord(transactionContext, transaction, request, requestDigest, now,
					authorizationActor{organizationID: role.Subject.Session.AccountID, subject: iamv1.Subject{Type: iamv1.SubjectRole, ID: string(role.Subject.Role.ID),
						RoleSession: &reference}},
					func(id iamv1.DecisionID) (authority.AuthorizationEvaluation, error) {
						return authority.DecideRole(role.Subject, caller.Identity.Purpose, request, id, now)
					})
				return roleErr
			}
			return err
		}
		decision, err = service.decideAndRecord(
			transactionContext,
			transaction,
			request,
			requestDigest,
			now,
			authorizationActor{
				organizationID: subject.Subject.Organization.ID,
				installationID: subject.Subject.InstallationID,
				subject:        iamv1.Subject{Type: iamv1.SubjectType(subject.Subject.Principal.Type), ID: string(subject.Subject.Principal.ID)},
			},
			func(decisionID iamv1.DecisionID) (authority.AuthorizationEvaluation, error) {
				return authority.Decide(
					subject.Subject, caller.Identity.Purpose, request, decisionID, now,
				)
			},
		)
		return err
	})
	if err != nil {
		return iamv1.AuthorizationDecision{}, err
	}
	if iamv1.ValidateAuthorizationDecision(decision) != nil {
		return iamv1.AuthorizationDecision{}, ErrUnavailable
	}
	return decision, nil
}

// ResolveAuthorizationSubject authenticates the exact calling service and one
// transient USER/ROLE bearer for its current product Profile. The result is
// lookup context only: it contains no action, resource, Policy or permit.
func (service *Authority) ResolveAuthorizationSubject(
	ctx context.Context,
	serviceCredential iamv1.Secret,
	subjectCredential iamv1.Secret,
	request iamv1.ResolveAuthorizationSubjectRequest,
) (iamv1.AuthorizationSubjectContext, error) {
	if iamv1.ValidateResolveAuthorizationSubjectRequest(request) != nil {
		return iamv1.AuthorizationSubjectContext{}, ErrInvalidArgument
	}
	var result iamv1.AuthorizationSubjectContext
	err := service.withinTransaction(ctx, func(transactionContext context.Context, transaction Transaction) error {
		now, err := transactionTime(transactionContext, transaction)
		if err != nil {
			return err
		}
		caller, err := service.authenticateService(transactionContext, transaction, serviceCredential)
		if err != nil {
			return err
		}
		profile, known := iamv1.LookupAuthorizationProfile(request.Profile.Product)
		if !known || iamv1.CheckAuthorizationProfileReference(profile, request.Profile) != nil ||
			profile.CallingService != caller.Identity.Purpose {
			return ErrForbidden
		}
		actor, _, err := service.batchAuthorizationActor(transactionContext, transaction, caller, subjectCredential, now)
		if err != nil {
			return err
		}
		result = iamv1.AuthorizationSubjectContext{
			APIVersion: iamv1.APIVersion,
			Kind:       "AuthorizationSubjectContext",
			TenantID:   actor.organizationID,
			Subject:    actor.subject,
			Profile:    request.Profile,
		}
		return nil
	})
	if err != nil {
		return iamv1.AuthorizationSubjectContext{}, err
	}
	if iamv1.CheckAuthorizationSubjectContextForRequest(result, request) != nil {
		return iamv1.AuthorizationSubjectContext{}, ErrUnavailable
	}
	return result, nil
}

// DiagnoseAuthorization explains the current evaluation without allocating or
// recording an authorization decision. Its result is never a permit.
func (service *Authority) DiagnoseAuthorization(
	ctx context.Context,
	serviceCredential iamv1.Secret,
	subjectCredential iamv1.Secret,
	request iamv1.AuthorizationRequest,
) (iamv1.CurrentAccessDiagnosis, error) {
	if iamv1.ValidateAuthorizationRequest(request) != nil {
		return iamv1.CurrentAccessDiagnosis{}, ErrInvalidArgument
	}
	var result iamv1.CurrentAccessDiagnosis
	err := service.withinTransaction(ctx, func(transactionContext context.Context, transaction Transaction) error {
		now, err := transactionTime(transactionContext, transaction)
		if err != nil {
			return err
		}
		caller, err := service.authenticateService(transactionContext, transaction, serviceCredential)
		if err != nil {
			return err
		}
		actor, decide, err := service.batchAuthorizationActor(transactionContext, transaction, caller, subjectCredential, now)
		if err != nil {
			return err
		}
		if err := transaction.CheckCurrentAuthorizationProfiles(transactionContext); err != nil {
			return err
		}
		evaluation, err := decide(request, iamv1.DecisionID("diagnosis-current-access"))
		if err != nil {
			return ErrUnavailable
		}
		result, err = authority.CurrentAccessDiagnosis(evaluation, actor.organizationID, actor.installationID, actor.subject, request)
		return err
	})
	if err != nil {
		return iamv1.CurrentAccessDiagnosis{}, err
	}
	if iamv1.ValidateCurrentAccessDiagnosis(result) != nil {
		return iamv1.CurrentAccessDiagnosis{}, ErrUnavailable
	}
	return result, nil
}

func (service *Authority) AuthorizeBatch(
	ctx context.Context,
	serviceCredential iamv1.Secret,
	subjectCredential iamv1.Secret,
	request iamv1.AuthorizationBatchRequest,
) (iamv1.AuthorizationBatchDecision, error) {
	if iamv1.ValidateAuthorizationBatchRequest(request) != nil {
		return iamv1.AuthorizationBatchDecision{}, ErrInvalidArgument
	}
	digests := make([]string, len(request.Requests))
	for index := range request.Requests {
		digest, err := digestSanitized("authorization", request.Requests[index])
		if err != nil {
			return iamv1.AuthorizationBatchDecision{}, err
		}
		digests[index] = digest
	}
	first := request.Requests[0]
	var result iamv1.AuthorizationBatchDecision
	err := service.withinTransaction(ctx, func(transactionContext context.Context, transaction Transaction) error {
		now, err := transactionTime(transactionContext, transaction)
		if err != nil {
			return err
		}
		caller, err := service.authenticateService(transactionContext, transaction, serviceCredential)
		if err != nil {
			return err
		}
		actor, decide, err := service.batchAuthorizationActor(
			transactionContext, transaction, caller, subjectCredential, now,
		)
		if err != nil {
			return err
		}
		decisions := make([]iamv1.AuthorizationDecision, 0, len(request.Requests))
		for index, item := range request.Requests {
			decision, decisionErr := service.decideAndRecord(
				transactionContext, transaction, item, digests[index], now, actor,
				func(id iamv1.DecisionID) (authority.AuthorizationEvaluation, error) {
					return decide(item, id)
				},
			)
			if decisionErr != nil {
				return decisionErr
			}
			decisions = append(decisions, decision)
		}
		result = iamv1.AuthorizationBatchDecision{
			APIVersion: iamv1.APIVersion, Kind: "AuthorizationBatchDecision",
			TenantID: actor.organizationID, Subject: actor.subject,
			Profile: first.Profile, Action: first.Action, ResourceKind: first.Resource.Kind,
			NetworkContext: first.NetworkContext, CorrelationID: first.CorrelationID,
			DecidedAt: now, Decisions: decisions,
		}
		return nil
	})
	if err != nil {
		return iamv1.AuthorizationBatchDecision{}, err
	}
	if iamv1.CheckAuthorizationBatchDecisionForRequest(result, request) != nil {
		return iamv1.AuthorizationBatchDecision{}, ErrUnavailable
	}
	return result, nil
}

type batchDecider func(iamv1.AuthorizationRequest, iamv1.DecisionID) (authority.AuthorizationEvaluation, error)

func (service *Authority) batchAuthorizationActor(
	ctx context.Context,
	transaction Transaction,
	caller ServiceCredential,
	credential iamv1.Secret,
	now time.Time,
) (authorizationActor, batchDecider, error) {
	subject, err := service.authenticateSession(ctx, transaction, credential, now)
	if err == nil {
		actor := authorizationActor{
			organizationID: subject.Subject.Organization.ID,
			installationID: subject.Subject.InstallationID,
			subject:        iamv1.Subject{Type: iamv1.SubjectType(subject.Subject.Principal.Type), ID: string(subject.Subject.Principal.ID)},
		}
		return actor, func(request iamv1.AuthorizationRequest, id iamv1.DecisionID) (authority.AuthorizationEvaluation, error) {
			return authority.Decide(subject.Subject, caller.Identity.Purpose, request, id, now)
		}, nil
	}
	if !errors.Is(err, ErrUnauthenticated) {
		return authorizationActor{}, nil, err
	}
	role, err := service.authenticateRoleSession(ctx, transaction, credential, now)
	if err != nil {
		return authorizationActor{}, nil, err
	}
	if role.Subject.Service != nil && role.Subject.Service.Identity != caller.Identity {
		return authorizationActor{}, nil, ErrUnauthenticated
	}
	reference, err := roleSessionReference(role.Subject.Session)
	if err != nil {
		return authorizationActor{}, nil, err
	}
	actor := authorizationActor{
		organizationID: role.Subject.Session.AccountID,
		installationID: caller.Identity.InstallationID,
		subject:        iamv1.Subject{Type: iamv1.SubjectRole, ID: string(role.Subject.Role.ID), RoleSession: &reference},
	}
	return actor, func(request iamv1.AuthorizationRequest, id iamv1.DecisionID) (authority.AuthorizationEvaluation, error) {
		return authority.DecideRole(role.Subject, caller.Identity.Purpose, request, id, now)
	}, nil
}

// VerifyInstallation authenticates the verifier service as both caller and
// subject. It cannot be used for a generic IAM, PaaS, or Audit action.
func (service *Authority) VerifyInstallation(
	ctx context.Context,
	serviceCredential iamv1.Secret,
	request iamv1.AuthorizationRequest,
) (iamv1.AuthorizationDecision, error) {
	if iamv1.ValidateAuthorizationRequest(request) != nil ||
		request.Action != iamv1.ActionInstallationVerify {
		return iamv1.AuthorizationDecision{}, ErrInvalidArgument
	}
	requestDigest, err := digestSanitized("installation-verification", request)
	if err != nil {
		return iamv1.AuthorizationDecision{}, err
	}
	var decision iamv1.AuthorizationDecision
	err = service.withinTransaction(ctx, func(transactionContext context.Context, transaction Transaction) error {
		now, err := transactionTime(transactionContext, transaction)
		if err != nil {
			return err
		}
		caller, err := service.authenticateService(
			transactionContext, transaction, serviceCredential,
		)
		if err != nil {
			return err
		}
		policies, err := transaction.LookupServicePolicies(
			transactionContext,
			caller.Identity.AccountID,
			caller.Identity.PrincipalID,
		)
		if err != nil {
			return err
		}
		status, err := transaction.BootstrapStatus(transactionContext)
		if err != nil || iamv1.ValidateBootstrapStatus(status) != nil ||
			status.State != iamv1.BootstrapReady ||
			status.AccountID != caller.Identity.AccountID {
			return ErrUnavailable
		}
		if status.InstallationID != request.Resource.ID {
			policies = nil
		}
		decision, err = service.decideAndRecord(
			transactionContext,
			transaction,
			request,
			requestDigest,
			now,
			authorizationActor{
				organizationID: caller.Identity.AccountID,
				subject:        iamv1.Subject{Type: iamv1.SubjectServiceAccount, ID: string(caller.Identity.PrincipalID)},
			},
			func(decisionID iamv1.DecisionID) (authority.AuthorizationEvaluation, error) {
				return authority.DecideService(caller.Identity, policies, request, decisionID, now)
			},
		)
		return err
	})
	if err != nil {
		return iamv1.AuthorizationDecision{}, err
	}
	if iamv1.ValidateAuthorizationDecision(decision) != nil {
		return iamv1.AuthorizationDecision{}, ErrUnavailable
	}
	return decision, nil
}

func (service *Authority) decideAndRecord(
	ctx context.Context,
	transaction Transaction,
	request iamv1.AuthorizationRequest,
	requestDigest string,
	now time.Time,
	actor authorizationActor,
	decide func(iamv1.DecisionID) (authority.AuthorizationEvaluation, error),
) (iamv1.AuthorizationDecision, error) {
	if err := transaction.CheckCurrentAuthorizationProfiles(ctx); err != nil {
		return iamv1.AuthorizationDecision{}, err
	}
	decisionID, err := service.config.NewID("decision")
	if err != nil {
		return iamv1.AuthorizationDecision{}, ErrUnavailable
	}
	decision, err := decide(iamv1.DecisionID(decisionID))
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
	auditActor, err := auditActorForSubject(actor.subject)
	if err != nil {
		return iamv1.AuthorizationDecision{}, err
	}
	event, err := newAuditEvent(
		eventID,
		actor.organizationID,
		"",
		auditActor,
		auditv1.ActionIAMAuthorizationDecided,
		auditv1.TargetReference{
			Kind: auditv1.TargetAuthorizationDecision,
			ID:   decisionID,
		},
		result,
		decision.ID,
		requestDigest,
		request.RequestID,
		request.CorrelationID,
		now,
	)
	if err != nil {
		return iamv1.AuthorizationDecision{}, err
	}
	if err := transaction.RecordAuthorization(ctx, AuthorizationMutation{
		AccountID:         actor.organizationID,
		Subject:           actor.subject,
		Request:           request,
		Decision:          decision.AuthorizationDecision,
		PolicyEvidence:    decision.PolicyEvidence,
		BoundaryEvidence:  decision.BoundaryEvidence,
		RoleEvidence:      decision.RoleEvidence,
		AccessKeyEvidence: actor.accessKeyEvidence,
		AuditEvent:        event,
	}); err != nil {
		return iamv1.AuthorizationDecision{}, err
	}
	return decision.AuthorizationDecision, nil
}

func auditActorForSubject(subject iamv1.Subject) (auditv1.ActorReference, error) {
	if iamv1.ValidateSubject(subject) != nil {
		return auditv1.ActorReference{}, ErrUnavailable
	}
	actor := auditv1.ActorReference{Type: auditv1.ActorType(subject.Type), ID: auditv1.ActorID(subject.ID), AccessKeyID: string(subject.AccessKeyID)}
	if subject.RoleSession != nil {
		actor.RoleSession = &auditv1.RoleSessionReference{SessionID: string(subject.RoleSession.SessionID),
			SourceUserID:             auditv1.ActorID(subject.RoleSession.SourceUserID),
			SourceServicePrincipalID: auditv1.ActorID(subject.RoleSession.SourceServicePrincipalID)}
	}
	if auditv1.ValidateActor(actor) != nil {
		return auditv1.ActorReference{}, ErrUnavailable
	}
	return actor, nil
}

func roleSessionReference(session iamv1.RoleSession) (iamv1.RoleSessionReference, error) {
	reference := iamv1.RoleSessionReference{SessionID: session.ID, SourceUserID: session.SourceUserID,
		SourceServicePrincipalID: session.SourceServicePrincipalID}
	subject := iamv1.Subject{Type: iamv1.SubjectRole, ID: string(session.RoleID), RoleSession: &reference}
	if iamv1.ValidateRoleSession(session) != nil || iamv1.ValidateSubject(subject) != nil {
		return iamv1.RoleSessionReference{}, ErrUnavailable
	}
	return reference, nil
}
