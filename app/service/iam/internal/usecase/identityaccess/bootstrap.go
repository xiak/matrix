package identityaccess

import (
	"context"
	"strings"

	auditv1 "github.com/xiak/matrix/api/audit/v1"
	iamv1 "github.com/xiak/matrix/api/iam/v1"
	"github.com/xiak/matrix/app/service/iam/internal/authority"
)

func (service *Authority) Bootstrap(
	ctx context.Context,
	document iamv1.BootstrapDocument,
) (iamv1.BootstrapStatus, error) {
	if iamv1.ValidateBootstrapDocument(document) != nil {
		return iamv1.BootstrapStatus{}, ErrInvalidArgument
	}
	contentDigest, err := authority.BootstrapDigest(document)
	if err != nil {
		return iamv1.BootstrapStatus{}, ErrUnavailable
	}
	passwordHash, err := service.passwords.Hash(document.Administrator.Password)
	if err != nil {
		if err == authority.ErrWeakPassword {
			return iamv1.BootstrapStatus{}, ErrInvalidArgument
		}
		return iamv1.BootstrapStatus{}, ErrUnavailable
	}
	services := make([]BootstrapService, len(document.Services))
	for index, credential := range document.Services {
		lookupDigest, err := authority.LookupCredentialDigest(
			authority.CredentialService,
			credential.Credential,
		)
		if err != nil {
			return iamv1.BootstrapStatus{}, ErrUnavailable
		}
		verificationDigest, err := authority.DigestCredential(
			authority.CredentialService,
			string(credential.PrincipalID),
			credential.Credential,
		)
		if err != nil {
			return iamv1.BootstrapStatus{}, ErrUnavailable
		}
		services[index] = BootstrapService{
			Purpose:            credential.Purpose,
			PrincipalID:        credential.PrincipalID,
			LookupDigest:       lookupDigest,
			VerificationDigest: verificationDigest,
		}
	}
	requestID := "bootstrap-" + strings.TrimPrefix(contentDigest, "sha256:")
	eventID := "event-" + requestID
	mutation := BootstrapMutation{
		InstallationID: document.InstallationID,
		ContentDigest:  contentDigest,
		Organization:   document.Organization,
		Administrator: BootstrapAdministrator{
			ID:           document.Administrator.ID,
			LoginName:    document.Administrator.LoginName,
			DisplayName:  document.Administrator.DisplayName,
			PasswordHash: passwordHash,
		},
		Services: services,
	}
	var status iamv1.BootstrapStatus
	err = service.withinTransaction(ctx, func(transactionContext context.Context, transaction Transaction) error {
		now, err := transactionTime(transactionContext, transaction)
		if err != nil {
			return err
		}
		event, err := newAuditEvent(
			eventID,
			document.Organization.ID,
			"",
			auditv1.ActorReference{Type: auditv1.ActorSystem, ID: "iam-bootstrap"},
			auditv1.ActionIAMBootstrapApplied,
			auditv1.TargetReference{Kind: auditv1.TargetInstallation, ID: document.InstallationID},
			auditv1.ResultSucceeded,
			"",
			contentDigest,
			requestID,
			requestID,
			now,
		)
		if err != nil {
			return err
		}
		mutation.AuditEvent = event
		if _, err := transaction.ApplyBootstrap(transactionContext, mutation); err != nil {
			return err
		}
		status, err = transaction.BootstrapStatus(transactionContext)
		return err
	})
	if err != nil {
		return iamv1.BootstrapStatus{}, err
	}
	if iamv1.ValidateBootstrapStatus(status) != nil || status.State != iamv1.BootstrapReady ||
		status.ContentDigest != contentDigest || status.InstallationID != document.InstallationID {
		return iamv1.BootstrapStatus{}, ErrUnavailable
	}
	return status, nil
}

func (service *Authority) BootstrapStatus(
	ctx context.Context,
	serviceCredential iamv1.Secret,
) (iamv1.BootstrapStatus, error) {
	var status iamv1.BootstrapStatus
	err := service.withinTransaction(ctx, func(transactionContext context.Context, transaction Transaction) error {
		if _, err := service.authenticateService(transactionContext, transaction, serviceCredential); err != nil {
			return err
		}
		var err error
		status, err = transaction.BootstrapStatus(transactionContext)
		return err
	})
	if err != nil {
		return iamv1.BootstrapStatus{}, err
	}
	if iamv1.ValidateBootstrapStatus(status) != nil {
		return iamv1.BootstrapStatus{}, ErrUnavailable
	}
	return status, nil
}
