package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	auditv1 "github.com/xiak/matrix/api/audit/v1"
	iamv1 "github.com/xiak/matrix/api/iam/v1"
	"github.com/xiak/matrix/app/service/iam/internal/authority"
	"github.com/xiak/matrix/app/service/iam/internal/usecase/identityaccess"
)

type transaction struct {
	tx pgx.Tx
}

func (value *transaction) TransactionTime(ctx context.Context) (time.Time, error) {
	if value == nil || value.tx == nil {
		return time.Time{}, identityaccess.ErrUnavailable
	}
	var databaseTime time.Time
	if err := value.tx.QueryRow(ctx, "SELECT transaction_timestamp()").Scan(&databaseTime); err != nil {
		return time.Time{}, mapDatabaseError("read IAM transaction time", err)
	}
	return databaseTime.UTC(), nil
}

func (value *transaction) BootstrapStatus(
	ctx context.Context,
) (iamv1.BootstrapStatus, error) {
	var (
		state          string
		installationID *string
		organizationID *string
		contentDigest  *string
		appliedAt      *time.Time
	)
	if err := value.tx.QueryRow(ctx, "SELECT * FROM iam.bootstrap_status()").Scan(
		&state,
		&installationID,
		&organizationID,
		&contentDigest,
		&appliedAt,
	); err != nil {
		return iamv1.BootstrapStatus{}, mapDatabaseError("read IAM bootstrap status", err)
	}
	status := iamv1.BootstrapStatus{
		APIVersion: iamv1.APIVersion,
		Kind:       "BootstrapStatus",
		State:      iamv1.BootstrapState(state),
	}
	if installationID != nil {
		status.InstallationID = *installationID
	}
	if organizationID != nil {
		status.OrganizationID = iamv1.OrganizationID(*organizationID)
	}
	if contentDigest != nil {
		status.ContentDigest = *contentDigest
	}
	if appliedAt != nil {
		converted := appliedAt.UTC()
		status.AppliedAt = &converted
	}
	if iamv1.ValidateBootstrapStatus(status) != nil {
		return iamv1.BootstrapStatus{}, identityaccess.ErrUnavailable
	}
	return status, nil
}

func (value *transaction) ApplyBootstrap(
	ctx context.Context,
	mutation identityaccess.BootstrapMutation,
) (authority.BootstrapOutcome, error) {
	services, err := json.Marshal(mutation.Services)
	if err != nil {
		return "", identityaccess.ErrUnavailable
	}
	event, err := json.Marshal(mutation.AuditEvent)
	if err != nil {
		return "", identityaccess.ErrUnavailable
	}
	var outcome string
	err = value.tx.QueryRow(
		ctx,
		`SELECT iam.apply_bootstrap(
			$1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb, $10::jsonb
		)`,
		mutation.InstallationID,
		mutation.ContentDigest,
		string(mutation.Organization.ID),
		mutation.Organization.DisplayName,
		string(mutation.Administrator.ID),
		mutation.Administrator.LoginName,
		mutation.Administrator.DisplayName,
		string(mutation.Administrator.PasswordHash),
		services,
		event,
	).Scan(&outcome)
	clear(services)
	clear(event)
	if err != nil {
		return "", mapDatabaseError("apply IAM bootstrap", err)
	}
	switch outcome {
	case "APPLIED":
		return authority.BootstrapApply, nil
	case "EQUAL_REPLAY":
		return authority.BootstrapEqualReplay, nil
	default:
		return "", identityaccess.ErrUnavailable
	}
}

func (value *transaction) LookupLogin(
	ctx context.Context,
	loginName string,
) (identityaccess.LoginAccount, bool, error) {
	var account identityaccess.LoginAccount
	var passwordHash string
	var organizationStatus, principalStatus string
	err := value.tx.QueryRow(ctx, "SELECT * FROM iam.lookup_login($1)", loginName).Scan(
		&account.OrganizationID,
		&account.PrincipalID,
		&passwordHash,
		&organizationStatus,
		&principalStatus,
		&account.MustChangePassword,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return identityaccess.LoginAccount{}, false, nil
	}
	if err != nil {
		return identityaccess.LoginAccount{}, false, mapDatabaseError("lookup IAM login", err)
	}
	account.PasswordHash = authority.PasswordHash(passwordHash)
	account.OrganizationStatus = iamv1.OrganizationStatus(organizationStatus)
	account.PrincipalStatus = iamv1.PrincipalStatus(principalStatus)
	return account, true, nil
}

func (value *transaction) IssueSession(
	ctx context.Context,
	mutation identityaccess.SessionMutation,
) (iamv1.Session, error) {
	if iamv1.ValidateSession(mutation.Session) != nil ||
		auditv1.ValidateEventForSource(auditv1.SourceIAM, mutation.AuditEvent) != nil {
		return iamv1.Session{}, identityaccess.ErrInvalidArgument
	}
	lifetime := mutation.Session.ExpiresAt.Sub(mutation.Session.IssuedAt)
	if lifetime%time.Second != 0 {
		return iamv1.Session{}, identityaccess.ErrInvalidArgument
	}
	event, err := json.Marshal(mutation.AuditEvent)
	if err != nil {
		return iamv1.Session{}, identityaccess.ErrUnavailable
	}
	var issuedAt, expiresAt time.Time
	err = value.tx.QueryRow(
		ctx,
		`SELECT * FROM iam.issue_session(
			$1, $2, $3, $4, $5, $6, $7::jsonb
		)`,
		string(mutation.Session.ID),
		string(mutation.Session.OrganizationID),
		string(mutation.Session.PrincipalID),
		mutation.LookupDigest,
		mutation.VerificationDigest,
		int(lifetime/time.Second),
		event,
	).Scan(&issuedAt, &expiresAt)
	clear(event)
	if err != nil {
		return iamv1.Session{}, mapSubjectDatabaseError("issue IAM session", err)
	}
	stored := mutation.Session
	stored.IssuedAt = issuedAt.UTC()
	stored.ExpiresAt = expiresAt.UTC()
	if stored.IssuedAt != mutation.Session.IssuedAt ||
		stored.ExpiresAt != mutation.Session.ExpiresAt ||
		iamv1.ValidateSession(stored) != nil {
		return iamv1.Session{}, identityaccess.ErrUnavailable
	}
	return stored, nil
}

func (value *transaction) LookupSession(
	ctx context.Context,
	lookupDigest string,
) (identityaccess.SessionCredential, bool, error) {
	var (
		organizationID, organizationDisplayName, organizationStatus string
		organizationVersion                                         uint64
		organizationCreatedAt, organizationUpdatedAt                time.Time
		principalID, principalType                                  string
		principalLoginName                                          *string
		principalDisplayName, principalStatus                       string
		principalMustChange                                         bool
		principalVersion                                            uint64
		principalCreatedAt, principalUpdatedAt                      time.Time
		sessionID, sessionStatus                                    string
		sessionIssuedAt, sessionExpiresAt                           time.Time
		sessionRevokedAt                                            *time.Time
		verificationDigest                                          string
		roles                                                       []string
		bootstrapAdministrator                                      bool
	)
	err := value.tx.QueryRow(ctx, "SELECT session.*, iam.is_bootstrap_administrator(session.organization_id, session.principal_id) FROM iam.lookup_session($1) AS session", lookupDigest).Scan(
		&organizationID,
		&organizationDisplayName,
		&organizationStatus,
		&organizationVersion,
		&organizationCreatedAt,
		&organizationUpdatedAt,
		&principalID,
		&principalType,
		&principalLoginName,
		&principalDisplayName,
		&principalStatus,
		&principalMustChange,
		&principalVersion,
		&principalCreatedAt,
		&principalUpdatedAt,
		&sessionID,
		&sessionStatus,
		&sessionIssuedAt,
		&sessionExpiresAt,
		&sessionRevokedAt,
		&verificationDigest,
		&roles,
		&bootstrapAdministrator,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return identityaccess.SessionCredential{}, false, nil
	}
	if err != nil {
		return identityaccess.SessionCredential{}, false, mapDatabaseError("lookup IAM session", err)
	}
	loginName := ""
	if principalLoginName != nil {
		loginName = *principalLoginName
	}
	var revokedAt *time.Time
	if sessionRevokedAt != nil {
		converted := sessionRevokedAt.UTC()
		revokedAt = &converted
	}
	subject := authority.SubjectContext{
		BootstrapAdministrator: bootstrapAdministrator,
		Organization: iamv1.Organization{
			APIVersion:      iamv1.APIVersion,
			Kind:            "Organization",
			ID:              iamv1.OrganizationID(organizationID),
			DisplayName:     organizationDisplayName,
			Status:          iamv1.OrganizationStatus(organizationStatus),
			ResourceVersion: organizationVersion,
			CreatedAt:       organizationCreatedAt.UTC(),
			UpdatedAt:       organizationUpdatedAt.UTC(),
		},
		Principal: iamv1.Principal{
			APIVersion:         iamv1.APIVersion,
			Kind:               "Principal",
			ID:                 iamv1.PrincipalID(principalID),
			OrganizationID:     iamv1.OrganizationID(organizationID),
			Type:               iamv1.PrincipalType(principalType),
			LoginName:          loginName,
			DisplayName:        principalDisplayName,
			Status:             iamv1.PrincipalStatus(principalStatus),
			MustChangePassword: principalMustChange,
			ResourceVersion:    principalVersion,
			CreatedAt:          principalCreatedAt.UTC(),
			UpdatedAt:          principalUpdatedAt.UTC(),
		},
		Session: iamv1.Session{
			APIVersion:     iamv1.APIVersion,
			Kind:           "Session",
			ID:             iamv1.SessionID(sessionID),
			OrganizationID: iamv1.OrganizationID(organizationID),
			PrincipalID:    iamv1.PrincipalID(principalID),
			Status:         iamv1.SessionStatus(sessionStatus),
			IssuedAt:       sessionIssuedAt.UTC(),
			ExpiresAt:      sessionExpiresAt.UTC(),
			RevokedAt:      revokedAt,
		},
	}
	for _, role := range roles {
		subject.Roles = append(subject.Roles, iamv1.BuiltinRole(role))
	}
	if iamv1.ValidateOrganization(subject.Organization) != nil ||
		iamv1.ValidatePrincipal(subject.Principal) != nil ||
		iamv1.ValidateSession(subject.Session) != nil {
		return identityaccess.SessionCredential{}, false, identityaccess.ErrUnavailable
	}
	return identityaccess.SessionCredential{
		Subject:            subject,
		VerificationDigest: verificationDigest,
	}, true, nil
}

func (value *transaction) LookupService(
	ctx context.Context,
	lookupDigest string,
) (identityaccess.ServiceCredential, bool, error) {
	var organizationID, principalID, purpose, verificationDigest, installationID string
	err := value.tx.QueryRow(ctx, "SELECT * FROM iam.lookup_service($1)", lookupDigest).Scan(
		&organizationID,
		&principalID,
		&purpose,
		&verificationDigest,
		&installationID,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return identityaccess.ServiceCredential{}, false, nil
	}
	if err != nil {
		return identityaccess.ServiceCredential{}, false, mapDatabaseError("lookup IAM service", err)
	}
	identity := iamv1.ServiceIdentity{
		APIVersion:     iamv1.APIVersion,
		Kind:           "ServiceIdentity",
		InstallationID: installationID,
		OrganizationID: iamv1.OrganizationID(organizationID),
		PrincipalID:    iamv1.PrincipalID(principalID),
		Purpose:        iamv1.ServicePurpose(purpose),
	}
	if iamv1.ValidateServiceIdentity(identity) != nil {
		return identityaccess.ServiceCredential{}, false, identityaccess.ErrUnavailable
	}
	return identityaccess.ServiceCredential{
		Identity:           identity,
		VerificationDigest: verificationDigest,
	}, true, nil
}

func (value *transaction) ReadAuditEvidence(
	ctx context.Context,
	identity iamv1.ServiceIdentity,
	event auditv1.Event,
) (identityaccess.AuditEvidence, bool, error) {
	if iamv1.ValidateServiceIdentity(identity) != nil || auditv1.ValidateEvent(event) != nil {
		return identityaccess.AuditEvidence{}, false, identityaccess.ErrInvalidArgument
	}
	encoded, err := json.Marshal(event)
	if err != nil {
		return identityaccess.AuditEvidence{}, false, identityaccess.ErrInvalidArgument
	}
	defer clear(encoded)
	var result identityaccess.AuditEvidence
	var storedEvent, decision []byte
	var verifier *string
	err = value.tx.QueryRow(ctx, "SELECT * FROM iam.read_audit_evidence($1,$2,$3,$4,$5::jsonb)",
		identity.OrganizationID, identity.PrincipalID, identity.Purpose, identity.InstallationID, encoded,
	).Scan(&result.InstallationID, &storedEvent, &decision, &verifier)
	if errors.Is(err, pgx.ErrNoRows) {
		return identityaccess.AuditEvidence{}, false, nil
	}
	if err != nil {
		return identityaccess.AuditEvidence{}, false, mapDatabaseError("read historical IAM Audit evidence", err)
	}
	if json.Unmarshal(storedEvent, &result.Event) != nil {
		return identityaccess.AuditEvidence{}, false, identityaccess.ErrUnavailable
	}
	result.Event.OccurredAt = result.Event.OccurredAt.UTC()
	if len(decision) > 0 {
		if json.Unmarshal(decision, &result.Decision) != nil || result.Decision == nil {
			return identityaccess.AuditEvidence{}, false, identityaccess.ErrUnavailable
		}
		result.Decision.DecidedAt = result.Decision.DecidedAt.UTC()
	}
	if verifier != nil {
		result.VerifierPrincipalID = iamv1.PrincipalID(*verifier)
	}
	return result, true, nil
}

func (value *transaction) LookupServiceRoles(
	ctx context.Context,
	organizationID iamv1.OrganizationID,
	principalID iamv1.PrincipalID,
) ([]iamv1.BuiltinRole, error) {
	if iamv1.ValidateID("organizationId", string(organizationID)) != nil ||
		iamv1.ValidateID("principalId", string(principalID)) != nil {
		return nil, identityaccess.ErrInvalidArgument
	}
	var stored []string
	err := value.tx.QueryRow(
		ctx,
		"SELECT * FROM iam.lookup_service_roles($1, $2)",
		string(organizationID),
		string(principalID),
	).Scan(&stored)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, identityaccess.ErrUnavailable
	}
	if err != nil {
		return nil, mapDatabaseError("lookup IAM service roles", err)
	}
	roles := make([]iamv1.BuiltinRole, 0, len(stored))
	for _, role := range stored {
		roles = append(roles, iamv1.BuiltinRole(role))
	}
	return roles, nil
}

func (value *transaction) LookupPassword(
	ctx context.Context,
	organizationID iamv1.OrganizationID,
	principalID iamv1.PrincipalID,
) (authority.PasswordHash, bool, error) {
	if iamv1.ValidateID("organizationId", string(organizationID)) != nil ||
		iamv1.ValidateID("principalId", string(principalID)) != nil {
		return "", false, identityaccess.ErrInvalidArgument
	}
	var passwordHash string
	err := value.tx.QueryRow(
		ctx,
		"SELECT * FROM iam.lookup_password($1, $2)",
		string(organizationID),
		string(principalID),
	).Scan(&passwordHash)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, mapDatabaseError("lookup IAM password", err)
	}
	return authority.PasswordHash(passwordHash), true, nil
}

func (value *transaction) RecordAuthorization(
	ctx context.Context,
	mutation identityaccess.AuthorizationMutation,
) error {
	if iamv1.ValidateAuthorizationDecision(mutation.Decision) != nil ||
		auditv1.ValidateEventForSource(auditv1.SourceIAM, mutation.AuditEvent) != nil {
		return identityaccess.ErrInvalidArgument
	}
	decision, err := json.Marshal(mutation.Decision)
	if err != nil {
		return identityaccess.ErrUnavailable
	}
	event, err := json.Marshal(mutation.AuditEvent)
	if err != nil {
		clear(decision)
		return identityaccess.ErrUnavailable
	}
	_, err = value.tx.Exec(
		ctx,
		"SELECT iam.record_authorization($1, $2, $3::jsonb, $4::jsonb)",
		string(mutation.OrganizationID),
		string(mutation.PrincipalID),
		decision,
		event,
	)
	clear(decision)
	clear(event)
	if err != nil {
		return mapSubjectDatabaseError("record IAM authorization", err)
	}
	return nil
}

func (value *transaction) ChangePassword(
	ctx context.Context,
	mutation identityaccess.PasswordMutation,
) (iamv1.ChangePasswordResponse, error) {
	if iamv1.ValidateID("organizationId", string(mutation.OrganizationID)) != nil ||
		iamv1.ValidateID("principalId", string(mutation.PrincipalID)) != nil ||
		mutation.ExpectedPasswordHash == "" || mutation.NewPasswordHash == "" ||
		auditv1.ValidateEventForSource(auditv1.SourceIAM, mutation.AuditEvent) != nil {
		return iamv1.ChangePasswordResponse{}, identityaccess.ErrInvalidArgument
	}
	event, err := json.Marshal(mutation.AuditEvent)
	if err != nil {
		return iamv1.ChangePasswordResponse{}, identityaccess.ErrUnavailable
	}
	var response iamv1.ChangePasswordResponse
	err = value.tx.QueryRow(
		ctx,
		"SELECT * FROM iam.change_password($1, $2, $3, $4, $5::jsonb)",
		string(mutation.OrganizationID),
		string(mutation.PrincipalID),
		string(mutation.ExpectedPasswordHash),
		string(mutation.NewPasswordHash),
		event,
	).Scan(&response.ChangedAt, &response.BootstrapFileRetirable)
	clear(event)
	if err != nil {
		return iamv1.ChangePasswordResponse{}, mapSubjectDatabaseError("change IAM password", err)
	}
	response.ChangedAt = response.ChangedAt.UTC()
	if iamv1.ValidateChangePasswordResponse(response) != nil ||
		response.ChangedAt != mutation.AuditEvent.OccurredAt {
		return iamv1.ChangePasswordResponse{}, identityaccess.ErrUnavailable
	}
	return response, nil
}

func (value *transaction) RevokeSession(
	ctx context.Context,
	mutation identityaccess.SessionRevocationMutation,
) (iamv1.Revocation, bool, error) {
	if iamv1.ValidateID("organizationId", string(mutation.OrganizationID)) != nil ||
		iamv1.ValidateID("sessionId", string(mutation.SessionID)) != nil ||
		iamv1.ValidateID("actorPrincipalId", string(mutation.ActorPrincipalID)) != nil ||
		auditv1.ValidateEventForSource(auditv1.SourceIAM, mutation.AuditEvent) != nil {
		return iamv1.Revocation{}, false, identityaccess.ErrInvalidArgument
	}
	var decisionID any
	if mutation.DecisionID != "" {
		if iamv1.ValidateID("decisionId", string(mutation.DecisionID)) != nil {
			return iamv1.Revocation{}, false, identityaccess.ErrInvalidArgument
		}
		decisionID = string(mutation.DecisionID)
	}
	event, err := json.Marshal(mutation.AuditEvent)
	if err != nil {
		return iamv1.Revocation{}, false, identityaccess.ErrUnavailable
	}
	var version uint64
	var revokedAt time.Time
	var applied bool
	err = value.tx.QueryRow(
		ctx,
		"SELECT * FROM iam.revoke_session($1, $2, $3, $4, $5::jsonb)",
		string(mutation.OrganizationID),
		string(mutation.SessionID),
		string(mutation.ActorPrincipalID),
		decisionID,
		event,
	).Scan(&version, &revokedAt, &applied)
	clear(event)
	if err != nil {
		return iamv1.Revocation{}, false, mapAuthorizationDatabaseError("revoke IAM session", err)
	}
	result := iamv1.Revocation{
		APIVersion:      iamv1.APIVersion,
		Kind:            "Revocation",
		ID:              string(mutation.SessionID),
		ResourceVersion: version,
		RevokedAt:       revokedAt.UTC(),
	}
	if iamv1.ValidateRevocation(result) != nil {
		return iamv1.Revocation{}, false, identityaccess.ErrUnavailable
	}
	return result, applied, nil
}

func (value *transaction) CreateUser(
	ctx context.Context,
	mutation identityaccess.UserMutation,
) (iamv1.Principal, error) {
	if iamv1.ValidatePrincipal(mutation.Principal) != nil ||
		iamv1.ValidateID("actorPrincipalId", string(mutation.ActorPrincipalID)) != nil ||
		iamv1.ValidateID("decisionId", string(mutation.DecisionID)) != nil ||
		mutation.PasswordHash == "" ||
		auditv1.ValidateEventForSource(auditv1.SourceIAM, mutation.AuditEvent) != nil {
		return iamv1.Principal{}, identityaccess.ErrInvalidArgument
	}
	event, err := json.Marshal(mutation.AuditEvent)
	if err != nil {
		return iamv1.Principal{}, identityaccess.ErrUnavailable
	}
	var createdAt, updatedAt time.Time
	err = value.tx.QueryRow(
		ctx,
		"SELECT * FROM iam.create_user($1, $2, $3, $4, $5, $6, $7, $8::jsonb)",
		string(mutation.Principal.OrganizationID),
		string(mutation.Principal.ID),
		mutation.Principal.LoginName,
		mutation.Principal.DisplayName,
		string(mutation.PasswordHash),
		string(mutation.ActorPrincipalID),
		string(mutation.DecisionID),
		event,
	).Scan(&createdAt, &updatedAt)
	clear(event)
	if err != nil {
		return iamv1.Principal{}, mapAuthorizationDatabaseError("create IAM user", err)
	}
	stored := mutation.Principal
	stored.CreatedAt = createdAt.UTC()
	stored.UpdatedAt = updatedAt.UTC()
	if iamv1.ValidatePrincipal(stored) != nil || stored.CreatedAt != mutation.Principal.CreatedAt ||
		stored.UpdatedAt != mutation.Principal.UpdatedAt {
		return iamv1.Principal{}, identityaccess.ErrUnavailable
	}
	return stored, nil
}

func (value *transaction) PutRoleBinding(
	ctx context.Context,
	mutation identityaccess.RoleBindingMutation,
) (iamv1.RoleBinding, bool, error) {
	if iamv1.ValidateRoleBinding(mutation.Binding) != nil ||
		iamv1.ValidateID("actorPrincipalId", string(mutation.ActorPrincipalID)) != nil ||
		iamv1.ValidateID("decisionId", string(mutation.DecisionID)) != nil ||
		auditv1.ValidateEventForSource(auditv1.SourceIAM, mutation.AuditEvent) != nil {
		return iamv1.RoleBinding{}, false, identityaccess.ErrInvalidArgument
	}
	event, err := json.Marshal(mutation.AuditEvent)
	if err != nil {
		return iamv1.RoleBinding{}, false, identityaccess.ErrUnavailable
	}
	var id, principalID, role string
	var version uint64
	var createdAt, updatedAt time.Time
	var applied bool
	err = value.tx.QueryRow(
		ctx,
		"SELECT * FROM iam.put_role_binding($1, $2, $3, $4, $5, $6, $7::jsonb)",
		string(mutation.Binding.OrganizationID),
		string(mutation.Binding.ID),
		string(mutation.Binding.PrincipalID),
		string(mutation.Binding.Role),
		string(mutation.ActorPrincipalID),
		string(mutation.DecisionID),
		event,
	).Scan(&id, &principalID, &role, &version, &createdAt, &updatedAt, &applied)
	clear(event)
	if err != nil {
		return iamv1.RoleBinding{}, false, mapAuthorizationDatabaseError("put IAM role binding", err)
	}
	stored := iamv1.RoleBinding{
		APIVersion:      iamv1.APIVersion,
		Kind:            "RoleBinding",
		ID:              iamv1.RoleBindingID(id),
		OrganizationID:  mutation.Binding.OrganizationID,
		PrincipalID:     iamv1.PrincipalID(principalID),
		Role:            iamv1.BuiltinRole(role),
		ResourceVersion: version,
		CreatedAt:       createdAt.UTC(),
		UpdatedAt:       updatedAt.UTC(),
	}
	if iamv1.ValidateRoleBinding(stored) != nil {
		return iamv1.RoleBinding{}, false, identityaccess.ErrUnavailable
	}
	return stored, applied, nil
}

func (value *transaction) LookupRoleBindingRole(
	ctx context.Context,
	organizationID iamv1.OrganizationID,
	bindingID iamv1.RoleBindingID,
) (iamv1.BuiltinRole, bool, error) {
	if iamv1.ValidateID("organizationId", string(organizationID)) != nil ||
		iamv1.ValidateID("roleBindingId", string(bindingID)) != nil {
		return "", false, identityaccess.ErrInvalidArgument
	}
	var role iamv1.BuiltinRole
	err := value.tx.QueryRow(ctx, "SELECT role_name FROM iam.lookup_role_binding_role($1, $2)",
		string(organizationID), string(bindingID)).Scan(&role)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, mapDatabaseError("look up IAM role binding authority", err)
	}
	for _, known := range iamv1.AllBuiltinRoles() {
		if role == known {
			return role, true, nil
		}
	}
	return "", false, identityaccess.ErrUnavailable
}

func (value *transaction) RevokeRoleBinding(
	ctx context.Context,
	mutation identityaccess.RoleBindingRevocationMutation,
) (iamv1.Revocation, bool, error) {
	if iamv1.ValidateID("organizationId", string(mutation.OrganizationID)) != nil ||
		iamv1.ValidateID("roleBindingId", string(mutation.RoleBindingID)) != nil ||
		iamv1.ValidateID("actorPrincipalId", string(mutation.ActorPrincipalID)) != nil ||
		iamv1.ValidateID("decisionId", string(mutation.DecisionID)) != nil ||
		auditv1.ValidateEventForSource(auditv1.SourceIAM, mutation.AuditEvent) != nil {
		return iamv1.Revocation{}, false, identityaccess.ErrInvalidArgument
	}
	event, err := json.Marshal(mutation.AuditEvent)
	if err != nil {
		return iamv1.Revocation{}, false, identityaccess.ErrUnavailable
	}
	var version uint64
	var revokedAt time.Time
	var applied bool
	err = value.tx.QueryRow(
		ctx,
		"SELECT * FROM iam.revoke_role_binding($1, $2, $3, $4, $5::jsonb)",
		string(mutation.OrganizationID),
		string(mutation.RoleBindingID),
		string(mutation.ActorPrincipalID),
		string(mutation.DecisionID),
		event,
	).Scan(&version, &revokedAt, &applied)
	clear(event)
	if err != nil {
		return iamv1.Revocation{}, false, mapAuthorizationDatabaseError("revoke IAM role binding", err)
	}
	result := iamv1.Revocation{
		APIVersion:      iamv1.APIVersion,
		Kind:            "Revocation",
		ID:              string(mutation.RoleBindingID),
		ResourceVersion: version,
		RevokedAt:       revokedAt.UTC(),
	}
	if iamv1.ValidateRevocation(result) != nil {
		return iamv1.Revocation{}, false, identityaccess.ErrUnavailable
	}
	return result, applied, nil
}

func (value *transaction) Readiness(
	ctx context.Context,
) (identityaccess.ReadinessSnapshot, error) {
	var snapshot identityaccess.ReadinessSnapshot
	if err := value.tx.QueryRow(ctx, "SELECT * FROM iam.readiness()").Scan(
		&snapshot.Ready,
		&snapshot.SchemaVersion,
		&snapshot.CheckedAt,
	); err != nil {
		return identityaccess.ReadinessSnapshot{}, mapDatabaseError("read IAM readiness", err)
	}
	snapshot.CheckedAt = snapshot.CheckedAt.UTC()
	if snapshot.SchemaVersion == 0 || snapshot.CheckedAt.IsZero() {
		return identityaccess.ReadinessSnapshot{}, identityaccess.ErrUnavailable
	}
	return snapshot, nil
}
