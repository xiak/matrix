package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	auditv1 "github.com/xiak/matrix/api/audit/v1"
	"github.com/xiak/matrix/api/contractjson"
	iamv1 "github.com/xiak/matrix/api/iam/v1"
	"github.com/xiak/matrix/app/service/iam/internal/authority"
	"github.com/xiak/matrix/app/service/iam/internal/usecase/identityaccess"
)

type transaction struct {
	tx               pgx.Tx
	profilesChecked  bool
	archivedProfiles map[iamv1.AuthorizationProfileReference]iamv1.AuthorizationProfile
}

// This cache is confined to one transaction, which retains share locks on the
// current heads. It must never become an across-request catalog/permission cache.
func (value *transaction) CheckCurrentAuthorizationProfiles(ctx context.Context) error {
	if value.profilesChecked {
		return nil
	}
	profiles := iamv1.AllAuthorizationProfiles()
	expected := make(map[iamv1.ProductID]iamv1.AuthorizationProfile, len(profiles))
	for _, profile := range profiles {
		expected[profile.Product] = profile
	}
	rows, err := value.tx.Query(ctx, "SELECT * FROM iam.current_authorization_profiles()")
	if err != nil {
		return mapDatabaseError("read IAM current product registrations", err)
	}
	defer rows.Close()
	for rows.Next() {
		var reference iamv1.AuthorizationProfileReference
		var canonical string
		if rows.Scan(&reference.Product, &reference.Revision, &canonical, &reference.ContentDigest) != nil {
			return identityaccess.ErrUnavailable
		}
		profile, found := expected[reference.Product]
		if !found {
			return identityaccess.ErrUnavailable
		}
		declared, digest, err := iamv1.CanonicalizeAuthorizationProfile(profile)
		if err != nil || profile.Revision != reference.Revision || digest != reference.ContentDigest || canonical != declared {
			return identityaccess.ErrUnavailable
		}
		delete(expected, reference.Product)
	}
	if err := rows.Err(); err != nil {
		return mapDatabaseError("read IAM current product registrations", err)
	}
	if len(expected) != 0 {
		return identityaccess.ErrUnavailable
	}
	value.profilesChecked = true
	return nil
}

// Historical resolution does not read or validate the current head. A changed
// release cannot make committed evidence disappear or choose a newer meaning.
func (value *transaction) LookupAuthorizationProfile(ctx context.Context, reference iamv1.AuthorizationProfileReference) (iamv1.AuthorizationProfile, bool, error) {
	if iamv1.ValidateID("product", string(reference.Product)) != nil || reference.Revision == 0 || reference.Revision > 9007199254740991 ||
		iamv1.ValidateDigest("contentDigest", reference.ContentDigest) != nil {
		return iamv1.AuthorizationProfile{}, false, identityaccess.ErrInvalidArgument
	}
	if profile, found := value.archivedProfiles[reference]; found {
		return profile, true, nil
	}
	var actual iamv1.AuthorizationProfileReference
	var canonical string
	err := value.tx.QueryRow(ctx, "SELECT * FROM iam.lookup_authorization_profile($1,$2,$3)", reference.Product, reference.Revision, reference.ContentDigest).
		Scan(&actual.Product, &actual.Revision, &canonical, &actual.ContentDigest)
	if errors.Is(err, pgx.ErrNoRows) {
		return iamv1.AuthorizationProfile{}, false, nil
	}
	if err != nil {
		return iamv1.AuthorizationProfile{}, false, mapDatabaseError("read IAM immutable product registration", err)
	}
	if actual != reference || int64(len(canonical)) > iamv1.MaxAuthorizationProfileBytes {
		return iamv1.AuthorizationProfile{}, false, identityaccess.ErrUnavailable
	}
	profile, err := iamv1.DecodeAuthorizationProfile(strings.NewReader(canonical))
	if err != nil || iamv1.CheckAuthorizationProfileReference(profile, reference) != nil {
		return iamv1.AuthorizationProfile{}, false, identityaccess.ErrUnavailable
	}
	normalized, _, err := iamv1.CanonicalizeAuthorizationProfile(profile)
	if err != nil || normalized != canonical {
		return iamv1.AuthorizationProfile{}, false, identityaccess.ErrUnavailable
	}
	if value.archivedProfiles == nil {
		value.archivedProfiles = make(map[iamv1.AuthorizationProfileReference]iamv1.AuthorizationProfile)
	}
	value.archivedProfiles[reference] = profile
	return profile, true, nil
}

// This is only the private storage projection of the existing version. Raw
// canonical bytes never leave this adapter or become authorization evidence.
type storedPolicyVersion struct {
	Value     *iamv1.PolicyVersion `json:"value"`
	Canonical string               `json:"canonical"`
}

const maxStoredPolicyVersionBytes = 3*iamv1.MaxPolicyCompilationBytes + 8192

func (value *transaction) resolvePolicyVersion(ctx context.Context, stored storedPolicyVersion) (iamv1.PolicyVersion, []iamv1.AuthorizationProfile, error) {
	if stored.Value == nil || stored.Canonical == "" || int64(len(stored.Canonical)) > iamv1.MaxPolicyCompilationBytes {
		return iamv1.PolicyVersion{}, nil, identityaccess.ErrUnavailable
	}
	version := *stored.Value
	canonical, err := iamv1.CanonicalizePolicyVersion(version)
	if err != nil || canonical != stored.Canonical {
		return iamv1.PolicyVersion{}, nil, identityaccess.ErrUnavailable
	}
	var references []iamv1.AuthorizationProfileReference
	if version.ContractVersion == iamv1.PolicyVersionLegacyContract {
		// Unknown legacy content remains management/history-readable, never a
		// current permit. Known SYSTEM content requires its exact ceiling.
		references, _ = authority.LegacySystemPolicyReferences(version)
	} else {
		references = version.Compilation.Profiles
	}
	profiles := make([]iamv1.AuthorizationProfile, 0, len(references))
	for _, reference := range references {
		profile, found, err := value.LookupAuthorizationProfile(ctx, reference)
		if err != nil || !found {
			return iamv1.PolicyVersion{}, nil, identityaccess.ErrUnavailable
		}
		profiles = append(profiles, profile)
	}
	if version.ContractVersion == iamv1.PolicyVersionLegacyContract {
		return version, profiles, nil
	}
	canonical, digest, err := iamv1.CanonicalizePolicyCompilation(version.Document, *version.Compilation, profiles)
	if err != nil || canonical != stored.Canonical || digest != version.ContentDigest {
		return iamv1.PolicyVersion{}, nil, identityaccess.ErrUnavailable
	}
	return version, profiles, nil
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
		status.AccountID = iamv1.AccountID(*organizationID)
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
		&account.AccountID,
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
	account.AccountStatus = iamv1.AccountStatus(organizationStatus)
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
		string(mutation.Session.AccountID),
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
		policies                                                    []byte
		boundary                                                    []byte
	)
	err := value.tx.QueryRow(ctx, "SELECT * FROM iam.lookup_session($1)", lookupDigest).Scan(
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
		&policies,
		&boundary,
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
		Organization: iamv1.Organization{
			APIVersion:      iamv1.APIVersion,
			Kind:            "Organization",
			ID:              iamv1.AccountID(organizationID),
			DisplayName:     organizationDisplayName,
			Status:          iamv1.AccountStatus(organizationStatus),
			ResourceVersion: organizationVersion,
			CreatedAt:       organizationCreatedAt.UTC(),
			UpdatedAt:       organizationUpdatedAt.UTC(),
		},
		Principal: iamv1.Principal{
			APIVersion:         iamv1.APIVersion,
			Kind:               "Principal",
			ID:                 iamv1.PrincipalID(principalID),
			AccountID:          iamv1.AccountID(organizationID),
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
			APIVersion:  iamv1.APIVersion,
			Kind:        "Session",
			ID:          iamv1.SessionID(sessionID),
			AccountID:   iamv1.AccountID(organizationID),
			PrincipalID: iamv1.PrincipalID(principalID),
			Status:      iamv1.SessionStatus(sessionStatus),
			IssuedAt:    sessionIssuedAt.UTC(),
			ExpiresAt:   sessionExpiresAt.UTC(),
			RevokedAt:   revokedAt,
		},
	}
	subject.Policies, err = value.decodeAttachedPolicies(ctx, policies)
	if err != nil {
		return identityaccess.SessionCredential{}, false, err
	}
	defer clear(boundary)
	subject.Boundary, err = value.decodeUserBoundary(ctx, boundary, subject.Organization.ID, subject.Principal.ID, subject.Principal.ResourceVersion)
	if err != nil {
		return identityaccess.SessionCredential{}, false, err
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

// The same boundary decoder protects USER authentication carriers; a key must
// not acquire a second policy representation or fabricated login Session.
func (value *transaction) decodeUserBoundary(ctx context.Context, boundary []byte, account iamv1.AccountID, user iamv1.PrincipalID, userVersion uint64) (*authority.ResolvedUserBoundary, error) {
	var storedBoundary struct {
		State               string               `json:"state"`
		AccountID           iamv1.AccountID      `json:"accountId"`
		UserID              iamv1.PrincipalID    `json:"userId"`
		UserResourceVersion uint64               `json:"userResourceVersion"`
		BoundaryID          string               `json:"boundaryId,omitempty"`
		ResourceVersion     uint64               `json:"resourceVersion,omitempty"`
		Policy              *iamv1.Policy        `json:"policy,omitempty"`
		Version             *storedPolicyVersion `json:"version,omitempty"`
	}
	if contractjson.DecodeObjectBytes(boundary, maxStoredPolicyVersionBytes+4096, &storedBoundary) != nil {
		return nil, identityaccess.ErrUnavailable
	}
	resolved := authority.ResolvedUserBoundary{State: storedBoundary.State, AccountID: storedBoundary.AccountID,
		UserID: storedBoundary.UserID, UserResourceVersion: storedBoundary.UserResourceVersion,
		BoundaryID: storedBoundary.BoundaryID, ResourceVersion: storedBoundary.ResourceVersion, Policy: storedBoundary.Policy}
	if storedBoundary.Version != nil {
		version, profiles, err := value.resolvePolicyVersion(ctx, *storedBoundary.Version)
		if err != nil {
			return nil, err
		}
		resolved.Version, resolved.Profiles = &version, profiles
	}
	if resolved.Policy != nil {
		resolved.Policy.CreatedAt, resolved.Policy.UpdatedAt = resolved.Policy.CreatedAt.UTC(), resolved.Policy.UpdatedAt.UTC()
	}
	if authority.ValidateUserBoundary(&resolved, account, user, userVersion) != nil {
		return nil, identityaccess.ErrUnavailable
	}
	return &resolved, nil
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
		AccountID:      iamv1.AccountID(organizationID),
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
	var decisionContract *int
	err = value.tx.QueryRow(ctx, "SELECT * FROM iam.read_audit_evidence($1,$2,$3,$4,$5::jsonb)",
		identity.AccountID, identity.PrincipalID, identity.Purpose, identity.InstallationID, encoded,
	).Scan(&result.InstallationID, &storedEvent, &decision, &verifier, &decisionContract)
	if errors.Is(err, pgx.ErrNoRows) {
		return identityaccess.AuditEvidence{}, false, nil
	}
	if err != nil {
		return identityaccess.AuditEvidence{}, false, mapDatabaseError("read historical IAM Audit evidence", err)
	}
	if iamv1.DecodeRequest(bytes.NewReader(storedEvent), &result.Event) != nil {
		return identityaccess.AuditEvidence{}, false, identityaccess.ErrUnavailable
	}
	result.Event.OccurredAt = result.Event.OccurredAt.UTC()
	if len(decision) > 0 {
		var decoded iamv1.AuthorizationDecision
		if decisionContract == nil || iamv1.DecodeRequest(bytes.NewReader(decision), &decoded) != nil {
			return identityaccess.AuditEvidence{}, false, identityaccess.ErrUnavailable
		}
		decoded.DecidedAt = decoded.DecidedAt.UTC()
		result.Decision, result.DecisionContractVersion = &decoded, *decisionContract
		switch *decisionContract {
		case 1:
			if iamv1.ValidateLegacyAuthorizationDecision(decoded) != nil {
				return identityaccess.AuditEvidence{}, false, identityaccess.ErrUnavailable
			}
		case 2, 3, 4:
			if decoded.Subject != nil && ((*decisionContract == 2 && decoded.Subject.Type == iamv1.SubjectRole) ||
				(*decisionContract < 4 && decoded.Subject.AccessKeyID != "")) {
				return identityaccess.AuditEvidence{}, false, identityaccess.ErrUnavailable
			}
			if decoded.Profile == nil {
				return identityaccess.AuditEvidence{}, false, identityaccess.ErrUnavailable
			}
			profile, found, err := value.LookupAuthorizationProfile(ctx, *decoded.Profile)
			if err != nil || !found || iamv1.ValidateAuthorizationDecisionForProfile(decoded, profile) != nil {
				return identityaccess.AuditEvidence{}, false, identityaccess.ErrUnavailable
			}
			result.DecisionProfile = &profile
		default:
			return identityaccess.AuditEvidence{}, false, identityaccess.ErrUnavailable
		}
	} else if decisionContract != nil {
		return identityaccess.AuditEvidence{}, false, identityaccess.ErrUnavailable
	}
	if verifier != nil {
		result.VerifierPrincipalID = iamv1.PrincipalID(*verifier)
	}
	return result, true, nil
}

func (value *transaction) LookupServicePolicies(
	ctx context.Context,
	organizationID iamv1.AccountID,
	principalID iamv1.PrincipalID,
) ([]authority.AttachedPolicy, error) {
	if iamv1.ValidateID("organizationId", string(organizationID)) != nil ||
		iamv1.ValidateID("principalId", string(principalID)) != nil {
		return nil, identityaccess.ErrInvalidArgument
	}
	var stored []byte
	err := value.tx.QueryRow(
		ctx,
		"SELECT * FROM iam.lookup_service_policies($1, $2)",
		string(organizationID),
		string(principalID),
	).Scan(&stored)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, identityaccess.ErrUnavailable
	}
	if err != nil {
		return nil, mapDatabaseError("lookup IAM service policies", err)
	}
	return value.decodeAttachedPolicies(ctx, stored)
}

func (value *transaction) decodeAttachedPolicies(ctx context.Context, encoded []byte) ([]authority.AttachedPolicy, error) {
	// The SQL projection returns at most budget+1 records, so excess authority
	// fails closed instead of silently discarding a later Deny.
	const maxSnapshotBytes = (maxStoredPolicyVersionBytes + 4096) * authority.MaxEvaluationPolicies
	if int64(len(encoded)) > maxSnapshotBytes {
		return nil, identityaccess.ErrUnavailable
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var stored []json.RawMessage
	if decoder.Decode(&stored) != nil || stored == nil || len(stored) > authority.MaxEvaluationPolicies {
		return nil, identityaccess.ErrUnavailable
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF {
		return nil, identityaccess.ErrUnavailable
	}
	policies := make([]authority.AttachedPolicy, len(stored))
	for index := range stored {
		var item struct {
			Policy     iamv1.Policy           `json:"policy"`
			Version    storedPolicyVersion    `json:"version"`
			Attachment iamv1.PolicyAttachment `json:"attachment"`
			Membership *iamv1.GroupMembership `json:"membership,omitempty"`
		}
		if contractjson.DecodeObjectBytes(stored[index], maxStoredPolicyVersionBytes+4096, &item) != nil {
			return nil, identityaccess.ErrUnavailable
		}
		row := &policies[index]
		*row = authority.AttachedPolicy{Policy: item.Policy, Attachment: item.Attachment, Membership: item.Membership}
		version, profiles, err := value.resolvePolicyVersion(ctx, item.Version)
		if err != nil {
			return nil, err
		}
		row.Version, row.Profiles = version, profiles
		row.Policy.CreatedAt, row.Policy.UpdatedAt = row.Policy.CreatedAt.UTC(), row.Policy.UpdatedAt.UTC()
		row.Attachment.CreatedAt, row.Attachment.UpdatedAt = row.Attachment.CreatedAt.UTC(), row.Attachment.UpdatedAt.UTC()
		if row.Attachment.RevokedAt != nil {
			revoked := row.Attachment.RevokedAt.UTC()
			row.Attachment.RevokedAt = &revoked
		}
		if row.Membership != nil {
			row.Membership.CreatedAt, row.Membership.UpdatedAt = row.Membership.CreatedAt.UTC(), row.Membership.UpdatedAt.UTC()
			if row.Membership.RemovedAt != nil {
				removed := row.Membership.RemovedAt.UTC()
				row.Membership.RemovedAt = &removed
			}
			if iamv1.ValidateGroupMembership(*row.Membership) != nil {
				return nil, identityaccess.ErrUnavailable
			}
		}
		if iamv1.ValidatePolicy(row.Policy) != nil || iamv1.ValidatePolicyAttachment(row.Attachment) != nil || iamv1.ValidatePolicyVersion(row.Version) != nil {
			return nil, identityaccess.ErrUnavailable
		}
	}
	return policies, nil
}

func (value *transaction) LookupPassword(
	ctx context.Context,
	organizationID iamv1.AccountID,
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
	if err := value.CheckCurrentAuthorizationProfiles(ctx); err != nil {
		return err
	}
	if iamv1.CheckAuthorizationDecisionForRequest(mutation.Decision, mutation.Request) != nil ||
		iamv1.ValidateSubject(mutation.Subject) != nil ||
		(mutation.Subject.Type == iamv1.SubjectRole) != (mutation.RoleEvidence != nil) ||
		(mutation.Subject.AccessKeyID != "") != (mutation.AccessKeyEvidence != nil) ||
		(mutation.AccessKeyEvidence != nil && mutation.AccessKeyEvidence.AccessKeyID != mutation.Subject.AccessKeyID) ||
		auditv1.ValidateEventForSource(auditv1.SourceIAM, mutation.AuditEvent) != nil {
		return identityaccess.ErrInvalidArgument
	}
	decision, err := json.Marshal(struct {
		Request  iamv1.AuthorizationRequest  `json:"request"`
		Decision iamv1.AuthorizationDecision `json:"decision"`
	}{mutation.Request, mutation.Decision})
	if err != nil {
		return identityaccess.ErrUnavailable
	}
	event, err := json.Marshal(mutation.AuditEvent)
	if err != nil {
		clear(decision)
		return identityaccess.ErrUnavailable
	}
	evidence, err := json.Marshal(mutation.PolicyEvidence)
	if err != nil || mutation.PolicyEvidence == nil || len(mutation.PolicyEvidence) > authority.MaxEvaluationPolicies {
		clear(decision)
		clear(event)
		return identityaccess.ErrUnavailable
	}
	boundary, err := json.Marshal(mutation.BoundaryEvidence)
	if err != nil {
		clear(decision)
		clear(event)
		clear(evidence)
		return identityaccess.ErrUnavailable
	}
	defer clear(boundary)
	roleEvidence, err := json.Marshal(mutation.RoleEvidence)
	if err != nil {
		clear(decision)
		clear(event)
		clear(evidence)
		return identityaccess.ErrUnavailable
	}
	defer clear(roleEvidence)
	// This local wire is the only explicit database encoder. The private
	// evidence type still rejects ordinary JSON and redacts formatting.
	type keyEvidenceWire identityaccess.AccessKeyAuthorizationEvidence
	keyEvidence, err := json.Marshal((*keyEvidenceWire)(mutation.AccessKeyEvidence))
	if err != nil {
		clear(decision)
		clear(event)
		clear(evidence)
		return identityaccess.ErrUnavailable
	}
	defer clear(keyEvidence)
	_, err = value.tx.Exec(
		ctx,
		"SELECT iam.record_authorization($1, $2, $3::jsonb, $4::jsonb, $5::jsonb, $6::jsonb, $7::integer, $8::jsonb, $9::jsonb)",
		string(mutation.AccountID),
		mutation.Subject.ID,
		decision,
		event,
		evidence,
		boundary,
		4,
		roleEvidence,
		keyEvidence,
	)
	clear(decision)
	clear(event)
	clear(evidence)
	if err != nil {
		return mapSubjectDatabaseError("record IAM authorization", err)
	}
	return nil
}

func (value *transaction) ChangePassword(
	ctx context.Context,
	mutation identityaccess.PasswordMutation,
) (iamv1.ChangePasswordResponse, error) {
	if iamv1.ValidateID("organizationId", string(mutation.AccountID)) != nil ||
		iamv1.ValidateID("principalId", string(mutation.PrincipalID)) != nil ||
		iamv1.ValidateID("sessionId", string(mutation.SessionID)) != nil ||
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
		"SELECT * FROM iam.change_password($1, $2, $3, $4, $5::jsonb, $6, $7)",
		string(mutation.AccountID),
		string(mutation.PrincipalID),
		string(mutation.ExpectedPasswordHash),
		string(mutation.NewPasswordHash),
		event,
		string(mutation.SessionID),
		mutation.RevokeOtherSessions,
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
	if iamv1.ValidateID("organizationId", string(mutation.AccountID)) != nil ||
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
		string(mutation.AccountID),
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
) (iamv1.User, error) {
	if iamv1.ValidateUser(mutation.User) != nil ||
		iamv1.ValidateID("actorPrincipalId", string(mutation.ActorPrincipalID)) != nil ||
		iamv1.ValidateID("decisionId", string(mutation.DecisionID)) != nil ||
		mutation.PasswordHash == "" ||
		auditv1.ValidateEventForSource(auditv1.SourceIAM, mutation.AuditEvent) != nil {
		return iamv1.User{}, identityaccess.ErrInvalidArgument
	}
	event, err := json.Marshal(mutation.AuditEvent)
	if err != nil {
		return iamv1.User{}, identityaccess.ErrUnavailable
	}
	var createdAt, updatedAt time.Time
	err = value.tx.QueryRow(
		ctx,
		"SELECT * FROM iam.create_user($1, $2, $3, $4, $5, $6, $7, $8::jsonb)",
		string(mutation.User.AccountID),
		string(mutation.User.ID),
		mutation.User.LoginName,
		mutation.User.DisplayName,
		string(mutation.PasswordHash),
		string(mutation.ActorPrincipalID),
		string(mutation.DecisionID),
		event,
	).Scan(&createdAt, &updatedAt)
	clear(event)
	if err != nil {
		return iamv1.User{}, mapAuthorizationDatabaseError("create IAM user", err)
	}
	stored := mutation.User
	stored.CreatedAt = createdAt.UTC()
	stored.UpdatedAt = updatedAt.UTC()
	if iamv1.ValidateUser(stored) != nil || stored.CreatedAt != mutation.User.CreatedAt ||
		stored.UpdatedAt != mutation.User.UpdatedAt {
		return iamv1.User{}, identityaccess.ErrUnavailable
	}
	return stored, nil
}

func (value *transaction) LookupPolicy(ctx context.Context, account iamv1.AccountID, id iamv1.PolicyID) (iamv1.Policy, bool, error) {
	if iamv1.ValidateID("accountId", string(account)) != nil || iamv1.ValidateID("policyId", string(id)) != nil {
		return iamv1.Policy{}, false, identityaccess.ErrInvalidArgument
	}
	var encoded []byte
	if err := value.tx.QueryRow(ctx, "SELECT iam.lookup_policy($1,$2)", string(account), string(id)).Scan(&encoded); err != nil {
		return iamv1.Policy{}, false, mapDatabaseError("read IAM policy", err)
	}
	if len(encoded) == 0 {
		return iamv1.Policy{}, false, nil
	}
	var policy iamv1.Policy
	if iamv1.DecodeRequest(bytes.NewReader(encoded), &policy) != nil {
		return iamv1.Policy{}, false, identityaccess.ErrUnavailable
	}
	policy.CreatedAt, policy.UpdatedAt = policy.CreatedAt.UTC(), policy.UpdatedAt.UTC()
	if iamv1.ValidatePolicy(policy) != nil {
		return iamv1.Policy{}, false, identityaccess.ErrUnavailable
	}
	return policy, true, nil
}

func decodePolicyAttachment(encoded []byte) (iamv1.PolicyAttachment, error) {
	var attachment iamv1.PolicyAttachment
	if iamv1.DecodeRequest(bytes.NewReader(encoded), &attachment) != nil {
		return attachment, identityaccess.ErrUnavailable
	}
	attachment.CreatedAt, attachment.UpdatedAt = attachment.CreatedAt.UTC(), attachment.UpdatedAt.UTC()
	if attachment.RevokedAt != nil {
		utc := attachment.RevokedAt.UTC()
		attachment.RevokedAt = &utc
	}
	if iamv1.ValidatePolicyAttachment(attachment) != nil {
		return iamv1.PolicyAttachment{}, identityaccess.ErrUnavailable
	}
	return attachment, nil
}

func (value *transaction) LookupPolicyAttachment(ctx context.Context, account iamv1.AccountID, id iamv1.PolicyAttachmentID) (iamv1.PolicyAttachment, bool, error) {
	if iamv1.ValidateID("accountId", string(account)) != nil || iamv1.ValidateID("attachmentId", string(id)) != nil {
		return iamv1.PolicyAttachment{}, false, identityaccess.ErrInvalidArgument
	}
	var encoded []byte
	if err := value.tx.QueryRow(ctx, "SELECT iam.lookup_policy_attachment($1,$2)", string(account), string(id)).Scan(&encoded); err != nil {
		return iamv1.PolicyAttachment{}, false, mapDatabaseError("read IAM policy attachment", err)
	}
	if len(encoded) == 0 {
		return iamv1.PolicyAttachment{}, false, nil
	}
	attachment, err := decodePolicyAttachment(encoded)
	return attachment, err == nil, err
}

func (value *transaction) CreatePolicyAttachment(ctx context.Context, mutation identityaccess.PolicyAttachmentMutation) (iamv1.PolicyAttachment, error) {
	attachment := mutation.Attachment
	if iamv1.ValidateID("actorSessionId", string(mutation.ActorSessionID)) != nil ||
		iamv1.ValidatePolicyAttachment(attachment) != nil || iamv1.ValidateCreatePolicyAttachmentRequest(iamv1.CreatePolicyAttachmentRequest{
		Target: attachment.Target, PolicyID: attachment.PolicyID, PolicyResourceVersion: mutation.PolicyResourceVersion, RequestID: mutation.AuditEvent.RequestID}) != nil ||
		auditv1.ValidateEventForSource(auditv1.SourceIAM, mutation.AuditEvent) != nil {
		return iamv1.PolicyAttachment{}, identityaccess.ErrInvalidArgument
	}
	event, err := json.Marshal(mutation.AuditEvent)
	if err != nil {
		return iamv1.PolicyAttachment{}, identityaccess.ErrUnavailable
	}
	var encoded []byte
	err = value.tx.QueryRow(ctx, "SELECT iam.create_policy_attachment($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10)",
		string(attachment.AccountID), string(attachment.ID), string(attachment.Target.Kind), attachment.Target.ID, string(attachment.PolicyID), mutation.PolicyResourceVersion,
		string(mutation.ActorPrincipalID), string(mutation.DecisionID), event, string(mutation.ActorSessionID)).Scan(&encoded)
	if err != nil {
		return iamv1.PolicyAttachment{}, mapAuthorizationDatabaseError("create IAM policy attachment", err)
	}
	return decodePolicyAttachment(encoded)
}

func (value *transaction) RevokePolicyAttachment(ctx context.Context, mutation identityaccess.PolicyAttachmentRevocationMutation) (iamv1.Revocation, bool, error) {
	if iamv1.ValidateID("actorSessionId", string(mutation.ActorSessionID)) != nil ||
		iamv1.ValidateID("accountId", string(mutation.AccountID)) != nil || iamv1.ValidateID("attachmentId", string(mutation.AttachmentID)) != nil ||
		iamv1.ValidateRevokePolicyAttachmentRequest(iamv1.RevokePolicyAttachmentRequest{ResourceVersion: mutation.ResourceVersion, RequestID: mutation.AuditEvent.RequestID}) != nil ||
		auditv1.ValidateEventForSource(auditv1.SourceIAM, mutation.AuditEvent) != nil {
		return iamv1.Revocation{}, false, identityaccess.ErrInvalidArgument
	}
	event, err := json.Marshal(mutation.AuditEvent)
	if err != nil {
		return iamv1.Revocation{}, false, identityaccess.ErrUnavailable
	}
	result := iamv1.Revocation{APIVersion: iamv1.APIVersion, Kind: "Revocation", ID: string(mutation.AttachmentID)}
	var applied bool
	err = value.tx.QueryRow(ctx, "SELECT * FROM iam.revoke_policy_attachment($1,$2,$3,$4,$5,$6::jsonb,$7)",
		string(mutation.AccountID), string(mutation.AttachmentID), mutation.ResourceVersion, string(mutation.ActorPrincipalID),
		string(mutation.DecisionID), event, string(mutation.ActorSessionID)).Scan(&result.ResourceVersion, &result.RevokedAt, &applied)
	if err != nil {
		return iamv1.Revocation{}, false, mapAuthorizationDatabaseError("revoke IAM policy attachment", err)
	}
	result.RevokedAt = result.RevokedAt.UTC()
	if iamv1.ValidateRevocation(result) != nil {
		return iamv1.Revocation{}, false, identityaccess.ErrUnavailable
	}
	return result, applied, nil
}

func (value *transaction) Readiness(
	ctx context.Context,
) (identityaccess.ReadinessSnapshot, error) {
	if err := value.CheckCurrentAuthorizationProfiles(ctx); err != nil {
		return identityaccess.ReadinessSnapshot{}, err
	}
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
