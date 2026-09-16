package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
	"time"

	auditv1 "github.com/xiak/matrix/api/audit/v1"
	"github.com/xiak/matrix/api/contractjson"
	iamv1 "github.com/xiak/matrix/api/iam/v1"
	"github.com/xiak/matrix/app/service/iam/internal/authority"
	"github.com/xiak/matrix/app/service/iam/internal/usecase/identityaccess"
)

func (value *transaction) LookupRoleSessionForExit(ctx context.Context, digest string) (identityaccess.RoleSessionExitCredential, bool, error) {
	var encoded []byte
	if err := value.tx.QueryRow(ctx, "SELECT iam.lookup_role_session_for_exit($1)", digest).Scan(&encoded); err != nil {
		return identityaccess.RoleSessionExitCredential{}, false, mapDatabaseError("lookup IAM role self-exit", err)
	}
	defer clear(encoded)
	if encoded == nil {
		return identityaccess.RoleSessionExitCredential{}, false, nil
	}
	var result identityaccess.RoleSessionExitCredential
	if contractjson.DecodeObjectBytes(encoded, 4096, &result) != nil {
		return identityaccess.RoleSessionExitCredential{}, false, identityaccess.ErrUnavailable
	}
	normalizeRoleSession(&result.Session)
	if iamv1.ValidateRoleSession(result.Session) != nil || iamv1.ValidateDigest("verificationDigest", result.VerificationDigest) != nil {
		return identityaccess.RoleSessionExitCredential{}, false, identityaccess.ErrUnavailable
	}
	return result, true, nil
}

func (value *transaction) ExitRoleSession(ctx context.Context, lookup string, fact auditv1.Event) (iamv1.RoleSession, error) {
	event, err := marshalManagementEvent(fact)
	if err != nil {
		return iamv1.RoleSession{}, err
	}
	defer clear(event)
	if fact.Action != auditv1.ActionIAMRoleSessionExited || iamv1.ValidateDigest("lookupDigest", lookup) != nil {
		return iamv1.RoleSession{}, identityaccess.ErrInvalidArgument
	}
	var encoded []byte
	if err := value.tx.QueryRow(ctx, "SELECT iam.exit_role_session($1,$2::jsonb)", lookup, event).Scan(&encoded); err != nil {
		return iamv1.RoleSession{}, mapAuthorizationDatabaseError("exit IAM role session", err)
	}
	result, err := decodeRoleSession(encoded, identityaccess.RoleAssumptionRead{AccountID: iamv1.AccountID(fact.TenantID),
		ActorPrincipalID: iamv1.PrincipalID(fact.Actor.RoleSession.SourceUserID)})
	if err != nil || result.ID != iamv1.RoleSessionID(fact.Target.ID) || result.RoleID != iamv1.RoleID(fact.Actor.ID) || result.Status != iamv1.SessionRevoked {
		return iamv1.RoleSession{}, identityaccess.ErrUnavailable
	}
	return result, nil
}

func (value *transaction) LookupRoleSession(ctx context.Context, digest string) (identityaccess.RoleSessionCredential, bool, error) {
	var encoded []byte
	if err := value.tx.QueryRow(ctx, "SELECT iam.lookup_role_session($1)", digest).Scan(&encoded); err != nil {
		return identityaccess.RoleSessionCredential{}, false, mapDatabaseError("lookup IAM role session", err)
	}
	defer clear(encoded)
	if encoded == nil {
		return identityaccess.RoleSessionCredential{}, false, nil
	}
	var stored struct {
		Session                iamv1.RoleSession `json:"session"`
		SourceSessionID        iamv1.SessionID   `json:"sourceSessionId"`
		SourceLookupDigest     string            `json:"sourceLookupDigest"`
		CredentialGeneration   uint64            `json:"credentialGeneration"`
		SecurityGeneration     uint64            `json:"securityGeneration"`
		AssumeDecisionID       iamv1.DecisionID  `json:"assumeDecisionId"`
		VerificationDigest     string            `json:"verificationDigest"`
		Role                   iamv1.Role        `json:"role"`
		AuthorityEvidence      json.RawMessage   `json:"authorityEvidence"`
		SessionPolicyCanonical *string           `json:"sessionPolicyCanonical"`
		SessionPolicyDigest    *string           `json:"sessionPolicyDigest"`
	}
	// The complete vector is bounded by the existing policy/attachment budgets.
	if contractjson.DecodeObjectBytes(encoded, 2*257*maxStoredPolicyVersionBytes, &stored) != nil ||
		stored.CredentialGeneration == 0 || stored.CredentialGeneration > 9007199254740991 ||
		stored.SecurityGeneration == 0 || stored.SecurityGeneration > 9007199254740991 ||
		iamv1.ValidateID("assumeDecisionId", string(stored.AssumeDecisionID)) != nil ||
		iamv1.ValidateDigest("sourceLookupDigest", stored.SourceLookupDigest) != nil ||
		iamv1.ValidateDigest("verificationDigest", stored.VerificationDigest) != nil ||
		(stored.SessionPolicyCanonical == nil) != (stored.SessionPolicyDigest == nil) {
		return identityaccess.RoleSessionCredential{}, false, identityaccess.ErrUnavailable
	}
	var evidence struct {
		AccountResourceVersion uint64                 `json:"accountResourceVersion"`
		UserResourceVersion    uint64                 `json:"userResourceVersion"`
		SourcePolicies         json.RawMessage        `json:"sourcePolicies"`
		SourceBoundary         json.RawMessage        `json:"sourceBoundary"`
		Role                   iamv1.Role             `json:"role"`
		Trust                  iamv1.RoleTrustVersion `json:"trust"`
		RolePolicies           json.RawMessage        `json:"rolePolicies"`
		RoleBoundary           struct {
			BoundaryID      string              `json:"boundaryId"`
			ResourceVersion uint64              `json:"resourceVersion"`
			Policy          iamv1.Policy        `json:"policy"`
			Version         storedPolicyVersion `json:"version"`
		} `json:"roleBoundary"`
	}
	if contractjson.DecodeObjectBytes(stored.AuthorityEvidence, 2*257*maxStoredPolicyVersionBytes, &evidence) != nil {
		return identityaccess.RoleSessionCredential{}, false, identityaccess.ErrUnavailable
	}
	source, found, err := value.LookupSession(ctx, stored.SourceLookupDigest)
	if err != nil || !found {
		return identityaccess.RoleSessionCredential{}, false, err
	}
	normalizeRoleSession(&stored.Session)
	normalizeRole(&stored.Role)
	normalizeRole(&evidence.Role)
	evidence.Trust.CreatedAt = evidence.Trust.CreatedAt.UTC()
	if iamv1.ValidateRoleSession(stored.Session) != nil || iamv1.ValidateRole(stored.Role) != nil || iamv1.ValidateRole(evidence.Role) != nil ||
		iamv1.ValidateRoleTrustVersion(evidence.Trust) != nil || stored.Session.Status != iamv1.SessionActive ||
		stored.Session.AccountID != source.Subject.Organization.ID || stored.Session.SourceUserID != source.Subject.Principal.ID ||
		stored.SourceSessionID != source.Subject.Session.ID || stored.Session.RoleID != stored.Role.ID ||
		evidence.AccountResourceVersion != source.Subject.Organization.ResourceVersion || evidence.UserResourceVersion != source.Subject.Principal.ResourceVersion ||
		evidence.Role.ID != stored.Role.ID || evidence.Role.AccountID != stored.Role.AccountID || evidence.Trust.ID != stored.Role.CurrentTrustVersionID {
		return identityaccess.RoleSessionCredential{}, false, identityaccess.ErrUnavailable
	}
	rolePolicies, err := value.decodeAttachedPolicies(ctx, evidence.RolePolicies)
	if err != nil {
		return identityaccess.RoleSessionCredential{}, false, err
	}
	for _, policy := range rolePolicies {
		if policy.Attachment.AccountID != stored.Session.AccountID || policy.Attachment.Target.Kind != iamv1.PolicyTargetRole ||
			policy.Attachment.Target.ID != string(stored.Session.RoleID) || policy.Attachment.Scope != iamv1.AuthorityScopeTenant || policy.Membership != nil {
			return identityaccess.RoleSessionCredential{}, false, identityaccess.ErrUnavailable
		}
	}
	boundaryVersion, boundaryProfiles, err := value.resolvePolicyVersion(ctx, evidence.RoleBoundary.Version)
	if err != nil {
		return identityaccess.RoleSessionCredential{}, false, err
	}
	boundary := &authority.ResolvedRoleBoundary{BoundaryID: evidence.RoleBoundary.BoundaryID, ResourceVersion: evidence.RoleBoundary.ResourceVersion,
		Policy: evidence.RoleBoundary.Policy, Version: boundaryVersion, Profiles: boundaryProfiles}
	boundary.Policy.CreatedAt, boundary.Policy.UpdatedAt = boundary.Policy.CreatedAt.UTC(), boundary.Policy.UpdatedAt.UTC()
	if authority.ValidateRoleBoundary(boundary, stored.Session.AccountID) != nil {
		return identityaccess.RoleSessionCredential{}, false, identityaccess.ErrUnavailable
	}
	var restriction *authority.ResolvedSessionPolicy
	if stored.SessionPolicyCanonical != nil {
		var content struct {
			Document           iamv1.PolicyDocument                  `json:"document"`
			CompilationVersion string                                `json:"compilationVersion"`
			Profiles           []iamv1.AuthorizationProfileReference `json:"profiles"`
			ResolvedStatements []iamv1.PolicyResolvedStatement       `json:"resolvedStatements"`
		}
		if contractjson.DecodeObjectBytes([]byte(*stored.SessionPolicyCanonical), iamv1.MaxPolicyCompilationBytes, &content) != nil {
			return identityaccess.RoleSessionCredential{}, false, identityaccess.ErrUnavailable
		}
		restriction = &authority.ResolvedSessionPolicy{Document: content.Document, Compilation: iamv1.PolicyCompilation{CompilationVersion: content.CompilationVersion,
			Profiles: content.Profiles, ResolvedStatements: content.ResolvedStatements}, ContentDigest: *stored.SessionPolicyDigest}
		for _, reference := range content.Profiles {
			profile, found, err := value.LookupAuthorizationProfile(ctx, reference)
			if err != nil || !found {
				return identityaccess.RoleSessionCredential{}, false, identityaccess.ErrUnavailable
			}
			restriction.Profiles = append(restriction.Profiles, profile)
		}
		canonical, digest, err := iamv1.CanonicalizePolicyCompilation(restriction.Document, restriction.Compilation, restriction.Profiles)
		if err != nil || canonical != *stored.SessionPolicyCanonical || digest != restriction.ContentDigest || authority.ValidateSessionPolicy(restriction) != nil {
			return identityaccess.RoleSessionCredential{}, false, identityaccess.ErrUnavailable
		}
	}
	return identityaccess.RoleSessionCredential{Subject: authority.RoleSessionContext{Session: stored.Session, Source: source.Subject,
		CredentialGeneration: stored.CredentialGeneration, SecurityGeneration: stored.SecurityGeneration, AssumeDecisionID: stored.AssumeDecisionID,
		SourceSessionID: stored.SourceSessionID, Role: stored.Role, Trust: evidence.Trust, Policies: rolePolicies, Boundary: boundary, SessionPolicy: restriction},
		VerificationDigest: stored.VerificationDigest}, true, nil
}

func normalizeRoleSession(session *iamv1.RoleSession) {
	session.IssuedAt, session.ExpiresAt = session.IssuedAt.UTC(), session.ExpiresAt.UTC()
	if session.RevokedAt != nil {
		revoked := session.RevokedAt.UTC()
		session.RevokedAt = &revoked
	}
}

func (value *transaction) ReadRoleAssumption(ctx context.Context, read identityaccess.RoleAssumptionRead) (identityaccess.RoleAssumption, error) {
	var encoded []byte
	if err := value.tx.QueryRow(ctx, "SELECT iam.read_role_assumption($1,$2,$3,$4,$5)", read.AccountID, read.ActorPrincipalID, read.ActorSessionID, read.RoleID, read.RequestID).Scan(&encoded); err != nil {
		return identityaccess.RoleAssumption{}, mapAuthorizationDatabaseError("read IAM role assumption", err)
	}
	defer clear(encoded)
	var stored struct {
		Role                 *iamv1.Role                        `json:"role,omitempty"`
		Trust                *iamv1.RoleTrustVersion            `json:"trust,omitempty"`
		CredentialGeneration uint64                             `json:"credentialGeneration"`
		SecurityGeneration   uint64                             `json:"securityGeneration,omitempty"`
		Existing             *identityaccess.RoleSessionReceipt `json:"existing,omitempty"`
	}
	if contractjson.DecodeObjectBytes(encoded, iamv1.MaxRoleAccessBytes, &stored) != nil || stored.CredentialGeneration == 0 || stored.CredentialGeneration > 9007199254740991 {
		return identityaccess.RoleAssumption{}, identityaccess.ErrUnavailable
	}
	result := identityaccess.RoleAssumption{CredentialGeneration: stored.CredentialGeneration, SecurityGeneration: stored.SecurityGeneration, Existing: stored.Existing}
	if stored.Existing != nil {
		previous := stored.Existing
		normalizeRoleSession(&previous.Session)
		if stored.Role != nil || stored.Trust != nil || stored.SecurityGeneration != 0 || iamv1.ValidateRoleSession(previous.Session) != nil ||
			previous.Session.AccountID != read.AccountID || previous.Session.SourceUserID != read.ActorPrincipalID ||
			iamv1.ValidateID("sourceSessionId", string(previous.SourceSessionID)) != nil || previous.CredentialGeneration == 0 || previous.CredentialGeneration > 9007199254740991 ||
			iamv1.ValidateDigest("requestDigest", previous.RequestDigest) != nil {
			return identityaccess.RoleAssumption{}, identityaccess.ErrUnavailable
		}
		return result, nil
	}
	if stored.Role == nil || stored.Trust == nil || stored.SecurityGeneration == 0 || stored.SecurityGeneration > 9007199254740991 {
		return identityaccess.RoleAssumption{}, identityaccess.ErrUnavailable
	}
	normalizeRole(stored.Role)
	stored.Trust.CreatedAt = stored.Trust.CreatedAt.UTC()
	if iamv1.ValidateRole(*stored.Role) != nil || iamv1.ValidateRoleTrustVersion(*stored.Trust) != nil || stored.Role.AccountID != read.AccountID || stored.Role.ID != read.RoleID ||
		stored.Trust.AccountID != read.AccountID || stored.Trust.RoleID != read.RoleID || stored.Role.CurrentTrustVersionID != stored.Trust.ID {
		return identityaccess.RoleAssumption{}, identityaccess.ErrUnavailable
	}
	result.Role, result.Trust = *stored.Role, *stored.Trust
	return result, nil
}

func decodeRoleSession(encoded []byte, read identityaccess.RoleAssumptionRead) (iamv1.RoleSession, error) {
	defer clear(encoded)
	var result iamv1.RoleSession
	if iamv1.DecodeRequest(bytes.NewReader(encoded), &result) != nil {
		return iamv1.RoleSession{}, identityaccess.ErrUnavailable
	}
	normalizeRoleSession(&result)
	if iamv1.ValidateRoleSession(result) != nil || result.AccountID != read.AccountID || result.SourceUserID != read.ActorPrincipalID {
		return iamv1.RoleSession{}, identityaccess.ErrUnavailable
	}
	return result, nil
}

func (value *transaction) IssueRoleSession(ctx context.Context, mutation identityaccess.RoleSessionIssuance) (iamv1.RoleSession, error) {
	if iamv1.ValidateRoleSession(mutation.Session) != nil || mutation.Session.Status != iamv1.SessionActive || mutation.Session.AccountID != mutation.AccountID ||
		mutation.Session.RoleID != mutation.RoleID || mutation.Session.SourceUserID != mutation.ActorPrincipalID || iamv1.ValidateID("sourceSessionId", string(mutation.ActorSessionID)) != nil {
		return iamv1.RoleSession{}, identityaccess.ErrInvalidArgument
	}
	intent, err := json.Marshal(struct {
		SessionID            iamv1.RoleSessionID `json:"sessionId"`
		RequestID            string              `json:"requestId"`
		RequestDigest        string              `json:"requestDigest"`
		ResourceVersion      uint64              `json:"resourceVersion"`
		CredentialGeneration uint64              `json:"credentialGeneration"`
		SecurityGeneration   uint64              `json:"securityGeneration"`
		DurationSeconds      uint32              `json:"durationSeconds"`
		IssuedAt             time.Time           `json:"issuedAt"`
		ExpiresAt            time.Time           `json:"expiresAt"`
	}{mutation.Session.ID, mutation.RequestID, mutation.RequestDigest, mutation.ExpectedRoleVersion, mutation.CredentialGeneration, mutation.SecurityGeneration,
		mutation.DurationSeconds, mutation.Session.IssuedAt, mutation.Session.ExpiresAt})
	if err != nil {
		return iamv1.RoleSession{}, identityaccess.ErrInvalidArgument
	}
	defer clear(intent)
	var policy []byte
	if mutation.SessionPolicyCanonical != "" || mutation.SessionPolicyDigest != "" {
		policy, err = json.Marshal(struct {
			Canonical     string `json:"canonical"`
			ContentDigest string `json:"contentDigest"`
		}{mutation.SessionPolicyCanonical, mutation.SessionPolicyDigest})
		if err != nil {
			return iamv1.RoleSession{}, identityaccess.ErrInvalidArgument
		}
		defer clear(policy)
	}
	event, err := marshalManagementEvent(mutation.AuditEvent)
	if err != nil {
		return iamv1.RoleSession{}, err
	}
	defer clear(event)
	var encoded []byte
	err = value.tx.QueryRow(ctx, "SELECT iam.issue_role_session($1,$2,$3,$4,$5,$6::jsonb,$7,$8,$9::jsonb,$10::jsonb)", mutation.AccountID,
		mutation.ActorPrincipalID, mutation.ActorSessionID, mutation.RoleID, mutation.DecisionID, intent, mutation.LookupDigest, mutation.VerificationDigest, policy, event).Scan(&encoded)
	if err != nil {
		return iamv1.RoleSession{}, mapAuthorizationDatabaseError("issue IAM role session", err)
	}
	result, err := decodeRoleSession(encoded, mutation.RoleAssumptionRead)
	if err != nil || !reflect.DeepEqual(result, mutation.Session) {
		return iamv1.RoleSession{}, identityaccess.ErrUnavailable
	}
	return result, nil
}

func (value *transaction) ReadRoleSessionByRequest(ctx context.Context, read identityaccess.RoleAssumptionRead) (iamv1.RoleSession, bool, error) {
	var encoded []byte
	if err := value.tx.QueryRow(ctx, "SELECT iam.read_role_session_by_request($1,$2,$3,$4)", read.AccountID, read.ActorPrincipalID, read.ActorSessionID, read.RequestID).Scan(&encoded); err != nil {
		return iamv1.RoleSession{}, false, mapAuthorizationDatabaseError("read IAM role issuance", err)
	}
	if encoded == nil {
		return iamv1.RoleSession{}, false, nil
	}
	result, err := decodeRoleSession(encoded, read)
	return result, err == nil, err
}

func (value *transaction) RevokeRoleSessionByRequest(ctx context.Context, mutation identityaccess.RoleSessionRevocation) (iamv1.RoleSession, error) {
	event, err := marshalManagementEvent(mutation.AuditEvent)
	if err != nil {
		return iamv1.RoleSession{}, err
	}
	defer clear(event)
	var encoded []byte
	err = value.tx.QueryRow(ctx, "SELECT iam.revoke_role_session_by_request($1,$2,$3,$4,$5::jsonb)", mutation.AccountID,
		mutation.ActorPrincipalID, mutation.ActorSessionID, mutation.RequestID, event).Scan(&encoded)
	if err != nil {
		return iamv1.RoleSession{}, mapAuthorizationDatabaseError("revoke IAM role issuance", err)
	}
	result, err := decodeRoleSession(encoded, mutation.RoleAssumptionRead)
	if err != nil || result.Status != iamv1.SessionRevoked {
		return iamv1.RoleSession{}, identityaccess.ErrUnavailable
	}
	return result, nil
}

func decodeRolePermissionBoundary(encoded []byte, account iamv1.AccountID, role iamv1.RoleID) (iamv1.RolePermissionBoundary, error) {
	defer clear(encoded)
	var result iamv1.RolePermissionBoundary
	if iamv1.DecodeRequest(bytes.NewReader(encoded), &result) != nil || iamv1.ValidateRolePermissionBoundary(result) != nil || result.AccountID != account || result.RoleID != role {
		return iamv1.RolePermissionBoundary{}, identityaccess.ErrUnavailable
	}
	return result, nil
}

func (value *transaction) ReadRolePermissionBoundary(ctx context.Context, read identityaccess.RoleRead) (iamv1.RolePermissionBoundary, error) {
	var encoded []byte
	if err := value.tx.QueryRow(ctx, "SELECT iam.read_role_permission_boundary($1,$2,$3,$4)", read.AccountID, read.ActorPrincipalID, read.DecisionID, read.RoleID).Scan(&encoded); err != nil {
		return iamv1.RolePermissionBoundary{}, mapAuthorizationDatabaseError("read IAM role boundary", err)
	}
	return decodeRolePermissionBoundary(encoded, read.AccountID, read.RoleID)
}

func (value *transaction) ChangeRolePermissionBoundary(ctx context.Context, mutation identityaccess.RoleBoundaryMutation) (iamv1.RolePermissionBoundary, error) {
	if iamv1.ValidateID("actorSessionId", string(mutation.ActorSessionID)) != nil {
		return iamv1.RolePermissionBoundary{}, identityaccess.ErrInvalidArgument
	}
	event, err := marshalManagementEvent(mutation.AuditEvent)
	if err != nil {
		return iamv1.RolePermissionBoundary{}, err
	}
	defer clear(event)
	var encoded []byte
	err = value.tx.QueryRow(ctx, "SELECT iam.change_role_permission_boundary($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10)",
		mutation.AccountID, mutation.ActorPrincipalID, mutation.DecisionID, mutation.RoleID, mutation.ResourceVersion,
		mutation.PolicyID, mutation.PolicyResourceVersion, mutation.BoundaryID, event, mutation.ActorSessionID).Scan(&encoded)
	if err != nil {
		return iamv1.RolePermissionBoundary{}, mapAuthorizationDatabaseError("change IAM role boundary", err)
	}
	result, err := decodeRolePermissionBoundary(encoded, mutation.AccountID, mutation.RoleID)
	if err != nil || result.ResourceVersion != mutation.ResourceVersion+1 || (mutation.PolicyID == "") != (result.Policy == nil) ||
		(result.Policy != nil && result.Policy.PolicyID != mutation.PolicyID) {
		return iamv1.RolePermissionBoundary{}, identityaccess.ErrUnavailable
	}
	return result, nil
}

type roleMetadata struct {
	Name                      string          `json:"name"`
	Description               string          `json:"description"`
	Tags                      []iamv1.RoleTag `json:"tags"`
	MaxSessionDurationSeconds uint32          `json:"maxSessionDurationSeconds"`
}

func normalizeRole(role *iamv1.Role) {
	role.CreatedAt, role.UpdatedAt = role.CreatedAt.UTC(), role.UpdatedAt.UTC()
}

func decodeRole(encoded []byte, account iamv1.AccountID, id iamv1.RoleID, revision uint64) (iamv1.Role, error) {
	var result iamv1.Role
	if json.Unmarshal(encoded, &result) != nil {
		return iamv1.Role{}, identityaccess.ErrUnavailable
	}
	normalizeRole(&result)
	if iamv1.ValidateRole(result) != nil || result.AccountID != account || result.ID != id || result.ResourceVersion != revision {
		return iamv1.Role{}, identityaccess.ErrUnavailable
	}
	return result, nil
}

func encodeRoleTrust(version iamv1.RoleTrustVersion) ([]byte, error) {
	if iamv1.ValidateRoleTrustVersion(version) != nil {
		return nil, identityaccess.ErrInvalidArgument
	}
	canonical, digest, err := iamv1.CanonicalizeTrustPolicyDocument(version.Document)
	if err != nil {
		return nil, identityaccess.ErrInvalidArgument
	}
	return json.Marshal(struct {
		CanonicalDocument string `json:"canonicalDocument"`
		ContentDigest     string `json:"contentDigest"`
	}{canonical, digest})
}

func (value *transaction) ListRoles(ctx context.Context, read identityaccess.AccountRead) (iamv1.RoleList, error) {
	var encoded []byte
	if err := value.tx.QueryRow(ctx, "SELECT iam.list_roles($1,$2,$3,$4)", read.AccountID, read.ActorPrincipalID, read.DecisionID, read.After).Scan(&encoded); err != nil {
		return iamv1.RoleList{}, mapAuthorizationDatabaseError("list IAM roles", err)
	}
	result := iamv1.RoleList{APIVersion: iamv1.APIVersion, Kind: "RoleList", AccountID: read.AccountID}
	if int64(len(encoded)) > iamv1.MaxRoleListBytes || json.Unmarshal(encoded, &result.Items) != nil || result.Items == nil || len(result.Items) > 101 {
		return iamv1.RoleList{}, identityaccess.ErrUnavailable
	}
	previous := read.After
	for index := range result.Items {
		item := &result.Items[index]
		normalizeRole(&item.Role)
		if iamv1.ValidateRole(item.Role) != nil || item.Role.AccountID != read.AccountID || string(item.Role.ID) <= previous || len(item.Capabilities) != 0 {
			return iamv1.RoleList{}, identityaccess.ErrUnavailable
		}
		previous = string(item.Role.ID)
	}
	if len(result.Items) > iamv1.DirectoryPageSize {
		result.Items = result.Items[:iamv1.DirectoryPageSize]
		result.NextAfter = string(result.Items[iamv1.DirectoryPageSize-1].Role.ID)
	}
	return result, nil
}

func (value *transaction) ReadRole(ctx context.Context, read identityaccess.RoleRead) (iamv1.RoleAccess, error) {
	var encoded []byte
	if err := value.tx.QueryRow(ctx, "SELECT iam.read_role($1,$2,$3,$4)", read.AccountID, read.ActorPrincipalID, read.DecisionID, read.RoleID).Scan(&encoded); err != nil {
		return iamv1.RoleAccess{}, mapAuthorizationDatabaseError("read IAM role", err)
	}
	var result iamv1.RoleAccess
	if int64(len(encoded)) > iamv1.MaxRoleAccessBytes || json.Unmarshal(encoded, &result) != nil {
		return iamv1.RoleAccess{}, identityaccess.ErrUnavailable
	}
	normalizeRole(&result.Role)
	result.TrustVersion.CreatedAt = result.TrustVersion.CreatedAt.UTC()
	if iamv1.ValidateRole(result.Role) != nil || result.Role.AccountID != read.AccountID || result.Role.ID != read.RoleID ||
		iamv1.ValidateRoleTrustVersion(result.TrustVersion) != nil || result.TrustVersion.AccountID != read.AccountID || result.TrustVersion.RoleID != read.RoleID ||
		result.TrustVersion.ID != result.Role.CurrentTrustVersionID || result.PolicyAttachments == nil || len(result.PolicyAttachments) > 256 || len(result.Capabilities) != 0 {
		return iamv1.RoleAccess{}, identityaccess.ErrUnavailable
	}
	attachments, policies := map[iamv1.PolicyAttachmentID]bool{}, map[iamv1.PolicyID]bool{}
	for index := range result.PolicyAttachments {
		attachment := &result.PolicyAttachments[index]
		attachment.CreatedAt, attachment.UpdatedAt = attachment.CreatedAt.UTC(), attachment.UpdatedAt.UTC()
		if iamv1.ValidatePolicyAttachment(*attachment) != nil || attachment.AccountID != read.AccountID || attachment.Target.Kind != iamv1.PolicyTargetRole ||
			attachment.Target.ID != string(read.RoleID) || attachment.Scope != iamv1.AuthorityScopeTenant || attachment.RevokedAt != nil || attachments[attachment.ID] || policies[attachment.PolicyID] {
			return iamv1.RoleAccess{}, identityaccess.ErrUnavailable
		}
		attachments[attachment.ID], policies[attachment.PolicyID] = true, true
	}
	return result, nil
}

func (value *transaction) CreateRole(ctx context.Context, mutation identityaccess.RoleCreation) (iamv1.Role, error) {
	role := mutation.Role
	if iamv1.ValidateID("actorSessionId", string(mutation.ActorSessionID)) != nil || iamv1.ValidateRole(role) != nil || mutation.TrustVersion.AccountID != role.AccountID || mutation.TrustVersion.RoleID != role.ID || mutation.TrustVersion.ID != role.CurrentTrustVersionID {
		return iamv1.Role{}, identityaccess.ErrInvalidArgument
	}
	trust, err := encodeRoleTrust(mutation.TrustVersion)
	if err != nil {
		return iamv1.Role{}, err
	}
	metadata, err := json.Marshal(roleMetadata{role.Name, role.Description, role.Tags, role.MaxSessionDurationSeconds})
	if err != nil {
		return iamv1.Role{}, identityaccess.ErrInvalidArgument
	}
	event, err := marshalManagementEvent(mutation.AuditEvent)
	if err != nil {
		return iamv1.Role{}, err
	}
	defer clear(event)
	var encoded []byte
	err = value.tx.QueryRow(ctx, "SELECT iam.create_role($1,$2,$3,$4,$5,$6::jsonb,$7::jsonb,$8::jsonb,$9)", role.AccountID,
		mutation.ActorPrincipalID, mutation.DecisionID, role.ID, mutation.TrustVersion.ID, metadata, trust, event, mutation.ActorSessionID).Scan(&encoded)
	if err != nil {
		return iamv1.Role{}, mapAuthorizationDatabaseError("create IAM role", err)
	}
	result, err := decodeRole(encoded, role.AccountID, role.ID, 1)
	if err != nil || result.CurrentTrustVersionID != role.CurrentTrustVersionID || result.Status != iamv1.RoleActive ||
		result.Name != role.Name || result.Description != role.Description || !reflect.DeepEqual(result.Tags, role.Tags) || result.MaxSessionDurationSeconds != role.MaxSessionDurationSeconds {
		return iamv1.Role{}, identityaccess.ErrUnavailable
	}
	return result, nil
}

func (value *transaction) UpdateRole(ctx context.Context, mutation identityaccess.RoleProfileMutation) (iamv1.Role, error) {
	if iamv1.ValidateID("actorSessionId", string(mutation.ActorSessionID)) != nil {
		return iamv1.Role{}, identityaccess.ErrInvalidArgument
	}
	metadata, err := json.Marshal(roleMetadata{mutation.Name, mutation.Description, mutation.Tags, mutation.MaxSessionDurationSeconds})
	if err != nil {
		return iamv1.Role{}, identityaccess.ErrInvalidArgument
	}
	event, err := marshalManagementEvent(mutation.AuditEvent)
	if err != nil {
		return iamv1.Role{}, err
	}
	defer clear(event)
	var encoded []byte
	err = value.tx.QueryRow(ctx, "SELECT iam.update_role($1,$2,$3,$4,$5,$6::jsonb,$7::jsonb,$8)", mutation.AccountID,
		mutation.ActorPrincipalID, mutation.DecisionID, mutation.RoleID, mutation.ResourceVersion, metadata, event, mutation.ActorSessionID).Scan(&encoded)
	if err != nil {
		return iamv1.Role{}, mapAuthorizationDatabaseError("update IAM role", err)
	}
	result, err := decodeRole(encoded, mutation.AccountID, mutation.RoleID, mutation.ResourceVersion+1)
	if err != nil || result.Name != mutation.Name || result.Description != mutation.Description || !reflect.DeepEqual(result.Tags, mutation.Tags) || result.MaxSessionDurationSeconds != mutation.MaxSessionDurationSeconds {
		return iamv1.Role{}, identityaccess.ErrUnavailable
	}
	return result, nil
}

func (value *transaction) SetRoleStatus(ctx context.Context, mutation identityaccess.RoleStatusMutation) (iamv1.Role, error) {
	if iamv1.ValidateID("actorSessionId", string(mutation.ActorSessionID)) != nil {
		return iamv1.Role{}, identityaccess.ErrInvalidArgument
	}
	event, err := marshalManagementEvent(mutation.AuditEvent)
	if err != nil {
		return iamv1.Role{}, err
	}
	defer clear(event)
	var encoded []byte
	err = value.tx.QueryRow(ctx, "SELECT iam.set_role_status($1,$2,$3,$4,$5,$6,$7::jsonb,$8)", mutation.AccountID,
		mutation.ActorPrincipalID, mutation.DecisionID, mutation.RoleID, mutation.ResourceVersion, mutation.Status, event, mutation.ActorSessionID).Scan(&encoded)
	if err != nil {
		return iamv1.Role{}, mapAuthorizationDatabaseError("set IAM role status", err)
	}
	result, err := decodeRole(encoded, mutation.AccountID, mutation.RoleID, mutation.ResourceVersion+1)
	if err != nil || result.Status != mutation.Status {
		return iamv1.Role{}, identityaccess.ErrUnavailable
	}
	return result, nil
}

func (value *transaction) SetRoleTrustPolicy(ctx context.Context, mutation identityaccess.RoleTrustMutation) (iamv1.Role, error) {
	if iamv1.ValidateID("actorSessionId", string(mutation.ActorSessionID)) != nil || mutation.TrustVersion.AccountID != mutation.AccountID || mutation.TrustVersion.RoleID != mutation.RoleID {
		return iamv1.Role{}, identityaccess.ErrInvalidArgument
	}
	trust, err := encodeRoleTrust(mutation.TrustVersion)
	if err != nil {
		return iamv1.Role{}, err
	}
	event, err := marshalManagementEvent(mutation.AuditEvent)
	if err != nil {
		return iamv1.Role{}, err
	}
	defer clear(event)
	var encoded []byte
	err = value.tx.QueryRow(ctx, "SELECT iam.set_role_trust_policy($1,$2,$3,$4,$5,$6,$7::jsonb,$8::jsonb,$9)", mutation.AccountID,
		mutation.ActorPrincipalID, mutation.DecisionID, mutation.RoleID, mutation.TrustVersion.ID, mutation.ResourceVersion, trust, event, mutation.ActorSessionID).Scan(&encoded)
	if err != nil {
		return iamv1.Role{}, mapAuthorizationDatabaseError("set IAM role trust", err)
	}
	result, err := decodeRole(encoded, mutation.AccountID, mutation.RoleID, mutation.ResourceVersion+1)
	if err != nil || result.CurrentTrustVersionID != mutation.TrustVersion.ID {
		return iamv1.Role{}, identityaccess.ErrUnavailable
	}
	return result, nil
}

func (value *transaction) DeleteRole(ctx context.Context, mutation identityaccess.RoleMutation) (iamv1.RoleDeletion, error) {
	if iamv1.ValidateID("actorSessionId", string(mutation.ActorSessionID)) != nil {
		return iamv1.RoleDeletion{}, identityaccess.ErrInvalidArgument
	}
	event, err := marshalManagementEvent(mutation.AuditEvent)
	if err != nil {
		return iamv1.RoleDeletion{}, err
	}
	defer clear(event)
	var encoded []byte
	err = value.tx.QueryRow(ctx, "SELECT iam.delete_role($1,$2,$3,$4,$5,$6::jsonb,$7)", mutation.AccountID,
		mutation.ActorPrincipalID, mutation.DecisionID, mutation.RoleID, mutation.ResourceVersion, event, mutation.ActorSessionID).Scan(&encoded)
	if err != nil {
		return iamv1.RoleDeletion{}, mapAuthorizationDatabaseError("delete IAM role", err)
	}
	var result iamv1.RoleDeletion
	if json.Unmarshal(encoded, &result) != nil {
		return iamv1.RoleDeletion{}, identityaccess.ErrUnavailable
	}
	result.DeletedAt = result.DeletedAt.UTC()
	if iamv1.ValidateRoleDeletion(result) != nil || result.ID != mutation.RoleID || result.AccountID != mutation.AccountID || result.ResourceVersion != mutation.ResourceVersion+1 {
		return iamv1.RoleDeletion{}, identityaccess.ErrUnavailable
	}
	return result, nil
}

func (value *transaction) ListRoleTrustVersions(ctx context.Context, read identityaccess.RoleRead) (iamv1.RoleTrustVersionList, error) {
	var encoded []byte
	if err := value.tx.QueryRow(ctx, "SELECT iam.list_role_trust_versions($1,$2,$3,$4,$5)", read.AccountID, read.ActorPrincipalID, read.DecisionID, read.RoleID, read.After).Scan(&encoded); err != nil {
		return iamv1.RoleTrustVersionList{}, mapAuthorizationDatabaseError("list IAM role trust", err)
	}
	result := iamv1.RoleTrustVersionList{APIVersion: iamv1.APIVersion, Kind: "RoleTrustVersionList", AccountID: read.AccountID, RoleID: read.RoleID}
	if int64(len(encoded)) > iamv1.MaxRoleListBytes || json.Unmarshal(encoded, &result.Items) != nil || result.Items == nil || len(result.Items) > 101 {
		return iamv1.RoleTrustVersionList{}, identityaccess.ErrUnavailable
	}
	previous := read.After
	for index := range result.Items {
		item := &result.Items[index]
		item.CreatedAt = item.CreatedAt.UTC()
		if iamv1.ValidateRoleTrustVersion(*item) != nil || item.AccountID != read.AccountID || item.RoleID != read.RoleID || string(item.ID) <= previous {
			return iamv1.RoleTrustVersionList{}, identityaccess.ErrUnavailable
		}
		previous = string(item.ID)
	}
	if len(result.Items) > iamv1.DirectoryPageSize {
		result.Items = result.Items[:iamv1.DirectoryPageSize]
		result.NextAfter = string(result.Items[iamv1.DirectoryPageSize-1].ID)
	}
	return result, nil
}

func (value *transaction) ReadRoleTrustVersion(ctx context.Context, read identityaccess.RoleRead, id iamv1.RoleTrustVersionID) (iamv1.RoleTrustVersion, error) {
	var encoded []byte
	if err := value.tx.QueryRow(ctx, "SELECT iam.read_role_trust_version($1,$2,$3,$4,$5)", read.AccountID, read.ActorPrincipalID, read.DecisionID, read.RoleID, id).Scan(&encoded); err != nil {
		return iamv1.RoleTrustVersion{}, mapAuthorizationDatabaseError("read IAM role trust", err)
	}
	var result iamv1.RoleTrustVersion
	if json.Unmarshal(encoded, &result) != nil {
		return iamv1.RoleTrustVersion{}, identityaccess.ErrUnavailable
	}
	result.CreatedAt = result.CreatedAt.UTC()
	if iamv1.ValidateRoleTrustVersion(result) != nil || result.ID != id || result.AccountID != read.AccountID || result.RoleID != read.RoleID {
		return iamv1.RoleTrustVersion{}, identityaccess.ErrUnavailable
	}
	return result, nil
}
