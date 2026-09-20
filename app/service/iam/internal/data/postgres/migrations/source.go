package migrations

import (
	_ "embed"
	"encoding/json"
	"errors"
	"strings"

	iamv1 "github.com/xiak/matrix/api/iam/v1"
	"github.com/xiak/matrix/app/service/iam/internal/authority"
	"github.com/xiak/matrix/app/service/internal/postgresmigration"
)

var (
	//go:embed 000001_authority/bootstrap.sql
	bootstrapSQL string
	//go:embed 000001_authority/up.sql
	authorityUpSQL string
	//go:embed 000001_authority/verify.sql
	authorityVerifySQL string
	//go:embed 000003_tenant_accounts/up.sql
	tenantAccountsUpSQL string
	//go:embed 000003_tenant_accounts/verify.sql
	tenantAccountsVerifySQL string
	//go:embed 000004_local_credential_recovery/up.sql
	localRecoveryUpSQL string
	//go:embed 000004_local_credential_recovery/verify.sql
	localRecoveryVerifySQL string
	//go:embed 000006_policy_authority/up.sql
	policyUpSQL string
	//go:embed 000006_policy_authority/verify.sql
	policyVerifySQL string
	//go:embed 000009_groups/up.sql
	groupsUpSQL string
	//go:embed 000009_groups/verify.sql
	groupsVerifySQL string
	//go:embed 000010_roles/up.sql
	rolesUpSQL string
	//go:embed 000010_roles/verify.sql
	rolesVerifySQL string
	//go:embed 000011_access_keys/up.sql
	accessKeysUpSQL string
	//go:embed 000011_access_keys/verify.sql
	accessKeysVerifySQL string
	//go:embed 000012_totp/up.sql
	totpUpSQL string
	//go:embed 000012_totp/verify.sql
	totpVerifySQL string
	//go:embed 000013_security_mail/up.sql
	securityMailUpSQL string
	//go:embed 000013_security_mail/verify.sql
	securityMailVerifySQL string
)

func Source() postgresmigration.Source {
	policySQL, err := systemPolicySQL()
	if err != nil {
		// A corrupt code-owned policy must stop bootstrap/apply, never omit a seed.
		return postgresmigration.Source{Context: "iam"}
	}
	profileSeeds, err := authorizationProfileSeeds()
	const profilePlaceholder = "__AUTHORIZATION_PROFILE_SEEDS__"
	if err != nil || strings.Count(authorityUpSQL, profilePlaceholder) != 1 || strings.Count(authorityVerifySQL, profilePlaceholder) != 1 {
		return postgresmigration.Source{Context: "iam"}
	}
	profileLiteral := "'" + strings.ReplaceAll(profileSeeds, "'", "''") + "'::jsonb"
	authoritySQL := strings.Replace(authorityUpSQL, profilePlaceholder, profileLiteral, 1)
	verification := strings.Replace(authorityVerifySQL, profilePlaceholder, profileLiteral, 1) + "\n" + tenantAccountsVerifySQL + "\n" + localRecoveryVerifySQL + "\n" + policyVerifySQL + "\n" + groupsVerifySQL + "\n" + rolesVerifySQL + "\n" + accessKeysVerifySQL + "\n" + totpVerifySQL + "\n" + securityMailVerifySQL
	return postgresmigration.Source{
		Context: "iam", BootstrapSQL: bootstrapSQL,
		// IAM owns one commit boundary across schema, retained-state changes and
		// its final invariant verification. A late failure exposes none of them.
		UpSQL:         "BEGIN;\n" + policyCutoverPreflight + "\n" + authoritySQL + "\n" + tenantAccountsUpSQL + "\n" + localRecoveryUpSQL + "\n" + policySQL + "\n" + groupsUpSQL + "\n" + rolesUpSQL + "\n" + accessKeysUpSQL + "\n" + totpUpSQL + "\n" + securityMailUpSQL + "\n" + verification + "\nCOMMIT;",
		VerifySQL:     verification,
		ExecutionRole: "matrix_iam_migrator",
	}
}

// Archive insertion and current selection are distinct release decisions.
// Required historical declarations are archived without becoming current.
// Never infer heads from archive order or reinterpret a stored compilation.
func authorizationProfileSeeds() (string, error) {
	type registration struct {
		iamv1.AuthorizationProfileReference
		CanonicalDocument string `json:"canonicalDocument"`
	}
	seeds := struct {
		Archive []registration                        `json:"archive"`
		Heads   []iamv1.AuthorizationProfileReference `json:"heads"`
	}{}
	profiles := iamv1.AllAuthorizationProfiles()
	if len(profiles) == 0 || len(profiles) > iamv1.MaxPolicyCompilationProfiles {
		return "", errors.New("invalid IAM profile registration set")
	}
	for _, profile := range profiles {
		canonical, digest, err := iamv1.CanonicalizeAuthorizationProfile(profile)
		if err != nil {
			return "", err
		}
		reference := iamv1.AuthorizationProfileReference{Product: profile.Product, Revision: profile.Revision, ContentDigest: digest}
		seeds.Archive = append(seeds.Archive, registration{reference, canonical})
		seeds.Heads = append(seeds.Heads, reference)
	}
	for _, profile := range iamv1.HistoricalAuthorizationProfiles() {
		canonical, digest, err := iamv1.CanonicalizeAuthorizationProfile(profile)
		if err != nil {
			return "", err
		}
		seeds.Archive = append(seeds.Archive, registration{
			iamv1.AuthorizationProfileReference{Product: profile.Product, Revision: profile.Revision, ContentDigest: digest}, canonical})
	}
	encoded, err := json.Marshal(seeds)
	return string(encoded), err
}

const policyCutoverPreflight = `SET LOCAL ROLE matrix_iam_owner;
DO $policy_preflight$
DECLARE target record; table_name text;
BEGIN
    IF to_regclass('iam.role_bindings') IS NOT NULL THEN
        IF to_regclass('iam.policy_attachments') IS NOT NULL THEN
            RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='IAM has conflicting old and new permission authorities';
        END IF;
        LOCK TABLE iam.role_bindings IN ACCESS EXCLUSIVE MODE;
    END IF;
    IF to_regclass('iam.policy_versions') IS NOT NULL AND NOT EXISTS(
        SELECT 1 FROM pg_catalog.pg_attribute WHERE attrelid=to_regclass('iam.policy_versions')
          AND attname='contract_version' AND NOT attisdropped) THEN
        -- This qualification precedes every legacy marker and new seed. Do not
        -- transform existing Root Deny/conditional attachments into a lockout.
        LOCK TABLE iam.accounts,iam.principals,iam.account_roots,iam.policies,iam.policy_versions,iam.policy_attachments IN ACCESS EXCLUSIVE MODE;
        FOREACH table_name IN ARRAY ARRAY['accounts','principals','account_roots','policies','policy_versions','policy_attachments'] LOOP
            EXECUTE format('ALTER TABLE iam.%I NO FORCE ROW LEVEL SECURITY',table_name);
        END LOOP;
        IF to_regclass('iam.group_memberships') IS NOT NULL THEN
            LOCK TABLE iam.groups,iam.group_memberships IN ACCESS EXCLUSIVE MODE;
            ALTER TABLE iam.groups NO FORCE ROW LEVEL SECURITY;
            ALTER TABLE iam.group_memberships NO FORCE ROW LEVEL SECURITY;
        END IF;
        IF EXISTS(SELECT 1 FROM iam.bootstrap_receipts receipt WHERE receipt.singleton AND NOT EXISTS(
            SELECT 1 FROM iam.account_roots root WHERE root.account_id=receipt.organization_id
              AND root.principal_id=receipt.administrator_principal_id)) THEN
            RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='IAM policy cutover bootstrap Root differs';
        END IF;
        FOR target IN SELECT account.id,root.principal_id FROM iam.accounts account
            LEFT JOIN iam.account_roots root ON root.account_id=account.id LOOP
            IF target.principal_id IS NULL OR NOT EXISTS(SELECT 1 FROM iam.principals p
                WHERE p.tenant_id=target.id AND p.id=target.principal_id AND p.principal_type='USER'
                  AND p.status='ACTIVE' AND p.deleted_at IS NULL) OR NOT EXISTS(
                SELECT 1 FROM iam.policy_attachments attachment JOIN iam.policies policy ON policy.id=attachment.policy_id
                  JOIN iam.policy_versions version ON version.policy_id=policy.id AND version.id=policy.default_version_id
                WHERE attachment.tenant_id=target.id AND attachment.target_kind='USER' AND attachment.target_id=target.principal_id
                  AND attachment.revoked_at IS NULL AND policy.id='system.account-administrator' AND policy.management='SYSTEM'
                  AND policy.status='ACTIVE' AND policy.authority_scope='TENANT' AND version.retired_at IS NULL
                  AND version.id='version-2202a829e32905bb3d522996f01b4b5141430a25d0733fa1c75ad620deb24273'
                  AND version.content_digest='sha256:2202a829e32905bb3d522996f01b4b5141430a25d0733fa1c75ad620deb24273') THEN
                RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='IAM policy cutover Root management is unsupported';
            END IF;
            IF EXISTS(SELECT 1 FROM iam.policy_attachments attachment JOIN iam.policies policy ON policy.id=attachment.policy_id
                WHERE attachment.tenant_id=target.id AND attachment.target_kind='USER' AND attachment.target_id=target.principal_id
                  AND attachment.revoked_at IS NULL AND policy.management='CUSTOMER') THEN
                RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='IAM policy cutover requires prior Root attachment removal';
            END IF;
            IF to_regclass('iam.group_memberships') IS NOT NULL THEN
              IF EXISTS(
                SELECT 1 FROM iam.group_memberships membership JOIN iam.groups group_subject
                  ON group_subject.tenant_id=membership.tenant_id AND group_subject.id=membership.group_id AND group_subject.deleted_at IS NULL
                JOIN iam.policy_attachments attachment ON attachment.tenant_id=membership.tenant_id
                  AND attachment.target_kind='GROUP' AND attachment.target_id=membership.group_id AND attachment.revoked_at IS NULL
                JOIN iam.policies policy ON policy.id=attachment.policy_id AND policy.management='CUSTOMER'
                WHERE membership.tenant_id=target.id AND membership.user_id=target.principal_id AND membership.removed_at IS NULL) THEN
                RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='IAM policy cutover requires prior Root group attachment removal';
              END IF;
            END IF;
        END LOOP;
        FOREACH table_name IN ARRAY ARRAY['accounts','principals','account_roots','policies','policy_versions','policy_attachments'] LOOP
            EXECUTE format('ALTER TABLE iam.%I FORCE ROW LEVEL SECURITY',table_name);
        END LOOP;
        IF to_regclass('iam.group_memberships') IS NOT NULL THEN
            ALTER TABLE iam.groups FORCE ROW LEVEL SECURITY;
            ALTER TABLE iam.group_memberships FORCE ROW LEVEL SECURITY;
        END IF;
    END IF;
END $policy_preflight$;`

func systemPolicySQL() (string, error) {
	type seed struct {
		LegacyRole        string                   `json:"legacyRole"`
		PolicyID          iamv1.PolicyID           `json:"policyId"`
		DisplayName       string                   `json:"displayName"`
		VersionID         iamv1.PolicyVersionID    `json:"versionId"`
		Scope             iamv1.AuthorityScope     `json:"scope"`
		Document          json.RawMessage          `json:"document"`
		CanonicalDocument string                   `json:"canonicalDocument"`
		ContentDigest     string                   `json:"contentDigest"`
		Compilation       *iamv1.PolicyCompilation `json:"compilation"`
	}
	seeds := []seed{
		{LegacyRole: "ORGANIZATION_ADMIN", PolicyID: iamv1.SystemPolicyAccountAdministrator, DisplayName: "AccountAdministrator"},
		{LegacyRole: "PLATFORM_OPERATOR", PolicyID: iamv1.SystemPolicyPlatformOperator, DisplayName: "PlatformOperator"},
		{LegacyRole: "PAAS_DEVELOPER", PolicyID: iamv1.SystemPolicyPaaSDeveloper, DisplayName: "PaaSDeveloper"},
		{LegacyRole: "PAAS_VIEWER", PolicyID: iamv1.SystemPolicyPaaSViewer, DisplayName: "PaaSViewer"},
		{LegacyRole: "AUDIT_READER", PolicyID: iamv1.SystemPolicyAuditReader, DisplayName: "AuditReader"},
		{LegacyRole: "INSTALLATION_VERIFIER", PolicyID: iamv1.SystemPolicyInstallationVerifier, DisplayName: "InstallationVerifier"},
	}
	for index := range seeds {
		version, err := authority.SystemPolicyVersion(seeds[index].PolicyID)
		if err != nil {
			return "", err
		}
		canonical, digest, err := iamv1.CanonicalizePolicyCompilation(version.Document, *version.Compilation, iamv1.AllAuthorizationProfiles())
		if err != nil {
			return "", err
		}
		seeds[index].VersionID, seeds[index].Scope = version.ID, version.Document.Scope
		var content struct {
			Document json.RawMessage `json:"document"`
		}
		if err := json.Unmarshal([]byte(canonical), &content); err != nil {
			return "", err
		}
		seeds[index].Document, seeds[index].CanonicalDocument, seeds[index].ContentDigest = content.Document, canonical, digest
		seeds[index].Compilation = version.Compilation
	}
	encoded, err := json.Marshal(seeds)
	if err != nil {
		return "", err
	}
	return strings.Replace(policyUpSQL, "__POLICY_SEED_DOCUMENT__", "'"+strings.ReplaceAll(string(encoded), "'", "''")+"'::jsonb", 1), nil
}
