package migrations

import (
	"cmp"
	_ "embed"
	"encoding/json"
	"errors"
	"slices"
	"strings"

	iamv1 "github.com/xiak/matrix/api/iam/v1"
	"github.com/xiak/matrix/app/service/iam/internal/authority"
	"github.com/xiak/matrix/app/service/internal/postgresmigration"
)

// Profile seeds are embedded twice in IAM's atomic migration/verification
// source. Keep explicit headroom below the shared 4 MiB SQL executor budget;
// a release with a larger catalog needs a non-embedded installation protocol.
const maxAuthorizationProfileSeedBytes = iamv1.MaxAuthorizationProfileReleaseCatalogBytes

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
	//go:embed 000014_authentication_recovery/up.sql
	authenticationRecoveryUpSQL string
	//go:embed 000014_authentication_recovery/verify.sql
	authenticationRecoveryVerifySQL string
	//go:embed 000015_authentication_recovery_inspection/up.sql
	authenticationRecoveryInspectionUpSQL string
	//go:embed 000015_authentication_recovery_inspection/verify.sql
	authenticationRecoveryInspectionVerifySQL string
	//go:embed 000016_service_roles/up.sql
	serviceRolesUpSQL string
	//go:embed 000016_service_roles/verify.sql
	serviceRolesVerifySQL string
	//go:embed 000017_security_reports/up.sql
	securityReportsUpSQL string
	//go:embed 000017_security_reports/verify.sql
	securityReportsVerifySQL string
	//go:embed 000018_access_analyzers/up.sql
	accessAnalyzersUpSQL string
	//go:embed 000018_access_analyzers/verify.sql
	accessAnalyzersVerifySQL string
	//go:embed 000019_access_analysis/up.sql
	accessAnalysisUpSQL string
	//go:embed 000019_access_analysis/verify.sql
	accessAnalysisVerifySQL string
	//go:embed 000020_access_disposition/up.sql
	accessDispositionUpSQL string
	//go:embed 000020_access_disposition/verify.sql
	accessDispositionVerifySQL string
	//go:embed 000021_policy_attachment_changes/up.sql
	policyAttachmentChangesUpSQL string
	//go:embed 000021_policy_attachment_changes/verify.sql
	policyAttachmentChangesVerifySQL string
	//go:embed 000022_access_key_list_authorization/up.sql
	accessKeyListAuthorizationUpSQL string
	//go:embed 000022_access_key_list_authorization/verify.sql
	accessKeyListAuthorizationVerifySQL string
	//go:embed 000023_access_key_credential_state/up.sql
	accessKeyCredentialStateUpSQL string
	//go:embed 000023_access_key_credential_state/verify.sql
	accessKeyCredentialStateVerifySQL string
)

func Source() postgresmigration.Source {
	return SourceWithAuthorizationProfiles(nil, nil)
}

// SourceWithAuthorizationProfiles assembles additional release-owned product
// declarations into IAM's immutable registry seed. Trust in these declarations
// must be established by the signed release/installation boundary before this
// function is called; this function validates content and registry evolution,
// but it is not a signature verifier or a tenant-facing registration API.
func SourceWithAuthorizationProfiles(additionalCurrent, additionalHistorical []iamv1.AuthorizationProfile) postgresmigration.Source {
	currentProfiles, historicalProfiles, err := authorizationProfilesForSource(additionalCurrent, additionalHistorical)
	if err != nil {
		return postgresmigration.Source{Context: "iam"}
	}
	policySQL, err := systemPolicySQL()
	if err != nil {
		// A corrupt code-owned policy must stop bootstrap/apply, never omit a seed.
		return postgresmigration.Source{Context: "iam"}
	}
	profileSeeds, err := authorizationProfileSeeds(currentProfiles, historicalProfiles)
	const profilePlaceholder = "__AUTHORIZATION_PROFILE_SEEDS__"
	if err != nil || strings.Count(authorityUpSQL, profilePlaceholder) != 1 || strings.Count(authorityVerifySQL, profilePlaceholder) != 1 {
		return postgresmigration.Source{Context: "iam"}
	}
	profileLiteral := "'" + strings.ReplaceAll(profileSeeds, "'", "''") + "'::jsonb"
	authoritySQL := strings.Replace(authorityUpSQL, profilePlaceholder, profileLiteral, 1)
	templateSeeds, err := serviceRoleTemplateSeeds()
	const templatePlaceholder = "__SERVICE_ROLE_TEMPLATE_SEEDS__"
	if err != nil || strings.Count(serviceRolesUpSQL, templatePlaceholder) != 1 || strings.Count(serviceRolesVerifySQL, templatePlaceholder) != 1 {
		return postgresmigration.Source{Context: "iam"}
	}
	templateLiteral := "'" + strings.ReplaceAll(templateSeeds, "'", "''") + "'::jsonb"
	serviceRolesSQL := strings.Replace(serviceRolesUpSQL, templatePlaceholder, templateLiteral, 1)
	serviceRolesVerification := strings.Replace(serviceRolesVerifySQL, templatePlaceholder, templateLiteral, 1)
	verification := strings.Replace(authorityVerifySQL, profilePlaceholder, profileLiteral, 1) + "\n" + tenantAccountsVerifySQL + "\n" + localRecoveryVerifySQL + "\n" + policyVerifySQL + "\n" + groupsVerifySQL + "\n" + rolesVerifySQL + "\n" + accessKeysVerifySQL + "\n" + totpVerifySQL + "\n" + securityMailVerifySQL + "\n" + authenticationRecoveryVerifySQL + "\n" + authenticationRecoveryInspectionVerifySQL + "\n" + serviceRolesVerification + "\n" + securityReportsVerifySQL + "\n" + accessAnalyzersVerifySQL + "\n" + accessAnalysisVerifySQL + "\n" + accessDispositionVerifySQL + "\n" + policyAttachmentChangesVerifySQL + "\n" + accessKeyListAuthorizationVerifySQL + "\n" + accessKeyCredentialStateVerifySQL
	return postgresmigration.Source{
		Context: "iam", BootstrapSQL: bootstrapSQL,
		// IAM owns one commit boundary across schema, retained-state changes and
		// its final invariant verification. A late failure exposes none of them.
		UpSQL:         "BEGIN;\n" + policyCutoverPreflight + "\n" + authoritySQL + "\n" + tenantAccountsUpSQL + "\n" + localRecoveryUpSQL + "\n" + policySQL + "\n" + groupsUpSQL + "\n" + rolesUpSQL + "\n" + accessKeysUpSQL + "\n" + totpUpSQL + "\n" + securityMailUpSQL + "\n" + authenticationRecoveryUpSQL + "\n" + authenticationRecoveryInspectionUpSQL + "\n" + serviceRolesSQL + "\n" + securityReportsUpSQL + "\n" + accessAnalyzersUpSQL + "\n" + accessAnalysisUpSQL + "\n" + accessDispositionUpSQL + "\n" + policyAttachmentChangesUpSQL + "\n" + accessKeyListAuthorizationUpSQL + "\n" + accessKeyCredentialStateUpSQL + "\n" + verification + "\nCOMMIT;",
		VerifySQL:     verification,
		ExecutionRole: "matrix_iam_migrator",
	}
}

func authorizationProfilesForSource(additionalCurrent, additionalHistorical []iamv1.AuthorizationProfile) ([]iamv1.AuthorizationProfile, []iamv1.AuthorizationProfile, error) {
	current := iamv1.AllAuthorizationProfiles()
	historical := iamv1.HistoricalAuthorizationProfiles()
	heads := make(map[iamv1.ProductID]iamv1.AuthorizationProfile, len(current)+len(additionalCurrent))
	additionalHeads := make(map[iamv1.ProductID]iamv1.AuthorizationProfile, len(additionalCurrent))
	for _, profile := range current {
		heads[profile.Product] = profile
	}
	for _, profile := range additionalCurrent {
		if !supportedAdditionalAuthorizationProfile(profile) {
			return nil, nil, errors.New("invalid additional current authorization profile")
		}
		if _, duplicate := heads[profile.Product]; duplicate {
			return nil, nil, errors.New("duplicate current authorization profile product")
		}
		heads[profile.Product] = iamv1.CloneAuthorizationProfile(profile)
		additionalHeads[profile.Product] = iamv1.CloneAuthorizationProfile(profile)
		current = append(current, iamv1.CloneAuthorizationProfile(profile))
	}
	if len(current) == 0 || len(current) > iamv1.MaxAuthorizationProfileRegistryItems {
		return nil, nil, errors.New("invalid current authorization profile registry size")
	}
	type archiveKey struct {
		product  iamv1.ProductID
		revision uint64
	}
	archive := make(map[archiveKey]struct{}, len(current)+len(historical)+len(additionalHistorical))
	for _, profile := range current {
		archive[archiveKey{profile.Product, profile.Revision}] = struct{}{}
	}
	for _, profile := range historical {
		archive[archiveKey{profile.Product, profile.Revision}] = struct{}{}
	}
	for _, profile := range additionalHistorical {
		head, known := additionalHeads[profile.Product]
		key := archiveKey{profile.Product, profile.Revision}
		if !known || !supportedAdditionalAuthorizationProfile(profile) || profile.Revision >= head.Revision ||
			profile.CallingService != head.CallingService {
			return nil, nil, errors.New("invalid additional historical authorization profile")
		}
		if _, duplicate := archive[key]; duplicate {
			return nil, nil, errors.New("duplicate historical authorization profile revision")
		}
		archive[key] = struct{}{}
		historical = append(historical, iamv1.CloneAuthorizationProfile(profile))
	}
	if len(historical)+len(current) > iamv1.MaxAuthorizationProfileArchiveItems {
		return nil, nil, errors.New("invalid authorization profile archive size")
	}
	slices.SortFunc(current, func(left, right iamv1.AuthorizationProfile) int { return cmp.Compare(left.Product, right.Product) })
	slices.SortFunc(historical, func(left, right iamv1.AuthorizationProfile) int {
		if order := cmp.Compare(left.Product, right.Product); order != 0 {
			return order
		}
		return cmp.Compare(left.Revision, right.Revision)
	})
	return current, historical, nil
}

// The first external-product slice is deliberately tenant-only. Installation
// and probe scopes need their own release/admission and response-schema slice;
// accepting them here would turn a syntactic Profile into unsupported platform
// authority. Calling services must already exist in the sealed bootstrap.
func supportedAdditionalAuthorizationProfile(profile iamv1.AuthorizationProfile) bool {
	return iamv1.CheckTenantProductAuthorizationProfile(profile) == nil
}

func serviceRoleTemplateSeeds() (string, error) {
	type seed struct {
		ID            iamv1.ServiceRoleTemplateID     `json:"id"`
		Version       uint64                          `json:"version"`
		CanonicalSpec string                          `json:"canonicalSpec"`
		ContentDigest string                          `json:"contentDigest"`
		Status        iamv1.ServiceRoleTemplateStatus `json:"status"`
	}
	templates, err := authority.ServiceRoleTemplates()
	if err != nil || len(templates) == 0 || len(templates) > iamv1.DirectoryPageSize {
		return "", errors.New("invalid service role template registration set")
	}
	slices.SortFunc(templates, func(left, right iamv1.ServiceRoleTemplate) int {
		if order := cmp.Compare(left.ID, right.ID); order != 0 {
			return order
		}
		return cmp.Compare(left.Version, right.Version)
	})
	seeds := make([]seed, 0, len(templates))
	for _, template := range templates {
		canonical, digest, err := iamv1.CanonicalizeServiceRoleTemplateSpec(template.Spec)
		if err != nil || digest != template.ContentDigest {
			return "", errors.New("invalid service role template registration")
		}
		seeds = append(seeds, seed{template.ID, template.Version, canonical, digest, template.Status})
	}
	encoded, err := json.Marshal(seeds)
	return string(encoded), err
}

// Archive insertion and current selection are distinct release decisions.
// Required historical declarations are archived without becoming current.
// Never infer heads from archive order or reinterpret a stored compilation.
func authorizationProfileSeeds(profiles, historical []iamv1.AuthorizationProfile) (string, error) {
	type registration struct {
		iamv1.AuthorizationProfileReference
		CanonicalDocument string `json:"canonicalDocument"`
	}
	seeds := struct {
		Archive []registration                        `json:"archive"`
		Heads   []iamv1.AuthorizationProfileReference `json:"heads"`
	}{}
	if len(profiles) == 0 || len(profiles) > iamv1.MaxAuthorizationProfileRegistryItems {
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
	for _, profile := range historical {
		canonical, digest, err := iamv1.CanonicalizeAuthorizationProfile(profile)
		if err != nil {
			return "", err
		}
		seeds.Archive = append(seeds.Archive, registration{
			iamv1.AuthorizationProfileReference{Product: profile.Product, Revision: profile.Revision, ContentDigest: digest}, canonical})
	}
	encoded, err := json.Marshal(seeds)
	if err != nil || int64(len(encoded)) > maxAuthorizationProfileSeedBytes {
		return "", errors.New("IAM profile registration seed exceeds its release budget")
	}
	return string(encoded), nil
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
		{PolicyID: iamv1.SystemPolicyManagedServiceInstallationReader, DisplayName: "ManagedServiceInstallationReader"},
		{PolicyID: iamv1.SystemPolicyServiceRoleAdministrator, DisplayName: "ServiceRoleAdministrator"},
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
