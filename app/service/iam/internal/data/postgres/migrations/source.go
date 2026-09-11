package migrations

import (
	_ "embed"
	"encoding/json"
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
)

func Source() postgresmigration.Source {
	policySQL, err := systemPolicySQL()
	if err != nil {
		// A corrupt code-owned policy must stop bootstrap/apply, never omit a seed.
		return postgresmigration.Source{Context: "iam"}
	}
	verification := authorityVerifySQL + "\n" + tenantAccountsVerifySQL + "\n" + localRecoveryVerifySQL + "\n" + policyVerifySQL
	return postgresmigration.Source{
		Context: "iam", BootstrapSQL: bootstrapSQL,
		// IAM owns one commit boundary across schema, retained-state changes and
		// its final invariant verification. A late failure exposes none of them.
		UpSQL:         "BEGIN;\n" + policyCutoverPreflight + "\n" + authorityUpSQL + "\n" + tenantAccountsUpSQL + "\n" + localRecoveryUpSQL + "\n" + policySQL + "\n" + verification + "\nCOMMIT;",
		VerifySQL:     verification,
		ExecutionRole: "matrix_iam_migrator",
	}
}

const policyCutoverPreflight = `SET LOCAL ROLE matrix_iam_owner;
DO $policy_preflight$
BEGIN
    IF to_regclass('iam.role_bindings') IS NOT NULL THEN
        IF to_regclass('iam.policy_attachments') IS NOT NULL THEN
            RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='IAM has conflicting old and new permission authorities';
        END IF;
        LOCK TABLE iam.role_bindings IN ACCESS EXCLUSIVE MODE;
    END IF;
END $policy_preflight$;`

func systemPolicySQL() (string, error) {
	type seed struct {
		LegacyRole        string                `json:"legacyRole"`
		PolicyID          iamv1.PolicyID        `json:"policyId"`
		DisplayName       string                `json:"displayName"`
		VersionID         iamv1.PolicyVersionID `json:"versionId"`
		Scope             iamv1.AuthorityScope  `json:"scope"`
		Document          json.RawMessage       `json:"document"`
		CanonicalDocument string                `json:"canonicalDocument"`
		ContentDigest     string                `json:"contentDigest"`
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
		canonical, digest, err := iamv1.CanonicalizePolicyDocument(version.Document)
		if err != nil {
			return "", err
		}
		seeds[index].VersionID, seeds[index].Scope = version.ID, version.Document.Scope
		seeds[index].Document, seeds[index].CanonicalDocument, seeds[index].ContentDigest = json.RawMessage(canonical), canonical, digest
	}
	encoded, err := json.Marshal(seeds)
	if err != nil {
		return "", err
	}
	return strings.Replace(policyUpSQL, "__POLICY_SEED_DOCUMENT__", "'"+strings.ReplaceAll(string(encoded), "'", "''")+"'::jsonb", 1), nil
}
