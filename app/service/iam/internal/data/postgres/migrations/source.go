package migrations

import (
	_ "embed"

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
)

func Source() postgresmigration.Source {
	verification := authorityVerifySQL + "\n" + tenantAccountsVerifySQL + "\n" + localRecoveryVerifySQL
	return postgresmigration.Source{
		Context: "iam", BootstrapSQL: bootstrapSQL,
		// IAM owns one commit boundary across schema, retained-state changes and
		// its final invariant verification. A late failure exposes none of them.
		UpSQL:         "BEGIN;\n" + authorityUpSQL + "\n" + tenantAccountsUpSQL + "\n" + localRecoveryUpSQL + "\n" + verification + "\nCOMMIT;",
		VerifySQL:     verification,
		ExecutionRole: "matrix_iam_migrator",
	}
}
