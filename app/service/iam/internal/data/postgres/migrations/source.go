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
)

func Source() postgresmigration.Source {
	return postgresmigration.Source{
		Context: "iam", BootstrapSQL: bootstrapSQL,
		UpSQL:         authorityUpSQL + "\n" + tenantAccountsUpSQL,
		VerifySQL:     authorityVerifySQL + "\n" + tenantAccountsVerifySQL,
		ExecutionRole: "matrix_iam_migrator",
	}
}
