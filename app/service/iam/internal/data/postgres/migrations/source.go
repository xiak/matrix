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
)

func Source() postgresmigration.Source {
	return postgresmigration.Source{
		Context: "iam", BootstrapSQL: bootstrapSQL,
		UpSQL:         authorityUpSQL,
		VerifySQL:     authorityVerifySQL,
		ExecutionRole: "matrix_iam_migrator",
	}
}
