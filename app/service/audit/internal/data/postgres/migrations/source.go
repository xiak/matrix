package migrations

import (
	_ "embed"

	"github.com/xiak/matrix/app/service/internal/postgresmigration"
)

var (
	//go:embed 000001_authority/bootstrap.sql
	bootstrapSQL string
	//go:embed 000001_authority/up.sql
	upSQL string
	//go:embed 000001_authority/verify.sql
	verifySQL string
)

func Source() postgresmigration.Source {
	return postgresmigration.Source{
		Context: "audit", BootstrapSQL: bootstrapSQL, UpSQL: upSQL,
		VerifySQL: verifySQL, ExecutionRole: "matrix_audit_migrator",
	}
}
