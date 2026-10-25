package migrations

import (
	_ "embed"

	"github.com/xiak/matrix/app/service/internal/postgresmigration"
)

var (
	//go:embed 000001_configuration_core/bootstrap.sql
	bootstrapSQL string
	//go:embed 000001_configuration_core/up.sql
	upSQL string
	//go:embed 000001_configuration_core/verify.sql
	verifySQL string
)

func Source() postgresmigration.Source {
	return postgresmigration.Source{
		Context: "devops", BootstrapSQL: bootstrapSQL, UpSQL: upSQL,
		VerifySQL: verifySQL, ExecutionRole: "matrix_devops_migrator",
	}
}
