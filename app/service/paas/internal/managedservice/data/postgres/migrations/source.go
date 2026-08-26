package migrations

import (
	_ "embed"

	"github.com/xiak/matrix/app/service/internal/postgresmigration"
)

var (
	//go:embed 000001_service_authority/up.sql
	upSQL string
	//go:embed 000001_service_authority/verify.sql
	verifySQL string
)

func Source() postgresmigration.Source {
	return postgresmigration.Source{Context: "managedservice", UpSQL: upSQL, VerifySQL: verifySQL}
}
