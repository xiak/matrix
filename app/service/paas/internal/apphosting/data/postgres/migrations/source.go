package migrations

import (
	_ "embed"

	"github.com/xiak/matrix/app/service/internal/postgresmigration"
)

var (
	//go:embed 000001_placement_core/up.sql
	upSQL string
	//go:embed 000001_placement_core/verify.sql
	verifySQL string
)

func Source() postgresmigration.Source {
	return postgresmigration.Source{
		Context: "paas", UpSQL: upSQL, VerifySQL: verifySQL,
	}
}
