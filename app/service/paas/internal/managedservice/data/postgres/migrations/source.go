package migrations

import (
	_ "embed"
	"fmt"
	"strings"

	"github.com/xiak/matrix/app/service/internal/postgresmigration"
	"github.com/xiak/matrix/app/service/paas/internal/managedservice/domain"
)

var (
	//go:embed 000001_service_authority/up.sql
	upSQL string
	//go:embed 000001_service_authority/verify.sql
	verifySQL string
)

func Source() postgresmigration.Source {
	// Only the compiled, validated domain catalog supplies these expressions.
	// Product onboarding must not maintain a second list inside SQL.
	var quotas, engines []string
	for _, offering := range domain.DefaultCatalog().List() {
		shapes := make([]string, 0, len(offering.QuotaShapes))
		for _, shape := range offering.QuotaShapes {
			shapes = append(shapes, catalogLiteral(shape.ID))
		}
		quotas = append(quotas, fmt.Sprintf("(offering_id = %s AND quota_shape_id IN (%s))",
			catalogLiteral(offering.ID), strings.Join(shapes, ", ")))
		engines = append(engines, fmt.Sprintf("(offering_id = %s AND engine_version = %s)",
			catalogLiteral(offering.ID), catalogLiteral(offering.EngineVersion)))
	}
	rendered := strings.NewReplacer(
		"{{managedservice.quota_catalog}}", strings.Join(quotas, " OR "),
		"{{managedservice.engine_catalog}}", strings.Join(engines, " OR "),
	).Replace(upSQL)
	return postgresmigration.Source{Context: "managedservice", UpSQL: rendered, VerifySQL: verifySQL}
}

// Catalog IDs and engine versions are validated identifiers, never SQL input.
func catalogLiteral(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "''") + "'"
}
