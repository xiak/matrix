// Package auditv1 defines the Matrix Audit v1 HTTP wire language. It contains
// contracts only and imports no service or persistence implementation.
package auditv1

//go:generate go run ./cmd/contractgen -output openapi.json

const (
	APIVersion = "audit.matrix.xiak.com/v1"
	MediaType  = "application/vnd.xiak.matrix.audit.v1+json"

	MaxRequestBytes  int64 = 128 * 1024
	MaxPageSize            = 200
	MaxVerifyRecords       = 10_000
)
