// Package managedservicev1 defines the public Matrix managed-service v1 wire
// language. It contains contracts only and imports no service or adapter
// implementation.
package managedservicev1

//go:generate go run ./cmd/contractgen -output openapi.json

const (
	APIVersion = "managedservice.matrix.xiak.com/v1"
	MediaType  = "application/vnd.xiak.matrix.managedservice.v1+json"
)
