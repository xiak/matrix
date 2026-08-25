// Package paasv1 defines the vendor-neutral Matrix Application PaaS v1 wire
// language. It contains contracts only and imports no service or adapter
// implementation.
package paasv1

//go:generate go run ./cmd/contractgen -output openapi.json

const (
	APIVersion = "paas.matrix.xiak.com/v1"
	MediaType  = "application/vnd.xiak.matrix.paas.v1+json"
)
