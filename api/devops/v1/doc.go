// Package devopsv1 defines the provider-neutral Matrix DevOps v1 wire
// language. It contains contracts only and imports no source-provider,
// executor, persistence, or service implementation.
package devopsv1

//go:generate go run ./cmd/contractgen -output openapi.json

const (
	APIVersion = "devops.matrix.xiak.com/v1"
	MediaType  = "application/vnd.xiak.matrix.devops.v1+json"

	MaxDocumentBytes int64 = 128 * 1024
	// MaximumContractInteger keeps versions and sequence-like values exactly
	// representable by every JSON consumer.
	MaximumContractInteger uint64 = 9_007_199_254_740_991
)
