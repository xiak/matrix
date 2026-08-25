// Package iamv1 defines the Matrix IAM v1 HTTP wire language. It contains
// contracts only and imports no service or persistence implementation.
package iamv1

//go:generate go run ./cmd/contractgen -output openapi.json

const (
	APIVersion = "iam.matrix.xiak.com/v1"
	MediaType  = "application/vnd.xiak.matrix.iam.v1+json"

	MaxRequestBytes   int64 = 64 * 1024
	MaxBootstrapBytes int64 = 128 * 1024
)
