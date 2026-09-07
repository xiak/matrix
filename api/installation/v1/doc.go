// Package installationv1 defines the read-only Matrix installation and
// installed-product discovery wire language. It contains contracts only and
// imports no service, release, topology, or persistence implementation.
package installationv1

//go:generate go run ./cmd/contractgen -output openapi.json

const (
	APIVersion = "installation.matrix.xiak.com/v1"
	MediaType  = "application/vnd.xiak.matrix.installation.v1+json"

	MaxDocumentBytes int64 = 128 * 1024
	MaxProducts            = 16
)
