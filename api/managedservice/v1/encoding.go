package managedservicev1

import (
	"io"

	"github.com/xiak/matrix/api/contractjson"
)

const MaxRequestBytes = 64 * 1024

// DecodeRequest applies the repository-wide strict, single-object JSON
// boundary so native provider and forged authority fields cannot be ignored.
func DecodeRequest(reader io.Reader, destination any) error {
	return contractjson.DecodeObject(reader, MaxRequestBytes, destination)
}
