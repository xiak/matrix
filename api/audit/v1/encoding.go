package auditv1

import (
	"io"

	"github.com/xiak/matrix/api/contractjson"
)

func DecodeRequest(reader io.Reader, destination any) error {
	return contractjson.DecodeObject(reader, MaxRequestBytes, destination)
}
