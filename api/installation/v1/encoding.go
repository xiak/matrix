package installationv1

import (
	"io"

	"github.com/xiak/matrix/api/contractjson"
)

func Decode(reader io.Reader, destination any) error {
	return contractjson.DecodeObject(reader, MaxDocumentBytes, destination)
}
