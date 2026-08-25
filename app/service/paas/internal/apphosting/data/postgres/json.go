package postgres

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

func decodeDocument[T any](kind string, document []byte, target *T) error {
	if len(document) == 0 {
		return fmt.Errorf("stored %s document is empty", kind)
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("decode stored %s document: %w", kind, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return fmt.Errorf("stored %s document contains trailing JSON", kind)
		}
		return fmt.Errorf("decode stored %s document trailer: %w", kind, err)
	}
	return nil
}
