package totpauthenticator

import (
	"bytes"
	"testing"
	"time"
)

func TestCodeUsesTheProvisionedRFC6238TimeStep(t *testing.T) {
	seed := []byte("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
	code, step, err := Code(seed, time.Unix(59, 0).UTC())
	if err != nil || step != 1 || !bytes.Equal(code, []byte("287082")) {
		t.Fatalf("code=%q step=%d err=%v", code, step, err)
	}
	for _, invalid := range []struct {
		seed    []byte
		instant time.Time
	}{{nil, time.Unix(59, 0)}, {seed, time.Time{}}, {seed, time.Unix(-1, 0)}} {
		if code, step, err := Code(invalid.seed, invalid.instant); err == nil || len(code) != 0 || step != 0 {
			t.Fatal("invalid authenticator input was accepted")
		}
	}
}
