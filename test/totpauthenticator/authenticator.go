// Package totpauthenticator is a test-only software authenticator used by
// signed lifecycle gates. It deliberately lives outside every product bounded
// context and never receives a Matrix identity, Session or permission.
package totpauthenticator

import (
	"errors"
	"time"

	"github.com/pquerna/otp/hotp"
)

// Code returns the six-digit code a standards-based authenticator displays
// for the supplied provisioning seed and wall-clock instant.
func Code(seed []byte, instant time.Time) ([]byte, int64, error) {
	if len(seed) == 0 || instant.IsZero() || instant.Unix() < 0 {
		return nil, 0, errors.New("test authenticator input is invalid")
	}
	step := instant.Unix() / 30
	code, err := hotp.GenerateCode(string(seed), uint64(step))
	if err != nil || len(code) != 6 {
		return nil, 0, errors.New("test authenticator code generation failed")
	}
	return []byte(code), step, nil
}
