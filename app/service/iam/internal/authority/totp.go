package authority

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"io"
	"time"

	iamv1 "github.com/xiak/matrix/api/iam/v1"
)

var ErrTOTPRejected = errors.New("TOTP verification failed")

const (
	totpSeedBytes     = 20
	totpPeriodSeconds = 30
	totpDigits        = 6
	totpMaximumUnix   = int64(253402300799)
	totpMaximumStep   = totpMaximumUnix / totpPeriodSeconds
)

func (issuer *CredentialIssuer) IssueTOTPSeed() (iamv1.Secret, error) {
	if issuer == nil || issuer.entropy == nil {
		return iamv1.Secret{}, ErrCredentialGeneration
	}
	material := make([]byte, totpSeedBytes)
	defer clear(material)
	if _, err := io.ReadFull(issuer.entropy, material); err != nil {
		return iamv1.Secret{}, ErrCredentialGeneration
	}
	secret, err := iamv1.NewSecret(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(material))
	if err != nil {
		return iamv1.Secret{}, ErrCredentialGeneration
	}
	return secret, nil
}

// VerifyTOTP checks the fixed SHA1/six-digit/30-second profile using the
// authoritative database instant and the factor's locked consumption state.
// -1 means proven never consumed, NOT missing or unknown state. Success is
// only a candidate step: the use case must consume it atomically with its
// authenticated result. This function does not persist, authorize or issue
// anything, and cannot by itself prevent concurrent/restarted replays.
func VerifyTOTP(seed, code iamv1.Secret, databaseTime time.Time, lastConsumedStep int64) (int64, error) {
	if validateAuthorityTime(databaseTime) != nil || databaseTime.Unix() < 0 || databaseTime.Unix() > totpMaximumUnix ||
		lastConsumedStep < -1 || lastConsumedStep > totpMaximumStep {
		return 0, ErrAuthorityUnavailable
	}
	material, err := totpSeedMaterial(seed)
	defer clear(material)
	if err != nil {
		return 0, err
	}
	candidate := code.CopyBytes()
	defer clear(candidate)
	if len(candidate) != totpDigits {
		return 0, ErrTOTPRejected
	}
	for _, digit := range candidate {
		if digit < '0' || digit > '9' {
			return 0, ErrTOTPRejected
		}
	}
	current := databaseTime.Unix() / totpPeriodSeconds
	matched, replay := int64(-1), false
	for step := max(int64(0), current-1); step <= min(totpMaximumStep, current+1); step++ {
		expected := totpCode(material, uint64(step))
		if subtle.ConstantTimeCompare(candidate, expected[:]) == 1 {
			matched = step
			replay = replay || step <= lastConsumedStep
		}
		clear(expected[:])
	}
	// A collision spanning an already consumed and a fresh candidate is a
	// replay, not permission to select a more convenient matching time step.
	if matched < 0 || replay {
		return 0, ErrTOTPRejected
	}
	return matched, nil
}

func totpSeedMaterial(seed iamv1.Secret) ([]byte, error) {
	encoded := seed.CopyBytes()
	defer clear(encoded)
	if len(encoded) != 32 {
		return nil, ErrAuthorityUnavailable
	}
	encoding := base32.StdEncoding.WithPadding(base32.NoPadding)
	material := make([]byte, totpSeedBytes)
	n, err := encoding.Decode(material, encoded)
	if err != nil || n != totpSeedBytes || encoding.EncodeToString(material) != string(encoded) {
		clear(material)
		return nil, ErrAuthorityUnavailable
	}
	return material, nil
}

func totpCode(material []byte, step uint64) [totpDigits]byte {
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], step)
	// HMAC-SHA1 is the fixed RFC4226 authenticator construction, not a
	// collision-resistant content digest or a selectable policy algorithm.
	mac := hmac.New(sha1.New, material)
	_, _ = mac.Write(counter[:])
	digest := mac.Sum(nil)
	defer clear(digest)
	offset := digest[len(digest)-1] & 0x0f
	number := (binary.BigEndian.Uint32(digest[offset:offset+4]) & 0x7fffffff) % 1000000
	var result [totpDigits]byte
	for index := len(result) - 1; index >= 0; index-- {
		result[index] = byte(number%10) + '0'
		number /= 10
	}
	return result
}
