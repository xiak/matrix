package nethttp

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"time"

	iamv1 "github.com/xiak/matrix/api/iam/v1"
	paasv1 "github.com/xiak/matrix/api/paas/v1"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/port"
)

var (
	errInvalidApplicationCursorKey = errors.New("PaaS application cursor key is invalid")
	errInvalidApplicationCursor    = errors.New("PaaS application cursor is invalid")
)

const (
	applicationCursorLifetime    = 15 * time.Minute
	applicationCursorHeaderBytes = 8 + 8 + sha256.Size
	applicationCursorTagBytes    = sha256.Size
	applicationCursorPrefix      = "pc1."
	applicationCursorQueryShape  = "applications:id:asc:50"
)

// applicationCursorCodec belongs to the PaaS product boundary. It shares no
// key, envelope or implementation with IAM/Audit cursors. The encrypted
// position can name a candidate that was denied, so a caller cannot recover a
// hidden Application ID from the continuation.
type applicationCursorCodec struct {
	key   [sha256.Size]byte
	ready bool
}

type applicationCursorBinding struct {
	InstallationID string
	TenantID       paasv1.TenantID
	Subject        paasv1.SubjectRef
	Profile        iamv1.AuthorizationProfileReference
	Action         iamv1.Action
	QueryShape     string
}

func newApplicationCursorCodec(key []byte) (applicationCursorCodec, error) {
	if len(key) != sha256.Size {
		return applicationCursorCodec{}, errInvalidApplicationCursorKey
	}
	codec := applicationCursorCodec{ready: true}
	copy(codec.key[:], key)
	return codec, nil
}

func (codec applicationCursorCodec) encode(
	installationID string,
	subject port.AuthorizationSubjectContext,
	after paasv1.ResourceID,
	now time.Time,
) (string, error) {
	if !codec.ready || paasv1.ValidateID("after", string(after)) != nil || now.Location() != time.UTC {
		return "", errInvalidApplicationCursor
	}
	binding, err := codec.binding(installationID, subject)
	if err != nil {
		return "", err
	}
	protector, err := codec.positionProtector(binding)
	if err != nil {
		return "", errInvalidApplicationCursor
	}
	position := protector.Seal(nil, nil, []byte(after), applicationCursorAAD(binding))
	defer clear(position)
	issued := now.Truncate(time.Microsecond)
	expires := issued.Add(applicationCursorLifetime)
	payload := make([]byte, applicationCursorHeaderBytes+len(position))
	binary.BigEndian.PutUint64(payload[:8], uint64(issued.UnixMicro()))
	binary.BigEndian.PutUint64(payload[8:16], uint64(expires.UnixMicro()))
	copy(payload[16:48], binding)
	copy(payload[applicationCursorHeaderBytes:], position)
	tag := codec.tag(payload)
	envelope := append(payload, tag...)
	result := applicationCursorPrefix + base64.RawURLEncoding.EncodeToString(envelope)
	clear(tag)
	clear(envelope)
	if paasv1.ValidateApplicationCursor(result) != nil {
		return "", errInvalidApplicationCursor
	}
	return result, nil
}

func (codec applicationCursorCodec) decode(
	value string,
	installationID string,
	subject port.AuthorizationSubjectContext,
	now time.Time,
) (paasv1.ResourceID, error) {
	if !codec.ready || now.Location() != time.UTC || paasv1.ValidateApplicationCursor(value) != nil {
		return "", errInvalidApplicationCursor
	}
	envelope, err := base64.RawURLEncoding.Strict().DecodeString(value[len(applicationCursorPrefix):])
	maximumPositionBytes := 128 + 28 // ID plus AES-GCM random nonce and tag.
	if err != nil || len(envelope) <= applicationCursorHeaderBytes+applicationCursorTagBytes ||
		len(envelope) > applicationCursorHeaderBytes+maximumPositionBytes+applicationCursorTagBytes {
		clear(envelope)
		return "", errInvalidApplicationCursor
	}
	defer clear(envelope)
	payload := envelope[:len(envelope)-applicationCursorTagBytes]
	tag := envelope[len(envelope)-applicationCursorTagBytes:]
	expectedTag := codec.tag(payload)
	validTag := hmac.Equal(tag, expectedTag)
	clear(expectedTag)
	if !validTag {
		return "", errInvalidApplicationCursor
	}
	binding, err := codec.binding(installationID, subject)
	if err != nil || !hmac.Equal(binding, payload[16:48]) {
		return "", errInvalidApplicationCursor
	}
	issued := time.UnixMicro(int64(binary.BigEndian.Uint64(payload[:8]))).UTC()
	expires := time.UnixMicro(int64(binary.BigEndian.Uint64(payload[8:16]))).UTC()
	if issued.After(now) || !now.Before(expires) || !issued.Before(expires) ||
		expires.Sub(issued) != applicationCursorLifetime {
		return "", errInvalidApplicationCursor
	}
	protector, err := codec.positionProtector(binding)
	if err != nil {
		return "", errInvalidApplicationCursor
	}
	position, err := protector.Open(nil, nil, payload[applicationCursorHeaderBytes:], applicationCursorAAD(binding))
	if err != nil {
		return "", errInvalidApplicationCursor
	}
	defer clear(position)
	after := paasv1.ResourceID(position)
	if paasv1.ValidateID("after", string(after)) != nil {
		return "", errInvalidApplicationCursor
	}
	return after, nil
}

func (codec applicationCursorCodec) binding(
	installationID string,
	subject port.AuthorizationSubjectContext,
) ([]byte, error) {
	if !codec.ready || paasv1.ValidateID("installationId", installationID) != nil ||
		port.ValidateAuthorizationSubjectContext(subject) != nil ||
		subject.Profile.Product != iamv1.ProductPaaS {
		return nil, errInvalidApplicationCursor
	}
	projection := applicationCursorBinding{
		InstallationID: installationID,
		TenantID:       subject.TenantID,
		Subject:        subject.Subject,
		Profile:        subject.Profile,
		Action:         port.AuthorizeApplicationRead,
		QueryShape:     applicationCursorQueryShape,
	}
	encoded, err := json.Marshal(projection)
	if err != nil {
		return nil, errInvalidApplicationCursor
	}
	defer clear(encoded)
	digest := hmac.New(sha256.New, codec.key[:])
	digest.Write([]byte("matrix.paas.application-directory.cursor.binding.v1\x00"))
	digest.Write(encoded)
	return digest.Sum(nil), nil
}

func (codec applicationCursorCodec) positionProtector(binding []byte) (cipher.AEAD, error) {
	digest := hmac.New(sha256.New, codec.key[:])
	digest.Write([]byte("matrix.paas.application-directory.cursor.position.v1\x00"))
	digest.Write(binding)
	key := digest.Sum(nil)
	defer clear(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCMWithRandomNonce(block)
}

func applicationCursorAAD(binding []byte) []byte {
	return append([]byte("matrix.paas.application-directory.cursor.pc1\x00"), binding...)
}

func (codec applicationCursorCodec) tag(payload []byte) []byte {
	digest := hmac.New(sha256.New, codec.key[:])
	digest.Write([]byte("matrix.paas.application-directory.cursor.tag.v1\x00"))
	digest.Write(payload)
	return digest.Sum(nil)
}
