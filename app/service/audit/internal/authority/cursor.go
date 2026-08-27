package authority

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"hash"
	"strings"
	"time"

	auditv1 "github.com/xiak/matrix/api/audit/v1"
)

var (
	ErrInvalidCursorKey = errors.New("Audit cursor key is invalid")
	ErrInvalidCursor    = errors.New("Audit cursor is invalid")
)

const cursorPayloadBytes = 1 + 16 + sha256.Size + 8

type CursorCodec struct {
	key [sha256.Size]byte
}

func NewCursorCodec(key []byte) (CursorCodec, error) {
	if len(key) != sha256.Size {
		return CursorCodec{}, ErrInvalidCursorKey
	}
	var codec CursorCodec
	copy(codec.key[:], key)
	return codec, nil
}

func (codec CursorCodec) Encode(
	chainID ChainID,
	query auditv1.QueryRecordsRequest,
	beforeSequence uint64,
) (auditv1.Cursor, error) {
	if err := validateCursorInput(chainID, query, beforeSequence); err != nil {
		return "", err
	}
	payload := make([]byte, cursorPayloadBytes)
	payload[0] = 1
	copy(payload[1:17], codec.chainBinding(chainID))
	filter := filterDigest(query)
	copy(payload[17:49], filter[:])
	binary.BigEndian.PutUint64(payload[49:], beforeSequence)
	tag := codec.tag(payload)
	encoded := "v1." + base64.RawURLEncoding.EncodeToString(payload) + "." +
		base64.RawURLEncoding.EncodeToString(tag)
	clear(payload)
	clear(tag)
	return auditv1.Cursor(encoded), nil
}

func (codec CursorCodec) Decode(
	cursor auditv1.Cursor,
	chainID ChainID,
	query auditv1.QueryRecordsRequest,
) (uint64, error) {
	validated := query
	validated.Cursor = cursor
	if chainID.Validate() != nil ||
		auditv1.ValidateQueryRecordsRequest(validated) != nil {
		return 0, ErrInvalidCursor
	}
	parts := strings.Split(string(cursor), ".")
	if len(parts) != 3 || parts[0] != "v1" {
		return 0, ErrInvalidCursor
	}
	payload, err := base64.RawURLEncoding.Strict().DecodeString(parts[1])
	if err != nil || len(payload) != cursorPayloadBytes || payload[0] != 1 {
		clear(payload)
		return 0, ErrInvalidCursor
	}
	defer clear(payload)
	tag, err := base64.RawURLEncoding.Strict().DecodeString(parts[2])
	if err != nil || len(tag) != sha256.Size {
		clear(tag)
		return 0, ErrInvalidCursor
	}
	defer clear(tag)
	expectedTag := codec.tag(payload)
	defer clear(expectedTag)
	if !hmac.Equal(tag, expectedTag) {
		return 0, ErrInvalidCursor
	}
	chainBinding := codec.chainBinding(chainID)
	defer clear(chainBinding)
	if subtle.ConstantTimeCompare(payload[1:17], chainBinding) != 1 {
		return 0, ErrInvalidCursor
	}
	filter := filterDigest(query)
	if subtle.ConstantTimeCompare(payload[17:49], filter[:]) != 1 {
		return 0, ErrInvalidCursor
	}
	beforeSequence := binary.BigEndian.Uint64(payload[49:])
	if beforeSequence == 0 || beforeSequence > 9007199254740991 {
		return 0, ErrInvalidCursor
	}
	return beforeSequence, nil
}

func (codec CursorCodec) chainBinding(chainID ChainID) []byte {
	digest := hmac.New(sha256.New, codec.key[:])
	if installationID := chainID.InstallationID(); installationID != "" {
		digest.Write([]byte("matrix.audit.cursor.installation.v1\x00"))
		digest.Write([]byte(installationID))
	} else {
		digest.Write([]byte("matrix.audit.cursor.tenant.v1\x00"))
		digest.Write([]byte(chainID.TenantID()))
	}
	return append([]byte(nil), digest.Sum(nil)[:16]...)
}

func (codec CursorCodec) tag(payload []byte) []byte {
	digest := hmac.New(sha256.New, codec.key[:])
	digest.Write([]byte("matrix.audit.cursor.tag.v1\x00"))
	digest.Write(payload)
	return digest.Sum(nil)
}

func validateCursorInput(
	chainID ChainID,
	query auditv1.QueryRecordsRequest,
	beforeSequence uint64,
) error {
	if chainID.Validate() != nil ||
		auditv1.ValidateQueryRecordsRequest(query) != nil ||
		beforeSequence == 0 || beforeSequence > 9007199254740991 {
		return ErrInvalidCursor
	}
	return nil
}

func filterDigest(query auditv1.QueryRecordsRequest) [sha256.Size]byte {
	digest := sha256.New()
	digest.Write([]byte("matrix.audit.cursor.filter.v1\x00"))
	var integer [8]byte
	binary.BigEndian.PutUint64(integer[:], uint64(query.PageSize))
	digest.Write(integer[:])
	writeOptionalTime(digest, query.From)
	writeOptionalTime(digest, query.To)
	writeCursorString(digest, string(query.Action))
	if query.Actor == nil {
		digest.Write([]byte{0})
	} else {
		digest.Write([]byte{1})
		writeCursorString(digest, string(query.Actor.Type))
		writeCursorString(digest, string(query.Actor.ID))
	}
	var result [sha256.Size]byte
	copy(result[:], digest.Sum(nil))
	return result
}

func writeOptionalTime(target hash.Hash, value *time.Time) {
	if value == nil {
		target.Write([]byte{0})
		return
	}
	target.Write([]byte{1})
	var integer [8]byte
	binary.BigEndian.PutUint64(integer[:], uint64(value.UnixMicro()))
	target.Write(integer[:])
}

func writeCursorString(target hash.Hash, value string) {
	var length [2]byte
	binary.BigEndian.PutUint16(length[:], uint16(len(value)))
	target.Write(length[:])
	target.Write([]byte(value))
}
