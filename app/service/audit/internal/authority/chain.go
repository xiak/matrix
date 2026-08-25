package authority

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"hash"
	"time"

	auditv1 "github.com/xiak/matrix/api/audit/v1"
)

var ErrInvalidChain = errors.New("Audit hash chain is invalid")

const GenesisHash = "sha256:0000000000000000000000000000000000000000000000000000000000000000"

type Checkpoint struct {
	TenantID   auditv1.TenantID
	Sequence   uint64
	RecordHash string
}

func GenesisCheckpoint(tenantID auditv1.TenantID) (Checkpoint, error) {
	if auditv1.ValidateID("tenantId", string(tenantID)) != nil {
		return Checkpoint{}, ErrInvalidChain
	}
	return Checkpoint{TenantID: tenantID, RecordHash: GenesisHash}, nil
}

func AppendRecord(
	previous Checkpoint,
	sequence uint64,
	source auditv1.Source,
	event auditv1.Event,
	ingestedAt time.Time,
) (auditv1.AuditRecord, CanonicalFact, error) {
	if validateCheckpoint(previous) != nil || sequence != previous.Sequence+1 {
		return auditv1.AuditRecord{}, CanonicalFact{}, ErrInvalidChain
	}
	fact, err := Canonicalize(source, event)
	if err != nil || fact.TenantID != previous.TenantID {
		return auditv1.AuditRecord{}, CanonicalFact{}, ErrInvalidChain
	}
	record := auditv1.AuditRecord{
		APIVersion:    auditv1.APIVersion,
		Kind:          "AuditRecord",
		Source:        source,
		Sequence:      sequence,
		Event:         event,
		ContentDigest: fact.ContentDigest,
		PreviousHash:  previous.RecordHash,
		IngestedAt:    ingestedAt,
		Retention:     auditv1.RetentionIndefinite,
	}
	record.RecordHash, err = computeRecordHash(record)
	if err != nil || auditv1.ValidateAuditRecord(record) != nil {
		return auditv1.AuditRecord{}, CanonicalFact{}, ErrInvalidChain
	}
	return record, fact, nil
}

func VerifyChain(initial Checkpoint, records []auditv1.AuditRecord) (Checkpoint, error) {
	if validateCheckpoint(initial) != nil {
		return Checkpoint{}, ErrInvalidChain
	}
	current := initial
	for _, record := range records {
		if auditv1.ValidateAuditRecord(record) != nil ||
			record.Event.TenantID != current.TenantID ||
			record.Sequence != current.Sequence+1 ||
			subtle.ConstantTimeCompare([]byte(record.PreviousHash), []byte(current.RecordHash)) != 1 {
			return Checkpoint{}, ErrInvalidChain
		}
		fact, err := Canonicalize(record.Source, record.Event)
		if err != nil || subtle.ConstantTimeCompare([]byte(fact.ContentDigest), []byte(record.ContentDigest)) != 1 {
			return Checkpoint{}, ErrInvalidChain
		}
		recomputed, err := computeRecordHash(record)
		if err != nil || subtle.ConstantTimeCompare([]byte(recomputed), []byte(record.RecordHash)) != 1 {
			return Checkpoint{}, ErrInvalidChain
		}
		current.Sequence = record.Sequence
		current.RecordHash = record.RecordHash
	}
	return current, nil
}

func computeRecordHash(record auditv1.AuditRecord) (string, error) {
	contentDigest, err := digestBytes(record.ContentDigest)
	if err != nil {
		return "", ErrInvalidChain
	}
	previousHash, err := digestBytes(record.PreviousHash)
	if err != nil {
		return "", ErrInvalidChain
	}
	if record.Sequence == 0 || record.Sequence > 9007199254740991 ||
		record.IngestedAt.IsZero() || record.IngestedAt.Location() != time.UTC ||
		record.IngestedAt != record.IngestedAt.Round(0) || record.IngestedAt.Nanosecond()%1_000 != 0 ||
		record.Retention != auditv1.RetentionIndefinite {
		return "", ErrInvalidChain
	}
	digest := sha256.New()
	digest.Write([]byte("matrix.audit.record.v1\x00"))
	writeHashString(digest, string(record.Event.TenantID))
	var integer [8]byte
	binary.BigEndian.PutUint64(integer[:], record.Sequence)
	digest.Write(integer[:])
	digest.Write(contentDigest)
	digest.Write(previousHash)
	writeHashString(digest, canonicalTimestamp(record.IngestedAt))
	writeHashString(digest, string(record.Retention))
	return "sha256:" + hex.EncodeToString(digest.Sum(nil)), nil
}

func validateCheckpoint(value Checkpoint) error {
	if auditv1.ValidateID("tenantId", string(value.TenantID)) != nil {
		return ErrInvalidChain
	}
	if value.Sequence == 0 {
		if value.RecordHash != GenesisHash {
			return ErrInvalidChain
		}
		return nil
	}
	if value.Sequence > 9007199254740991 || auditv1.ValidateDigest("recordHash", value.RecordHash) != nil {
		return ErrInvalidChain
	}
	return nil
}

func digestBytes(value string) ([]byte, error) {
	if auditv1.ValidateDigest("digest", value) != nil {
		return nil, ErrInvalidChain
	}
	decoded, err := hex.DecodeString(value[len("sha256:"):])
	if err != nil || len(decoded) != sha256.Size {
		clear(decoded)
		return nil, ErrInvalidChain
	}
	return decoded, nil
}

func writeHashString(target hash.Hash, value string) {
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(value)))
	target.Write(length[:])
	target.Write([]byte(value))
}
