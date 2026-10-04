package authority

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"

	auditv1 "github.com/xiak/matrix/api/audit/v1"
)

var (
	ErrCanonicalEvent     = errors.New("Audit event cannot be canonicalized")
	ErrInvalidReplayState = errors.New("stored Audit replay state is invalid")
	ErrReplayConflict     = errors.New("Audit event replay content conflicts")
)

type CanonicalFact struct {
	Source        auditv1.Source
	EventID       auditv1.EventID
	ChainID       ChainID
	Document      string
	ContentDigest string
}

type ReplayState struct {
	Source            auditv1.Source
	EventID           auditv1.EventID
	CanonicalDocument string
	ContentDigest     string
}

type ReplayOutcome string

const (
	ReplayNew   ReplayOutcome = "NEW"
	ReplayEqual ReplayOutcome = "EQUAL"
)

func Canonicalize(source auditv1.Source, event auditv1.Event) (CanonicalFact, error) {
	document, digest, err := auditv1.CanonicalizeEvent(source, event)
	if err != nil {
		return CanonicalFact{}, ErrCanonicalEvent
	}
	return CanonicalFact{
		Source: source, EventID: event.EventID, ChainID: ChainFor(event.TenantID, event.InstallationID),
		Document: document, ContentDigest: digest,
	}, nil
}

func ClassifyReplay(
	existing *ReplayState,
	source auditv1.Source,
	event auditv1.Event,
) (ReplayOutcome, CanonicalFact, error) {
	fact, err := Canonicalize(source, event)
	if err != nil {
		return "", CanonicalFact{}, err
	}
	if existing == nil {
		return ReplayNew, fact, nil
	}
	if err := validateReplayState(*existing); err != nil ||
		existing.Source != source || existing.EventID != event.EventID {
		return "", CanonicalFact{}, ErrInvalidReplayState
	}
	if subtle.ConstantTimeCompare([]byte(existing.ContentDigest), []byte(fact.ContentDigest)) != 1 ||
		existing.CanonicalDocument != fact.Document {
		return "", CanonicalFact{}, ErrReplayConflict
	}
	return ReplayEqual, fact, nil
}

func validateReplayState(value ReplayState) error {
	if !knownSource(value.Source) || auditv1.ValidateID("eventId", string(value.EventID)) != nil ||
		auditv1.ValidateDigest("contentDigest", value.ContentDigest) != nil || len(value.CanonicalDocument) == 0 ||
		len(value.CanonicalDocument) > int(auditv1.MaxRequestBytes) {
		return ErrInvalidReplayState
	}
	digest := sha256.Sum256([]byte(value.CanonicalDocument))
	actual := "sha256:" + hex.EncodeToString(digest[:])
	if subtle.ConstantTimeCompare([]byte(actual), []byte(value.ContentDigest)) != 1 {
		return ErrInvalidReplayState
	}
	return nil
}

func knownSource(value auditv1.Source) bool {
	return value == auditv1.SourceIAM || value == auditv1.SourcePaaS || value == auditv1.SourceAudit
}
