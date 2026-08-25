package authority

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	auditv1 "github.com/xiak/matrix/api/audit/v1"
)

var (
	ErrCanonicalEvent     = errors.New("Audit event cannot be canonicalized")
	ErrInvalidReplayState = errors.New("stored Audit replay state is invalid")
	ErrReplayConflict     = errors.New("Audit event replay content conflicts")
)

const canonicalEventVersion = "matrix.audit.canonical-event.v1"

type CanonicalFact struct {
	Source        auditv1.Source
	EventID       auditv1.EventID
	TenantID      auditv1.TenantID
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
	if err := auditv1.ValidateEventForSource(source, event); err != nil {
		return CanonicalFact{}, ErrCanonicalEvent
	}
	wire := canonicalEnvelope{
		CanonicalVersion: canonicalEventVersion,
		Source:           source,
		Event: canonicalEvent{
			APIVersion:    event.APIVersion,
			Kind:          event.Kind,
			EventID:       event.EventID,
			TenantID:      event.TenantID,
			Actor:         event.Actor,
			IAMDecisionID: event.IAMDecisionID,
			Action:        event.Action,
			Target:        event.Target,
			Result:        event.Result,
			RequestDigest: event.RequestDigest,
			RequestID:     event.RequestID,
			CorrelationID: event.CorrelationID,
			OperationID:   event.OperationID,
			TraceParent:   event.TraceParent,
			OccurredAt:    canonicalTimestamp(event.OccurredAt),
		},
	}
	encoded, err := json.Marshal(wire)
	if err != nil {
		return CanonicalFact{}, ErrCanonicalEvent
	}
	digest := sha256.Sum256(encoded)
	return CanonicalFact{
		Source: source, EventID: event.EventID, TenantID: event.TenantID,
		Document: string(encoded), ContentDigest: "sha256:" + hex.EncodeToString(digest[:]),
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

func canonicalTimestamp(value time.Time) string {
	return value.Format("2006-01-02T15:04:05.000000Z")
}

type canonicalEnvelope struct {
	CanonicalVersion string         `json:"canonicalVersion"`
	Source           auditv1.Source `json:"source"`
	Event            canonicalEvent `json:"event"`
}

type canonicalEvent struct {
	APIVersion    string                  `json:"apiVersion"`
	Kind          string                  `json:"kind"`
	EventID       auditv1.EventID         `json:"eventId"`
	TenantID      auditv1.TenantID        `json:"tenantId"`
	Actor         auditv1.ActorReference  `json:"actor"`
	IAMDecisionID auditv1.DecisionID      `json:"iamDecisionId,omitempty"`
	Action        auditv1.Action          `json:"action"`
	Target        auditv1.TargetReference `json:"target"`
	Result        auditv1.Result          `json:"result"`
	RequestDigest string                  `json:"requestDigest"`
	RequestID     string                  `json:"requestId"`
	CorrelationID string                  `json:"correlationId"`
	OperationID   auditv1.OperationID     `json:"operationId,omitempty"`
	TraceParent   string                  `json:"traceparent,omitempty"`
	OccurredAt    string                  `json:"occurredAt"`
}
