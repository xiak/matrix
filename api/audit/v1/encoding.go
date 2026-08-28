package auditv1

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"

	"github.com/xiak/matrix/api/contractjson"
)

func DecodeRequest(reader io.Reader, destination any) error {
	return contractjson.DecodeObject(reader, MaxRequestBytes, destination)
}

// An explicitly supplied empty/null namespace must not disappear during
// decoding and bypass the action's closed target-field contract.
func (target *TargetReference) UnmarshalJSON(document []byte) error {
	var wire struct {
		Kind     TargetKind      `json:"kind"`
		ID       string          `json:"id"`
		TenantID json.RawMessage `json:"tenantId"`
	}
	if err := contractjson.DecodeObjectBytes(document, MaxRequestBytes, &wire); err != nil {
		return err
	}
	var tenantID TenantID
	if wire.TenantID != nil {
		if json.Unmarshal(wire.TenantID, &tenantID) != nil || ValidateID("target.tenantId", string(tenantID)) != nil {
			return errors.New("Audit target namespace is invalid")
		}
	}
	*target = TargetReference{Kind: wire.Kind, ID: wire.ID, TenantID: tenantID}
	return nil
}

// CanonicalizeEvent owns the byte representation and digest shared by Audit
// ingestion and IAM producer proofs. It validates the source-bound closed event
// before encoding; equal historical tenant facts retain their exact bytes.
func CanonicalizeEvent(source Source, event Event) (document, contentDigest string, err error) {
	if err := ValidateEventForSource(source, event); err != nil {
		return "", "", errors.New("Audit event cannot be canonicalized")
	}
	wire := canonicalEnvelope{
		CanonicalVersion: "matrix.audit.canonical-event.v1",
		Source:           source,
		Event: canonicalEvent{
			APIVersion:     event.APIVersion,
			Kind:           event.Kind,
			EventID:        event.EventID,
			TenantID:       event.TenantID,
			InstallationID: event.InstallationID,
			Actor:          event.Actor,
			IAMDecisionID:  event.IAMDecisionID,
			Action:         event.Action,
			Target:         event.Target,
			Result:         event.Result,
			RequestDigest:  event.RequestDigest,
			RequestID:      event.RequestID,
			CorrelationID:  event.CorrelationID,
			OperationID:    event.OperationID,
			TraceParent:    event.TraceParent,
			OccurredAt:     event.OccurredAt.Format("2006-01-02T15:04:05.000000Z"),
		},
	}
	encoded, err := json.Marshal(wire)
	if err != nil {
		return "", "", errors.New("Audit event cannot be canonicalized")
	}
	digest := sha256.Sum256(encoded)
	return string(encoded), "sha256:" + hex.EncodeToString(digest[:]), nil
}

type canonicalEnvelope struct {
	CanonicalVersion string         `json:"canonicalVersion"`
	Source           Source         `json:"source"`
	Event            canonicalEvent `json:"event"`
}

type canonicalEvent struct {
	APIVersion     string          `json:"apiVersion"`
	Kind           string          `json:"kind"`
	EventID        EventID         `json:"eventId"`
	TenantID       TenantID        `json:"tenantId,omitempty"`
	InstallationID string          `json:"installationId,omitempty"`
	Actor          ActorReference  `json:"actor"`
	IAMDecisionID  DecisionID      `json:"iamDecisionId,omitempty"`
	Action         Action          `json:"action"`
	Target         TargetReference `json:"target"`
	Result         Result          `json:"result"`
	RequestDigest  string          `json:"requestDigest"`
	RequestID      string          `json:"requestId"`
	CorrelationID  string          `json:"correlationId"`
	OperationID    OperationID     `json:"operationId,omitempty"`
	TraceParent    string          `json:"traceparent,omitempty"`
	OccurredAt     string          `json:"occurredAt"`
}
