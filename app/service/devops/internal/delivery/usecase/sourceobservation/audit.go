package sourceobservation

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"time"

	auditv1 "github.com/xiak/matrix/api/audit/v1"
	devopsv1 "github.com/xiak/matrix/api/devops/v1"
)

const observationDigestDomain = "matrix-devops-source-health-observation-v1"

func NewSourceConnectionHealthEvent(value devopsv1.SourceConnection) (auditv1.Event, error) {
	if devopsv1.ValidateSourceConnection(value) != nil ||
		value.Status.Health == devopsv1.SourceConnectionPending {
		return auditv1.Event{}, errors.New("source connection health Audit fact is invalid")
	}
	return newHealthEvent(
		value.Metadata.Scope.TenantID,
		auditv1.ActionDevOpsSourceConnectionHealthTransitioned,
		auditv1.TargetSourceConnection,
		value.Metadata.ID,
		string(value.Status.Health),
		string(value.Status.Reason),
		value.Metadata.ResourceVersion,
		value.Status.ObservedAt,
	)
}

func NewRepositoryBindingHealthEvent(value devopsv1.RepositoryBinding) (auditv1.Event, error) {
	if devopsv1.ValidateRepositoryBinding(value) != nil ||
		value.Status.Reason == devopsv1.RepositoryBindingReasonConfigurationChanged {
		return auditv1.Event{}, errors.New("repository binding health Audit fact is invalid")
	}
	return newHealthEvent(
		value.Metadata.Scope.TenantID,
		auditv1.ActionDevOpsRepositoryBindingHealthTransitioned,
		auditv1.TargetRepositoryBinding,
		value.Metadata.ID,
		string(value.Status.Health),
		string(value.Status.Reason),
		value.Metadata.ResourceVersion,
		value.Status.ObservedAt,
	)
}

func newHealthEvent(
	tenantID devopsv1.TenantID,
	action auditv1.Action,
	targetKind auditv1.TargetKind,
	targetID devopsv1.ResourceID,
	health string,
	reason string,
	resourceVersion uint64,
	observedAt time.Time,
) (auditv1.Event, error) {
	payload := strings.Join([]string{
		observationDigestDomain,
		string(targetKind),
		string(tenantID),
		string(targetID),
		health,
		reason,
		strconv.FormatUint(resourceVersion, 10),
		observedAt.Format("2006-01-02T15:04:05.000000Z"),
	}, "\n")
	digest := sha256.Sum256([]byte(payload))
	digestHex := hex.EncodeToString(digest[:])
	operationID := "source-observation-" + digestHex
	eventDigest := sha256.Sum256([]byte("matrix-devops-audit-event-v1\x00" + operationID))
	event := auditv1.Event{
		APIVersion: auditv1.APIVersion,
		Kind:       "AuditEvent",
		EventID:    auditv1.EventID("audit-" + hex.EncodeToString(eventDigest[:])),
		TenantID:   auditv1.TenantID(tenantID),
		Actor: auditv1.ActorReference{
			Type: auditv1.ActorSystem,
			ID:   auditv1.ActorID(ActorID),
		},
		Action:        action,
		Target:        auditv1.TargetReference{Kind: targetKind, ID: string(targetID)},
		Result:        auditv1.ResultSucceeded,
		RequestDigest: "sha256:" + digestHex,
		RequestID:     operationID,
		CorrelationID: string(targetID),
		OperationID:   auditv1.OperationID(operationID),
		OccurredAt:    observedAt,
	}
	if auditv1.ValidateEventForSource(auditv1.SourceDevOps, event) != nil {
		return auditv1.Event{}, errors.New("source health Audit fact is invalid")
	}
	return event, nil
}
