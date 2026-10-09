package accessanalysis

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	randv2 "math/rand/v2"
	"strconv"
	"strings"
	"time"

	auditv1 "github.com/xiak/matrix/api/audit/v1"
	iamv1 "github.com/xiak/matrix/api/iam/v1"
)

const maxTransactionAttempts = 8

var (
	ErrUnavailable          = errors.New("IAM access analysis unavailable")
	ErrStaleLease           = errors.New("IAM access analysis lease conflicts")
	ErrRetryableTransaction = errors.New("IAM access analysis transaction retryable")
)

type Claim struct {
	AttemptID      string
	WorkerID       string
	Fence          uint64
	LeaseExpiresAt time.Time
	SnapshotDigest string
	Snapshot       Snapshot
}

type DetectionResult struct {
	Finding iamv1.AccessFinding `json:"finding"`
	Event   auditv1.Event       `json:"event"`
}

type ResolutionResult struct {
	FindingID               iamv1.AccessFindingID `json:"findingId"`
	ExpectedResourceVersion uint64                `json:"expectedResourceVersion"`
	Event                   auditv1.Event         `json:"event"`
}

type Completion struct {
	Detections  []DetectionResult  `json:"detections"`
	Resolutions []ResolutionResult `json:"resolutions"`
}

// DispositionSnapshot is the closed evidence returned by the authority for a
// single automatic action. It is not a lifecycle permit: completion locks and
// recomputes the same evidence before applying any effect.
type DispositionSnapshot struct {
	AccountID                iamv1.AccountID        `json:"accountId"`
	AnalyzerID               iamv1.AccessAnalyzerID `json:"analyzerId"`
	AnalyzerRevision         uint64                 `json:"analyzerRevision"`
	FindingID                iamv1.AccessFindingID  `json:"findingId"`
	FindingResourceVersion   uint64                 `json:"findingResourceVersion"`
	FindingCreatedAt         time.Time              `json:"findingCreatedAt"`
	ConditionGeneration      uint64                 `json:"conditionGeneration"`
	TargetResourceVersion    uint64                 `json:"targetResourceVersion"`
	ActivityRevision         uint64                 `json:"activityRevision"`
	RecoveryEpoch            uint64                 `json:"recoveryEpoch"`
	AccessKeyID              string                 `json:"accessKeyId"`
	AccessKeyResourceVersion uint64                 `json:"accessKeyResourceVersion"`
	UserID                   iamv1.PrincipalID      `json:"userId"`
	LastActivityAt           *time.Time             `json:"lastActivityAt,omitempty"`
	EvaluatedAt              time.Time              `json:"evaluatedAt"`
}

type DispositionClaim struct {
	AttemptID      string
	WorkerID       string
	Fence          uint64
	LeaseExpiresAt time.Time
	SnapshotDigest string
	Snapshot       DispositionSnapshot
}

type DispositionCompletion struct {
	KeyEventID       auditv1.EventID `json:"keyEventId"`
	KeyRequestID     string          `json:"keyRequestId"`
	FindingEventID   auditv1.EventID `json:"findingEventId"`
	FindingRequestID string          `json:"findingRequestId"`
}

type Transaction interface {
	Claim(context.Context, string, string) (Claim, bool, error)
	Complete(context.Context, Claim, Completion) error
	ClaimDisposition(context.Context, string, string) (DispositionClaim, bool, error)
	CompleteDisposition(context.Context, DispositionClaim, DispositionCompletion) error
}

type Repository interface {
	Ready(context.Context) error
	WithinTransaction(context.Context, func(context.Context, Transaction) error) error
}

type IDGenerator func(string) (string, error)

type Scanner struct {
	repository Repository
	newID      IDGenerator
	workerID   string
}

type Result struct {
	Claimed     bool
	Detections  int
	Resolutions int
}

type DispositionResult struct {
	Claimed bool
	Applied bool
}

func NewScanner(repository Repository, newID IDGenerator, workerID string) (*Scanner, error) {
	if repository == nil || newID == nil || iamv1.ValidateID("workerId", workerID) != nil {
		return nil, ErrUnavailable
	}
	return &Scanner{repository: repository, newID: newID, workerID: workerID}, nil
}

func (service *Scanner) Ready(ctx context.Context) error {
	if service == nil || ctx == nil {
		return ErrUnavailable
	}
	return service.repository.Ready(ctx)
}

func (service *Scanner) ScanOnce(ctx context.Context) (Result, error) {
	if service == nil || ctx == nil {
		return Result{}, ErrUnavailable
	}
	attemptID, err := service.identifier("access-analysis-attempt")
	if err != nil {
		return Result{}, err
	}
	var claim Claim
	var found bool
	err = service.withinTransaction(ctx, func(ctx context.Context, tx Transaction) error {
		var err error
		claim, found, err = tx.Claim(ctx, service.workerID, attemptID)
		return err
	})
	if err != nil {
		return Result{}, err
	}
	if !found {
		return Result{}, nil
	}
	if claim.AttemptID != attemptID || claim.WorkerID != service.workerID || claim.Fence == 0 ||
		claim.LeaseExpiresAt.Location() != time.UTC || !claim.LeaseExpiresAt.After(claim.Snapshot.ObservedAt) ||
		!validDigest(claim.SnapshotDigest) {
		return Result{Claimed: true}, ErrUnavailable
	}
	plan, err := Evaluate(claim.Snapshot)
	if err != nil {
		return Result{Claimed: true}, ErrUnavailable
	}
	completion, err := service.completion(claim, plan)
	if err != nil {
		return Result{Claimed: true}, err
	}
	err = service.withinTransaction(ctx, func(ctx context.Context, tx Transaction) error {
		return tx.Complete(ctx, claim, completion)
	})
	if err != nil {
		return Result{Claimed: true}, err
	}
	return Result{Claimed: true, Detections: len(completion.Detections), Resolutions: len(completion.Resolutions)}, nil
}

func (service *Scanner) DisposeOnce(ctx context.Context) (DispositionResult, error) {
	if service == nil || ctx == nil {
		return DispositionResult{}, ErrUnavailable
	}
	attemptID, err := service.identifier("access-disposition-attempt")
	if err != nil {
		return DispositionResult{}, err
	}
	var claim DispositionClaim
	var found bool
	err = service.withinTransaction(ctx, func(ctx context.Context, tx Transaction) error {
		var err error
		claim, found, err = tx.ClaimDisposition(ctx, service.workerID, attemptID)
		return err
	})
	if err != nil {
		return DispositionResult{}, err
	}
	if !found {
		return DispositionResult{}, nil
	}
	if !validDispositionClaim(claim, attemptID, service.workerID) {
		return DispositionResult{Claimed: true}, ErrUnavailable
	}
	completion, err := service.dispositionCompletion()
	if err != nil {
		return DispositionResult{Claimed: true}, err
	}
	err = service.withinTransaction(ctx, func(ctx context.Context, tx Transaction) error {
		return tx.CompleteDisposition(ctx, claim, completion)
	})
	if err != nil {
		return DispositionResult{Claimed: true}, err
	}
	return DispositionResult{Claimed: true, Applied: true}, nil
}

func (service *Scanner) dispositionCompletion() (DispositionCompletion, error) {
	keyEvent, err := service.identifier("audit-event")
	if err != nil {
		return DispositionCompletion{}, err
	}
	keyRequest, err := service.identifier("access-disposition-request")
	if err != nil {
		return DispositionCompletion{}, err
	}
	findingEvent, err := service.identifier("audit-event")
	if err != nil {
		return DispositionCompletion{}, err
	}
	findingRequest, err := service.identifier("access-disposition-request")
	if err != nil {
		return DispositionCompletion{}, err
	}
	return DispositionCompletion{KeyEventID: auditv1.EventID(keyEvent), KeyRequestID: keyRequest,
		FindingEventID: auditv1.EventID(findingEvent), FindingRequestID: findingRequest}, nil
}

func validDispositionClaim(claim DispositionClaim, attempt, worker string) bool {
	const maxVersion = uint64(1<<53 - 1)
	snapshot := claim.Snapshot
	validTime := func(value time.Time) bool { return value.Location() == time.UTC && !value.IsZero() }
	if claim.AttemptID != attempt || claim.WorkerID != worker || claim.Fence == 0 || claim.Fence > maxVersion ||
		!validDigest(claim.SnapshotDigest) || !validTime(claim.LeaseExpiresAt) || !validTime(snapshot.FindingCreatedAt) ||
		!validTime(snapshot.EvaluatedAt) || !claim.LeaseExpiresAt.After(snapshot.EvaluatedAt) ||
		iamv1.ValidateID("accountId", string(snapshot.AccountID)) != nil ||
		iamv1.ValidateID("analyzerId", string(snapshot.AnalyzerID)) != nil ||
		iamv1.ValidateID("findingId", string(snapshot.FindingID)) != nil ||
		iamv1.ValidateID("accessKeyId", snapshot.AccessKeyID) != nil ||
		iamv1.ValidateID("userId", string(snapshot.UserID)) != nil {
		return false
	}
	for _, version := range []uint64{snapshot.AnalyzerRevision, snapshot.FindingResourceVersion, snapshot.ConditionGeneration,
		snapshot.TargetResourceVersion, snapshot.ActivityRevision, snapshot.AccessKeyResourceVersion} {
		if version == 0 || version > maxVersion {
			return false
		}
	}
	return snapshot.LastActivityAt == nil || (validTime(*snapshot.LastActivityAt) && !snapshot.LastActivityAt.After(snapshot.EvaluatedAt))
}

func (service *Scanner) withinTransaction(ctx context.Context, callback func(context.Context, Transaction) error) error {
	if service == nil || service.repository == nil || ctx == nil || callback == nil {
		return ErrUnavailable
	}
	var transactionErr error
	for attempt := 0; attempt < maxTransactionAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		transactionErr = service.repository.WithinTransaction(ctx, callback)
		if transactionErr == nil || !errors.Is(transactionErr, ErrRetryableTransaction) {
			return transactionErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if attempt+1 < maxTransactionAttempts {
			// Yield after the failed transaction has ended so the winning
			// serializable transaction can commit before a fresh snapshot is
			// taken. The immutable scan attempt and completion are reused.
			ceiling := min(50*time.Millisecond<<attempt, 200*time.Millisecond)
			delay := ceiling/2 + time.Duration(randv2.Int64N(int64(ceiling/2)))
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-timer.C:
			}
		}
	}
	return fmt.Errorf("IAM access analysis transaction attempts exhausted: %w", transactionErr)
}

func (service *Scanner) completion(claim Claim, plan Plan) (Completion, error) {
	result := Completion{Detections: make([]DetectionResult, 0, len(plan.Detections)), Resolutions: make([]ResolutionResult, 0, len(plan.Resolutions))}
	for _, detection := range plan.Detections {
		findingID, err := service.identifier("access-finding")
		if err != nil {
			return Completion{}, err
		}
		finding := iamv1.AccessFinding{APIVersion: iamv1.APIVersion, Kind: "AccessFinding", ID: iamv1.AccessFindingID(findingID),
			AccountID: claim.Snapshot.Analyzer.AccountID, AnalyzerID: claim.Snapshot.Analyzer.ID,
			AnalyzerRevision: claim.Snapshot.Analyzer.ResourceVersion, Type: detection.Type, Status: iamv1.AccessFindingActive,
			Target: detection.Target, TargetResourceVersion: detection.TargetResourceVersion,
			ConditionGeneration: detection.ConditionGeneration, ActivityRevision: detection.ActivityRevision,
			RecoveryEpoch: claim.Snapshot.RecoveryEpoch, RecoveryCommandID: claim.Snapshot.RecoveryCommandID,
			RecoveryCompletedAt: claim.Snapshot.RecoveryCompletedAt, WindowStartedAt: plan.WindowStartedAt,
			ObservedAt: claim.Snapshot.ObservedAt, LastActivityAt: detection.LastActivityAt,
			ResourceVersion: 1, CreatedAt: claim.Snapshot.ObservedAt, UpdatedAt: claim.Snapshot.ObservedAt}
		if iamv1.ValidateAccessFinding(finding) != nil {
			return Completion{}, ErrUnavailable
		}
		event, err := service.event(claim, auditv1.ActionIAMAccessFindingDetected, finding.ID)
		if err != nil {
			return Completion{}, err
		}
		result.Detections = append(result.Detections, DetectionResult{Finding: finding, Event: event})
	}
	for _, resolution := range plan.Resolutions {
		event, err := service.event(claim, auditv1.ActionIAMAccessFindingResolved, resolution.FindingID)
		if err != nil {
			return Completion{}, err
		}
		result.Resolutions = append(result.Resolutions, ResolutionResult{FindingID: resolution.FindingID,
			ExpectedResourceVersion: resolution.ResourceVersion, Event: event})
	}
	return result, nil
}

func (service *Scanner) event(claim Claim, action auditv1.Action, findingID iamv1.AccessFindingID) (auditv1.Event, error) {
	eventID, err := service.identifier("audit-event")
	if err != nil {
		return auditv1.Event{}, err
	}
	requestID, err := service.identifier("access-analysis-request")
	if err != nil {
		return auditv1.Event{}, err
	}
	digest := analysisEventDigest(action, claim.AttemptID, findingID, claim.SnapshotDigest)
	event := auditv1.Event{APIVersion: auditv1.APIVersion, Kind: "AuditEvent", EventID: auditv1.EventID(eventID),
		TenantID: auditv1.TenantID(claim.Snapshot.Analyzer.AccountID),
		Actor:    auditv1.ActorReference{Type: auditv1.ActorSystem, ID: "iam.access-analyzer"}, Action: action,
		Target: auditv1.TargetReference{Kind: auditv1.TargetAccessFinding, ID: string(findingID)}, Result: auditv1.ResultSucceeded,
		RequestDigest: digest, RequestID: requestID, CorrelationID: claim.AttemptID, OccurredAt: claim.Snapshot.ObservedAt}
	if auditv1.ValidateEventForSource(auditv1.SourceIAM, event) != nil {
		return auditv1.Event{}, ErrUnavailable
	}
	return event, nil
}

func (service *Scanner) identifier(prefix string) (string, error) {
	value, err := service.newID(prefix)
	if err != nil || iamv1.ValidateID(prefix, value) != nil {
		return "", ErrUnavailable
	}
	return value, nil
}

func analysisEventDigest(action auditv1.Action, attempt string, finding iamv1.AccessFindingID, snapshotDigest string) string {
	fields := []string{string(action), attempt, string(finding), snapshotDigest}
	var document strings.Builder
	document.WriteString("matrix.iam.access-analysis-event.v1|")
	for _, field := range fields {
		document.WriteString(strconv.Itoa(len(field)))
		document.WriteByte(':')
		document.WriteString(field)
		document.WriteByte('|')
	}
	digest := sha256.Sum256([]byte(document.String()))
	return "sha256:" + hex.EncodeToString(digest[:])
}

func validDigest(value string) bool {
	if len(value) != len("sha256:")+sha256.Size*2 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	_, err := hex.DecodeString(value[len("sha256:"):])
	return err == nil && value == strings.ToLower(value)
}

func NewRandomID(prefix string) (string, error) {
	if iamv1.ValidateID("idPrefix", prefix) != nil {
		return "", ErrUnavailable
	}
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		clear(random)
		return "", ErrUnavailable
	}
	result := prefix + "-" + hex.EncodeToString(random)
	clear(random)
	if iamv1.ValidateID("generatedId", result) != nil {
		return "", ErrUnavailable
	}
	return result, nil
}
