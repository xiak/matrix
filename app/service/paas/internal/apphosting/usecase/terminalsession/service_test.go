package terminalsession

import (
	"context"
	"errors"
	"testing"
	"time"

	paasv1 "github.com/xiak/matrix/api/paas/v1"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/port"
	"github.com/xiak/matrix/app/service/paas/internal/audit"
)

func TestTerminalSessionLifecycleIsIdempotentAndOperationIndependent(t *testing.T) {
	repository := newMemoryRepository()
	service, err := New(repository, Config{MaxTransactionAttempts: 3})
	if err != nil {
		t.Fatal(err)
	}
	command := terminalCreateCommand("terminal-one", '1')
	created, err := service.Create(context.Background(), command)
	if err != nil || created.Replayed || created.ReplacedID != "" {
		t.Fatalf("create = %#v / %v", created, err)
	}
	assertTerminalFact(t, repository.events[0], audit.TerminalSessionCreated, audit.Accepted, created.Stored)

	replay := command
	replay.TicketDigest = terminalDigest('2')
	replayed, err := service.Create(context.Background(), replay)
	if err != nil || !replayed.Replayed || replayed.Stored.Session != created.Stored.Session ||
		repository.tickets[created.Stored.Session.ID] != replay.TicketDigest {
		t.Fatalf("equal replay = %#v / %v", replayed, err)
	}
	if len(repository.events) != 1 {
		t.Fatal("equal replay emitted another Audit fact")
	}

	changed := command
	changed.Request.Size.Columns++
	if _, err := service.Create(context.Background(), changed); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("changed replay error = %v", err)
	}

	consumed, err := service.Consume(context.Background(), created.Stored.Session.ID, replay.TicketDigest)
	if err != nil || consumed.Session.State != paasv1.TerminalSessionConnecting {
		t.Fatalf("consume = %#v / %v", consumed, err)
	}
	if _, err := service.Create(context.Background(), replay); !errors.Is(err, ErrConflict) {
		t.Fatalf("consumed replay error = %v", err)
	}
	active, err := service.Activate(context.Background(), consumed)
	if err != nil || active.Session.State != paasv1.TerminalSessionActive {
		t.Fatalf("activate = %#v / %v", active, err)
	}
	assertTerminalFact(t, repository.events[1], audit.TerminalSessionStarted, audit.Succeeded, active)
	ended, changedState, err := service.End(
		context.Background(), active.Session.Scope.TenantID, active.Session.ID,
		paasv1.TerminalSessionCompleted,
	)
	if err != nil || !changedState || ended.Session.State != paasv1.TerminalSessionEnded ||
		ended.Session.Outcome != paasv1.TerminalSessionCompleted {
		t.Fatalf("end = %#v/%t/%v", ended, changedState, err)
	}
	assertTerminalFact(t, repository.events[2], audit.TerminalSessionEnded, audit.Completed, ended)
	if repository.events[2].OperationID != "" {
		t.Fatal("terminal lifecycle was attached to an Operation")
	}
}

func TestTerminalSessionReplacementAndCloseStaySubjectBound(t *testing.T) {
	repository := newMemoryRepository()
	service, _ := New(repository, Config{MaxTransactionAttempts: 3})
	first, err := service.Create(context.Background(), terminalCreateCommand("terminal-first", '3'))
	if err != nil {
		t.Fatal(err)
	}
	secondCommand := terminalCreateCommand("terminal-second", '4')
	second, err := service.Create(context.Background(), secondCommand)
	if err != nil || second.ReplacedID != first.Stored.Session.ID {
		t.Fatalf("replacement = %#v / %v", second, err)
	}
	old := repository.sessions[first.Stored.Session.ID]
	if old.Session.State != paasv1.TerminalSessionEnded || old.Session.Outcome != paasv1.TerminalSessionReplaced ||
		repository.tickets[first.Stored.Session.ID] != "" {
		t.Fatal("replacement retained the old live session or ticket")
	}
	assertTerminalFact(t, repository.events[1], audit.TerminalSessionEnded, audit.Replaced, old)

	other := secondCommand.Authorization
	other.Subject.ID = "principal-other"
	if _, _, err := service.Close(context.Background(), CloseCommand{Authorization: other, SessionID: second.Stored.Session.ID}); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("cross-subject close error = %v", err)
	}
	closed, changed, err := service.Close(context.Background(), CloseCommand{
		Authorization: secondCommand.Authorization, SessionID: second.Stored.Session.ID,
	})
	if err != nil || !changed || closed.Session.Outcome != paasv1.TerminalSessionRevoked {
		t.Fatalf("close = %#v/%t/%v", closed, changed, err)
	}
	assertTerminalFact(t, repository.events[len(repository.events)-1], audit.TerminalSessionEnded, audit.Revoked, closed)
}

func TestExpiredTicketIsClosedAtomicallyAndCannotBeReissued(t *testing.T) {
	repository := newMemoryRepository()
	service, _ := New(repository, Config{MaxTransactionAttempts: 3})
	command := terminalCreateCommand("terminal-expiry", '5')
	created, err := service.Create(context.Background(), command)
	if err != nil {
		t.Fatal(err)
	}
	repository.now = created.Stored.Session.ConnectBefore
	if _, err := service.Consume(context.Background(), created.Stored.Session.ID, command.TicketDigest); !errors.Is(err, ErrExpired) {
		t.Fatalf("expired consume error = %v", err)
	}
	stored := repository.sessions[created.Stored.Session.ID]
	if stored.Session.State != paasv1.TerminalSessionEnded || stored.Session.Outcome != paasv1.TerminalSessionExpired ||
		repository.tickets[stored.Session.ID] != "" {
		t.Fatal("expired ticket did not reach a durable terminal state")
	}
	if _, err := service.Create(context.Background(), command); !errors.Is(err, ErrConflict) {
		t.Fatalf("expired command was reissued: %v", err)
	}
	assertTerminalFact(t, repository.events[len(repository.events)-1], audit.TerminalSessionEnded, audit.Expired, stored)
}

type memoryRepository struct {
	now      time.Time
	binding  RuntimeBinding
	sessions map[paasv1.ResourceID]StoredSession
	tickets  map[paasv1.ResourceID]string
	events   []audit.Event
}

func newMemoryRepository() *memoryRepository {
	return &memoryRepository{
		now: time.Date(2026, 8, 31, 13, 0, 0, 0, time.UTC),
		binding: RuntimeBinding{
			DeploymentID: "deployment-a", Generation: 2,
			ApplicationRevisionID: "application-revision-a",
			ContentDigest:         terminalDigest('a'), ExecutionTargetID: "target-a",
			PlacementDecisionID: "placement-a", BindingRef: "binding-a",
			InstanceID: "instance-0123456789abcdef0123456789abcdef",
		},
		sessions: map[paasv1.ResourceID]StoredSession{},
		tickets:  map[paasv1.ResourceID]string{},
	}
}

func (repository *memoryRepository) WithinTenant(_ context.Context, tenantID paasv1.TenantID, callback func(context.Context, Transaction) error) error {
	if tenantID != "tenant-a" {
		return ErrNotFound
	}
	return callback(context.Background(), (*memoryTransaction)(repository))
}

func (repository *memoryRepository) WithinTicket(_ context.Context, id paasv1.ResourceID, digest string, callback func(context.Context, Transaction, StoredSession) error) error {
	stored, found := repository.sessions[id]
	if !found || repository.tickets[id] != digest || digest == "" {
		return ErrNotFound
	}
	return callback(context.Background(), (*memoryTransaction)(repository), stored)
}

type memoryTransaction memoryRepository

func (transaction *memoryTransaction) TransactionTime(context.Context) (time.Time, error) {
	return transaction.now, nil
}

func (transaction *memoryTransaction) FindByFingerprint(_ context.Context, fingerprint string) (StoredSession, bool, error) {
	for _, stored := range transaction.sessions {
		if stored.IdempotencyFingerprint == fingerprint {
			return stored, true, nil
		}
	}
	return StoredSession{}, false, nil
}

func (transaction *memoryTransaction) LoadAndLockSession(_ context.Context, id paasv1.ResourceID) (StoredSession, bool, error) {
	stored, found := transaction.sessions[id]
	return stored, found, nil
}

func (transaction *memoryTransaction) LoadAndLockOpenForSubjectInstance(_ context.Context, subject paasv1.SubjectRef, deploymentID, instanceID paasv1.ResourceID) (StoredSession, bool, error) {
	for _, stored := range transaction.sessions {
		if stored.Subject == subject && stored.Session.DeploymentID == deploymentID && stored.Session.InstanceID == instanceID && stored.Session.State != paasv1.TerminalSessionEnded {
			return stored, true, nil
		}
	}
	return StoredSession{}, false, nil
}

func (transaction *memoryTransaction) LoadAndLockCurrentRuntime(_ context.Context, deploymentID, instanceID paasv1.ResourceID, _ time.Time) (RuntimeBinding, bool, error) {
	if transaction.binding.DeploymentID != deploymentID || transaction.binding.InstanceID != instanceID {
		return RuntimeBinding{}, false, nil
	}
	return transaction.binding, true, nil
}

func (transaction *memoryTransaction) Insert(_ context.Context, stored StoredSession, ticket string, event audit.Event) error {
	if _, exists := transaction.sessions[stored.Session.ID]; exists {
		return ErrRetryableTransaction
	}
	transaction.sessions[stored.Session.ID] = stored
	transaction.tickets[stored.Session.ID] = ticket
	transaction.events = append(transaction.events, event)
	return nil
}

func (transaction *memoryTransaction) RotateTicket(_ context.Context, id paasv1.ResourceID, digest string) error {
	transaction.tickets[id] = digest
	return nil
}

func (transaction *memoryTransaction) ConsumeTicket(_ context.Context, current StoredSession, next paasv1.TerminalSession) error {
	current.Session = next
	transaction.sessions[current.Session.ID] = current
	transaction.tickets[current.Session.ID] = ""
	return nil
}

func (transaction *memoryTransaction) Transition(_ context.Context, current StoredSession, next paasv1.TerminalSession, event audit.Event) error {
	current.Session = next
	transaction.sessions[current.Session.ID] = current
	transaction.tickets[current.Session.ID] = ""
	transaction.events = append(transaction.events, event)
	return nil
}

func terminalCreateCommand(key string, ticket byte) CreateCommand {
	return CreateCommand{
		Authorization: port.Authorization{
			TenantID: "tenant-a", Subject: paasv1.SubjectRef{Type: paasv1.SubjectUser, ID: "principal-a"},
			DecisionID: "decision-a", RequestID: "request-a",
		},
		DeploymentID: "deployment-a",
		Request: paasv1.CreateTerminalSessionRequest{
			InstanceID: "instance-0123456789abcdef0123456789abcdef",
			Size:       paasv1.TerminalSize{Columns: 80, Rows: 24},
		},
		IdempotencyKey: key, TicketDigest: terminalDigest(ticket),
	}
}

func terminalDigest(value byte) string {
	return "sha256:" + string(make([]byte, 0)) + repeatByte(value, 64)
}

func repeatByte(value byte, count int) string {
	result := make([]byte, count)
	for index := range result {
		result[index] = value
	}
	return string(result)
}

func assertTerminalFact(t *testing.T, event audit.Event, action string, result audit.Result, stored StoredSession) {
	t.Helper()
	if event.Action != action || event.Result != result || event.Target.Kind != audit.TargetTerminalSession ||
		event.Target.ID != stored.Session.ID || event.OperationID != "" ||
		event.IAMDecisionID != stored.IAMDecisionID || event.RequestDigest != stored.RequestDigest ||
		audit.ValidateEvent(event) != nil {
		t.Fatalf("invalid terminal Audit fact: %#v", event)
	}
}
