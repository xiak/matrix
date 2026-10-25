package runnerexecution

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/xiak/matrix/app/service/devops/internal/delivery/port"
)

type leaseEvent struct {
	cancellation bool
	err          error
}

type leaseSession struct {
	service *Service
	ctx     context.Context
	cancel  context.CancelFunc
	done    chan struct{}
	events  chan leaseEvent

	mutex              sync.Mutex
	entry              port.RunnerJournalEntry
	failure            error
	cancellationSignal bool
	stopOnce           sync.Once
}

func startLeaseSession(
	ctx context.Context,
	service *Service,
	entry port.RunnerJournalEntry,
) (*leaseSession, error) {
	if ctx == nil || service == nil || service.renewalInterval <= 0 ||
		!service.now().Before(entry.Assignment.LeaseExpiresAt) {
		return nil, ErrUnavailable
	}
	renewContext, cancel := context.WithCancel(ctx)
	session := &leaseSession{
		service: service, ctx: renewContext, cancel: cancel,
		done: make(chan struct{}), events: make(chan leaseEvent, 1), entry: entry,
	}
	// Claim streaming and its durable journal commit can consume a material
	// part of the short gateway lease. Re-prove and extend authority before
	// workspace work or a sandbox side effect is allowed to begin.
	if err := session.renewOnce(); err != nil {
		cancel()
		return nil, err
	}
	go session.renew()
	return session, nil
}

func (session *leaseSession) renew() {
	defer close(session.done)
	ticker := time.NewTicker(session.service.renewalInterval)
	defer ticker.Stop()
	for {
		select {
		case <-session.ctx.Done():
			return
		case <-ticker.C:
			if err := session.renewOnce(); err != nil {
				session.fail(err)
				return
			}
		}
	}
}

func (session *leaseSession) renewOnce() error {
	session.mutex.Lock()
	defer session.mutex.Unlock()
	if session.failure != nil {
		return session.failure
	}
	renewal, err := session.service.gateway.Renew(session.ctx, session.entry.Assignment)
	if err != nil {
		return errors.Join(ErrOutcomeUnknown, err)
	}
	next, err := session.service.journal.ApplyRenewal(
		session.ctx, session.entry.Assignment, renewal,
	)
	if err != nil || validateEntry(next, session.service.gateway.RunnerID()) != nil {
		return errors.Join(ErrOutcomeUnknown, err)
	}
	session.entry = next
	if next.CancellationRequested && !session.cancellationSignal {
		session.cancellationSignal = true
		select {
		case session.events <- leaseEvent{cancellation: true}:
		default:
		}
	}
	return nil
}

func (session *leaseSession) fail(err error) {
	session.mutex.Lock()
	if session.failure == nil {
		session.failure = err
	}
	session.mutex.Unlock()
	select {
	case session.events <- leaseEvent{err: err}:
	default:
	}
	session.cancel()
}

func (session *leaseSession) current() port.RunnerJournalEntry {
	session.mutex.Lock()
	defer session.mutex.Unlock()
	return session.entry
}

func (session *leaseSession) currentFailure() error {
	session.mutex.Lock()
	defer session.mutex.Unlock()
	return session.failure
}

func (session *leaseSession) change(
	transition func(port.RunnerJournalEntry) (port.RunnerJournalEntry, error),
) error {
	if session == nil || transition == nil {
		return ErrInvalid
	}
	session.mutex.Lock()
	defer session.mutex.Unlock()
	if session.failure != nil {
		return session.failure
	}
	next, err := transition(session.entry)
	if err != nil {
		return err
	}
	session.entry = next
	return nil
}

func (session *leaseSession) stop() {
	if session == nil {
		return
	}
	session.stopOnce.Do(func() {
		session.cancel()
		<-session.done
	})
}
