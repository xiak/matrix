// Package notificationdispatch owns one durable security-mail attempt. It has
// no generic send endpoint or identity authority; SMTP follows a committed
// fenced claim, and uncertainty can never be reinterpreted as unsent mail.
package notificationdispatch

import (
	"context"
	"errors"
	"time"

	iamv1 "github.com/xiak/matrix/api/iam/v1"
	"github.com/xiak/matrix/app/service/iam/internal/authority"
)

var (
	ErrUnavailable          = errors.New("IAM notification delivery unavailable")
	ErrStaleLease           = errors.New("IAM notification lease conflicts")
	ErrRetryableTransaction = errors.New("IAM notification transaction retryable")
)

type Claim struct {
	AccountID      iamv1.AccountID
	UserID         iamv1.PrincipalID
	InstallationID string
	NotificationID string
	Kind           authority.SecurityMailKind
	Recipient      string
	CreatedAt      time.Time
	Fence          uint64
	LeaseExpiresAt time.Time
	Binding        iamv1.EmailVerificationBinding
	Sealed         authority.SealedEmailVerificationCode
}

func (Claim) String() string               { return "[REDACTED]" }
func (Claim) GoString() string             { return "notificationdispatch.Claim{[REDACTED]}" }
func (Claim) MarshalJSON() ([]byte, error) { return nil, ErrUnavailable }

type Transaction interface {
	ReadKeyset(context.Context) (*authority.EmailVerificationKeyset, error)
	Claim(context.Context, string) (Claim, bool, error)
	Complete(context.Context, Claim, string, authority.MailSubmission) error
}

type Repository interface {
	WithinTransaction(context.Context, func(context.Context, Transaction) error) error
}
type Submitter interface {
	Submit(context.Context, authority.SecurityMail) (authority.MailSubmission, error)
}

type Config struct {
	WorkerID     string
	ChannelScope iamv1.SecurityMailInstallationScope
	Keyring      iamv1.EmailVerificationKeyring
}

type Dispatcher struct {
	repository Repository
	submitter  Submitter
	workerID   string
	protector  *authority.EmailVerificationProtector
	slots      chan struct{}
}

// Result contains no subject, address, secret or SMTP-provided error text.
// A false Claimed says nothing about pending work held by another replica.
type Result struct {
	Claimed     bool
	Observation authority.MailSubmission
}

func NewDispatcher(repository Repository, submitter Submitter, config Config) (*Dispatcher, error) {
	if repository == nil || submitter == nil || iamv1.ValidateID("workerId", config.WorkerID) != nil || config.ChannelScope != config.Keyring.Scope {
		return nil, ErrUnavailable
	}
	protector, err := authority.NewEmailVerificationProtector(config.Keyring)
	if err != nil {
		return nil, ErrUnavailable
	}
	return &Dispatcher{repository: repository, submitter: submitter, workerID: config.WorkerID, protector: protector, slots: make(chan struct{}, 2)}, nil
}

func (service *Dispatcher) check(ctx context.Context, tx Transaction) error {
	actual, err := tx.ReadKeyset(ctx)
	if err != nil {
		return err
	}
	if actual == nil || !service.protector.Matches(*actual) {
		return ErrUnavailable
	}
	return nil
}

func (service *Dispatcher) Ready(ctx context.Context) error {
	if service == nil || ctx == nil {
		return ErrUnavailable
	}
	return service.repository.WithinTransaction(ctx, func(ctx context.Context, tx Transaction) error { return service.check(ctx, tx) })
}

func (service *Dispatcher) DispatchOnce(ctx context.Context) (Result, error) {
	if service == nil || ctx == nil {
		return Result{}, ErrUnavailable
	}
	select {
	case service.slots <- struct{}{}:
		defer func() { <-service.slots }()
	default:
		return Result{}, ErrUnavailable
	}
	var claim Claim
	var found bool
	err := service.repository.WithinTransaction(ctx, func(ctx context.Context, tx Transaction) error {
		if err := service.check(ctx, tx); err != nil {
			return err
		}
		var err error
		claim, found, err = tx.Claim(ctx, service.workerID)
		return err
	})
	if err != nil {
		return Result{}, err
	}
	if !found {
		return Result{}, nil
	}
	defer clear(claim.Sealed.Nonce)
	defer clear(claim.Sealed.Ciphertext)
	scope := service.protector.Registration().Scope
	if claim.InstallationID != scope.InstallationID || claim.Binding.InstallationID != scope.InstallationID || claim.Binding.BootstrapDigest != scope.BootstrapDigest || claim.Fence == 0 ||
		iamv1.ValidateID("accountId", string(claim.AccountID)) != nil || iamv1.ValidateID("userId", string(claim.UserID)) != nil ||
		claim.Binding.AccountID != claim.AccountID || claim.Binding.UserID != claim.UserID || claim.Binding.Recipient != claim.Recipient ||
		claim.LeaseExpiresAt.Location() != time.UTC || !claim.LeaseExpiresAt.After(claim.CreatedAt) {
		return Result{Claimed: true}, ErrUnavailable
	}
	message := authority.SecurityMail{NotificationID: claim.NotificationID, Kind: claim.Kind, Recipient: claim.Recipient, OccurredAt: claim.CreatedAt}
	switch claim.Kind {
	case authority.MailAddressVerification:
		message.VerificationCode, err = service.protector.Open(claim.Binding, claim.Sealed)
		if err != nil {
			return Result{Claimed: true}, ErrUnavailable
		}
		message.VerificationExpiresAt = claim.Binding.ExpiresAt
	case authority.MailContactVerified, authority.MailAuthenticatorBound:
		if len(claim.Sealed.Nonce) != 0 || len(claim.Sealed.Ciphertext) != 0 || claim.Sealed.KeyID != "" || claim.Sealed.FormatVersion != 0 {
			return Result{Claimed: true}, ErrUnavailable
		}
	default:
		return Result{Claimed: true}, ErrUnavailable
	}
	if message.Validate() != nil {
		return Result{Claimed: true}, ErrUnavailable
	}
	// Do not begin a send whose original verification has already expired.
	// Identity changes after a claim cannot recall SMTP bytes; confirmation
	// always rechecks current identity and the original absolute expiry in SQL.
	deadline := claim.LeaseExpiresAt.Add(-5 * time.Second)
	if claim.Kind == authority.MailAddressVerification && claim.Binding.ExpiresAt.Before(deadline) {
		deadline = claim.Binding.ExpiresAt
	}
	observation := authority.MailSubmission{State: authority.MailUnavailable}
	if time.Now().Before(deadline) {
		sendCtx, cancel := context.WithDeadline(ctx, deadline)
		observation, err = service.submitter.Submit(sendCtx, message)
		cancel()
		// An unknown adapter failure cannot be logged as an explicit rejection
		// or immediately retried. Leave the committed lease to expire UNKNOWN.
		if err != nil || observation.Validate() != nil {
			return Result{Claimed: true}, ErrUnavailable
		}
	}
	err = service.repository.WithinTransaction(ctx, func(ctx context.Context, tx Transaction) error {
		return tx.Complete(ctx, claim, service.workerID, observation)
	})
	if err != nil {
		return Result{Claimed: true}, err
	}
	return Result{Claimed: true, Observation: observation}, nil
}
