package notificationdispatch

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	iamv1 "github.com/xiak/matrix/api/iam/v1"
	"github.com/xiak/matrix/app/service/iam/internal/authority"
)

type dispatchTestRepository struct {
	mu            sync.Mutex
	active        atomic.Bool
	registration  *authority.EmailVerificationKeyset
	claims        []Claim
	observations  []authority.MailSubmission
	commitError   error
	completeError error
}

type dispatchTestTransaction struct {
	registration  *authority.EmailVerificationKeyset
	claims        []Claim
	observations  []authority.MailSubmission
	completeError error
}

func (repository *dispatchTestRepository) WithinTransaction(ctx context.Context, callback func(context.Context, Transaction) error) error {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	repository.active.Store(true)
	defer repository.active.Store(false)
	tx := &dispatchTestTransaction{registration: repository.registration, claims: repository.claims, completeError: repository.completeError}
	if err := callback(ctx, tx); err != nil {
		return err
	}
	if repository.commitError != nil {
		return repository.commitError
	}
	repository.claims = tx.claims
	repository.observations = append(repository.observations, tx.observations...)
	return nil
}

func (tx *dispatchTestTransaction) ReadKeyset(context.Context) (*authority.EmailVerificationKeyset, error) {
	return tx.registration, nil
}

func (tx *dispatchTestTransaction) Claim(context.Context, string) (Claim, bool, error) {
	if len(tx.claims) == 0 {
		return Claim{}, false, nil
	}
	claim := tx.claims[0]
	claim.Sealed.Nonce = bytes.Clone(claim.Sealed.Nonce)
	claim.Sealed.Ciphertext = bytes.Clone(claim.Sealed.Ciphertext)
	tx.claims = tx.claims[1:]
	return claim, true, nil
}

func (tx *dispatchTestTransaction) Complete(_ context.Context, claim Claim, worker string, observation authority.MailSubmission) error {
	if claim.Fence != 1 || worker != "mail-worker" || observation.Validate() != nil {
		return ErrUnavailable
	}
	if tx.completeError != nil {
		return tx.completeError
	}
	tx.observations = append(tx.observations, observation)
	return nil
}

type dispatchTestSubmitter func(context.Context, authority.SecurityMail) (authority.MailSubmission, error)

func (submit dispatchTestSubmitter) Submit(ctx context.Context, message authority.SecurityMail) (authority.MailSubmission, error) {
	return submit(ctx, message)
}

func dispatchFixture(t *testing.T) (Config, *dispatchTestRepository, Claim) {
	t.Helper()
	secret := func(value string) iamv1.Secret {
		t.Helper()
		result, err := iamv1.NewSecret(value)
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	scope := iamv1.SecurityMailInstallationScope{InstallationID: "mxi-" + strings.Repeat("a", 32), BootstrapDigest: "sha256:" + strings.Repeat("b", 64)}
	keyring := iamv1.EmailVerificationKeyring{APIVersion: iamv1.APIVersion, Kind: "EmailVerificationKeyring", Purpose: iamv1.EmailVerificationWrappingPurpose,
		Scope: scope, KeysetRevision: 1, ActiveKeyID: "email-key", Keys: []iamv1.EmailVerificationWrappingKey{{KeyID: "email-key", FormatVersion: 1,
			KeyMaterial: secret(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x53}, 32)))}}}
	protector, err := authority.NewEmailVerificationProtector(keyring)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	binding := iamv1.EmailVerificationBinding{InstallationID: scope.InstallationID, BootstrapDigest: scope.BootstrapDigest, AccountID: "account-a", UserID: "user-a",
		VerificationID: "verification-a", Recipient: "receiver@example.test", CredentialGeneration: 2, ContactRevision: 0, IssuedAt: now, ExpiresAt: now.Add(10 * time.Minute)}
	sealed, err := protector.Seal(binding, secret("01234567"))
	if err != nil {
		t.Fatal(err)
	}
	claim := Claim{AccountID: binding.AccountID, UserID: binding.UserID, InstallationID: scope.InstallationID, NotificationID: "notification-a",
		Kind: authority.MailAddressVerification, Recipient: binding.Recipient, CreatedAt: now, Fence: 1, LeaseExpiresAt: now.Add(45 * time.Second), Binding: binding, Sealed: sealed}
	registration := protector.Registration()
	return Config{WorkerID: "mail-worker", ChannelScope: scope, Keyring: keyring}, &dispatchTestRepository{registration: &registration, claims: []Claim{claim}}, claim
}

func TestDispatchSendsOnlyAfterCommitAndPreservesObservation(t *testing.T) {
	for _, observation := range []authority.MailSubmission{{State: authority.MailAccepted, SMTPCode: 250}, {State: authority.MailRejected, SMTPCode: 450},
		{State: authority.MailRejected, SMTPCode: 550}, {State: authority.MailUnknown}, {State: authority.MailUnavailable}} {
		t.Run(fmt.Sprint(observation), func(t *testing.T) {
			config, repository, claim := dispatchFixture(t)
			calls := 0
			submit := dispatchTestSubmitter(func(ctx context.Context, message authority.SecurityMail) (authority.MailSubmission, error) {
				calls++
				deadline, bounded := ctx.Deadline()
				if repository.active.Load() || len(repository.claims) != 0 || message.NotificationID != claim.NotificationID || message.Recipient != claim.Recipient ||
					!bytes.Equal(message.VerificationCode.CopyBytes(), []byte("01234567")) || !bounded || deadline.After(claim.LeaseExpiresAt.Add(-5*time.Second)) {
					t.Error("submission violated committed intent, transaction or deadline boundary")
				}
				return observation, nil
			})
			dispatcher, err := NewDispatcher(repository, submit, config)
			if err != nil {
				t.Fatal(err)
			}
			result, err := dispatcher.DispatchOnce(t.Context())
			if err != nil || !result.Claimed || result.Observation != observation || calls != 1 || len(repository.observations) != 1 || repository.observations[0] != observation {
				t.Fatal("durable observation changed", result, err)
			}
			if result, err := dispatcher.DispatchOnce(t.Context()); err != nil || result.Claimed || calls != 1 {
				t.Fatal("implicit resubmission", err)
			}
		})
	}
}

func TestDispatchFailureNeverInventsAnUnsentOrSuccessfulResult(t *testing.T) {
	for _, scenario := range []string{"missing-custody", "wrong-custody", "claim-commit-unknown", "bad-ciphertext", "wrong-installation", "wrong-user", "wrong-recipient", "adapter-error", "invalid-observation", "completion-conflict"} {
		t.Run(scenario, func(t *testing.T) {
			config, repository, _ := dispatchFixture(t)
			wantSends := 0
			switch scenario {
			case "missing-custody":
				repository.registration = nil
			case "wrong-custody":
				repository.registration.ContentDigest = "sha256:" + strings.Repeat("c", 64)
			case "claim-commit-unknown":
				repository.commitError = ErrUnavailable
			case "bad-ciphertext":
				repository.claims[0].Sealed.Ciphertext[0] ^= 1
			case "wrong-installation":
				repository.claims[0].Binding.InstallationID = "mxi-" + strings.Repeat("c", 32)
			case "wrong-user":
				repository.claims[0].UserID = "user-b"
			case "wrong-recipient":
				repository.claims[0].Recipient = "other@example.test"
			case "adapter-error", "invalid-observation":
				wantSends = 1
			case "completion-conflict":
				repository.completeError = ErrStaleLease
				wantSends = 1
			}
			calls := 0
			submit := dispatchTestSubmitter(func(context.Context, authority.SecurityMail) (authority.MailSubmission, error) {
				calls++
				if scenario == "adapter-error" {
					return authority.MailSubmission{}, errors.New("private external failure")
				}
				if scenario == "invalid-observation" {
					return authority.MailSubmission{State: authority.MailAccepted}, nil
				}
				return authority.MailSubmission{State: authority.MailAccepted, SMTPCode: 250}, nil
			})
			dispatcher, err := NewDispatcher(repository, submit, config)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := dispatcher.DispatchOnce(t.Context()); err == nil || strings.Contains(err.Error(), "private") {
				t.Fatal("missing sanitized failure", err)
			}
			if calls != wantSends || len(repository.observations) != 0 {
				t.Fatal("failed delivery invented an observation or retried")
			}
		})
	}
}

func TestDispatchHistoricalNoticeCannotCarryVerificationSecret(t *testing.T) {
	for _, kind := range []authority.SecurityMailKind{authority.MailContactVerified, authority.MailAuthenticatorBound} {
		t.Run(string(kind), func(t *testing.T) {
			config, repository, _ := dispatchFixture(t)
			repository.claims[0].Kind = kind
			sends := 0
			dispatcher, err := NewDispatcher(repository, dispatchTestSubmitter(func(_ context.Context, message authority.SecurityMail) (authority.MailSubmission, error) {
				sends++
				if message.VerificationCode.Present() || !message.VerificationExpiresAt.IsZero() {
					t.Error("notice carried old verification")
				}
				return authority.MailSubmission{State: authority.MailAccepted, SMTPCode: 250}, nil
			}), config)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := dispatcher.DispatchOnce(t.Context()); err == nil || sends != 0 {
				t.Fatal("notice accepted old ciphertext")
			}
			_, _, claim := dispatchFixture(t)
			claim.Kind, claim.Sealed = kind, authority.SealedEmailVerificationCode{}
			repository.claims = []Claim{claim}
			if result, err := dispatcher.DispatchOnce(t.Context()); err != nil || !result.Claimed || sends != 1 {
				t.Fatal("historical notice rejected", err)
			}
		})
	}
}

func TestDispatchHasTwoSlotsAndNoLocalWaitingQueue(t *testing.T) {
	config, repository, claim := dispatchFixture(t)
	repository.claims = []Claim{claim, claim, claim}
	entered, release := make(chan struct{}, 2), make(chan struct{})
	submitter := dispatchTestSubmitter(func(ctx context.Context, _ authority.SecurityMail) (authority.MailSubmission, error) {
		entered <- struct{}{}
		select {
		case <-release:
			return authority.MailSubmission{State: authority.MailAccepted, SMTPCode: 250}, nil
		case <-ctx.Done():
			return authority.MailSubmission{State: authority.MailUnknown}, nil
		}
	})
	dispatcher, err := NewDispatcher(repository, submitter, config)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	done := make(chan error, 2)
	for range 2 {
		go func() { _, err := dispatcher.DispatchOnce(ctx); done <- err }()
	}
	for range 2 {
		select {
		case <-entered:
		case <-ctx.Done():
			t.Fatal("two submissions did not start")
		}
	}
	if _, err := dispatcher.DispatchOnce(ctx); !errors.Is(err, ErrUnavailable) {
		t.Fatal("third submission queued", err)
	}
	close(release)
	for range 2 {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
	if len(repository.claims) != 1 || len(repository.observations) != 2 {
		t.Fatal("local capacity consumed a third intent")
	}
}

func TestDispatchClaimCannotBeAccidentallySerialized(t *testing.T) {
	_, _, claim := dispatchFixture(t)
	if _, err := json.Marshal(claim); err == nil {
		t.Fatal("private delivery claim serialized")
	}
	for _, value := range []string{fmt.Sprint(claim), fmt.Sprintf("%#v", claim)} {
		if strings.Contains(value, claim.Recipient) || strings.Contains(value, claim.NotificationID) {
			t.Fatal("claim formatting leaked identity")
		}
	}
}
