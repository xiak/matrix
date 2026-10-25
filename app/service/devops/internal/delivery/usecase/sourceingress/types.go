// Package sourceingress authenticates bounded provider webhooks and hands only
// provider-neutral change identity to the atomic run-admission workflow.
package sourceingress

import (
	"bytes"
	"context"
	"crypto/subtle"
	"errors"
	"fmt"

	devopsv1 "github.com/xiak/matrix/api/devops/v1"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/usecase/runadmission"
)

const (
	MaximumWebhookBodyBytes = 1 << 20
	minimumWebhookSecret    = 32
	maximumWebhookSecret    = 128
)

var (
	ErrInvalidArgument  = errors.New("source ingress input is invalid")
	ErrUnauthenticated  = errors.New("source ingress authentication failed")
	ErrUnsupportedEvent = errors.New("source ingress event is unsupported")
	ErrPrecondition     = errors.New("source ingress precondition failed")
	ErrUnavailable      = errors.New("source ingress is unavailable")
	ErrSecretNotFound   = errors.New("webhook secret is absent")
)

type Command struct {
	Scope              devopsv1.ResourceScope
	SourceConnectionID devopsv1.ResourceID
	ProviderEvent      string
	DeliveryID         string
	Signature          string
	Body               []byte
	RequestID          string
	CorrelationID      string
	TraceParent        string
}

type ProviderRequest struct {
	Connection devopsv1.SourceConnection
	Event      string
	DeliveryID string
	Signature  string
	Body       []byte
	SecretSet  WebhookSecretSet
}

// ProviderChange is the smallest authenticated provider projection. Endpoint
// scope, connection identity/version, delivery identity, and payload digest
// are supplied by the use case rather than trusted from an adapter result.
type ProviderChange struct {
	ExternalRepositoryID devopsv1.ResourceID
	TrustedBaseBranch    string
	Change               devopsv1.ChangeIdentity
}

type ConnectionReader interface {
	ReadSourceConnection(
		context.Context,
		devopsv1.ResourceScope,
		devopsv1.ResourceID,
	) (devopsv1.SourceConnection, bool, error)
}

type WebhookSecretResolver interface {
	ResolveWebhookSecrets(
		context.Context,
		devopsv1.ResourceScope,
		devopsv1.ResourceID,
	) (WebhookSecretSet, error)
}

type ProviderAdapter interface {
	ID() devopsv1.ResourceID
	AuthenticateAndNormalize(context.Context, ProviderRequest) (ProviderChange, error)
}

type AdmissionWorkflow interface {
	Admit(context.Context, runadmission.Command) (runadmission.Result, error)
}

// WebhookSecretSet carries one mandatory current value and one optional
// previous value during a bounded rotation window. Values are copied on entry
// and erased by the use case after the adapter returns.
type WebhookSecretSet struct {
	current  []byte
	previous []byte
}

func NewWebhookSecretSet(current, previous []byte) (WebhookSecretSet, error) {
	if !validWebhookSecret(current) || len(previous) != 0 && !validWebhookSecret(previous) {
		return WebhookSecretSet{}, errors.New("webhook secret set is invalid")
	}
	if len(previous) != 0 && subtle.ConstantTimeCompare(current, previous) == 1 {
		return WebhookSecretSet{}, errors.New("webhook rotation secrets must be distinct")
	}
	return WebhookSecretSet{
		current: append([]byte(nil), current...), previous: append([]byte(nil), previous...),
	}, nil
}

// Matches invokes matcher for every present candidate and does not
// short-circuit when the current key matches.
func (value WebhookSecretSet) Matches(matcher func([]byte) bool) bool {
	if matcher == nil || !value.valid() {
		return false
	}
	currentMatch := matcher(value.current)
	previousMatch := false
	if len(value.previous) != 0 {
		previousMatch = matcher(value.previous)
	}
	return currentMatch || previousMatch
}

func (value *WebhookSecretSet) Clear() {
	if value == nil {
		return
	}
	clear(value.current)
	clear(value.previous)
	value.current = nil
	value.previous = nil
}

func (value WebhookSecretSet) valid() bool {
	return validWebhookSecret(value.current) &&
		(len(value.previous) == 0 || validWebhookSecret(value.previous)) &&
		(len(value.previous) == 0 || !bytes.Equal(value.current, value.previous))
}

func validWebhookSecret(value []byte) bool {
	if len(value) < minimumWebhookSecret || len(value) > maximumWebhookSecret {
		return false
	}
	for _, character := range value {
		if character < 0x21 || character > 0x7e {
			return false
		}
	}
	return true
}

func validateProviderChange(value ProviderChange) error {
	if err := errors.Join(
		devopsv1.ValidateID("externalRepositoryId", string(value.ExternalRepositoryID)),
		devopsv1.ValidateTrustedDefaultBranch(value.TrustedBaseBranch),
		devopsv1.ValidateChangeIdentity(value.Change),
	); err != nil {
		return fmt.Errorf("provider change is invalid: %w", err)
	}
	return nil
}
