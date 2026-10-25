package sourceingress

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"unicode"
	"unicode/utf8"

	devopsv1 "github.com/xiak/matrix/api/devops/v1"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/domain"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/port"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/usecase/runadmission"
)

type Usecase struct {
	connections ConnectionReader
	secrets     WebhookSecretResolver
	admission   AdmissionWorkflow
	adapters    map[devopsv1.ResourceID]ProviderAdapter
}

func NewUsecase(
	connections ConnectionReader,
	secrets WebhookSecretResolver,
	admission AdmissionWorkflow,
	adapters ...ProviderAdapter,
) (*Usecase, error) {
	if connections == nil || secrets == nil || admission == nil || len(adapters) == 0 {
		return nil, errors.New("source ingress dependencies are required")
	}
	registered := make(map[devopsv1.ResourceID]ProviderAdapter, len(adapters))
	for _, adapter := range adapters {
		if adapter == nil || devopsv1.ValidateID("adapterId", string(adapter.ID())) != nil {
			return nil, errors.New("source ingress adapter is invalid")
		}
		if _, exists := registered[adapter.ID()]; exists {
			return nil, errors.New("source ingress adapter identity is duplicated")
		}
		registered[adapter.ID()] = adapter
	}
	return &Usecase{
		connections: connections, secrets: secrets, admission: admission, adapters: registered,
	}, nil
}

func (usecase *Usecase) Receive(ctx context.Context, command Command) (runadmission.Result, error) {
	if usecase == nil || usecase.connections == nil || usecase.secrets == nil || usecase.admission == nil {
		return runadmission.Result{}, ErrUnavailable
	}
	if ctx == nil {
		return runadmission.Result{}, fmt.Errorf("%w: context is nil", ErrInvalidArgument)
	}
	if err := validateCommand(command); err != nil {
		return runadmission.Result{}, err
	}
	connection, found, err := usecase.connections.ReadSourceConnection(
		ctx, command.Scope, command.SourceConnectionID,
	)
	if err != nil {
		return runadmission.Result{}, mapUnavailable(ctx, err)
	}
	if !found {
		return runadmission.Result{}, ErrUnauthenticated
	}
	if devopsv1.ValidateSourceConnection(connection) != nil ||
		connection.Metadata.Scope != command.Scope ||
		connection.Metadata.ID != command.SourceConnectionID {
		return runadmission.Result{}, ErrUnavailable
	}
	adapter, found := usecase.adapters[connection.Spec.AdapterID]
	if !found {
		return runadmission.Result{}, ErrPrecondition
	}
	secrets, err := usecase.secrets.ResolveWebhookSecrets(
		ctx, command.Scope, connection.Spec.WebhookSecretRef,
	)
	if err != nil {
		if errors.Is(err, ErrSecretNotFound) {
			return runadmission.Result{}, ErrUnauthenticated
		}
		return runadmission.Result{}, mapUnavailable(ctx, err)
	}
	defer secrets.Clear()
	if !secrets.valid() {
		return runadmission.Result{}, ErrUnavailable
	}

	body := append([]byte(nil), command.Body...)
	defer clear(body)
	digest := sha256.Sum256(command.Body)
	providerChange, err := adapter.AuthenticateAndNormalize(ctx, ProviderRequest{
		Connection: connection, Event: command.ProviderEvent, DeliveryID: command.DeliveryID,
		Signature: command.Signature, Body: body, SecretSet: secrets,
	})
	if err != nil {
		switch {
		case errors.Is(err, ErrUnauthenticated), errors.Is(err, ErrInvalidArgument),
			errors.Is(err, ErrUnsupportedEvent), errors.Is(err, ErrPrecondition):
			return runadmission.Result{}, err
		default:
			return runadmission.Result{}, mapUnavailable(ctx, err)
		}
	}
	if validateProviderChange(providerChange) != nil {
		return runadmission.Result{}, ErrUnavailable
	}
	normalized := domain.NormalizedChange{
		Scope:                           command.Scope,
		SourceConnectionID:              command.SourceConnectionID,
		VerifiedSourceConnectionVersion: connection.Metadata.ResourceVersion,
		ExternalRepositoryID:            providerChange.ExternalRepositoryID,
		TrustedBaseBranch:               providerChange.TrustedBaseBranch,
		DeliveryID:                      command.DeliveryID,
		CanonicalPayloadDigest:          "sha256:" + hex.EncodeToString(digest[:]),
		Change:                          providerChange.Change,
	}
	result, err := usecase.admission.Admit(ctx, runadmission.Command{
		Change: normalized, RequestID: command.RequestID,
		CorrelationID: command.CorrelationID, TraceParent: command.TraceParent,
	})
	if err != nil {
		return runadmission.Result{}, err
	}
	return result, nil
}

func validateCommand(value Command) error {
	var problems []error
	problems = append(problems,
		devopsv1.ValidateResourceScope(value.Scope),
		devopsv1.ValidateID("sourceConnectionId", string(value.SourceConnectionID)),
		devopsv1.ValidateID("requestId", value.RequestID),
		devopsv1.ValidateID("correlationId", value.CorrelationID),
	)
	if value.TraceParent != "" {
		problems = append(problems, port.ValidateTraceParent(value.TraceParent))
	}
	for _, candidate := range []struct {
		name  string
		field string
	}{
		{name: "provider event", field: value.ProviderEvent},
		{name: "delivery identity", field: value.DeliveryID},
		{name: "signature", field: value.Signature},
	} {
		name, field := candidate.name, candidate.field
		if len(field) == 0 || len(field) > 256 || !utf8.ValidString(field) {
			problems = append(problems, fmt.Errorf("%s is invalid", name))
			continue
		}
		for _, character := range field {
			if unicode.IsControl(character) {
				problems = append(problems, fmt.Errorf("%s is invalid", name))
				break
			}
		}
	}
	if len(value.Body) == 0 || len(value.Body) > MaximumWebhookBodyBytes {
		problems = append(problems, errors.New("webhook body is invalid"))
	}
	if err := errors.Join(problems...); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidArgument, err)
	}
	return nil
}

func mapUnavailable(ctx context.Context, _ error) error {
	if contextErr := ctx.Err(); contextErr != nil {
		return contextErr
	}
	return fmt.Errorf("%w: dependency failed", ErrUnavailable)
}
