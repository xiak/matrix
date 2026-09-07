package sourceingress

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	devopsv1 "github.com/xiak/matrix/api/devops/v1"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/usecase/runadmission"
)

func TestReceiveBuildsServerOwnedNormalizedAdmission(t *testing.T) {
	connection := ingressConnection()
	reader := &fakeConnectionReader{connection: connection, found: true}
	resolver := &fakeSecretResolver{}
	adapter := &fakeProviderAdapter{change: ProviderChange{
		ExternalRepositoryID: "42", TrustedBaseBranch: "main",
		Change: devopsv1.ChangeIdentity{
			Number: 17, Action: devopsv1.ChangeUpdated,
			HeadCommit: strings.Repeat("1", 40), TrustedBaseCommit: strings.Repeat("2", 40),
		},
	}}
	admission := &fakeAdmissionWorkflow{}
	usecase, err := NewUsecase(reader, resolver, admission, adapter)
	if err != nil {
		t.Fatal(err)
	}
	command := ingressCommand()
	result, err := usecase.Receive(context.Background(), command)
	if err != nil || !result.Replayed {
		t.Fatalf("receive source event=%#v err=%v", result, err)
	}
	digest := sha256.Sum256(command.Body)
	change := admission.command.Change
	if change.Scope != command.Scope || change.SourceConnectionID != command.SourceConnectionID ||
		change.VerifiedSourceConnectionVersion != connection.Metadata.ResourceVersion ||
		change.ExternalRepositoryID != "42" || change.TrustedBaseBranch != "main" ||
		change.DeliveryID != command.DeliveryID ||
		change.CanonicalPayloadDigest != "sha256:"+hex.EncodeToString(digest[:]) ||
		change.Change != adapter.change.Change || admission.command.RequestID != command.RequestID ||
		admission.command.CorrelationID != command.CorrelationID ||
		admission.command.TraceParent != command.TraceParent {
		t.Fatalf("admission command did not bind the endpoint and payload: %#v", admission.command)
	}
	if reader.calls != 1 || resolver.calls != 1 || adapter.calls != 1 || admission.calls != 1 {
		t.Fatalf("source ingress calls reader=%d resolver=%d adapter=%d admission=%d",
			reader.calls, resolver.calls, adapter.calls, admission.calls)
	}
	for _, retained := range adapter.retainedSecrets {
		for _, character := range retained {
			if character != 0 {
				t.Fatal("webhook secret was not cleared after adapter use")
			}
		}
	}
}

func TestReceiveFailsClosedBeforeAdmission(t *testing.T) {
	tests := map[string]struct {
		configure func(*fakeConnectionReader, *fakeSecretResolver, *fakeProviderAdapter)
		want      error
	}{
		"missing connection": {
			configure: func(reader *fakeConnectionReader, _ *fakeSecretResolver, _ *fakeProviderAdapter) {
				reader.found = false
			},
			want: ErrUnauthenticated,
		},
		"connection read failure": {
			configure: func(reader *fakeConnectionReader, _ *fakeSecretResolver, _ *fakeProviderAdapter) {
				reader.err = errors.New("database detail")
			},
			want: ErrUnavailable,
		},
		"uninstalled adapter": {
			configure: func(reader *fakeConnectionReader, _ *fakeSecretResolver, _ *fakeProviderAdapter) {
				reader.connection.Spec.AdapterID = "adapter-not-installed"
			},
			want: ErrPrecondition,
		},
		"missing secret": {
			configure: func(_ *fakeConnectionReader, resolver *fakeSecretResolver, _ *fakeProviderAdapter) {
				resolver.err = ErrSecretNotFound
			},
			want: ErrUnauthenticated,
		},
		"secret backend failure": {
			configure: func(_ *fakeConnectionReader, resolver *fakeSecretResolver, _ *fakeProviderAdapter) {
				resolver.err = errors.New("filesystem detail")
			},
			want: ErrUnavailable,
		},
		"forged request": {
			configure: func(_ *fakeConnectionReader, _ *fakeSecretResolver, adapter *fakeProviderAdapter) {
				adapter.err = ErrUnauthenticated
			},
			want: ErrUnauthenticated,
		},
		"invalid adapter projection": {
			configure: func(_ *fakeConnectionReader, _ *fakeSecretResolver, adapter *fakeProviderAdapter) {
				adapter.change.ExternalRepositoryID = "bad/repository"
			},
			want: ErrUnavailable,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			reader := &fakeConnectionReader{connection: ingressConnection(), found: true}
			resolver := &fakeSecretResolver{}
			adapter := &fakeProviderAdapter{change: validProviderChange()}
			admission := &fakeAdmissionWorkflow{}
			test.configure(reader, resolver, adapter)
			usecase, err := NewUsecase(reader, resolver, admission, adapter)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := usecase.Receive(context.Background(), ingressCommand()); !errors.Is(err, test.want) {
				t.Fatalf("source ingress error=%v want=%v", err, test.want)
			}
			if admission.calls != 0 {
				t.Fatal("failed source ingress reached durable admission")
			}
		})
	}
}

func TestWebhookSecretSetRotationIsBoundedAndConstantWork(t *testing.T) {
	current := []byte("current-secret-00000000000000000001")
	previous := []byte("previous-secret-000000000000000001")
	set, err := NewWebhookSecretSet(current, previous)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	if !set.Matches(func(candidate []byte) bool {
		calls++
		return string(candidate) == string(current)
	}) || calls != 2 {
		t.Fatalf("rotating secret match calls=%d", calls)
	}
	set.Clear()
	if set.Matches(func([]byte) bool { return true }) {
		t.Fatal("cleared secret set remained usable")
	}
	if _, err := NewWebhookSecretSet([]byte("short"), nil); err == nil {
		t.Fatal("short webhook secret was accepted")
	}
	if _, err := NewWebhookSecretSet(current, current); err == nil {
		t.Fatal("duplicate rotation secret was accepted")
	}
}

type fakeConnectionReader struct {
	connection devopsv1.SourceConnection
	found      bool
	err        error
	calls      int
}

func (value *fakeConnectionReader) ReadSourceConnection(
	_ context.Context,
	_ devopsv1.ResourceScope,
	_ devopsv1.ResourceID,
) (devopsv1.SourceConnection, bool, error) {
	value.calls++
	return value.connection, value.found, value.err
}

type fakeSecretResolver struct {
	err   error
	calls int
}

func (value *fakeSecretResolver) ResolveWebhookSecrets(
	_ context.Context,
	_ devopsv1.ResourceScope,
	_ devopsv1.ResourceID,
) (WebhookSecretSet, error) {
	value.calls++
	if value.err != nil {
		return WebhookSecretSet{}, value.err
	}
	return NewWebhookSecretSet(
		[]byte("current-webhook-secret-000000000001"),
		[]byte("previous-webhook-secret-0000000001"),
	)
}

type fakeProviderAdapter struct {
	change          ProviderChange
	err             error
	calls           int
	retainedSecrets [][]byte
}

func (*fakeProviderAdapter) ID() devopsv1.ResourceID { return "adapter-one" }

func (value *fakeProviderAdapter) AuthenticateAndNormalize(
	_ context.Context,
	request ProviderRequest,
) (ProviderChange, error) {
	value.calls++
	request.SecretSet.Matches(func(candidate []byte) bool {
		value.retainedSecrets = append(value.retainedSecrets, candidate)
		return true
	})
	return value.change, value.err
}

type fakeAdmissionWorkflow struct {
	command runadmission.Command
	calls   int
}

func (value *fakeAdmissionWorkflow) Admit(
	_ context.Context,
	command runadmission.Command,
) (runadmission.Result, error) {
	value.calls++
	value.command = command
	return runadmission.Result{Replayed: true}, nil
}

func ingressConnection() devopsv1.SourceConnection {
	now := time.Date(2026, 9, 8, 1, 2, 3, 0, time.UTC)
	return devopsv1.SourceConnection{
		APIVersion: devopsv1.APIVersion, Kind: "SourceConnection",
		Metadata: devopsv1.ResourceMetadata{
			ID: "connection-one", Name: "connection-one",
			Scope: devopsv1.ResourceScope{TenantID: "tenant-one"}, ResourceVersion: 7,
			CreatedAt: now, UpdatedAt: now,
		},
		Spec: devopsv1.SourceConnectionSpec{
			AdapterID: "adapter-one", AllowedEndpointOrigins: []string{"https://git.example.com"},
			WebhookSecretRef: "webhook-secret", FetchCredentialRef: "fetch-secret", ReportCredentialRef: "report-secret",
		},
		Status: devopsv1.SourceConnectionStatus{Health: devopsv1.SourceConnectionReady, ObservedAt: now},
	}
}

func validProviderChange() ProviderChange {
	return ProviderChange{
		ExternalRepositoryID: "42", TrustedBaseBranch: "main",
		Change: devopsv1.ChangeIdentity{
			Number: 17, Action: devopsv1.ChangeOpened,
			HeadCommit: strings.Repeat("1", 40), TrustedBaseCommit: strings.Repeat("2", 40),
		},
	}
}

func ingressCommand() Command {
	return Command{
		Scope: devopsv1.ResourceScope{TenantID: "tenant-one"}, SourceConnectionID: "connection-one",
		ProviderEvent: "pull_request", DeliveryID: "123e4567-e89b-42d3-a456-426614174000",
		Signature: strings.Repeat("a", 64), Body: []byte(`{"action":"opened"}`),
		RequestID: "request-ingress", CorrelationID: "correlation-ingress",
		TraceParent: "00-5bf92f3577b34da6a3ce929d0e0e4736-10f067aa0ba902b7-01",
	}
}
