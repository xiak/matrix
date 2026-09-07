package gitea

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	devopsv1 "github.com/xiak/matrix/api/devops/v1"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/usecase/sourceingress"
)

const (
	currentSecret  = "current-webhook-secret-000000000001"
	previousSecret = "previous-webhook-secret-0000000001"
)

func TestAuthenticateAndNormalizeFixedGiteaPullRequest(t *testing.T) {
	for providerAction, expected := range map[string]devopsv1.ChangeAction{
		"opened": devopsv1.ChangeOpened, "reopened": devopsv1.ChangeReopened,
		"synchronized": devopsv1.ChangeUpdated,
	} {
		t.Run(providerAction, func(t *testing.T) {
			body := []byte(strings.ReplaceAll(validPayload, `"ACTION"`, `"`+providerAction+`"`))
			request := providerRequest(t, body, previousSecret)
			change, err := NewAdapter().AuthenticateAndNormalize(context.Background(), request)
			if err != nil {
				t.Fatalf("normalize authenticated webhook: %v", err)
			}
			if change.ExternalRepositoryID != "42" || change.TrustedBaseBranch != "main" ||
				change.Change.Number != 17 || change.Change.Action != expected ||
				change.Change.HeadCommit != strings.Repeat("1", 40) ||
				change.Change.TrustedBaseCommit != strings.Repeat("2", 40) {
				t.Fatalf("normalized change=%#v", change)
			}
		})
	}
}

func TestGiteaAuthenticationPrecedesPayloadInterpretation(t *testing.T) {
	body := []byte(`{"action":"opened","action":"closed"}`)
	request := providerRequest(t, body, "wrong-webhook-secret-0000000000001")
	if _, err := NewAdapter().AuthenticateAndNormalize(context.Background(), request); !errors.Is(err, sourceingress.ErrUnauthenticated) {
		t.Fatalf("unsigned ambiguous payload error=%v", err)
	}
	request = providerRequest(t, body, currentSecret)
	if _, err := NewAdapter().AuthenticateAndNormalize(context.Background(), request); !errors.Is(err, sourceingress.ErrInvalidArgument) {
		t.Fatalf("signed ambiguous payload error=%v", err)
	}
}

func TestGiteaWebhookFailsClosed(t *testing.T) {
	tests := map[string]func(*sourceingress.ProviderRequest){
		"uppercase signature":   func(value *sourceingress.ProviderRequest) { value.Signature = strings.ToUpper(value.Signature) },
		"wrong event":           func(value *sourceingress.ProviderRequest) { value.Event = "push" },
		"noncanonical delivery": func(value *sourceingress.ProviderRequest) { value.DeliveryID = "delivery-1" },
		"unsupported action": func(value *sourceingress.ProviderRequest) {
			value.Body = []byte(strings.Replace(validPayload, `"ACTION"`, `"closed"`, 1))
			resign(value, currentSecret)
		},
		"repository mismatch": func(value *sourceingress.ProviderRequest) {
			value.Body = []byte(strings.Replace(validPayload, `"repo_id":42`, `"repo_id":43`, 1))
			resign(value, currentSecret)
		},
		"untrusted origin": func(value *sourceingress.ProviderRequest) {
			value.Body = []byte(strings.ReplaceAll(validPayload, "https://git.example.com", "https://other.example.com"))
			resign(value, currentSecret)
		},
		"invalid base branch": func(value *sourceingress.ProviderRequest) {
			value.Body = []byte(strings.Replace(validPayload, `"ref":"main"`, `"ref":"refs/main.lock"`, 1))
			resign(value, currentSecret)
		},
		"mixed object format": func(value *sourceingress.ProviderRequest) {
			value.Body = []byte(strings.ReplaceAll(validPayload, `"object_format_name":"sha1"`, `"object_format_name":"sha256"`))
			resign(value, currentSecret)
		},
		"case-folded duplicate": func(value *sourceingress.ProviderRequest) {
			value.Body = []byte(strings.Replace(validPayload, `"action":"ACTION"`, `"action":"opened","Action":"opened"`, 1))
			resign(value, currentSecret)
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			body := []byte(strings.Replace(validPayload, `"ACTION"`, `"opened"`, 1))
			request := providerRequest(t, body, currentSecret)
			mutate(&request)
			_, err := NewAdapter().AuthenticateAndNormalize(context.Background(), request)
			if err == nil {
				t.Fatal("invalid Gitea webhook was accepted")
			}
		})
	}
}

func FuzzAuthenticatedGiteaPayload(f *testing.F) {
	f.Add([]byte(strings.Replace(validPayload, `"ACTION"`, `"opened"`, 1)))
	f.Add([]byte(`{"action":"opened","action":"closed"}`))
	f.Add([]byte(`null`))
	f.Fuzz(func(t *testing.T, body []byte) {
		if len(body) == 0 || len(body) > sourceingress.MaximumWebhookBodyBytes {
			return
		}
		secretSet, err := sourceingress.NewWebhookSecretSet([]byte(currentSecret), nil)
		if err != nil {
			t.Fatal(err)
		}
		defer secretSet.Clear()
		request := sourceingress.ProviderRequest{
			Connection: validConnection(), Event: "pull_request",
			DeliveryID: "123e4567-e89b-42d3-a456-426614174000",
			Body:       append([]byte(nil), body...), SecretSet: secretSet,
		}
		resign(&request, currentSecret)
		change, err := NewAdapter().AuthenticateAndNormalize(context.Background(), request)
		if err == nil {
			if devopsv1.ValidateID("externalRepositoryId", string(change.ExternalRepositoryID)) != nil ||
				devopsv1.ValidateTrustedDefaultBranch(change.TrustedBaseBranch) != nil ||
				devopsv1.ValidateChangeIdentity(change.Change) != nil {
				t.Fatalf("adapter emitted invalid normalized change: %#v", change)
			}
		}
	})
}

func providerRequest(t *testing.T, body []byte, signingSecret string) sourceingress.ProviderRequest {
	t.Helper()
	secretSet, err := sourceingress.NewWebhookSecretSet([]byte(currentSecret), []byte(previousSecret))
	if err != nil {
		t.Fatal(err)
	}
	request := sourceingress.ProviderRequest{
		Connection: validConnection(), Event: "pull_request",
		DeliveryID: "123e4567-e89b-42d3-a456-426614174000",
		Body:       body, SecretSet: secretSet,
	}
	resign(&request, signingSecret)
	return request
}

func resign(request *sourceingress.ProviderRequest, secret string) {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(request.Body)
	request.Signature = hex.EncodeToString(mac.Sum(nil))
}

func validConnection() devopsv1.SourceConnection {
	now := time.Date(2026, 9, 8, 1, 2, 3, 0, time.UTC)
	return devopsv1.SourceConnection{
		APIVersion: devopsv1.APIVersion, Kind: "SourceConnection",
		Metadata: devopsv1.ResourceMetadata{
			ID: "connection-gitea", Name: "gitea", Scope: devopsv1.ResourceScope{TenantID: "tenant-one"},
			ResourceVersion: 3, CreatedAt: now, UpdatedAt: now,
		},
		Spec: devopsv1.SourceConnectionSpec{
			AdapterID: AdapterID, AllowedEndpointOrigins: []string{"https://git.example.com"},
			WebhookSecretRef: "webhook-secret", FetchCredentialRef: "fetch-secret", ReportCredentialRef: "report-secret",
		},
		Status: devopsv1.SourceConnectionStatus{Health: devopsv1.SourceConnectionReady, ObservedAt: now},
	}
}

var validPayload = `{
  "action":"ACTION",
  "number":17,
  "repository":{
    "id":42,
    "full_name":"matrix/api",
    "url":"https://git.example.com/api/v1/repos/matrix/api",
    "html_url":"https://git.example.com/matrix/api",
    "clone_url":"https://git.example.com/matrix/api.git",
    "object_format_name":"sha1"
  },
  "pull_request":{
    "number":17,
    "base":{
      "ref":"main",
      "sha":"` + strings.Repeat("2", 40) + `",
      "repo_id":42,
      "repo":{
        "id":42,
        "full_name":"matrix/api",
        "url":"https://git.example.com/api/v1/repos/matrix/api",
        "html_url":"https://git.example.com/matrix/api",
        "clone_url":"https://git.example.com/matrix/api.git",
        "object_format_name":"sha1"
      }
    },
    "head":{"ref":"feature/change","sha":"` + strings.Repeat("1", 40) + `","repo_id":77}
  },
  "sender":{"id":999,"login":"must-not-cross-boundary"},
  "labels":[{"name":"must-not-cross-boundary"}]
}`
