package audithttp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"

	auditv1 "github.com/xiak/matrix/api/audit/v1"
	iamv1 "github.com/xiak/matrix/api/iam/v1"
	"github.com/xiak/matrix/app/service/internal/authorityhttp"
	"github.com/xiak/matrix/app/service/paas/internal/audit"
)

var _ audit.Ingestor = (*Client)(nil)

type Config struct {
	Endpoint   string
	Credential iamv1.Secret
	HTTPClient *http.Client
}

type Client struct {
	http       *authorityhttp.Client
	credential iamv1.Secret
}

func NewClient(config Config) (*Client, error) {
	httpClient, err := authorityhttp.New(config.Endpoint, config.HTTPClient)
	if err != nil {
		return nil, errors.New("Audit endpoint is invalid")
	}
	if !config.Credential.Present() {
		return nil, errors.New("PaaS Audit producer credential is required")
	}
	return &Client{http: httpClient, credential: config.Credential}, nil
}

func (client *Client) Ready(ctx context.Context) error {
	if client == nil || client.http == nil || ctx == nil {
		return audit.ErrUnavailable
	}
	response, err := client.http.Do(
		ctx,
		http.MethodGet,
		"/ready",
		nil,
		"",
		client.credential,
		iamv1.Secret{},
	)
	if err != nil {
		return audit.ErrUnavailable
	}
	defer response.Body.Close()
	var readiness auditv1.Readiness
	if response.StatusCode != http.StatusOK || !authorityhttp.ResponseIsJSON(response) ||
		auditv1.DecodeRequest(response.Body, &readiness) != nil ||
		auditv1.ValidateReadiness(readiness) != nil ||
		readiness.State != auditv1.ReadinessReady {
		return audit.ErrUnavailable
	}
	return nil
}

func (client *Client) Ingest(ctx context.Context, event audit.Event) error {
	if client == nil || client.http == nil {
		return audit.ErrUnavailable
	}
	if ctx == nil || audit.ValidateEvent(event) != nil {
		return audit.ErrInvalid
	}
	auditEvent, err := audit.ToV1(event)
	if err != nil {
		return audit.ErrInvalid
	}
	body, err := json.Marshal(auditEvent)
	if err != nil {
		return audit.ErrInvalid
	}
	defer clear(body)
	response, err := client.http.Do(
		ctx,
		http.MethodPost,
		"/v1/events",
		bytes.NewReader(body),
		"application/json",
		client.credential,
		iamv1.Secret{},
	)
	if err != nil {
		return audit.ErrUnavailable
	}
	defer response.Body.Close()
	wantOutcome := auditv1.IngestionOutcome("")
	switch response.StatusCode {
	case http.StatusCreated:
		wantOutcome = auditv1.IngestionAccepted
	case http.StatusOK:
		wantOutcome = auditv1.IngestionDuplicate
	default:
		return auditStatusError(response.StatusCode)
	}
	var result auditv1.IngestionResult
	if !authorityhttp.ResponseIsJSON(response) ||
		auditv1.DecodeRequest(response.Body, &result) != nil ||
		auditv1.ValidateIngestionResult(result) != nil ||
		result.Outcome != wantOutcome || result.Record.Source != auditv1.SourcePaaS ||
		result.Record.Event != auditEvent {
		return audit.ErrUnavailable
	}
	return nil
}

func auditStatusError(status int) error {
	switch status {
	case http.StatusUnauthorized, http.StatusForbidden:
		return audit.ErrUnauthenticated
	case http.StatusBadRequest, http.StatusRequestEntityTooLarge,
		http.StatusUnsupportedMediaType, http.StatusUnprocessableEntity:
		return audit.ErrInvalid
	case http.StatusConflict:
		return audit.ErrConflict
	default:
		return audit.ErrUnavailable
	}
}
