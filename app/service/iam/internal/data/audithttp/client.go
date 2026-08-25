package audithttp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	auditv1 "github.com/xiak/matrix/api/audit/v1"
	iamv1 "github.com/xiak/matrix/api/iam/v1"
	"github.com/xiak/matrix/app/service/iam/internal/usecase/auditdispatch"
	"github.com/xiak/matrix/app/service/internal/authorityhttp"
)

var _ auditdispatch.AuditIngestor = (*Client)(nil)

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
		return nil, errors.New("IAM Audit producer credential is required")
	}
	return &Client{http: httpClient, credential: config.Credential}, nil
}

func (client *Client) Ingest(ctx context.Context, event auditv1.Event) error {
	if client == nil || client.http == nil {
		return auditdispatch.ErrIngestUnavailable
	}
	if ctx == nil || auditv1.ValidateEventForSource(auditv1.SourceIAM, event) != nil {
		return auditdispatch.ErrIngestInvalid
	}
	body, err := json.Marshal(event)
	if err != nil {
		return auditdispatch.ErrIngestInvalid
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
		return fmt.Errorf("call Audit authority: %w", auditdispatch.ErrIngestUnavailable)
	}
	defer response.Body.Close()
	expectedOutcome := auditv1.IngestionOutcome("")
	switch response.StatusCode {
	case http.StatusCreated:
		expectedOutcome = auditv1.IngestionAccepted
	case http.StatusOK:
		expectedOutcome = auditv1.IngestionDuplicate
	default:
		return statusError(response.StatusCode)
	}
	var result auditv1.IngestionResult
	if !authorityhttp.ResponseIsJSON(response) || auditv1.DecodeRequest(response.Body, &result) != nil ||
		auditv1.ValidateIngestionResult(result) != nil || result.Outcome != expectedOutcome ||
		result.Record.Source != auditv1.SourceIAM || result.Record.Event != event {
		return auditdispatch.ErrIngestUnavailable
	}
	return nil
}

func statusError(status int) error {
	switch status {
	case http.StatusUnauthorized, http.StatusForbidden:
		return auditdispatch.ErrIngestUnauthenticated
	case http.StatusBadRequest, http.StatusRequestEntityTooLarge,
		http.StatusUnsupportedMediaType, http.StatusUnprocessableEntity:
		return auditdispatch.ErrIngestInvalid
	case http.StatusConflict:
		return auditdispatch.ErrIngestConflict
	default:
		return auditdispatch.ErrIngestUnavailable
	}
}
