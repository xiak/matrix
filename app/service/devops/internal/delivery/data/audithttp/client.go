// Package audithttp adapts delivery's Audit producer boundary to the
// independently deployed Matrix Audit public API.
package audithttp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"

	auditv1 "github.com/xiak/matrix/api/audit/v1"
	iamv1 "github.com/xiak/matrix/api/iam/v1"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/port"
	"github.com/xiak/matrix/app/service/internal/authorityhttp"
)

var _ port.AuditIngestor = (*Client)(nil)

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
		return nil, errors.New("DevOps Audit producer credential is required")
	}
	return &Client{http: httpClient, credential: config.Credential}, nil
}

func (client *Client) Ready(ctx context.Context) error {
	if client == nil || client.http == nil || ctx == nil {
		return port.ErrAuditUnavailable
	}
	response, err := client.http.Do(
		ctx, http.MethodGet, "/ready", nil, "", client.credential, iamv1.Secret{},
	)
	if err != nil {
		return port.ErrAuditUnavailable
	}
	defer response.Body.Close()
	var readiness auditv1.Readiness
	if response.StatusCode != http.StatusOK || !authorityhttp.ResponseIsJSON(response) ||
		auditv1.DecodeRequest(response.Body, &readiness) != nil ||
		auditv1.ValidateReadiness(readiness) != nil || readiness.State != auditv1.ReadinessReady {
		return port.ErrAuditUnavailable
	}
	return nil
}

func (client *Client) Ingest(ctx context.Context, event auditv1.Event) error {
	if client == nil || client.http == nil {
		return port.ErrAuditUnavailable
	}
	if ctx == nil || auditv1.ValidateEventForSource(auditv1.SourceDevOps, event) != nil {
		return port.ErrAuditInvalid
	}
	body, err := json.Marshal(event)
	if err != nil {
		return port.ErrAuditInvalid
	}
	defer clear(body)
	response, err := client.http.Do(
		ctx, http.MethodPost, "/v1/events", bytes.NewReader(body), "application/json",
		client.credential, iamv1.Secret{},
	)
	if err != nil {
		return port.ErrAuditUnavailable
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
		result.Outcome != wantOutcome || result.Record.Source != auditv1.SourceDevOps ||
		result.Record.Event != event {
		return port.ErrAuditUnavailable
	}
	return nil
}

func auditStatusError(status int) error {
	switch status {
	case http.StatusUnauthorized, http.StatusForbidden:
		return port.ErrAuditUnauthenticated
	case http.StatusBadRequest, http.StatusRequestEntityTooLarge,
		http.StatusUnsupportedMediaType, http.StatusUnprocessableEntity:
		return port.ErrAuditInvalid
	case http.StatusConflict:
		return port.ErrAuditConflict
	default:
		return port.ErrAuditUnavailable
	}
}
