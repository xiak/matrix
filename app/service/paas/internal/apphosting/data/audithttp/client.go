package audithttp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"

	auditv1 "github.com/xiak/matrix/api/audit/v1"
	iamv1 "github.com/xiak/matrix/api/iam/v1"
	paasv1 "github.com/xiak/matrix/api/paas/v1"
	"github.com/xiak/matrix/app/service/internal/authorityhttp"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/port"
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
		return nil, errors.New("PaaS Audit producer credential is required")
	}
	return &Client{http: httpClient, credential: config.Credential}, nil
}

func (client *Client) Ingest(ctx context.Context, event port.AuditEvent) error {
	if client == nil || client.http == nil {
		return port.ErrAuditUnavailable
	}
	if ctx == nil || port.ValidateAuditEvent(event) != nil {
		return port.ErrAuditInvalid
	}
	auditEvent, err := toAuditEvent(event)
	if err != nil {
		return port.ErrAuditInvalid
	}
	body, err := json.Marshal(auditEvent)
	if err != nil {
		return port.ErrAuditInvalid
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
		result.Outcome != wantOutcome || result.Record.Source != auditv1.SourcePaaS ||
		result.Record.Event != auditEvent {
		return port.ErrAuditUnavailable
	}
	return nil
}

func toAuditEvent(value port.AuditEvent) (auditv1.Event, error) {
	actorType, err := toAuditActorType(value.Actor.Type)
	if err != nil {
		return auditv1.Event{}, err
	}
	targetKind, err := toAuditTargetKind(value.Target.Kind)
	if err != nil {
		return auditv1.Event{}, err
	}
	correlationID := value.AuditID
	if correlationID == "" {
		correlationID = value.RequestID
	}
	result := auditv1.Event{
		APIVersion:    auditv1.APIVersion,
		Kind:          "AuditEvent",
		EventID:       auditv1.EventID(value.EventID),
		TenantID:      auditv1.TenantID(value.TenantID),
		Actor:         auditv1.ActorReference{Type: actorType, ID: auditv1.ActorID(value.Actor.ID)},
		IAMDecisionID: auditv1.DecisionID(value.IAMDecisionID),
		Action:        auditv1.Action(value.Action),
		Target:        auditv1.TargetReference{Kind: targetKind, ID: string(value.Target.ID)},
		Result:        auditv1.Result(value.Result),
		RequestDigest: value.RequestDigest,
		RequestID:     value.RequestID,
		CorrelationID: correlationID,
		OperationID:   auditv1.OperationID(value.OperationID),
		TraceParent:   value.TraceParent,
		OccurredAt:    value.OccurredAt,
	}
	if auditv1.ValidateEventForSource(auditv1.SourcePaaS, result) != nil {
		return auditv1.Event{}, errors.New("PaaS event cannot map to Audit v1")
	}
	return result, nil
}

func toAuditActorType(value paasv1.SubjectType) (auditv1.ActorType, error) {
	switch value {
	case paasv1.SubjectUser:
		return auditv1.ActorUser, nil
	case paasv1.SubjectServiceAccount:
		return auditv1.ActorServiceAccount, nil
	case paasv1.SubjectAgent, paasv1.SubjectSystemUser:
		return auditv1.ActorSystem, nil
	default:
		return "", errors.New("PaaS actor type cannot map to Audit")
	}
}

func toAuditTargetKind(value string) (auditv1.TargetKind, error) {
	switch value {
	case "Application":
		return auditv1.TargetApplication, nil
	case "Configuration":
		return auditv1.TargetConfiguration, nil
	case "ConfigurationRevision":
		return auditv1.TargetConfigurationRevision, nil
	case "ApplicationRevision":
		return auditv1.TargetApplicationRevision, nil
	case "Deployment":
		return auditv1.TargetDeployment, nil
	default:
		return "", errors.New("PaaS target kind cannot map to Audit")
	}
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
