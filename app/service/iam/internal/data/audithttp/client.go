package audithttp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"net/http"
	"net/url"
	"time"

	auditv1 "github.com/xiak/matrix/api/audit/v1"
	iamv1 "github.com/xiak/matrix/api/iam/v1"
	"github.com/xiak/matrix/app/service/iam/internal/usecase/auditdispatch"
)

const defaultTimeout = 5 * time.Second

var _ auditdispatch.AuditIngestor = (*Client)(nil)

type Config struct {
	Endpoint   string
	Credential iamv1.Secret
	HTTPClient *http.Client
}

type Client struct {
	endpoint   url.URL
	credential iamv1.Secret
	httpClient *http.Client
}

func NewClient(config Config) (*Client, error) {
	endpoint, err := url.Parse(config.Endpoint)
	if err != nil || !validEndpoint(endpoint) {
		return nil, errors.New("Audit endpoint is invalid")
	}
	if !config.Credential.Present() {
		return nil, errors.New("IAM Audit producer credential is required")
	}
	httpClient := config.HTTPClient
	if httpClient == nil {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.Proxy = nil
		httpClient = &http.Client{Transport: transport, Timeout: defaultTimeout}
	} else {
		clone := *httpClient
		httpClient = &clone
		if httpClient.Timeout <= 0 {
			httpClient.Timeout = defaultTimeout
		}
	}
	httpClient.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &Client{endpoint: *endpoint, credential: config.Credential, httpClient: httpClient}, nil
}

func (client *Client) Ingest(ctx context.Context, event auditv1.Event) error {
	if client == nil || client.httpClient == nil {
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
	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		client.route("/v1/events"),
		bytes.NewReader(body),
	)
	if err != nil {
		return auditdispatch.ErrIngestUnavailable
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/json")
	credential := client.credential.CopyBytes()
	request.Header.Set("Authorization", "Bearer "+string(credential))
	clear(credential)
	response, err := client.httpClient.Do(request)
	request.Header.Del("Authorization")
	if err != nil {
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
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
	if !responseIsJSON(response) || auditv1.DecodeRequest(response.Body, &result) != nil ||
		auditv1.ValidateIngestionResult(result) != nil || result.Outcome != expectedOutcome ||
		result.Record.Source != auditv1.SourceIAM || result.Record.Event != event {
		return auditdispatch.ErrIngestUnavailable
	}
	return nil
}

func (client *Client) route(path string) string {
	endpoint := client.endpoint
	endpoint.Path = path
	return endpoint.String()
}

func validEndpoint(endpoint *url.URL) bool {
	return endpoint != nil && (endpoint.Scheme == "http" || endpoint.Scheme == "https") &&
		endpoint.Host != "" && endpoint.User == nil &&
		(endpoint.Path == "" || endpoint.Path == "/") && endpoint.RawPath == "" &&
		endpoint.RawQuery == "" && endpoint.Fragment == ""
}

func responseIsJSON(response *http.Response) bool {
	if response == nil || response.Header.Get("Content-Encoding") != "" {
		return false
	}
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	return err == nil && mediaType == "application/json"
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
