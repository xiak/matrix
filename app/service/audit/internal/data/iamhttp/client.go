package iamhttp

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

	iamv1 "github.com/xiak/matrix/api/iam/v1"
	"github.com/xiak/matrix/app/service/audit/internal/usecase/auditlog"
)

const defaultTimeout = 5 * time.Second

var _ auditlog.IAM = (*Client)(nil)

type Config struct {
	Endpoint          string
	ServiceCredential iamv1.Secret
	HTTPClient        *http.Client
}

type Client struct {
	endpoint          url.URL
	serviceCredential iamv1.Secret
	httpClient        *http.Client
}

func NewClient(config Config) (*Client, error) {
	endpoint, err := url.Parse(config.Endpoint)
	if err != nil || !validEndpoint(endpoint) {
		return nil, errors.New("IAM endpoint is invalid")
	}
	if !config.ServiceCredential.Present() {
		return nil, errors.New("Audit service credential is required")
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
	return &Client{
		endpoint:          *endpoint,
		serviceCredential: config.ServiceCredential,
		httpClient:        httpClient,
	}, nil
}

func (client *Client) ServiceIdentity(
	ctx context.Context,
	producerCredential iamv1.Secret,
) (iamv1.ServiceIdentity, error) {
	if client == nil || client.httpClient == nil {
		return iamv1.ServiceIdentity{}, auditlog.ErrUnavailable
	}
	if ctx == nil || !producerCredential.Present() {
		return iamv1.ServiceIdentity{}, auditlog.ErrInvalidArgument
	}
	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		client.route("/v1/service-identity"),
		nil,
	)
	if err != nil {
		return iamv1.ServiceIdentity{}, auditlog.ErrUnavailable
	}
	request.Header.Set("Accept", "application/json")
	response, err := client.do(request, producerCredential, iamv1.Secret{})
	if err != nil {
		return iamv1.ServiceIdentity{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return iamv1.ServiceIdentity{}, statusError(response.StatusCode)
	}
	var identity iamv1.ServiceIdentity
	if !responseIsJSON(response) || iamv1.DecodeRequest(response.Body, &identity) != nil ||
		iamv1.ValidateServiceIdentity(identity) != nil {
		return iamv1.ServiceIdentity{}, auditlog.ErrUnavailable
	}
	return identity, nil
}

func (client *Client) Authorize(
	ctx context.Context,
	subjectCredential iamv1.Secret,
	authorization iamv1.AuthorizationRequest,
) (iamv1.AuthorizationDecision, error) {
	if client == nil || client.httpClient == nil {
		return iamv1.AuthorizationDecision{}, auditlog.ErrUnavailable
	}
	if ctx == nil || !subjectCredential.Present() ||
		iamv1.ValidateAuthorizationRequest(authorization) != nil {
		return iamv1.AuthorizationDecision{}, auditlog.ErrInvalidArgument
	}
	body, err := json.Marshal(authorization)
	if err != nil {
		return iamv1.AuthorizationDecision{}, auditlog.ErrUnavailable
	}
	defer clear(body)
	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		client.route("/v1/authorize"),
		bytes.NewReader(body),
	)
	if err != nil {
		return iamv1.AuthorizationDecision{}, auditlog.ErrUnavailable
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/json")
	response, err := client.do(request, client.serviceCredential, subjectCredential)
	if err != nil {
		return iamv1.AuthorizationDecision{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return iamv1.AuthorizationDecision{}, statusError(response.StatusCode)
	}
	var decision iamv1.AuthorizationDecision
	if !responseIsJSON(response) || iamv1.DecodeRequest(response.Body, &decision) != nil ||
		iamv1.ValidateAuthorizationDecision(decision) != nil {
		return iamv1.AuthorizationDecision{}, auditlog.ErrUnavailable
	}
	return decision, nil
}

func (client *Client) do(
	request *http.Request,
	serviceCredential iamv1.Secret,
	subjectCredential iamv1.Secret,
) (*http.Response, error) {
	serviceBytes := serviceCredential.CopyBytes()
	if len(serviceBytes) == 0 {
		return nil, auditlog.ErrInvalidArgument
	}
	request.Header.Set("Authorization", "Bearer "+string(serviceBytes))
	clear(serviceBytes)
	if subjectCredential.Present() {
		subjectBytes := subjectCredential.CopyBytes()
		request.Header.Set("Matrix-Subject-Credential", string(subjectBytes))
		clear(subjectBytes)
	}
	response, err := client.httpClient.Do(request)
	request.Header.Del("Authorization")
	request.Header.Del("Matrix-Subject-Credential")
	if err != nil {
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		return nil, fmt.Errorf("call IAM authority: %w", auditlog.ErrUnavailable)
	}
	return response, nil
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
	case http.StatusUnauthorized:
		return auditlog.ErrUnauthenticated
	case http.StatusForbidden:
		return auditlog.ErrForbidden
	default:
		return auditlog.ErrUnavailable
	}
}
