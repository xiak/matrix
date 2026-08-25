package authorityhttp

import (
	"context"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"

	iamv1 "github.com/xiak/matrix/api/iam/v1"
)

const defaultTimeout = 5 * time.Second

var ErrUnavailable = errors.New("authority HTTP request is unavailable")

type Client struct {
	endpoint   url.URL
	httpClient *http.Client
}

func New(endpointText string, supplied *http.Client) (*Client, error) {
	endpoint, err := url.Parse(endpointText)
	if err != nil || !validEndpoint(endpoint) {
		return nil, errors.New("authority HTTP endpoint is invalid")
	}
	httpClient := supplied
	if httpClient == nil {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.Proxy = nil
		httpClient = &http.Client{Transport: transport, Timeout: defaultTimeout}
	} else {
		clone := *httpClient
		httpClient = &clone
		if httpClient.Transport == nil {
			transport := http.DefaultTransport.(*http.Transport).Clone()
			transport.Proxy = nil
			httpClient.Transport = transport
		}
		if httpClient.Timeout <= 0 {
			httpClient.Timeout = defaultTimeout
		}
	}
	httpClient.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &Client{endpoint: *endpoint, httpClient: httpClient}, nil
}

func (client *Client) Do(
	ctx context.Context,
	method string,
	route string,
	body io.Reader,
	contentType string,
	serviceCredential iamv1.Secret,
	subjectCredential iamv1.Secret,
) (*http.Response, error) {
	if client == nil || client.httpClient == nil || ctx == nil ||
		!validRoute(route) || !serviceCredential.Present() {
		return nil, ErrUnavailable
	}
	endpoint := client.endpoint
	endpoint.Path = route
	request, err := http.NewRequestWithContext(ctx, method, endpoint.String(), body)
	if err != nil {
		return nil, ErrUnavailable
	}
	request.Header.Set("Accept", "application/json")
	if contentType != "" {
		request.Header.Set("Content-Type", contentType)
	}
	serviceBytes := serviceCredential.CopyBytes()
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
		return nil, ErrUnavailable
	}
	return response, nil
}

func ResponseIsJSON(response *http.Response) bool {
	if response == nil || response.Header.Get("Content-Encoding") != "" {
		return false
	}
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	return err == nil && mediaType == "application/json"
}

func validEndpoint(endpoint *url.URL) bool {
	return endpoint != nil && (endpoint.Scheme == "http" || endpoint.Scheme == "https") &&
		endpoint.Host != "" && endpoint.User == nil &&
		(endpoint.Path == "" || endpoint.Path == "/") && endpoint.RawPath == "" &&
		endpoint.RawQuery == "" && endpoint.Fragment == ""
}

func validRoute(route string) bool {
	return strings.HasPrefix(route, "/") && route != "/" &&
		!strings.ContainsAny(route, "?#\\") && !strings.Contains(route, "//")
}
