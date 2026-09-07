package readinesshttp

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"time"

	"github.com/xiak/matrix/api/contractjson"
	installationv1 "github.com/xiak/matrix/api/installation/v1"
	paasv1 "github.com/xiak/matrix/api/paas/v1"
	"github.com/xiak/matrix/app/service/installation/internal/productdiscovery"
	"github.com/xiak/matrix/app/service/internal/authorityhttp"
)

var _ productdiscovery.ProductObserver = (*Observer)(nil)

const defaultTimeout = 3 * time.Second

type Config struct {
	PaaSEndpoint string
	HTTPClient   *http.Client
}

type Observer struct {
	paasEndpoint url.URL
	http         *http.Client
}

func NewObserver(config Config) (*Observer, error) {
	endpoint, err := url.Parse(config.PaaSEndpoint)
	if err != nil || !validEndpoint(endpoint) {
		return nil, errors.New("PaaS readiness endpoint is invalid")
	}
	client := config.HTTPClient
	if client == nil {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.Proxy = nil
		client = &http.Client{Transport: transport, Timeout: defaultTimeout}
	} else {
		clone := *client
		client = &clone
		if client.Transport == nil {
			transport := http.DefaultTransport.(*http.Transport).Clone()
			transport.Proxy = nil
			client.Transport = transport
		}
		if client.Timeout <= 0 || client.Timeout > 5*time.Second {
			client.Timeout = defaultTimeout
		}
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &Observer{paasEndpoint: *endpoint, http: client}, nil
}

func (observer *Observer) Observe(
	ctx context.Context,
	product installationv1.ProductID,
) (productdiscovery.ProductObservation, error) {
	if observer == nil || observer.http == nil || ctx == nil ||
		product != installationv1.ProductApplicationPaaS {
		return productdiscovery.ProductObservation{}, productdiscovery.ErrUnavailable
	}
	endpoint := observer.paasEndpoint
	endpoint.Path = "/ready"
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return productdiscovery.ProductObservation{}, productdiscovery.ErrUnavailable
	}
	request.Header.Set("Accept", "application/json")
	response, err := observer.http.Do(request)
	if err != nil {
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		return productdiscovery.ProductObservation{}, productdiscovery.ErrUnavailable
	}
	defer response.Body.Close()
	var readiness paasv1.Readiness
	if response.StatusCode != http.StatusOK ||
		!authorityhttp.ResponseIsJSON(response) ||
		contractjson.DecodeObject(response.Body, 64*1024, &readiness) != nil ||
		paasv1.ValidateReadiness(readiness) != nil {
		return productdiscovery.ProductObservation{}, productdiscovery.ErrUnavailable
	}
	result := productdiscovery.ProductObservation{
		State:      installationv1.ProductUnavailable,
		Reason:     installationv1.ReasonDependencyUnavailable,
		ObservedAt: readiness.CheckedAt,
	}
	if readiness.State == paasv1.ReadinessReady {
		result.State = installationv1.ProductReady
		result.Reason = ""
	}
	return result, nil
}

func validEndpoint(endpoint *url.URL) bool {
	return endpoint != nil && (endpoint.Scheme == "http" || endpoint.Scheme == "https") &&
		endpoint.Host != "" && endpoint.User == nil &&
		(endpoint.Path == "" || endpoint.Path == "/") &&
		endpoint.RawPath == "" && endpoint.RawQuery == "" && endpoint.Fragment == ""
}
