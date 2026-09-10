package gitea

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"

	devopsv1 "github.com/xiak/matrix/api/devops/v1"
)

// TrustResolver selects either the system trust store or one custom-only pool
// for an exact tenant and canonical provider origin.
type TrustResolver interface {
	Resolve(
		context.Context, devopsv1.ResourceScope, string,
	) (*x509.CertPool, bool, error)
}

func providerHTTPClient(
	ctx context.Context,
	template *http.Client,
	trust TrustResolver,
	scope devopsv1.ResourceScope,
	endpointOrigin string,
) (*http.Client, func(), error) {
	// Package-local constructors inject a fixed client for bounded adapter tests.
	// Exported production constructors always require a trust resolver.
	if trust == nil {
		if template == nil {
			return nil, nil, errors.New("provider HTTP client is unavailable")
		}
		return template, func() {}, nil
	}
	if ctx == nil || template == nil ||
		devopsv1.ValidateResourceScope(scope) != nil ||
		devopsv1.ValidateEndpointOrigin(endpointOrigin) != nil {
		return nil, nil, errors.New("provider trust request is invalid")
	}
	roots, custom, err := trust.Resolve(ctx, scope, endpointOrigin)
	if err != nil || custom != (roots != nil) || custom && len(roots.Subjects()) == 0 {
		return nil, nil, errors.New("provider trust is unavailable")
	}
	base, ok := template.Transport.(*http.Transport)
	if !ok || base == nil || base.TLSClientConfig == nil ||
		base.TLSClientConfig.MinVersion < tls.VersionTLS12 {
		return nil, nil, errors.New("provider transport is invalid")
	}
	transport := base.Clone()
	tlsConfig := base.TLSClientConfig.Clone()
	if custom {
		tlsConfig.RootCAs = roots
	} else {
		tlsConfig.RootCAs = nil
	}
	transport.TLSClientConfig = tlsConfig
	client := *template
	client.Transport = transport
	return &client, transport.CloseIdleConnections, nil
}
