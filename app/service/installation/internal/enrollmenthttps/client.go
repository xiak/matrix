// Package enrollmenthttps adapts the bounded bootstrap ceremony to the
// dedicated installation-authenticated TLS ingress. It carries no IAM session
// and cannot select a target, pool, label, endpoint, or host-side path.
package enrollmenthttps

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/xiak/matrix/api/contractjson"
	paasv1 "github.com/xiak/matrix/api/paas/v1"
	"github.com/xiak/matrix/app/service/installation/internal/nodecommand"
)

const (
	maximumResponseBytes = int64(64 * 1024)
	requestTimeout       = 15 * time.Second
)

type Client struct{}

func New() *Client { return &Client{} }

func (client *Client) Exchange(
	ctx context.Context,
	join paasv1.NodeEnrollmentJoin,
	request paasv1.ExchangeNodeEnrollmentRequest,
) (paasv1.NodeEnrollmentExchangeResponse, error) {
	if paasv1.ValidateExchangeNodeEnrollmentRequest(request) != nil ||
		request.EnrollmentID != join.EnrollmentID || request.InstallationID != join.InstallationID ||
		request.ExecutionTargetID != join.ExecutionTargetID {
		return paasv1.NodeEnrollmentExchangeResponse{}, nodecommand.ErrEnrollmentRejected
	}
	var response paasv1.NodeEnrollmentExchangeResponse
	if err := client.post(ctx, join, "exchange", request, &response, false); err != nil {
		return paasv1.NodeEnrollmentExchangeResponse{}, err
	}
	if paasv1.ValidateNodeEnrollmentExchangeResponseForRequest(response, request) != nil {
		// The server may already have consumed the one-time credential. Preserve
		// the local intent so a later proof-of-possession recovery can reconcile
		// an invalid or truncated success result without sending it again.
		return paasv1.NodeEnrollmentExchangeResponse{}, nodecommand.ErrEnrollmentUnavailable
	}
	return response, nil
}

func (client *Client) CreateRecoveryChallenge(
	ctx context.Context,
	join paasv1.NodeEnrollmentJoin,
	request paasv1.CreateNodeEnrollmentRecoveryChallengeRequest,
) (paasv1.NodeEnrollmentRecoveryChallenge, error) {
	if paasv1.ValidateCreateNodeEnrollmentRecoveryChallengeRequest(request) != nil ||
		request.EnrollmentID != join.EnrollmentID || request.InstallationID != join.InstallationID ||
		request.ExecutionTargetID != join.ExecutionTargetID {
		return paasv1.NodeEnrollmentRecoveryChallenge{}, nodecommand.ErrEnrollmentRejected
	}
	var response paasv1.NodeEnrollmentRecoveryChallenge
	if err := client.post(ctx, join, "recovery-challenge", request, &response, true); err != nil {
		return paasv1.NodeEnrollmentRecoveryChallenge{}, err
	}
	if paasv1.ValidateNodeEnrollmentRecoveryChallengeForRequest(response, request) != nil {
		return paasv1.NodeEnrollmentRecoveryChallenge{}, nodecommand.ErrEnrollmentUnavailable
	}
	return response, nil
}

func (client *Client) RecoverExchange(
	ctx context.Context,
	join paasv1.NodeEnrollmentJoin,
	request paasv1.RecoverNodeEnrollmentExchangeRequest,
) (paasv1.NodeEnrollmentExchangeResponse, error) {
	if paasv1.ValidateRecoverNodeEnrollmentExchangeRequest(request) != nil ||
		request.Challenge.EnrollmentID != join.EnrollmentID ||
		request.Challenge.InstallationID != join.InstallationID ||
		request.Challenge.ExecutionTargetID != join.ExecutionTargetID {
		return paasv1.NodeEnrollmentExchangeResponse{}, nodecommand.ErrEnrollmentRejected
	}
	var response paasv1.NodeEnrollmentExchangeResponse
	if err := client.post(ctx, join, "recover", request, &response, false); err != nil {
		return paasv1.NodeEnrollmentExchangeResponse{}, err
	}
	challenge := request.Challenge
	if paasv1.ValidateNodeEnrollmentExchangeResponse(response) != nil ||
		response.EnrollmentID != challenge.EnrollmentID || response.InstallationID != challenge.InstallationID ||
		response.ExecutionTargetID != challenge.ExecutionTargetID || response.ExchangeID != challenge.ExchangeID ||
		response.MachineFingerprint != challenge.MachineFingerprint ||
		response.RuntimeContractDigest != challenge.RuntimeContractDigest {
		return paasv1.NodeEnrollmentExchangeResponse{}, nodecommand.ErrEnrollmentUnavailable
	}
	return response, nil
}

func (client *Client) Complete(
	ctx context.Context,
	join paasv1.NodeEnrollmentJoin,
	request paasv1.CompleteNodeEnrollmentRequest,
) error {
	if paasv1.ValidateCompleteNodeEnrollmentRequest(request) != nil ||
		request.EnrollmentID != join.EnrollmentID || request.InstallationID != join.InstallationID ||
		request.ExecutionTargetID != join.ExecutionTargetID {
		return nodecommand.ErrEnrollmentRejected
	}
	var response paasv1.CompleteNodeEnrollmentResponse
	if err := client.post(ctx, join, "complete", request, &response, false); err != nil {
		return err
	}
	if paasv1.ValidateCompleteNodeEnrollmentResponse(response) != nil ||
		response.Enrollment.Metadata.ID != request.EnrollmentID ||
		response.ExecutionTarget.Metadata.ID != request.ExecutionTargetID {
		// Completion is a publishing operation. A malformed success response
		// cannot prove that publication did not commit, so keep COMMITTING and
		// reconcile with an exact replay.
		return nodecommand.ErrEnrollmentUnavailable
	}
	return nil
}

func (client *Client) post(
	ctx context.Context,
	join paasv1.NodeEnrollmentJoin,
	action string,
	requestBody any,
	responseBody any,
	recoveryChallenge bool,
) error {
	if client == nil || ctx == nil || paasv1.ValidateNodeEnrollmentJoin(join) != nil {
		return nodecommand.ErrEnrollmentRejected
	}
	endpoint, err := enrollmentEndpoint(join, action)
	if err != nil {
		return nodecommand.ErrEnrollmentRejected
	}
	connection, err := enrollmentHTTPClient(join)
	if err != nil {
		return nodecommand.ErrEnrollmentRejected
	}
	defer connection.CloseIdleConnections()
	encoded, err := json.Marshal(requestBody)
	if err != nil || len(encoded) == 0 || len(encoded) > int(maximumResponseBytes) {
		clear(encoded)
		return nodecommand.ErrEnrollmentRejected
	}
	defer clear(encoded)
	bounded, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(bounded, http.MethodPost, endpoint, bytes.NewReader(encoded))
	if err != nil {
		return nodecommand.ErrEnrollmentRejected
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	response, err := connection.Do(request)
	if err != nil {
		if definitiveTLSFailure(err) {
			return nodecommand.ErrEnrollmentRejected
		}
		return nodecommand.ErrEnrollmentUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		if response.StatusCode == http.StatusRequestTimeout || response.StatusCode == http.StatusTooManyRequests ||
			response.StatusCode == http.StatusBadGateway || response.StatusCode == http.StatusServiceUnavailable ||
			response.StatusCode == http.StatusGatewayTimeout || response.StatusCode >= 500 {
			_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maximumResponseBytes+1))
			return nodecommand.ErrEnrollmentUnavailable
		}
		problem, authoritative := authoritativeProblem(response)
		if !authoritative || problem.Retryable {
			return nodecommand.ErrEnrollmentUnavailable
		}
		if recoveryChallenge && isAuthoritativeNotExchanged(problem) {
			return nodecommand.ErrEnrollmentNotExchanged
		}
		return nodecommand.ErrEnrollmentRejected
	}
	if !exactResponseMediaType(response, "application/json") {
		return nodecommand.ErrEnrollmentUnavailable
	}
	if contractjson.DecodeObject(io.LimitReader(response.Body, maximumResponseBytes+1), maximumResponseBytes, responseBody) != nil {
		return nodecommand.ErrEnrollmentUnavailable
	}
	return nil
}

func authoritativeProblem(response *http.Response) (paasv1.Problem, bool) {
	if response == nil || response.Body == nil || response.StatusCode < http.StatusBadRequest ||
		response.StatusCode >= http.StatusInternalServerError ||
		!exactResponseMediaType(response, "application/problem+json") {
		return paasv1.Problem{}, false
	}
	var problem paasv1.Problem
	if contractjson.DecodeObject(
		io.LimitReader(response.Body, maximumResponseBytes+1), maximumResponseBytes, &problem,
	) != nil || paasv1.ValidateProblem(problem) != nil || problem.Status != response.StatusCode ||
		problem.Type != "https://xiak.com/problems/"+strings.ToLower(strings.ReplaceAll(string(problem.Code), "_", "-")) {
		return paasv1.Problem{}, false
	}
	return problem, true
}

func exactResponseMediaType(response *http.Response, expected string) bool {
	if response == nil || expected == "" {
		return false
	}
	contentTypes := response.Header.Values("Content-Type")
	return len(contentTypes) == 1 && contentTypes[0] == expected &&
		len(response.Header.Values("Content-Encoding")) == 0
}

func isAuthoritativeNotExchanged(problem paasv1.Problem) bool {
	return problem.Status == http.StatusNotFound && problem.Code == paasv1.ErrorNotFound &&
		problem.Type == "https://xiak.com/problems/not-found" && problem.Title == "Exchange not found" &&
		problem.Detail == "node enrollment has no exchange result" && !problem.Retryable && len(problem.Violations) == 0
}

func enrollmentEndpoint(join paasv1.NodeEnrollmentJoin, action string) (string, error) {
	endpoint, err := url.Parse(join.ControlPlaneURL)
	if err != nil || endpoint.RawPath != "" || !strings.HasSuffix(endpoint.Path, "/exchange") {
		return "", errors.New("node enrollment endpoint is invalid")
	}
	switch action {
	case "exchange":
	case "recovery-challenge", "recover", "complete":
		endpoint.Path = strings.TrimSuffix(endpoint.Path, "/exchange") + "/" + action
	default:
		return "", errors.New("node enrollment endpoint action is invalid")
	}
	return endpoint.String(), nil
}

func enrollmentHTTPClient(join paasv1.NodeEnrollmentJoin) (*http.Client, error) {
	issuerDER, err := base64.RawURLEncoding.Strict().DecodeString(join.IssuerCertificate)
	if err != nil || base64.RawURLEncoding.EncodeToString(issuerDER) != join.IssuerCertificate {
		return nil, errors.New("node enrollment issuer is invalid")
	}
	issuer, err := x509.ParseCertificate(issuerDER)
	if err != nil {
		return nil, errors.New("node enrollment issuer is invalid")
	}
	// x509.Certificate retains slices backed by issuerDER. The certificate is
	// public, and its DER must remain intact for RootCAs during every handshake.
	serverName, err := paasv1.NodeEnrollmentIngressServerName(join.InstallationID)
	if err != nil {
		return nil, errors.New("node enrollment server identity is invalid")
	}
	roots := x509.NewCertPool()
	roots.AddCert(issuer)
	security := &tls.Config{
		MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: serverName,
		NextProtos: []string{"http/1.1"}, SessionTicketsDisabled: true,
	}
	transport := &http.Transport{
		Proxy: nil, DialContext: (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
		TLSClientConfig: security, TLSHandshakeTimeout: 5 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second, MaxResponseHeaderBytes: 32 * 1024,
		DisableCompression: true, DisableKeepAlives: true, MaxConnsPerHost: 1,
	}
	return &http.Client{
		Transport: transport, Timeout: requestTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}, nil
}

func definitiveTLSFailure(err error) bool {
	var verification *tls.CertificateVerificationError
	var unknown x509.UnknownAuthorityError
	var hostname x509.HostnameError
	var invalid x509.CertificateInvalidError
	var record tls.RecordHeaderError
	return errors.As(err, &verification) || errors.As(err, &unknown) || errors.As(err, &hostname) ||
		errors.As(err, &invalid) || errors.As(err, &record)
}

var _ nodecommand.EnrollmentClient = (*Client)(nil)
