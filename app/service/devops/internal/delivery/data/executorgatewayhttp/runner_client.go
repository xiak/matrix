package executorgatewayhttp

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	devopsbuildv1 "github.com/xiak/matrix/api/adapter/devopsbuild/v1"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/port"
)

var _ port.RunnerGateway = (*RunnerClient)(nil)

var (
	ErrRunnerInvalid        = errors.New("executor runner request is invalid")
	ErrRunnerRejected       = errors.New("executor runner request was rejected")
	ErrRunnerStale          = errors.New("executor runner assignment is stale")
	ErrRunnerUnavailable    = errors.New("executor runner gateway is unavailable")
	ErrRunnerOutcomeUnknown = errors.New("executor runner gateway outcome is unknown")
)

type RunnerClient struct {
	origin     string
	runnerID   string
	httpClient *http.Client
}

func NewRunnerClient(
	origin string,
	serverName string,
	certificate tls.Certificate,
	serverRoots *x509.CertPool,
	runnerNamespace string,
) (*RunnerClient, error) {
	canonicalOrigin, err := validateGatewayOrigin(origin)
	if err != nil || !validServerName(serverName) || len(certificate.Certificate) == 0 ||
		certificate.PrivateKey == nil || serverRoots == nil ||
		len(serverRoots.Subjects()) == 0 {
		return nil, errors.New("executor runner client configuration is invalid")
	}
	namespace, err := parseSPIFFEIdentity(runnerNamespace)
	if err != nil {
		return nil, errors.New("executor runner client configuration is invalid")
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		return nil, errors.New("executor runner client certificate is invalid")
	}
	identity, err := certificateSPIFFEIdentity(leaf)
	if err != nil || runnerIdentityInNamespace(identity, namespace) != nil {
		return nil, errors.New("executor runner client certificate is invalid")
	}
	identityID, err := runnerID(identity)
	if err != nil {
		return nil, errors.New("executor runner client certificate is invalid")
	}
	tlsConfig := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		ServerName:   serverName,
		RootCAs:      serverRoots.Clone(),
		Certificates: []tls.Certificate{certificate},
		NextProtos:   []string{"http/1.1"},
	}
	transport := &http.Transport{
		Proxy:                  nil,
		DialContext:            (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
		ForceAttemptHTTP2:      false,
		DisableCompression:     true,
		TLSClientConfig:        tlsConfig,
		TLSHandshakeTimeout:    5 * time.Second,
		ResponseHeaderTimeout:  10 * time.Second,
		MaxResponseHeaderBytes: maximumResponseHeader,
		MaxIdleConns:           2,
		MaxIdleConnsPerHost:    2,
		IdleConnTimeout:        30 * time.Second,
	}
	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("executor runner redirects are disabled")
		},
	}
	return &RunnerClient{
		origin: canonicalOrigin, runnerID: identityID, httpClient: client,
	}, nil
}

func (client *RunnerClient) RunnerID() string {
	if client == nil {
		return ""
	}
	return client.runnerID
}

func (client *RunnerClient) Claim(
	ctx context.Context,
	destination devopsbuildv1.AssignmentDestination,
) (devopsbuildv1.Assignment, bool, error) {
	if client == nil || client.httpClient == nil || client.runnerID == "" ||
		ctx == nil || destination == nil {
		return devopsbuildv1.Assignment{}, false, ErrRunnerInvalid
	}
	content, err := devopsbuildv1.EncodeClaim()
	if err != nil {
		return devopsbuildv1.Assignment{}, false, ErrRunnerInvalid
	}
	response, err := client.post(
		ctx, client.origin+runnerClaimsPath,
		devopsbuildv1.FramedMediaType, content,
	)
	if err != nil {
		return devopsbuildv1.Assignment{}, false, err
	}
	if response.StatusCode == http.StatusNoContent {
		if err := closeEmptyRunnerResponse(response, http.StatusNoContent); err != nil {
			return devopsbuildv1.Assignment{}, false, err
		}
		return devopsbuildv1.Assignment{}, false, nil
	}
	if response.StatusCode != http.StatusOK {
		return devopsbuildv1.Assignment{}, false, runnerResponseError(response)
	}
	if !responseHasSingleHeader(
		response, "Content-Type", devopsbuildv1.FramedMediaType,
	) || response.Header.Get("Content-Encoding") != "" ||
		len(response.TransferEncoding) != 0 || response.ContentLength <= 8 ||
		response.ContentLength > maximumSubmissionBody {
		_ = response.Body.Close()
		return devopsbuildv1.Assignment{}, false, ErrRunnerOutcomeUnknown
	}
	counted := &countingReader{source: response.Body}
	assignment, readErr := devopsbuildv1.ReadAssignment(counted, destination)
	closeErr := response.Body.Close()
	if readErr != nil || closeErr != nil || counted.bytes != response.ContentLength {
		return devopsbuildv1.Assignment{}, false, ErrRunnerOutcomeUnknown
	}
	return assignment, true, nil
}

func (client *RunnerClient) Renew(
	ctx context.Context,
	assignment devopsbuildv1.Assignment,
) (devopsbuildv1.Renewal, error) {
	if client == nil || client.httpClient == nil || client.runnerID == "" || ctx == nil ||
		devopsbuildv1.ValidateAssignment(assignment) != nil {
		return devopsbuildv1.Renewal{}, ErrRunnerInvalid
	}
	content, err := devopsbuildv1.EncodeRenewalRequest(
		assignment.ExecutionID, assignment.FencingToken,
	)
	if err != nil {
		return devopsbuildv1.Renewal{}, ErrRunnerInvalid
	}
	target := client.executionTarget(assignment.ExecutionID, "renew")
	response, err := client.post(ctx, target, devopsbuildv1.DocumentMediaType, content)
	if err != nil {
		return devopsbuildv1.Renewal{}, err
	}
	if response.StatusCode != http.StatusOK {
		return devopsbuildv1.Renewal{}, runnerResponseError(response)
	}
	body, err := readRunnerDocument(response)
	if err != nil {
		return devopsbuildv1.Renewal{}, err
	}
	renewal, err := devopsbuildv1.DecodeRenewal(assignment.Request, body)
	if err != nil || renewal.ExecutionID != assignment.ExecutionID ||
		renewal.FencingToken != assignment.FencingToken {
		return devopsbuildv1.Renewal{}, ErrRunnerOutcomeUnknown
	}
	return renewal, nil
}

func (client *RunnerClient) Complete(
	ctx context.Context,
	assignment devopsbuildv1.Assignment,
	receipt devopsbuildv1.Receipt,
) error {
	if client == nil || client.httpClient == nil || client.runnerID == "" || ctx == nil ||
		devopsbuildv1.ValidateAssignment(assignment) != nil ||
		devopsbuildv1.ValidateReceipt(assignment.Request, receipt) != nil ||
		receipt.ExecutorID != client.runnerID {
		return ErrRunnerInvalid
	}
	content, err := devopsbuildv1.EncodeCompletion(
		assignment.Request,
		devopsbuildv1.Completion{
			APIVersion:   devopsbuildv1.APIVersion,
			Kind:         devopsbuildv1.CompletionKind,
			ExecutionID:  assignment.ExecutionID,
			FencingToken: assignment.FencingToken,
			Receipt:      receipt,
		},
	)
	if err != nil {
		return ErrRunnerInvalid
	}
	target := client.executionTarget(assignment.ExecutionID, "complete")
	response, err := client.post(ctx, target, devopsbuildv1.DocumentMediaType, content)
	if err != nil {
		return err
	}
	return closeEmptyRunnerResponse(response, http.StatusNoContent)
}

func (client *RunnerClient) executionTarget(executionID, action string) string {
	return client.origin + runnerExecutionsPath + "/" +
		url.PathEscape(executionID) + "/" + action
}

func (client *RunnerClient) post(
	ctx context.Context,
	target string,
	accept string,
	content []byte,
) (*http.Response, error) {
	request, err := http.NewRequestWithContext(
		ctx, http.MethodPost, target, bytes.NewReader(content),
	)
	if err != nil {
		return nil, ErrRunnerInvalid
	}
	request.ContentLength = int64(len(content))
	request.Header.Set("Content-Type", devopsbuildv1.DocumentMediaType)
	request.Header.Set("Accept", accept)
	request.Header.Set("User-Agent", "matrix-devops-runner/v1")
	response, err := client.httpClient.Do(request)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, ErrRunnerOutcomeUnknown
	}
	return response, nil
}

func readRunnerDocument(response *http.Response) ([]byte, error) {
	if response == nil || response.Body == nil || !responseHasSingleHeader(
		response, "Content-Type", devopsbuildv1.DocumentMediaType,
	) || response.Header.Get("Content-Encoding") != "" ||
		len(response.TransferEncoding) != 0 || response.ContentLength <= 0 ||
		response.ContentLength > devopsbuildv1.MaximumDocumentBytes {
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		return nil, ErrRunnerOutcomeUnknown
	}
	content, readErr := io.ReadAll(io.LimitReader(
		response.Body, int64(devopsbuildv1.MaximumDocumentBytes)+1,
	))
	closeErr := response.Body.Close()
	if readErr != nil || closeErr != nil || int64(len(content)) != response.ContentLength {
		return nil, ErrRunnerOutcomeUnknown
	}
	return content, nil
}

func closeEmptyRunnerResponse(response *http.Response, expectedStatus int) error {
	if response == nil || response.Body == nil {
		return ErrRunnerOutcomeUnknown
	}
	if response.StatusCode != expectedStatus {
		return runnerResponseError(response)
	}
	body, readErr := io.ReadAll(io.LimitReader(response.Body, 1))
	closeErr := response.Body.Close()
	if readErr != nil || closeErr != nil || len(body) != 0 ||
		response.ContentLength != 0 || len(response.TransferEncoding) != 0 ||
		response.Header.Get("Content-Encoding") != "" {
		return ErrRunnerOutcomeUnknown
	}
	return nil
}

func runnerResponseError(response *http.Response) error {
	if response == nil || response.Body == nil {
		return ErrRunnerOutcomeUnknown
	}
	status := response.StatusCode
	body, readErr := io.ReadAll(io.LimitReader(response.Body, 1))
	closeErr := response.Body.Close()
	if readErr != nil || closeErr != nil || len(body) != 0 ||
		response.ContentLength != 0 || len(response.TransferEncoding) != 0 ||
		response.Header.Get("Content-Encoding") != "" {
		return ErrRunnerOutcomeUnknown
	}
	switch status {
	case http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden,
		http.StatusMethodNotAllowed, http.StatusNotAcceptable:
		return ErrRunnerRejected
	case http.StatusNotFound, http.StatusConflict:
		return ErrRunnerStale
	case http.StatusServiceUnavailable:
		return ErrRunnerUnavailable
	default:
		return ErrRunnerOutcomeUnknown
	}
}

func responseHasSingleHeader(response *http.Response, name, value string) bool {
	values := response.Header.Values(name)
	return len(values) == 1 && values[0] == value
}

type countingReader struct {
	source io.Reader
	bytes  int64
}

func (reader *countingReader) Read(destination []byte) (int, error) {
	read, err := reader.source.Read(destination)
	reader.bytes += int64(read)
	return read, err
}
