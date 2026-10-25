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
	"strconv"
	"strings"
	"time"

	devopsbuildv1 "github.com/xiak/matrix/api/adapter/devopsbuild/v1"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/port"
)

const (
	defaultPollInterval   = 250 * time.Millisecond
	maximumResponseHeader = 16 * 1024
)

type AdminClient struct {
	origin       string
	httpClient   *http.Client
	pollInterval time.Duration
}

func NewAdminClient(
	origin string,
	serverName string,
	certificate tls.Certificate,
	serverRoots *x509.CertPool,
) (*AdminClient, error) {
	canonicalOrigin, err := validateGatewayOrigin(origin)
	if err != nil || !validServerName(serverName) || len(certificate.Certificate) == 0 ||
		certificate.PrivateKey == nil || serverRoots == nil || len(serverRoots.Subjects()) == 0 {
		return nil, errors.New("executor admin client configuration is invalid")
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
			return errors.New("executor admin redirects are disabled")
		},
	}
	return &AdminClient{
		origin: canonicalOrigin, httpClient: client, pollInterval: defaultPollInterval,
	}, nil
}

func (client *AdminClient) Execute(
	ctx context.Context,
	request devopsbuildv1.Request,
	archive io.Reader,
) (devopsbuildv1.Receipt, error) {
	if client == nil || client.httpClient == nil || ctx == nil || archive == nil ||
		devopsbuildv1.ValidateRequest(request) != nil {
		return devopsbuildv1.Receipt{}, port.ErrBuildConflict
	}
	observation, err := client.create(ctx, request, archive)
	if err != nil {
		return devopsbuildv1.Receipt{}, err
	}
	receipt, _, err := client.await(
		ctx, request, observation, devopsbuildv1.ControlObserve,
	)
	return receipt, err
}

func (client *AdminClient) Observe(
	ctx context.Context,
	request devopsbuildv1.Request,
) (devopsbuildv1.Receipt, bool, error) {
	if client == nil || client.httpClient == nil || ctx == nil ||
		devopsbuildv1.ValidateRequest(request) != nil {
		return devopsbuildv1.Receipt{}, false, port.ErrBuildConflict
	}
	observation, err := client.control(ctx, request, devopsbuildv1.ControlObserve)
	if err != nil {
		return devopsbuildv1.Receipt{}, false, err
	}
	return client.await(ctx, request, observation, devopsbuildv1.ControlObserve)
}

func (client *AdminClient) Cancel(
	ctx context.Context,
	request devopsbuildv1.Request,
) (devopsbuildv1.Receipt, bool, error) {
	if client == nil || client.httpClient == nil || ctx == nil ||
		devopsbuildv1.ValidateRequest(request) != nil {
		return devopsbuildv1.Receipt{}, false, port.ErrBuildConflict
	}
	observation, err := client.control(ctx, request, devopsbuildv1.ControlCancel)
	if err != nil {
		return devopsbuildv1.Receipt{}, false, err
	}
	return client.await(ctx, request, observation, devopsbuildv1.ControlCancel)
}

func (client *AdminClient) ReadLogs(
	ctx context.Context,
	request devopsbuildv1.Request,
	afterSequence uint64,
) (devopsbuildv1.LogBatch, bool, error) {
	if client == nil || client.httpClient == nil || ctx == nil ||
		devopsbuildv1.ValidateRequest(request) != nil {
		return devopsbuildv1.LogBatch{}, false, port.ErrBuildConflict
	}
	content, err := devopsbuildv1.EncodeLogRead(request, afterSequence)
	if err != nil {
		return devopsbuildv1.LogBatch{}, false, port.ErrBuildConflict
	}
	executionID, _ := devopsbuildv1.ExecutionID(request)
	target := client.origin + executionsPath + "/" +
		url.PathEscape(executionID) + "/logs"
	httpRequest, err := http.NewRequestWithContext(
		ctx, http.MethodPost, target, bytes.NewReader(content),
	)
	if err != nil {
		return devopsbuildv1.LogBatch{}, false, port.ErrBuildConflict
	}
	httpRequest.ContentLength = int64(len(content))
	setRequestHeaders(
		httpRequest, devopsbuildv1.DocumentMediaType,
		devopsbuildv1.LogDocumentMediaType,
	)
	response, err := client.httpClient.Do(httpRequest)
	if err != nil {
		if ctx.Err() != nil {
			return devopsbuildv1.LogBatch{}, false, ctx.Err()
		}
		return devopsbuildv1.LogBatch{}, false, port.ErrBuildUnavailable
	}
	return decodeLogResponse(request, afterSequence, response)
}

func (client *AdminClient) create(
	ctx context.Context,
	request devopsbuildv1.Request,
	archive io.Reader,
) (devopsbuildv1.Observation, error) {
	metadata, err := devopsbuildv1.EncodeSubmission(request)
	if err != nil {
		return devopsbuildv1.Observation{}, port.ErrBuildConflict
	}
	contentLength := int64(8+len(metadata)) + request.SourceArchiveBytes
	if contentLength <= 8 || contentLength > maximumSubmissionBody {
		return devopsbuildv1.Observation{}, port.ErrBuildConflict
	}
	reader, writer := io.Pipe()
	writeDone := make(chan error, 1)
	go func() {
		writeErr := devopsbuildv1.WriteSubmission(writer, request, archive)
		closeErr := writer.CloseWithError(writeErr)
		writeDone <- errors.Join(writeErr, closeErr)
	}()
	httpRequest, err := http.NewRequestWithContext(
		ctx, http.MethodPost, client.origin+executionsPath, reader,
	)
	if err != nil {
		_ = reader.CloseWithError(err)
		<-writeDone
		return devopsbuildv1.Observation{}, port.ErrBuildConflict
	}
	httpRequest.ContentLength = contentLength
	setRequestHeaders(
		httpRequest, devopsbuildv1.FramedMediaType,
		devopsbuildv1.DocumentMediaType,
	)
	response, requestErr := client.httpClient.Do(httpRequest)
	_ = reader.CloseWithError(requestErr)
	writeErr := <-writeDone
	if requestErr != nil {
		if ctx.Err() != nil {
			return devopsbuildv1.Observation{}, ctx.Err()
		}
		return devopsbuildv1.Observation{}, port.ErrBuildOutcomeUnknown
	}
	if writeErr != nil {
		_ = response.Body.Close()
		return devopsbuildv1.Observation{}, port.ErrBuildOutcomeUnknown
	}
	return decodeAdminResponse(request, response, false)
}

func (client *AdminClient) control(
	ctx context.Context,
	request devopsbuildv1.Request,
	action devopsbuildv1.ControlAction,
) (devopsbuildv1.Observation, error) {
	content, err := devopsbuildv1.EncodeControl(action, request)
	if err != nil {
		return devopsbuildv1.Observation{}, port.ErrBuildConflict
	}
	executionID, _ := devopsbuildv1.ExecutionID(request)
	operation := strings.ToLower(string(action))
	target := client.origin + executionsPath + "/" + url.PathEscape(executionID) + "/" + operation
	httpRequest, err := http.NewRequestWithContext(
		ctx, http.MethodPost, target, bytes.NewReader(content),
	)
	if err != nil {
		return devopsbuildv1.Observation{}, port.ErrBuildConflict
	}
	httpRequest.ContentLength = int64(len(content))
	setRequestHeaders(
		httpRequest, devopsbuildv1.DocumentMediaType,
		devopsbuildv1.DocumentMediaType,
	)
	response, err := client.httpClient.Do(httpRequest)
	if err != nil {
		if ctx.Err() != nil {
			return devopsbuildv1.Observation{}, ctx.Err()
		}
		return devopsbuildv1.Observation{}, port.ErrBuildOutcomeUnknown
	}
	return decodeAdminResponse(request, response, true)
}

func (client *AdminClient) await(
	ctx context.Context,
	request devopsbuildv1.Request,
	current devopsbuildv1.Observation,
	action devopsbuildv1.ControlAction,
) (devopsbuildv1.Receipt, bool, error) {
	for {
		switch current.State {
		case devopsbuildv1.ExecutionTerminal:
			if current.Receipt == nil {
				return devopsbuildv1.Receipt{}, false, port.ErrBuildOutcomeUnknown
			}
			return *current.Receipt, true, nil
		case devopsbuildv1.ExecutionCancelled:
			return devopsbuildv1.Receipt{}, false, port.ErrBuildUnavailable
		case devopsbuildv1.ExecutionQueued, devopsbuildv1.ExecutionAssigned,
			devopsbuildv1.ExecutionCancellationRequested:
		default:
			return devopsbuildv1.Receipt{}, false, port.ErrBuildOutcomeUnknown
		}
		timer := time.NewTimer(client.pollInterval)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return devopsbuildv1.Receipt{}, false, ctx.Err()
		case <-timer.C:
		}
		next, err := client.control(ctx, request, action)
		if err != nil {
			return devopsbuildv1.Receipt{}, false, err
		}
		current = next
	}
}

func decodeAdminResponse(
	request devopsbuildv1.Request,
	response *http.Response,
	notFoundDefinitive bool,
) (devopsbuildv1.Observation, error) {
	if response == nil || response.Body == nil {
		return devopsbuildv1.Observation{}, port.ErrBuildOutcomeUnknown
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK && response.StatusCode != http.StatusAccepted {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 1))
		if len(body) != 0 {
			return devopsbuildv1.Observation{}, port.ErrBuildOutcomeUnknown
		}
		switch response.StatusCode {
		case http.StatusConflict:
			return devopsbuildv1.Observation{}, port.ErrBuildConflict
		case http.StatusNotFound:
			if notFoundDefinitive {
				return devopsbuildv1.Observation{}, port.ErrBuildUnavailable
			}
		}
		return devopsbuildv1.Observation{}, port.ErrBuildOutcomeUnknown
	}
	if response.Header.Get("Content-Type") != devopsbuildv1.DocumentMediaType ||
		response.Header.Get("Content-Encoding") != "" || len(response.TransferEncoding) != 0 ||
		response.ContentLength <= 0 ||
		response.ContentLength > devopsbuildv1.MaximumDocumentBytes {
		return devopsbuildv1.Observation{}, port.ErrBuildOutcomeUnknown
	}
	content, err := io.ReadAll(io.LimitReader(
		response.Body, int64(devopsbuildv1.MaximumDocumentBytes)+1,
	))
	if err != nil || int64(len(content)) != response.ContentLength {
		return devopsbuildv1.Observation{}, port.ErrBuildOutcomeUnknown
	}
	observation, err := devopsbuildv1.DecodeObservation(request, content)
	if err != nil {
		return devopsbuildv1.Observation{}, port.ErrBuildOutcomeUnknown
	}
	return observation, nil
}

func decodeLogResponse(
	request devopsbuildv1.Request,
	afterSequence uint64,
	response *http.Response,
) (devopsbuildv1.LogBatch, bool, error) {
	if response == nil || response.Body == nil {
		return devopsbuildv1.LogBatch{}, false, port.ErrBuildOutcomeUnknown
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNoContent {
		content, readErr := io.ReadAll(io.LimitReader(response.Body, 1))
		if readErr != nil || len(content) != 0 || response.ContentLength != 0 ||
			len(response.TransferEncoding) != 0 ||
			response.Header.Get("Content-Encoding") != "" ||
			response.Header.Get("Content-Type") != "" {
			return devopsbuildv1.LogBatch{}, false, port.ErrBuildOutcomeUnknown
		}
		return devopsbuildv1.LogBatch{}, false, nil
	}
	if response.StatusCode != http.StatusOK {
		content, readErr := io.ReadAll(io.LimitReader(response.Body, 1))
		if readErr != nil || len(content) != 0 || response.ContentLength != 0 ||
			len(response.TransferEncoding) != 0 ||
			response.Header.Get("Content-Encoding") != "" {
			return devopsbuildv1.LogBatch{}, false, port.ErrBuildOutcomeUnknown
		}
		switch response.StatusCode {
		case http.StatusBadRequest, http.StatusConflict:
			return devopsbuildv1.LogBatch{}, false, port.ErrBuildConflict
		case http.StatusNotFound, http.StatusServiceUnavailable:
			return devopsbuildv1.LogBatch{}, false, port.ErrBuildUnavailable
		default:
			return devopsbuildv1.LogBatch{}, false, port.ErrBuildOutcomeUnknown
		}
	}
	if !responseHasSingleHeader(
		response, "Content-Type", devopsbuildv1.LogDocumentMediaType,
	) || response.Header.Get("Content-Encoding") != "" ||
		len(response.TransferEncoding) != 0 || response.ContentLength <= 0 ||
		response.ContentLength > devopsbuildv1.MaximumLogDocumentBytes {
		return devopsbuildv1.LogBatch{}, false, port.ErrBuildOutcomeUnknown
	}
	content, err := io.ReadAll(io.LimitReader(
		response.Body, devopsbuildv1.MaximumLogDocumentBytes+1,
	))
	if err != nil || int64(len(content)) != response.ContentLength {
		return devopsbuildv1.LogBatch{}, false, port.ErrBuildOutcomeUnknown
	}
	batch, err := devopsbuildv1.DecodeLogBatch(request, content)
	if err != nil || batch.Previous.LastSequence != afterSequence {
		return devopsbuildv1.LogBatch{}, false, port.ErrBuildOutcomeUnknown
	}
	return batch, true, nil
}

func setRequestHeaders(request *http.Request, contentType, accept string) {
	request.Header.Set("Content-Type", contentType)
	request.Header.Set("Accept", accept)
	request.Header.Set("User-Agent", "matrix-devops-build-worker/v1")
}

func validateGatewayOrigin(value string) (string, error) {
	parsed, err := url.Parse(value)
	if err != nil || parsed == nil {
		return "", errors.New("executor gateway origin is invalid")
	}
	if parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil ||
		(parsed.Path != "" && parsed.Path != "/") || parsed.RawPath != "" ||
		parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" {
		return "", errors.New("executor gateway origin is invalid")
	}
	hostname := parsed.Hostname()
	if hostname == "" || !validServerName(hostname) {
		return "", errors.New("executor gateway origin is invalid")
	}
	canonicalHost := hostname
	if address := net.ParseIP(hostname); address != nil {
		if address.String() != hostname {
			return "", errors.New("executor gateway origin is invalid")
		}
		if strings.Contains(hostname, ":") {
			canonicalHost = "[" + hostname + "]"
		}
	}
	if portText := parsed.Port(); portText != "" {
		port, portErr := strconv.Atoi(portText)
		if portErr != nil || port < 1 || port > 65535 ||
			strconv.Itoa(port) != portText || port == 443 {
			return "", errors.New("executor gateway origin is invalid")
		}
		canonicalHost += ":" + portText
	}
	canonical := "https://" + canonicalHost
	if parsed.Host != canonicalHost || (value != canonical && value != canonical+"/") {
		return "", errors.New("executor gateway origin is invalid")
	}
	return canonical, nil
}

func validServerName(value string) bool {
	if value == "" || len(value) > 253 || strings.ContainsAny(value, "/:@") ||
		strings.TrimSpace(value) != value {
		return false
	}
	if address := net.ParseIP(value); address != nil {
		return address.String() == value
	}
	if strings.Contains(value, ":") {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') &&
				(character < '0' || character > '9') && character != '-' {
				return false
			}
		}
	}
	return true
}

var _ port.BuildExecutor = (*AdminClient)(nil)
var _ port.BuildLogSource = (*AdminClient)(nil)
