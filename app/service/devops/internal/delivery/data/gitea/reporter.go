package gitea

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	devopsv1 "github.com/xiak/matrix/api/devops/v1"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/usecase/checkreporting"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/usecase/runlifecycle"
	"github.com/xiak/matrix/app/service/devops/sourcecredential"
)

const maximumObservedStatuses = 50

type CheckReporter struct {
	credentials CredentialResolver
	client      *http.Client
}

var _ checkreporting.Reporter = (*CheckReporter)(nil)

func NewCheckReporter(credentials CredentialResolver) (*CheckReporter, error) {
	if credentials == nil {
		return nil, errors.New("Gitea report credential resolver is required")
	}
	dialer := &net.Dialer{Timeout: requestTimeout, KeepAlive: -1}
	transport := &http.Transport{
		Proxy:                  nil,
		DialContext:            dialer.DialContext,
		ForceAttemptHTTP2:      true,
		DisableCompression:     true,
		DisableKeepAlives:      true,
		TLSHandshakeTimeout:    requestTimeout,
		ResponseHeaderTimeout:  requestTimeout,
		ExpectContinueTimeout:  time.Second,
		MaxResponseHeaderBytes: maximumResponseBody,
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12},
	}
	return newCheckReporter(credentials, &http.Client{
		Transport: transport,
		Timeout:   checkreporting.ProviderDeadline,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("provider redirects are not permitted")
		},
	})
}

func newCheckReporter(
	credentials CredentialResolver,
	client *http.Client,
) (*CheckReporter, error) {
	if credentials == nil || client == nil || client.Transport == nil ||
		client.Timeout != checkreporting.ProviderDeadline || client.CheckRedirect == nil {
		return nil, errors.New("Gitea check reporter configuration is invalid")
	}
	return &CheckReporter{credentials: credentials, client: client}, nil
}

func (reporter *CheckReporter) Create(
	ctx context.Context,
	command checkreporting.Command,
) (checkreporting.Receipt, error) {
	if reporter == nil || reporter.credentials == nil || reporter.client == nil || ctx == nil ||
		checkreporting.ValidateCommand(command) != nil ||
		command.Connection.Spec.AdapterID != AdapterID ||
		command.Lease.Mode != runlifecycle.ClaimExecute {
		return checkreporting.Receipt{}, checkreporting.ErrReportUnavailable
	}
	if err := ctx.Err(); err != nil {
		return checkreporting.Receipt{}, err
	}
	requestPath, err := checkStatusPath(command)
	if err != nil {
		return checkreporting.Receipt{}, checkreporting.ErrReportUnavailable
	}
	document, err := checkStatusDocument(command)
	if err != nil {
		return checkreporting.Receipt{}, checkreporting.ErrReportUnavailable
	}
	body, err := json.Marshal(document)
	if err != nil || len(body) == 0 || len(body) > maximumResponseBody {
		clear(body)
		return checkreporting.Receipt{}, checkreporting.ErrReportUnavailable
	}
	defer clear(body)
	token, err := reporter.resolveToken(ctx, command)
	if err != nil {
		return checkreporting.Receipt{}, err
	}
	defer token.Clear()
	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		command.Connection.Spec.EndpointOrigin+requestPath,
		bytes.NewReader(body),
	)
	if err != nil {
		return checkreporting.Receipt{}, checkreporting.ErrReportUnavailable
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "token "+string(token.Current))
	defer request.Header.Del("Authorization")

	response, err := reporter.client.Do(request)
	if err != nil {
		closeResponse(response)
		return checkreporting.Receipt{}, reportRequestFailure(ctx)
	}
	content, contentErr := readCheckResponse(response)
	defer clear(content)
	if definitiveCreateRejection(response.StatusCode) {
		return checkreporting.Receipt{}, checkreporting.ErrReportUnavailable
	}
	if response.StatusCode != http.StatusCreated || contentErr != nil ||
		!validJSONMediaType(response.Header.Get("Content-Type")) {
		return checkreporting.Receipt{}, checkreporting.ErrOutcomeUnknown
	}
	status, err := decodeCheckStatus(content)
	if err != nil || !validCheckStatus(status, command.Connection.Spec.EndpointOrigin, requestPath) ||
		!status.matches(document) {
		return checkreporting.Receipt{}, checkreporting.ErrOutcomeUnknown
	}
	return checkreporting.NewReceipt(command, uint64(status.ID))
}

func (reporter *CheckReporter) Observe(
	ctx context.Context,
	command checkreporting.Command,
) (checkreporting.Receipt, bool, error) {
	if reporter == nil || reporter.credentials == nil || reporter.client == nil || ctx == nil ||
		checkreporting.ValidateCommand(command) != nil ||
		command.Connection.Spec.AdapterID != AdapterID ||
		command.Lease.Mode != runlifecycle.ClaimObserve {
		return checkreporting.Receipt{}, false, checkreporting.ErrReportUnavailable
	}
	if err := ctx.Err(); err != nil {
		return checkreporting.Receipt{}, false, err
	}
	requestPath, err := checkStatusPath(command)
	if err != nil {
		return checkreporting.Receipt{}, false, checkreporting.ErrReportUnavailable
	}
	document, err := checkStatusDocument(command)
	if err != nil {
		return checkreporting.Receipt{}, false, checkreporting.ErrReportUnavailable
	}
	query := url.Values{}
	query.Set("limit", "50")
	query.Set("page", "1")
	// Gitea 1.27.3's pinned implementation orders index DESC for
	// "leastindex" despite the option name. This is the newest-first order.
	query.Set("sort", "leastindex")
	token, err := reporter.resolveToken(ctx, command)
	if err != nil {
		return checkreporting.Receipt{}, false, err
	}
	defer token.Clear()
	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		command.Connection.Spec.EndpointOrigin+requestPath+"?"+query.Encode(),
		nil,
	)
	if err != nil {
		return checkreporting.Receipt{}, false, checkreporting.ErrReportUnavailable
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Authorization", "token "+string(token.Current))
	defer request.Header.Del("Authorization")

	response, err := reporter.client.Do(request)
	if err != nil {
		closeResponse(response)
		return checkreporting.Receipt{}, false, reportRequestFailure(ctx)
	}
	content, contentErr := readCheckResponse(response)
	defer clear(content)
	if definitiveObservationRejection(response.StatusCode) {
		return checkreporting.Receipt{}, false, checkreporting.ErrReportUnavailable
	}
	if response.StatusCode != http.StatusOK || contentErr != nil ||
		!validJSONMediaType(response.Header.Get("Content-Type")) {
		return checkreporting.Receipt{}, false, checkreporting.ErrOutcomeUnknown
	}
	statuses, err := decodeCheckStatuses(content)
	if err != nil || len(statuses) > maximumObservedStatuses {
		return checkreporting.Receipt{}, false, checkreporting.ErrOutcomeUnknown
	}
	providerStatusID := uint64(0)
	for _, status := range statuses {
		if !validCheckStatus(status, command.Connection.Spec.EndpointOrigin, requestPath) {
			return checkreporting.Receipt{}, false, checkreporting.ErrOutcomeUnknown
		}
		if status.Context != document.Context {
			continue
		}
		if providerStatusID != 0 || !status.matches(document) {
			return checkreporting.Receipt{}, false, checkreporting.ErrReportConflict
		}
		providerStatusID = uint64(status.ID)
	}
	if providerStatusID == 0 {
		return checkreporting.Receipt{}, false, nil
	}
	receipt, err := checkreporting.NewReceipt(command, providerStatusID)
	if err != nil {
		return checkreporting.Receipt{}, false, checkreporting.ErrOutcomeUnknown
	}
	return receipt, true, nil
}

type createCheckStatus struct {
	Context     string                    `json:"context"`
	Description string                    `json:"description"`
	State       checkreporting.CheckState `json:"state"`
	TargetURL   string                    `json:"target_url"`
}

type checkStatus struct {
	ID          int64           `json:"id"`
	Status      string          `json:"status"`
	TargetURL   string          `json:"target_url"`
	Description string          `json:"description"`
	URL         string          `json:"url"`
	Context     string          `json:"context"`
	Creator     json.RawMessage `json:"creator"`
	CreatedAt   string          `json:"created_at"`
	UpdatedAt   string          `json:"updated_at"`
}

func (status checkStatus) matches(expected createCheckStatus) bool {
	return status.Status == string(expected.State) &&
		status.TargetURL == expected.TargetURL &&
		status.Description == expected.Description &&
		status.Context == expected.Context
}

func checkStatusDocument(command checkreporting.Command) (createCheckStatus, error) {
	contextName, err := checkreporting.CheckContext(command)
	if err != nil {
		return createCheckStatus{}, err
	}
	state, description, err := checkreporting.CheckOutcome(command)
	if err != nil {
		return createCheckStatus{}, err
	}
	return createCheckStatus{
		Context: contextName, Description: description, State: state, TargetURL: "",
	}, nil
}

func checkStatusPath(command checkreporting.Command) (string, error) {
	segments := strings.Split(command.BindingRevision.Spec.RepositoryPath, "/")
	if len(segments) != 2 || segments[0] == "" || segments[1] == "" {
		return "", errors.New("Gitea report repository path is invalid")
	}
	return "/api/v1/repos/" + url.PathEscape(segments[0]) + "/" +
		url.PathEscape(segments[1]) + "/statuses/" +
		url.PathEscape(command.Lease.Run.Input.Change.HeadCommit), nil
}

func (reporter *CheckReporter) resolveToken(
	ctx context.Context,
	command checkreporting.Command,
) (sourcecredential.Material, error) {
	material, err := reporter.credentials.Resolve(
		ctx,
		command.Connection.Metadata.Scope,
		command.Connection.Spec.ReportCredentialRef,
	)
	if err != nil {
		if ctx.Err() != nil {
			return sourcecredential.Material{}, ctx.Err()
		}
		return sourcecredential.Material{}, checkreporting.ErrReportUnavailable
	}
	defer material.Clear()
	validated, err := sourcecredential.NewMaterial(
		sourcecredential.PurposeReport, material.Current, nil,
	)
	if err != nil {
		return sourcecredential.Material{}, checkreporting.ErrReportUnavailable
	}
	return validated, nil
}

func readCheckResponse(response *http.Response) ([]byte, error) {
	if response == nil || response.Body == nil {
		return nil, errors.New("provider response is absent")
	}
	defer response.Body.Close()
	content, err := io.ReadAll(io.LimitReader(response.Body, maximumResponseBody+1))
	if err != nil || len(content) > maximumResponseBody {
		return content, errors.New("provider response is unavailable")
	}
	return content, nil
}

func closeResponse(response *http.Response) {
	if response != nil && response.Body != nil {
		_ = response.Body.Close()
	}
}

func reportRequestFailure(ctx context.Context) error {
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	return checkreporting.ErrOutcomeUnknown
}

func definitiveCreateRejection(status int) bool {
	switch status {
	case http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden,
		http.StatusNotFound, http.StatusUnprocessableEntity:
		return true
	default:
		return false
	}
}

func definitiveObservationRejection(status int) bool {
	switch status {
	case http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden,
		http.StatusNotFound, http.StatusUnprocessableEntity:
		return true
	default:
		return false
	}
}

func decodeCheckStatus(content []byte) (checkStatus, error) {
	var status checkStatus
	if err := decodeStrictProviderJSON(content, &status); err != nil {
		return checkStatus{}, err
	}
	return status, nil
}

func decodeCheckStatuses(content []byte) ([]checkStatus, error) {
	var statuses []checkStatus
	if err := decodeStrictProviderJSON(content, &statuses); err != nil || statuses == nil {
		return nil, errors.New("provider status list is invalid")
	}
	return statuses, nil
}

func decodeStrictProviderJSON(content []byte, target any) error {
	if len(content) == 0 || len(content) > maximumResponseBody ||
		rejectAmbiguousJSON(content) != nil {
		return errors.New("provider response JSON is invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return errors.New("provider response JSON is invalid")
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("provider response JSON has trailing content")
	}
	return nil
}

func validCheckStatus(status checkStatus, endpointOrigin, requestPath string) bool {
	if status.ID < 1 || uint64(status.ID) > devopsv1.MaximumContractInteger ||
		!validCommitStatusState(status.Status) ||
		!validProviderText(status.Context, 1, 255) ||
		!validProviderText(status.Description, 0, 255) ||
		!validProviderText(status.TargetURL, 0, 2048) ||
		status.URL != endpointOrigin+requestPath || len(status.Creator) == 0 ||
		bytes.Equal(status.Creator, []byte("null")) {
		return false
	}
	createdAt, createdErr := time.Parse(time.RFC3339Nano, status.CreatedAt)
	updatedAt, updatedErr := time.Parse(time.RFC3339Nano, status.UpdatedAt)
	return createdErr == nil && updatedErr == nil && !createdAt.IsZero() && createdAt.Equal(updatedAt)
}

func validCommitStatusState(value string) bool {
	switch value {
	case "pending", "success", "error", "failure", "warning":
		return true
	default:
		return false
	}
}
