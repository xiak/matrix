package gitea

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	devopsv1 "github.com/xiak/matrix/api/devops/v1"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/domain"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/usecase/sourceobservation"
	"github.com/xiak/matrix/app/service/devops/sourcecredential"
)

const (
	SupportedVersion    = "1.27.3"
	maximumResponseBody = 64 * 1024
	requestTimeout      = 5 * time.Second
)

type CredentialResolver interface {
	Resolve(
		context.Context, devopsv1.ResourceScope, devopsv1.ResourceID,
	) (sourcecredential.Material, error)
}

type Observer struct {
	webhook CredentialResolver
	fetch   CredentialResolver
	report  CredentialResolver
	client  *http.Client
}

var _ sourceobservation.Provider = (*Observer)(nil)

func NewObserver(
	webhook CredentialResolver,
	fetch CredentialResolver,
	report CredentialResolver,
) (*Observer, error) {
	dialer := &net.Dialer{Timeout: requestTimeout, KeepAlive: 30 * time.Second}
	transport := &http.Transport{
		Proxy:                 nil,
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          16,
		MaxIdleConnsPerHost:   4,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   requestTimeout,
		ResponseHeaderTimeout: requestTimeout,
		ExpectContinueTimeout: time.Second,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
	}
	return newObserver(webhook, fetch, report, &http.Client{
		Transport: transport,
		Timeout:   requestTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("provider redirects are not permitted")
		},
	})
}

func newObserver(
	webhook CredentialResolver,
	fetch CredentialResolver,
	report CredentialResolver,
	client *http.Client,
) (*Observer, error) {
	if webhook == nil || fetch == nil || report == nil || client == nil ||
		client.Timeout != requestTimeout || client.CheckRedirect == nil {
		return nil, errors.New("Gitea source observer configuration is invalid")
	}
	return &Observer{webhook: webhook, fetch: fetch, report: report, client: client}, nil
}

func (observer *Observer) ObserveSourceConnection(
	ctx context.Context,
	connection devopsv1.SourceConnection,
) (domain.SourceConnectionHealthObservation, error) {
	if observer == nil || observer.client == nil || ctx == nil ||
		devopsv1.ValidateSourceConnection(connection) != nil ||
		connection.Spec.AdapterID != AdapterID {
		return domain.SourceConnectionHealthObservation{},
			errors.New("Gitea source connection observation is invalid")
	}
	webhook, err := observer.webhook.Resolve(
		ctx, connection.Metadata.Scope, connection.Spec.WebhookSecretRef,
	)
	if err != nil {
		return connectionUnavailable(ctx, devopsv1.SourceConnectionReasonSecretUnavailable, err)
	}
	webhook.Clear()
	fetch, err := observer.fetch.Resolve(
		ctx, connection.Metadata.Scope, connection.Spec.FetchCredentialRef,
	)
	if err != nil {
		return connectionUnavailable(ctx, devopsv1.SourceConnectionReasonSecretUnavailable, err)
	}
	defer fetch.Clear()
	report, err := observer.report.Resolve(
		ctx, connection.Metadata.Scope, connection.Spec.ReportCredentialRef,
	)
	if err != nil {
		return connectionUnavailable(ctx, devopsv1.SourceConnectionReasonSecretUnavailable, err)
	}
	defer report.Clear()

	var version versionResponse
	status, err := observer.getJSON(ctx, connection.Spec.EndpointOrigin, "/api/v1/version", nil, &version)
	if err != nil || status != http.StatusOK {
		return connectionUnavailable(ctx, devopsv1.SourceConnectionReasonProviderUnavailable, err)
	}
	if version.Version != SupportedVersion {
		return unavailableConnection(devopsv1.SourceConnectionReasonProviderUnsupported), nil
	}
	for _, token := range [][]byte{fetch.Current, report.Current} {
		var user userResponse
		status, err = observer.getJSON(ctx, connection.Spec.EndpointOrigin, "/api/v1/user", token, &user)
		if err != nil {
			return connectionUnavailable(ctx, devopsv1.SourceConnectionReasonProviderUnavailable, err)
		}
		if status == http.StatusUnauthorized || status == http.StatusForbidden {
			return unavailableConnection(devopsv1.SourceConnectionReasonCredentialRejected), nil
		}
		if status != http.StatusOK || !validUser(user) {
			return unavailableConnection(devopsv1.SourceConnectionReasonProviderUnavailable), nil
		}
	}
	return domain.SourceConnectionHealthObservation{
		Health: devopsv1.SourceConnectionReady,
		Reason: devopsv1.SourceConnectionReasonObserved,
	}, nil
}

func (observer *Observer) ObserveRepositoryBinding(
	ctx context.Context,
	connection devopsv1.SourceConnection,
	binding devopsv1.RepositoryBinding,
) (domain.RepositoryBindingHealthObservation, error) {
	if observer == nil || observer.client == nil || ctx == nil ||
		devopsv1.ValidateSourceConnection(connection) != nil ||
		devopsv1.ValidateRepositoryBinding(binding) != nil ||
		connection.Spec.AdapterID != AdapterID ||
		connection.Metadata.Scope != binding.Metadata.Scope ||
		binding.Spec.SourceConnectionID != connection.Metadata.ID {
		return domain.RepositoryBindingHealthObservation{},
			errors.New("Gitea repository binding observation is invalid")
	}
	fetch, err := observer.fetch.Resolve(
		ctx, connection.Metadata.Scope, connection.Spec.FetchCredentialRef,
	)
	if err != nil {
		return bindingUnavailable(ctx, devopsv1.RepositoryBindingReasonFetchPermissionDenied, err)
	}
	defer fetch.Clear()
	report, err := observer.report.Resolve(
		ctx, connection.Metadata.Scope, connection.Spec.ReportCredentialRef,
	)
	if err != nil {
		return bindingUnavailable(ctx, devopsv1.RepositoryBindingReasonReportPermissionDenied, err)
	}
	defer report.Clear()

	segments := strings.Split(binding.Spec.RepositoryPath, "/")
	if len(segments) != 2 {
		return domain.RepositoryBindingHealthObservation{}, errors.New("Gitea repository path is invalid")
	}
	requestPath := "/api/v1/repos/" + url.PathEscape(segments[0]) + "/" + url.PathEscape(segments[1])
	for index, token := range [][]byte{fetch.Current, report.Current} {
		var repository repositoryResponse
		status, requestErr := observer.getJSON(
			ctx, connection.Spec.EndpointOrigin, requestPath, token, &repository,
		)
		permissionReason := devopsv1.RepositoryBindingReasonFetchPermissionDenied
		if index == 1 {
			permissionReason = devopsv1.RepositoryBindingReasonReportPermissionDenied
		}
		if requestErr != nil {
			return bindingUnavailable(ctx, devopsv1.RepositoryBindingReasonRepositoryUnavailable, requestErr)
		}
		if status == http.StatusUnauthorized || status == http.StatusForbidden {
			return unavailableBinding(permissionReason), nil
		}
		if status != http.StatusOK {
			return unavailableBinding(devopsv1.RepositoryBindingReasonRepositoryUnavailable), nil
		}
		if !repositoryMatches(connection, binding, repository) {
			return unavailableBinding(devopsv1.RepositoryBindingReasonIdentityMismatch), nil
		}
		if repository.Permissions == nil || index == 0 && !repository.Permissions.Pull ||
			index == 1 && !repository.Permissions.Push {
			return unavailableBinding(permissionReason), nil
		}
	}
	return domain.RepositoryBindingHealthObservation{
		Health: devopsv1.RepositoryBindingReady,
		Reason: devopsv1.RepositoryBindingReasonObserved,
	}, nil
}

type versionResponse struct {
	Version string `json:"version"`
}

type userResponse struct {
	ID    int64  `json:"id"`
	Login string `json:"login"`
}

type repositoryResponse struct {
	ID               int64       `json:"id"`
	FullName         string      `json:"full_name"`
	URL              string      `json:"url"`
	HTMLURL          string      `json:"html_url"`
	CloneURL         string      `json:"clone_url"`
	DefaultBranch    string      `json:"default_branch"`
	ObjectFormatName string      `json:"object_format_name"`
	Permissions      *permission `json:"permissions"`
}

type permission struct {
	Pull bool `json:"pull"`
	Push bool `json:"push"`
}

func (observer *Observer) getJSON(
	ctx context.Context,
	endpointOrigin string,
	requestPath string,
	token []byte,
	target any,
) (int, error) {
	requestContext, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(
		requestContext, http.MethodGet, endpointOrigin+requestPath, nil,
	)
	if err != nil {
		return 0, errors.New("provider request is invalid")
	}
	request.Header.Set("Accept", "application/json")
	if len(token) != 0 {
		request.Header.Set("Authorization", "token "+string(token))
	}
	response, err := observer.client.Do(request)
	if err != nil {
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		return 0, errors.New("provider request failed")
	}
	defer response.Body.Close()
	content, err := io.ReadAll(io.LimitReader(response.Body, maximumResponseBody+1))
	if err != nil || len(content) > maximumResponseBody {
		clear(content)
		return 0, errors.New("provider response is unavailable")
	}
	defer clear(content)
	if response.StatusCode != http.StatusOK {
		return response.StatusCode, nil
	}
	if !validJSONMediaType(response.Header.Get("Content-Type")) {
		return response.StatusCode, errors.New("provider response media type is invalid")
	}
	if rejectAmbiguousJSON(content) != nil || json.Unmarshal(content, target) != nil {
		return response.StatusCode, errors.New("provider response JSON is invalid")
	}
	return response.StatusCode, nil
}

func validJSONMediaType(value string) bool {
	mediaType, parameters, err := mime.ParseMediaType(value)
	if err != nil || mediaType != "application/json" {
		return false
	}
	for name, parameter := range parameters {
		if name != "charset" || !strings.EqualFold(parameter, "utf-8") {
			return false
		}
	}
	return true
}

func validUser(value userResponse) bool {
	return value.ID > 0 && uint64(value.ID) <= devopsv1.MaximumContractInteger &&
		validProviderText(value.Login, 1, 255)
}

func repositoryMatches(
	connection devopsv1.SourceConnection,
	binding devopsv1.RepositoryBinding,
	repository repositoryResponse,
) bool {
	if repository.ID < 1 || uint64(repository.ID) > devopsv1.MaximumContractInteger ||
		strconv.FormatInt(repository.ID, 10) != string(binding.Spec.ExternalRepositoryID) ||
		repository.FullName != binding.Spec.RepositoryPath ||
		repository.DefaultBranch != binding.Spec.TrustedDefaultBranch ||
		repository.ObjectFormatName != "sha1" {
		return false
	}
	return repositoryUsesEndpointOrigin(hookRepository{
		URL: repository.URL, HTMLURL: repository.HTMLURL, CloneURL: repository.CloneURL,
	}, connection.Spec.EndpointOrigin)
}

func validProviderText(value string, minimum, maximum int) bool {
	if !utf8.ValidString(value) || len(value) < minimum || len(value) > maximum ||
		strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func connectionUnavailable(
	ctx context.Context,
	reason devopsv1.SourceConnectionHealthReason,
	_ error,
) (domain.SourceConnectionHealthObservation, error) {
	if ctx.Err() != nil {
		return domain.SourceConnectionHealthObservation{}, ctx.Err()
	}
	return unavailableConnection(reason), nil
}

func bindingUnavailable(
	ctx context.Context,
	reason devopsv1.RepositoryBindingHealthReason,
	_ error,
) (domain.RepositoryBindingHealthObservation, error) {
	if ctx.Err() != nil {
		return domain.RepositoryBindingHealthObservation{}, ctx.Err()
	}
	return unavailableBinding(reason), nil
}

func unavailableConnection(
	reason devopsv1.SourceConnectionHealthReason,
) domain.SourceConnectionHealthObservation {
	return domain.SourceConnectionHealthObservation{
		Health: devopsv1.SourceConnectionUnavailable, Reason: reason,
	}
}

func unavailableBinding(
	reason devopsv1.RepositoryBindingHealthReason,
) domain.RepositoryBindingHealthObservation {
	return domain.RepositoryBindingHealthObservation{
		Health: devopsv1.RepositoryBindingUnavailable, Reason: reason,
	}
}
