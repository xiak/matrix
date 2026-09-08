// Package gitea implements the fixed Gitea 1.27.3 webhook protocol boundary.
package gitea

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"

	devopsv1 "github.com/xiak/matrix/api/devops/v1"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/usecase/sourceingress"
)

const (
	AdapterID         = devopsv1.ResourceID("source-adapter-gitea-v1")
	maximumJSONDepth  = 64
	maximumJSONTokens = 65_536
)

type Adapter struct{}

var _ sourceingress.ProviderAdapter = (*Adapter)(nil)

func NewAdapter() *Adapter {
	return &Adapter{}
}

func (*Adapter) ID() devopsv1.ResourceID {
	return AdapterID
}

func (*Adapter) AuthenticateAndNormalize(
	ctx context.Context,
	request sourceingress.ProviderRequest,
) (sourceingress.ProviderChange, error) {
	if ctx == nil {
		return sourceingress.ProviderChange{}, sourceingress.ErrInvalidArgument
	}
	if err := ctx.Err(); err != nil {
		return sourceingress.ProviderChange{}, err
	}
	if len(request.Body) == 0 || len(request.Body) > sourceingress.MaximumWebhookBodyBytes {
		return sourceingress.ProviderChange{}, sourceingress.ErrInvalidArgument
	}
	signature, validSignature := decodeSignature(request.Signature)
	if !validSignature || !request.SecretSet.Matches(func(secret []byte) bool {
		mac := hmac.New(sha256.New, secret)
		_, _ = mac.Write(request.Body)
		expected := mac.Sum(nil)
		matched := subtle.ConstantTimeCompare(expected, signature) == 1
		clear(expected)
		return matched
	}) {
		clear(signature)
		return sourceingress.ProviderChange{}, sourceingress.ErrUnauthenticated
	}
	clear(signature)

	if devopsv1.ValidateSourceConnection(request.Connection) != nil ||
		request.Connection.Spec.AdapterID != AdapterID {
		return sourceingress.ProviderChange{}, sourceingress.ErrPrecondition
	}
	if request.Event != "pull_request" {
		return sourceingress.ProviderChange{}, sourceingress.ErrUnsupportedEvent
	}
	if _, err := devopsv1.SourceEventID(
		request.Connection.Metadata.Scope,
		request.Connection.Metadata.ID,
		request.DeliveryID,
	); err != nil {
		return sourceingress.ProviderChange{}, sourceingress.ErrInvalidArgument
	}
	if rejectAmbiguousJSON(request.Body) != nil {
		return sourceingress.ProviderChange{}, sourceingress.ErrInvalidArgument
	}
	var payload pullRequestPayload
	if json.Unmarshal(request.Body, &payload) != nil {
		return sourceingress.ProviderChange{}, sourceingress.ErrInvalidArgument
	}
	return normalizePayload(payload, request.Connection.Spec.EndpointOrigin)
}

type pullRequestPayload struct {
	Action      string          `json:"action"`
	Number      int64           `json:"number"`
	PullRequest *pullRequest    `json:"pull_request"`
	Repository  *hookRepository `json:"repository"`
}

type pullRequest struct {
	Number int64      `json:"number"`
	Base   hookBranch `json:"base"`
	Head   hookBranch `json:"head"`
}

type hookBranch struct {
	Ref    string          `json:"ref"`
	SHA    string          `json:"sha"`
	RepoID int64           `json:"repo_id"`
	Repo   *hookRepository `json:"repo"`
}

type hookRepository struct {
	ID               int64  `json:"id"`
	FullName         string `json:"full_name"`
	URL              string `json:"url"`
	HTMLURL          string `json:"html_url"`
	CloneURL         string `json:"clone_url"`
	ObjectFormatName string `json:"object_format_name"`
}

func normalizePayload(
	payload pullRequestPayload,
	endpointOrigin string,
) (sourceingress.ProviderChange, error) {
	if payload.PullRequest == nil || payload.Repository == nil ||
		payload.Number < 1 || uint64(payload.Number) > devopsv1.MaximumContractInteger ||
		payload.PullRequest.Number != payload.Number ||
		payload.Repository.ID < 1 || uint64(payload.Repository.ID) > devopsv1.MaximumContractInteger ||
		payload.PullRequest.Base.RepoID != payload.Repository.ID ||
		payload.PullRequest.Base.Repo == nil ||
		!sameRepository(*payload.Repository, *payload.PullRequest.Base.Repo) ||
		!repositoryUsesEndpointOrigin(*payload.Repository, endpointOrigin) ||
		!repositoryUsesEndpointOrigin(*payload.PullRequest.Base.Repo, endpointOrigin) {
		return sourceingress.ProviderChange{}, sourceingress.ErrInvalidArgument
	}
	action, found := mapAction(payload.Action)
	if !found {
		return sourceingress.ProviderChange{}, sourceingress.ErrUnsupportedEvent
	}
	change := devopsv1.ChangeIdentity{
		Number:            uint64(payload.Number),
		Action:            action,
		HeadCommit:        payload.PullRequest.Head.SHA,
		TrustedBaseCommit: payload.PullRequest.Base.SHA,
	}
	if devopsv1.ValidateTrustedDefaultBranch(payload.PullRequest.Base.Ref) != nil ||
		devopsv1.ValidateChangeIdentity(change) != nil ||
		!objectFormatMatches(payload.Repository.ObjectFormatName, change.HeadCommit) ||
		!objectFormatMatches(payload.Repository.ObjectFormatName, change.TrustedBaseCommit) {
		return sourceingress.ProviderChange{}, sourceingress.ErrInvalidArgument
	}
	return sourceingress.ProviderChange{
		ExternalRepositoryID: devopsv1.ResourceID(strconv.FormatInt(payload.Repository.ID, 10)),
		TrustedBaseBranch:    payload.PullRequest.Base.Ref,
		Change:               change,
	}, nil
}

func mapAction(value string) (devopsv1.ChangeAction, bool) {
	switch value {
	case "opened":
		return devopsv1.ChangeOpened, true
	case "reopened":
		return devopsv1.ChangeReopened, true
	case "synchronized":
		return devopsv1.ChangeUpdated, true
	default:
		return "", false
	}
}

func sameRepository(left, right hookRepository) bool {
	return left.ID == right.ID && left.FullName != "" && left.FullName == right.FullName &&
		left.URL == right.URL && left.HTMLURL == right.HTMLURL &&
		left.CloneURL == right.CloneURL && left.ObjectFormatName == right.ObjectFormatName
}

func repositoryUsesEndpointOrigin(repository hookRepository, endpointOrigin string) bool {
	if endpointOrigin == "" {
		return false
	}
	for _, raw := range []string{repository.URL, repository.HTMLURL, repository.CloneURL} {
		parsed, err := url.Parse(raw)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil ||
			parsed.Opaque != "" || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" {
			return false
		}
		if parsed.Scheme+"://"+parsed.Host != endpointOrigin {
			return false
		}
	}
	return true
}

func objectFormatMatches(format, objectID string) bool {
	return format == "sha1" && len(objectID) == 40 || format == "sha256" && len(objectID) == 64
}

func decodeSignature(value string) ([]byte, bool) {
	if len(value) != sha256.Size*2 {
		return nil, false
	}
	for _, character := range value {
		if character < '0' || character > '9' && character < 'a' || character > 'f' {
			return nil, false
		}
	}
	decoded, err := hex.DecodeString(value)
	return decoded, err == nil
}

type jsonBudget struct {
	remaining int
}

func rejectAmbiguousJSON(document []byte) error {
	if !utf8.Valid(document) {
		return errors.New("provider JSON is not UTF-8")
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.UseNumber()
	budget := &jsonBudget{remaining: maximumJSONTokens}
	if err := walkJSON(decoder, budget, 0); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("provider JSON contains multiple values")
	}
	return nil
}

func walkJSON(decoder *json.Decoder, budget *jsonBudget, depth int) error {
	if depth > maximumJSONDepth || budget.remaining < 1 {
		return errors.New("provider JSON complexity is invalid")
	}
	budget.remaining--
	token, err := decoder.Token()
	if err != nil {
		return errors.New("provider JSON is invalid")
	}
	delimiter, composite := token.(json.Delim)
	if !composite {
		return nil
	}
	switch delimiter {
	case '{':
		keys := make(map[string]struct{})
		for decoder.More() {
			if budget.remaining < 1 {
				return errors.New("provider JSON complexity is invalid")
			}
			budget.remaining--
			keyToken, err := decoder.Token()
			key, ok := keyToken.(string)
			if err != nil || !ok {
				return errors.New("provider JSON object is invalid")
			}
			folded := strings.ToLower(key)
			if _, duplicate := keys[folded]; duplicate {
				return errors.New("provider JSON contains duplicate keys")
			}
			keys[folded] = struct{}{}
			if err := walkJSON(decoder, budget, depth+1); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return errors.New("provider JSON object is invalid")
		}
	case '[':
		for decoder.More() {
			if err := walkJSON(decoder, budget, depth+1); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return errors.New("provider JSON array is invalid")
		}
	default:
		return errors.New("provider JSON delimiter is invalid")
	}
	return nil
}
