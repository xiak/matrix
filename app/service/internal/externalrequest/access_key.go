// Package externalrequest owns the trusted edge-to-service description of the
// public HTTP request. It does not authenticate an AccessKey or authorize a
// product action; product PEPs still bind the extracted request to IAM.
package externalrequest

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"

	iamv1 "github.com/xiak/matrix/api/iam/v1"
)

const (
	HeaderExternalOrigin        = "X-Matrix-External-Origin"
	HeaderExternalRequestTarget = "X-Matrix-External-Request-Target"
)

var (
	ErrInvalidConfiguration = errors.New("external request configuration is invalid")
	ErrInvalidRequest       = errors.New("external signed request is invalid")
)

// Boundary binds one product's internal route space to the single configured
// public origin and public route prefix installed by the edge owner.
type Boundary struct {
	origin         string
	scheme         string
	authority      string
	externalPrefix string
	audience       iamv1.ProductID
	installationID string
}

func NewBoundary(origin, externalPrefix, installationID string, audience iamv1.ProductID) (*Boundary, error) {
	parsed, err := parseOrigin(origin)
	if err != nil {
		return nil, ErrInvalidConfiguration
	}
	if externalPrefix == "" || externalPrefix == "/" || strings.HasSuffix(externalPrefix, "/") ||
		!strings.HasPrefix(externalPrefix, "/") || strings.ContainsAny(externalPrefix, "?#") ||
		iamv1.ValidateID("installationId", installationID) != nil {
		return nil, ErrInvalidConfiguration
	}
	probe := iamv1.AccessKeyHTTPRequest{
		Method: "GET", Scheme: parsed.Scheme, Authority: parsed.Host, EscapedPath: externalPrefix,
		BodyDigest: emptyBodyDigest,
	}
	if iamv1.ValidateAccessKeyHTTPRequest(probe) != nil {
		return nil, ErrInvalidConfiguration
	}
	return &Boundary{origin: origin, scheme: parsed.Scheme, authority: parsed.Host,
		externalPrefix: externalPrefix, audience: audience, installationID: installationID}, nil
}

// ValidateOrigin admits one explicit canonical public scheme/authority with a
// mandatory port. It deliberately does not infer public identity from a Host
// header, listener address, proxy metadata, or certificate.
func ValidateOrigin(origin string) error {
	_, err := parseOrigin(origin)
	return err
}

func parseOrigin(origin string) (*url.URL, error) {
	parsed, err := url.Parse(origin)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.User != nil || parsed.Opaque != "" ||
		parsed.Path != "" || parsed.RawPath != "" || parsed.RawQuery != "" || parsed.Fragment != "" ||
		origin != parsed.Scheme+"://"+parsed.Host || (parsed.Scheme != "http" && parsed.Scheme != "https") ||
		strings.ToLower(parsed.Host) != parsed.Host {
		return nil, ErrInvalidConfiguration
	}
	if _, port, splitErr := net.SplitHostPort(parsed.Host); splitErr != nil || port == "" {
		return nil, ErrInvalidConfiguration
	}
	return parsed, nil
}

func IsAccessKeyAuthorization(request *http.Request) bool {
	if request == nil {
		return false
	}
	values := request.Header.Values("Authorization")
	for _, value := range values {
		if strings.HasPrefix(value, iamv1.AccessKeySignatureScheme+" ") {
			return true
		}
	}
	return false
}

// SignedRequest reconstructs the canonical input from edge-owned facts and
// the actual request/body handled by the product. The caller must enforce its
// route/action mapping separately and must reuse body for business decoding.
func (boundary *Boundary) SignedRequest(request *http.Request, body []byte) (iamv1.AccessKeySignedRequest, error) {
	invalid := func() (iamv1.AccessKeySignedRequest, error) {
		return iamv1.AccessKeySignedRequest{}, ErrInvalidRequest
	}
	if boundary == nil || request == nil || request.URL == nil || request.Host == "" ||
		len(request.Header.Values("Authorization")) != 1 ||
		len(request.Header.Values(HeaderExternalOrigin)) != 1 ||
		len(request.Header.Values(HeaderExternalRequestTarget)) != 1 ||
		request.Header.Get(HeaderExternalOrigin) != boundary.origin || hasForbiddenSemantics(request) {
		return invalid()
	}
	parameters, signature, err := iamv1.ParseAccessKeyAuthorization(request.Header.Get("Authorization"))
	if err != nil || parameters.InstallationID != boundary.installationID || parameters.Audience != boundary.audience {
		return invalid()
	}
	externalPath, rawQuery, err := boundary.mapTarget(request.Header.Get(HeaderExternalRequestTarget), request)
	if err != nil {
		return invalid()
	}
	contentType, idempotencyKey, ifMatch, err := coveredHeaders(request, len(body) != 0)
	if err != nil {
		return invalid()
	}
	digest := sha256.Sum256(body)
	signed := iamv1.AccessKeySignedRequest{
		Parameters: parameters,
		HTTP: iamv1.AccessKeyHTTPRequest{
			Method: request.Method, Scheme: boundary.scheme, Authority: boundary.authority,
			EscapedPath: externalPath, RawQuery: rawQuery, ContentType: contentType,
			IdempotencyKey: idempotencyKey, IfMatch: ifMatch,
			BodyDigest: "sha256:" + hex.EncodeToString(digest[:]),
		},
		Signature: signature,
	}
	if iamv1.ValidateAccessKeySignedRequest(signed) != nil {
		return invalid()
	}
	return signed, nil
}

func (boundary *Boundary) mapTarget(target string, request *http.Request) (string, string, error) {
	if target == "" || target[0] != '/' || strings.Contains(target, "#") || strings.Count(target, "?") > 1 {
		return "", "", ErrInvalidRequest
	}
	externalPath, rawQuery, hasQuery := strings.Cut(target, "?")
	if hasQuery && rawQuery == "" {
		return "", "", ErrInvalidRequest
	}
	if !strings.HasPrefix(externalPath, boundary.externalPrefix+"/") {
		return "", "", ErrInvalidRequest
	}
	internalPath := strings.TrimPrefix(externalPath, boundary.externalPrefix)
	if internalPath != request.URL.EscapedPath() || rawQuery != request.URL.RawQuery || hasQuery != (request.URL.RawQuery != "") || request.URL.ForceQuery {
		return "", "", ErrInvalidRequest
	}
	return externalPath, rawQuery, nil
}

func coveredHeaders(request *http.Request, hasBody bool) (string, string, string, error) {
	contentTypes := request.Header.Values("Content-Type")
	if hasBody {
		if len(contentTypes) != 1 || contentTypes[0] != "application/json" {
			return "", "", "", ErrInvalidRequest
		}
	} else if len(contentTypes) != 0 {
		return "", "", "", ErrInvalidRequest
	}
	idempotency := request.Header.Values("Idempotency-Key")
	ifMatch := request.Header.Values("If-Match")
	if len(idempotency) > 1 || len(ifMatch) > 1 {
		return "", "", "", ErrInvalidRequest
	}
	var idempotencyValue, ifMatchValue string
	if len(idempotency) == 1 {
		idempotencyValue = idempotency[0]
	}
	if len(ifMatch) == 1 {
		ifMatchValue = ifMatch[0]
	}
	return first(contentTypes), idempotencyValue, ifMatchValue, nil
}

func hasForbiddenSemantics(request *http.Request) bool {
	if len(request.TransferEncoding) > 0 && len(request.Trailer) > 0 {
		return true
	}
	for _, name := range []string{
		"Cookie", "Matrix-Subject-Credential", "Content-Encoding", "X-HTTP-Method-Override", "Trailer",
		"Range", "Content-Range", "If-None-Match", "If-Modified-Since", "If-Unmodified-Since", "Prefer", "Digest", "Want-Digest",
	} {
		if len(request.Header.Values(name)) != 0 {
			return true
		}
	}
	return false
}

func first(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

const emptyBodyDigest = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
