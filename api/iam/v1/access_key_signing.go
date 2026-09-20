package iamv1

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/xiak/matrix/api/contractjson"
)

const (
	AccessKeySignatureScheme              = "Matrix-HMAC-SHA256-V1"
	MaxAccessKeyAuthorizationBytes        = 1024
	MaxAccessKeySignedRequestBytes  int64 = 32 * 1024
	AccessKeySignaturePastSeconds         = int64(300)
	AccessKeySignatureFutureSeconds       = int64(30)
)

var ErrInvalidAccessKeySignature = errors.New("access key signature request is invalid")

// Parameters are transport claims, never authoritative installation, product
// membership or identity. IAM must match them to the current service and key.
type AccessKeySignatureParameters struct {
	AccessKeyID    AccessKeyID
	InstallationID string
	Audience       ProductID
	SignedAt       int64
	Nonce          Secret
}

// The product PEP constructs these values from the request it actually handles,
// not a caller-supplied digest or forwarded-header selector. Empty covered
// headers remain explicit fields. This data alone proves no HTTP extraction.
type AccessKeyHTTPRequest struct {
	Method         string `json:"method"`
	Scheme         string `json:"scheme"`
	Authority      string `json:"authority"`
	EscapedPath    string `json:"escapedPath"`
	RawQuery       string `json:"rawQuery"`
	ContentType    string `json:"contentType"`
	IdempotencyKey string `json:"idempotencyKey"`
	IfMatch        string `json:"ifMatch"`
	BodyDigest     string `json:"bodyDigest"`
}

func (value *AccessKeyHTTPRequest) UnmarshalJSON(source []byte) error {
	type wire AccessKeyHTTPRequest
	var decoded wire
	if value == nil || contractjson.DecodeObjectBytes(source, MaxAccessKeySignedRequestBytes, &decoded) != nil {
		return ErrInvalidAccessKeySignature
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(source, &fields) != nil {
		return ErrInvalidAccessKeySignature
	}
	for _, name := range []string{"method", "scheme", "authority", "escapedPath", "rawQuery", "contentType", "idempotencyKey", "ifMatch", "bodyDigest"} {
		encoded, present := fields[name]
		if !present || bytes.Equal(bytes.TrimSpace(encoded), []byte("null")) {
			return ErrInvalidAccessKeySignature
		}
	}
	if ValidateAccessKeyHTTPRequest(AccessKeyHTTPRequest(decoded)) != nil {
		return ErrInvalidAccessKeySignature
	}
	*value = AccessKeyHTTPRequest(decoded)
	return nil
}

// This is purpose-limited service-to-IAM input, not a public decision, Audit
// actor, session, or reusable authorization token. Ordinary JSON is forbidden.
type AccessKeySignedRequest struct {
	Parameters AccessKeySignatureParameters
	HTTP       AccessKeyHTTPRequest
	Signature  Secret
}

// Internal product-to-IAM request. The service authenticates independently;
// this document cannot select the subject/account or supply reusable authority.
type AccessKeyAuthorizationRequest struct {
	Authorization AuthorizationRequest
	SignedRequest AccessKeySignedRequest
}

type AccessKeyAuthorization struct {
	APIVersion          string                `json:"apiVersion"`
	Kind                string                `json:"kind"`
	Decision            AuthorizationDecision `json:"decision"`
	SignedRequestDigest string                `json:"signedRequestDigest"`
}

func (AccessKeyAuthorizationRequest) String() string { return "[REDACTED]" }
func (AccessKeyAuthorizationRequest) GoString() string {
	return "iamv1.AccessKeyAuthorizationRequest{[REDACTED]}"
}
func (AccessKeyAuthorizationRequest) MarshalJSON() ([]byte, error) {
	return nil, ErrInvalidAccessKeySignature
}
func (*AccessKeyAuthorizationRequest) UnmarshalJSON([]byte) error {
	return ErrInvalidAccessKeySignature
}

func ValidateAccessKeyAuthorizationRequest(value AccessKeyAuthorizationRequest) error {
	if ValidateAuthorizationRequest(value.Authorization) != nil || ValidateAccessKeySignedRequest(value.SignedRequest) != nil ||
		value.Authorization.Profile.Product != value.SignedRequest.Parameters.Audience {
		return ErrInvalidAccessKeySignature
	}
	// Lack of current carrier capability is a recorded Deny after MAC checking,
	// not malformed transport. Service/install authority and the real HTTP-to-
	// action mapping are also separate from this pure syntax/binding check.
	return nil
}

func EncodeAccessKeyAuthorizationRequest(value AccessKeyAuthorizationRequest) ([]byte, error) {
	if ValidateAccessKeyAuthorizationRequest(value) != nil {
		return nil, ErrInvalidAccessKeySignature
	}
	signed, err := EncodeAccessKeySignedRequest(value.SignedRequest)
	if err != nil {
		return nil, err
	}
	defer clear(signed)
	encoded, err := json.Marshal(struct {
		Authorization AuthorizationRequest `json:"authorization"`
		SignedRequest json.RawMessage      `json:"signedRequest"`
	}{value.Authorization, signed})
	if err != nil || int64(len(encoded)) > MaxRequestBytes {
		clear(encoded)
		return nil, ErrInvalidAccessKeySignature
	}
	return encoded, nil
}

func DecodeAccessKeyAuthorizationRequest(reader io.Reader) (AccessKeyAuthorizationRequest, error) {
	var wire struct {
		Authorization AuthorizationRequest `json:"authorization"`
		SignedRequest json.RawMessage      `json:"signedRequest"`
	}
	if contractjson.DecodeObject(reader, MaxRequestBytes, &wire) != nil {
		return AccessKeyAuthorizationRequest{}, ErrInvalidAccessKeySignature
	}
	defer clear(wire.SignedRequest)
	signed, err := DecodeAccessKeySignedRequest(bytes.NewReader(wire.SignedRequest))
	value := AccessKeyAuthorizationRequest{Authorization: wire.Authorization, SignedRequest: signed}
	if err != nil || ValidateAccessKeyAuthorizationRequest(value) != nil {
		return AccessKeyAuthorizationRequest{}, ErrInvalidAccessKeySignature
	}
	return value, nil
}

func ValidateAccessKeyAuthorization(value AccessKeyAuthorization) error {
	if value.APIVersion != APIVersion || value.Kind != "AccessKeyAuthorization" || ValidateAuthorizationDecision(value.Decision) != nil ||
		ValidateDigest("signedRequestDigest", value.SignedRequestDigest) != nil {
		return ErrInvalidAccessKeySignature
	}
	if value.Decision.Allowed && (value.Decision.Subject == nil || value.Decision.Subject.Type != SubjectUser ||
		value.Decision.Subject.AccessKeyID == "" || value.Decision.InstallationID != "") {
		return ErrInvalidAccessKeySignature
	}
	return nil
}

func DecodeAccessKeyAuthorization(reader io.Reader) (AccessKeyAuthorization, error) {
	var result AccessKeyAuthorization
	if contractjson.DecodeObject(reader, MaxRequestBytes, &result) != nil || ValidateAccessKeyAuthorization(result) != nil {
		return AccessKeyAuthorization{}, ErrInvalidAccessKeySignature
	}
	return result, nil
}

// The actual product PEP compares the once-only result to the request it sent.
// A digest match is not permission to cache or replay this response.
func CheckAccessKeyAuthorizationForRequest(value AccessKeyAuthorization, request AccessKeyAuthorizationRequest) error {
	if ValidateAccessKeyAuthorizationRequest(request) != nil || ValidateAccessKeyAuthorization(value) != nil ||
		CheckAuthorizationDecisionForRequest(value.Decision, request.Authorization) != nil {
		return ErrInvalidAccessKeySignature
	}
	digest, err := AccessKeySignedRequestDigest(request.SignedRequest)
	if err != nil || digest != value.SignedRequestDigest ||
		value.Decision.Allowed && value.Decision.Subject.AccessKeyID != request.SignedRequest.Parameters.AccessKeyID {
		return ErrInvalidAccessKeySignature
	}
	return nil
}

func (AccessKeySignatureParameters) String() string { return "[REDACTED]" }
func (AccessKeySignatureParameters) GoString() string {
	return "iamv1.AccessKeySignatureParameters{[REDACTED]}"
}
func (AccessKeySignatureParameters) MarshalJSON() ([]byte, error) {
	return nil, ErrInvalidAccessKeySignature
}
func (*AccessKeySignatureParameters) UnmarshalJSON([]byte) error { return ErrInvalidAccessKeySignature }
func (AccessKeyHTTPRequest) String() string                      { return "[REDACTED]" }
func (AccessKeyHTTPRequest) GoString() string                    { return "iamv1.AccessKeyHTTPRequest{[REDACTED]}" }
func (AccessKeySignedRequest) String() string                    { return "[REDACTED]" }
func (AccessKeySignedRequest) GoString() string                  { return "iamv1.AccessKeySignedRequest{[REDACTED]}" }
func (AccessKeySignedRequest) MarshalJSON() ([]byte, error) {
	return nil, ErrInvalidAccessKeySignature
}
func (*AccessKeySignedRequest) UnmarshalJSON([]byte) error { return ErrInvalidAccessKeySignature }

func ValidateAccessKeySignatureParameters(value AccessKeySignatureParameters) error {
	if ValidateID("accessKeyId", string(value.AccessKeyID)) != nil ||
		ValidateID("installationId", value.InstallationID) != nil || !profileIdentifier(string(value.Audience), false) ||
		value.SignedAt <= 0 || value.SignedAt > 253402300799 || !accessKeyBase64(value.Nonce, 16) {
		return ErrInvalidAccessKeySignature
	}
	return nil
}

func ValidateAccessKeyHTTPRequest(value AccessKeyHTTPRequest) error {
	switch value.Method {
	case "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS":
	default:
		return ErrInvalidAccessKeySignature
	}
	if (value.Scheme != "http" && value.Scheme != "https") || !accessKeyAuthority(value.Authority) || !accessKeyPath(value.EscapedPath) || !accessKeyQuery(value.RawQuery) ||
		(value.ContentType != "" && value.ContentType != "application/json") || !accessKeyCoveredHeader(value.IdempotencyKey, 128) ||
		!accessKeyCoveredHeader(value.IfMatch, 128) || ValidateDigest("bodyDigest", value.BodyDigest) != nil {
		return ErrInvalidAccessKeySignature
	}
	const emptyBodyDigest = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if (value.ContentType == "") != (value.BodyDigest == emptyBodyDigest) {
		return ErrInvalidAccessKeySignature
	}
	return nil
}

func ValidateAccessKeySignedRequest(value AccessKeySignedRequest) error {
	if ValidateAccessKeySignatureParameters(value.Parameters) != nil || ValidateAccessKeyHTTPRequest(value.HTTP) != nil ||
		!accessKeyBase64(value.Signature, sha256.Size) {
		return ErrInvalidAccessKeySignature
	}
	return nil
}

// AccessKeySigningBytes is the sole, bounded signature-base encoder. It does
// not authenticate the transport claims or mutate/repair their HTTP values.
func AccessKeySigningBytes(parameters AccessKeySignatureParameters, request AccessKeyHTTPRequest) ([]byte, error) {
	if ValidateAccessKeySignatureParameters(parameters) != nil || ValidateAccessKeyHTTPRequest(request) != nil {
		return nil, ErrInvalidAccessKeySignature
	}
	nonce := parameters.Nonce.CopyBytes()
	defer clear(nonce)
	return credentialBindingBytes("matrix.iam.access-key-http-signature.v1",
		[]byte(AccessKeySignatureScheme), []byte(parameters.AccessKeyID), []byte(parameters.InstallationID), []byte(parameters.Audience),
		[]byte(strconv.FormatInt(parameters.SignedAt, 10)), nonce, []byte(request.Method), []byte(request.Scheme), []byte(request.Authority),
		[]byte(request.EscapedPath), []byte(request.RawQuery), []byte(request.ContentType), []byte(request.IdempotencyKey),
		[]byte(request.IfMatch), []byte(request.BodyDigest)), nil
}

func AccessKeySignedRequestDigest(value AccessKeySignedRequest) (string, error) {
	if ValidateAccessKeySignedRequest(value) != nil {
		return "", ErrInvalidAccessKeySignature
	}
	encoded, err := AccessKeySigningBytes(value.Parameters, value.HTTP)
	if err != nil {
		return "", err
	}
	defer clear(encoded)
	digest := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

// The nonce identity is per installation and actual key, not per audience,
// request body or time window. This digest is not proof of nonce consumption.
func AccessKeyNonceDigest(parameters AccessKeySignatureParameters) (string, error) {
	if ValidateAccessKeySignatureParameters(parameters) != nil {
		return "", ErrInvalidAccessKeySignature
	}
	nonce := parameters.Nonce.CopyBytes()
	defer clear(nonce)
	encoded := credentialBindingBytes("matrix.iam.access-key-http-nonce.v1", []byte(parameters.InstallationID), []byte(parameters.AccessKeyID), nonce)
	defer clear(encoded)
	digest := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

func EncodeAccessKeyAuthorization(parameters AccessKeySignatureParameters, signature Secret) (Secret, error) {
	if ValidateAccessKeySignatureParameters(parameters) != nil || !accessKeyBase64(signature, sha256.Size) {
		return Secret{}, ErrInvalidAccessKeySignature
	}
	nonce, mac := parameters.Nonce.CopyBytes(), signature.CopyBytes()
	defer clear(nonce)
	defer clear(mac)
	value := AccessKeySignatureScheme + " KeyId=" + string(parameters.AccessKeyID) + ",Installation=" + parameters.InstallationID +
		",Audience=" + string(parameters.Audience) + ",SignedAt=" + strconv.FormatInt(parameters.SignedAt, 10) +
		",Nonce=" + string(nonce) + ",Signature=" + string(mac)
	if len(value) > MaxAccessKeyAuthorizationBytes {
		return Secret{}, ErrInvalidAccessKeySignature
	}
	result, err := NewSecret(value)
	if err != nil {
		return Secret{}, ErrInvalidAccessKeySignature
	}
	return result, nil
}

// The HTTP owner must separately reject duplicate Authorization fields. This
// parser consumes exactly one field; it never folds lists or selects a value.
func ParseAccessKeyAuthorization(value string) (AccessKeySignatureParameters, Secret, error) {
	invalid := func() (AccessKeySignatureParameters, Secret, error) {
		return AccessKeySignatureParameters{}, Secret{}, ErrInvalidAccessKeySignature
	}
	if len(value) > MaxAccessKeyAuthorizationBytes || !strings.HasPrefix(value, AccessKeySignatureScheme+" ") {
		return invalid()
	}
	parts := strings.Split(value[len(AccessKeySignatureScheme)+1:], ",")
	names := [...]string{"KeyId", "Installation", "Audience", "SignedAt", "Nonce", "Signature"}
	if len(parts) != len(names) {
		return invalid()
	}
	for i, name := range names {
		prefix := name + "="
		if !strings.HasPrefix(parts[i], prefix) || len(parts[i]) == len(prefix) {
			return invalid()
		}
		parts[i] = parts[i][len(prefix):]
	}
	signedAt, err := strconv.ParseInt(parts[3], 10, 64)
	if err != nil || strconv.FormatInt(signedAt, 10) != parts[3] {
		return invalid()
	}
	nonce, nonceErr := NewSecret(parts[4])
	signature, signatureErr := NewSecret(parts[5])
	parameters := AccessKeySignatureParameters{AccessKeyID: AccessKeyID(parts[0]), InstallationID: parts[1], Audience: ProductID(parts[2]), SignedAt: signedAt, Nonce: nonce}
	if nonceErr != nil || signatureErr != nil || ValidateAccessKeySignatureParameters(parameters) != nil || !accessKeyBase64(signature, sha256.Size) {
		return invalid()
	}
	return parameters, signature, nil
}

type accessKeySignedRequestWire struct {
	APIVersion string               `json:"apiVersion"`
	Kind       string               `json:"kind"`
	HTTP       AccessKeyHTTPRequest `json:"http"`
	// Reuse the one Authorization codec; no parallel metadata JSON grammar.
	Authorization string `json:"authorization"`
}

func EncodeAccessKeySignedRequest(value AccessKeySignedRequest) ([]byte, error) {
	if ValidateAccessKeySignedRequest(value) != nil {
		return nil, ErrInvalidAccessKeySignature
	}
	header, err := EncodeAccessKeyAuthorization(value.Parameters, value.Signature)
	if err != nil {
		return nil, err
	}
	plain := header.CopyBytes()
	defer clear(plain)
	encoded, err := json.Marshal(accessKeySignedRequestWire{APIVersion: APIVersion, Kind: "AccessKeySignedRequest", HTTP: value.HTTP, Authorization: string(plain)})
	if err != nil || int64(len(encoded)) > MaxAccessKeySignedRequestBytes {
		clear(encoded)
		return nil, ErrInvalidAccessKeySignature
	}
	return encoded, nil
}

func DecodeAccessKeySignedRequest(reader io.Reader) (AccessKeySignedRequest, error) {
	var wire accessKeySignedRequestWire
	if contractjson.DecodeObject(reader, MaxAccessKeySignedRequestBytes, &wire) != nil || wire.APIVersion != APIVersion || wire.Kind != "AccessKeySignedRequest" {
		return AccessKeySignedRequest{}, ErrInvalidAccessKeySignature
	}
	parameters, signature, err := ParseAccessKeyAuthorization(wire.Authorization)
	wire.Authorization = ""
	value := AccessKeySignedRequest{Parameters: parameters, HTTP: wire.HTTP, Signature: signature}
	if err != nil || ValidateAccessKeySignedRequest(value) != nil {
		return AccessKeySignedRequest{}, ErrInvalidAccessKeySignature
	}
	return value, nil
}

func accessKeyBase64(value Secret, size int) bool {
	encoded := value.CopyBytes()
	defer clear(encoded)
	if len(encoded) != base64.RawURLEncoding.EncodedLen(size) {
		return false
	}
	decoded := make([]byte, size)
	defer clear(decoded)
	n, err := base64.RawURLEncoding.Strict().Decode(decoded, encoded)
	return err == nil && n == size && base64.RawURLEncoding.EncodeToString(decoded) == string(encoded)
}

func accessKeyCoveredHeader(value string, maximum int) bool {
	if len(value) > maximum || strings.TrimSpace(value) != value {
		return false
	}
	for _, b := range []byte(value) {
		if b < 0x20 || b > 0x7e {
			return false
		}
	}
	return true
}

func accessKeyAuthority(value string) bool {
	if value == "" || len(value) > 255 || strings.ToLower(value) != value {
		return false
	}
	host := value
	if strings.Contains(value, ":") && !(strings.HasPrefix(value, "[") && strings.HasSuffix(value, "]")) {
		var port string
		var err error
		host, port, err = net.SplitHostPort(value)
		n, parseErr := strconv.ParseUint(port, 10, 16)
		if err != nil || parseErr != nil || n == 0 || strconv.FormatUint(n, 10) != port {
			return false
		}
	}
	ipText := host
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		ipText = host[1 : len(host)-1]
	}
	if ip, err := netip.ParseAddr(ipText); err == nil {
		return ip.Zone() == "" && ip.String() == ipText &&
			(ip.Is6() && strings.HasPrefix(value, "[") || ip.Is4() && !strings.ContainsAny(value, "[]"))
	}
	if strings.ContainsAny(host, "[]:") || len(host) > 253 {
		return false
	}
	onlyNumeric := true
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, b := range []byte(label) {
			if !(b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || b == '-') {
				return false
			}
			onlyNumeric = onlyNumeric && b >= '0' && b <= '9'
		}
	}
	return !onlyNumeric
}

func accessKeyPath(value string) bool {
	if value == "" || len(value) > 2048 || value[0] != '/' {
		return false
	}
	if value == "/" {
		return true
	}
	for _, segment := range strings.Split(value[1:], "/") {
		decoded, err := url.PathUnescape(segment)
		if err != nil || decoded == "" || decoded == "." || decoded == ".." || strings.ContainsAny(decoded, "/\\%") ||
			!accessKeyURIComponent(segment, decoded, true) {
			return false
		}
	}
	return true
}

func accessKeyQuery(value string) bool {
	if len(value) > 4096 {
		return false
	}
	if value == "" {
		return true
	}
	parts := strings.Split(value, "&")
	if len(parts) > 64 {
		return false
	}
	previous := ""
	for _, part := range parts {
		name, data, found := strings.Cut(part, "=")
		decodedName, nameErr := url.PathUnescape(name)
		decodedValue, valueErr := url.PathUnescape(data)
		if !found || name == "" || name < previous || nameErr != nil || valueErr != nil ||
			!accessKeyURIComponent(name, decodedName, false) || !accessKeyURIComponent(data, decodedValue, false) {
			return false
		}
		previous = name
	}
	return true
}

func accessKeyURIComponent(encoded, decoded string, path bool) bool {
	if !utf8.ValidString(decoded) || strings.ContainsFunc(decoded, unicode.IsControl) {
		return false
	}
	const upperHex = "0123456789ABCDEF"
	var canonical strings.Builder
	for _, b := range []byte(decoded) {
		unreserved := b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || strings.ContainsRune("-._~", rune(b))
		if unreserved || path && strings.ContainsRune("!$&'()*+,;=:@", rune(b)) {
			canonical.WriteByte(b)
		} else {
			canonical.WriteByte('%')
			canonical.WriteByte(upperHex[b>>4])
			canonical.WriteByte(upperHex[b&15])
		}
	}
	return canonical.String() == encoded
}
