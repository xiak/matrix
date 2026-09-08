package executorgatewayhttp

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"net/url"
	"path"
	"strings"
)

func parseSPIFFEIdentity(value string) (*url.URL, error) {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "spiffe" || parsed.Host == "" ||
		parsed.Host != strings.ToLower(parsed.Host) || parsed.Port() != "" ||
		parsed.User != nil || parsed.Opaque != "" || parsed.RawPath != "" ||
		parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" ||
		parsed.Path == "" || parsed.Path == "/" || path.Clean(parsed.Path) != parsed.Path ||
		parsed.String() != value {
		return nil, errors.New("executor peer identity is invalid")
	}
	return parsed, nil
}

func peerSPIFFEIdentity(state *tls.ConnectionState) (*url.URL, error) {
	if state == nil || state.Version != tls.VersionTLS13 ||
		len(state.VerifiedChains) == 0 || len(state.PeerCertificates) == 0 {
		return nil, errors.New("executor peer is not mutually authenticated")
	}
	leaf := state.PeerCertificates[0]
	if len(leaf.URIs) != 1 || len(leaf.DNSNames) != 0 || len(leaf.EmailAddresses) != 0 ||
		len(leaf.IPAddresses) != 0 {
		return nil, errors.New("executor peer identity is ambiguous")
	}
	return parseSPIFFEIdentity(leaf.URIs[0].String())
}

func exactPeerIdentity(state *tls.ConnectionState, expected *url.URL) error {
	actual, err := peerSPIFFEIdentity(state)
	if err != nil || expected == nil || actual.String() != expected.String() {
		return errors.New("executor peer identity is unauthorized")
	}
	return nil
}

func runnerPeerIdentity(
	state *tls.ConnectionState,
	namespace *url.URL,
) (*url.URL, error) {
	actual, err := peerSPIFFEIdentity(state)
	if err != nil || namespace == nil || actual.Host != namespace.Host ||
		!strings.HasPrefix(actual.Path, namespace.Path+"/") {
		return nil, errors.New("executor runner identity is unauthorized")
	}
	return actual, nil
}

// runnerID is deliberately opaque. Certificate rotation preserves ownership
// when the canonical SPIFFE identity is unchanged, while the URI itself never
// enters a spool document or runner-controlled receipt field.
func runnerID(identity *url.URL) (string, error) {
	if identity == nil {
		return "", errors.New("executor runner identity is invalid")
	}
	digest := sha256.Sum256([]byte("matrix-devops-runner-identity-v1\x00" + identity.String()))
	return "runner-" + hex.EncodeToString(digest[:]), nil
}

func runnerIDFromPeer(state *tls.ConnectionState, namespace *url.URL) (string, error) {
	identity, err := runnerPeerIdentity(state, namespace)
	if err != nil {
		return "", err
	}
	return runnerID(identity)
}
