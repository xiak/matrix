package nodehttps

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net"
	"slices"
	"time"

	nodev1 "github.com/xiak/matrix/api/adapter/node/v1"
)

var errTLSIdentity = errors.New("node TLS identity or trust is invalid")

// Credentials keeps key material out of configuration diagnostics. Files are
// read by the owning process with its protected-file policy, never by a remote
// request. Both peers must have an installation-issued identity certificate.
type Credentials struct {
	certificate tls.Certificate
	roots       *x509.CertPool
	trustRoots  []*x509.Certificate
}

func (Credentials) String() string   { return "node TLS credentials <redacted>" }
func (Credentials) GoString() string { return "node TLS credentials <redacted>" }

func NewCredentials(certificatePEM, privateKeyPEM, trustPEM []byte) (Credentials, error) {
	if len(certificatePEM) == 0 || len(certificatePEM) > 64*1024 ||
		len(privateKeyPEM) == 0 || len(privateKeyPEM) > 64*1024 ||
		len(trustPEM) == 0 || len(trustPEM) > 256*1024 {
		return Credentials{}, errTLSIdentity
	}
	certificate, err := tls.X509KeyPair(certificatePEM, privateKeyPEM)
	if err != nil {
		return Credentials{}, errTLSIdentity
	}
	certificate.Leaf, err = x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		return Credentials{}, errTLSIdentity
	}
	roots := x509.NewCertPool()
	var trustRoots []*x509.Certificate
	count := 0
	for remaining := bytes.TrimSpace(trustPEM); len(remaining) > 0; count++ {
		block, rest := pem.Decode(remaining)
		if count >= 16 || block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return Credentials{}, errTLSIdentity
		}
		root, err := x509.ParseCertificate(block.Bytes)
		if err != nil || !root.IsCA || root.KeyUsage&x509.KeyUsageCertSign == 0 {
			return Credentials{}, errTLSIdentity
		}
		roots.AddCert(root)
		trustRoots = append(trustRoots, root)
		remaining = bytes.TrimSpace(rest)
	}
	if count == 0 {
		return Credentials{}, errTLSIdentity
	}
	return Credentials{certificate: certificate, roots: roots, trustRoots: trustRoots}, nil
}

// ValidateCredentialRotation separates renewal from retirement of a complete
// management trust set. Old material is already bound by the installation's
// sealed commitment; it need not still be within its validity period.
func ValidateCredentialRotation(previousNode, previousCollector, node, collector Credentials,
	identity nodev1.Identity, nodeAddress, collectorAddress string, revokePrevious bool) error {
	if ValidateEnrollment(node, collector, identity, nodeAddress, collectorAddress) != nil {
		return errTLSIdentity
	}
	nodeURI, _ := nodev1.NodeURI(identity)
	collectorURI, _ := nodev1.CollectorURI(identity)
	for _, previous := range []struct {
		credentials Credentials
		uri         string
	}{{previousNode, nodeURI}, {previousCollector, collectorURI}} {
		leaf := previous.credentials.certificate.Leaf
		if leaf == nil || leaf.IsCA || len(previous.credentials.trustRoots) == 0 || !nodev1.MatchesIdentity(leaf.URIs, previous.uri) {
			return errTLSIdentity
		}
	}
	if !revokePrevious {
		return nil
	}
	for _, previous := range []Credentials{previousNode, previousCollector} {
		for _, candidate := range []Credentials{node, collector} {
			if bytes.Equal(previous.certificate.Leaf.RawSubjectPublicKeyInfo, candidate.certificate.Leaf.RawSubjectPublicKeyInfo) {
				return errTLSIdentity
			}
			for _, oldRoot := range previous.trustRoots {
				for _, newRoot := range candidate.trustRoots {
					if bytes.Equal(oldRoot.RawSubjectPublicKeyInfo, newRoot.RawSubjectPublicKeyInfo) {
						return errTLSIdentity
					}
				}
			}
		}
	}
	return nil
}

func ServerTLS(credentials Credentials, identity nodev1.Identity, controllerID string) (*tls.Config, error) {
	ownURI, err := nodev1.NodeURI(identity)
	if err != nil {
		return nil, errTLSIdentity
	}
	peerURI, err := nodev1.ControllerURI(identity.InstallationID, controllerID)
	if err != nil || !credentials.validFor(ownURI, x509.ExtKeyUsageServerAuth) {
		return nil, errTLSIdentity
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{credentials.certificate},
		ClientCAs:    credentials.roots.Clone(), ClientAuth: tls.RequireAndVerifyClientCert,
		NextProtos: []string{"http/1.1"}, SessionTicketsDisabled: true,
		// HTTP keeps a separate action guard: self identity is only admitted to
		// installation readiness, never the controller command surface.
		VerifyConnection: func(state tls.ConnectionState) error {
			if verifyPeer(state, peerURI) == nil {
				return nil
			}
			return verifyPeer(state, ownURI)
		},
	}, nil
}

func readinessClientTLS(credentials Credentials, identity nodev1.Identity) (*tls.Config, error) {
	uri, err := nodev1.NodeURI(identity)
	if err != nil || !credentials.validFor(uri, x509.ExtKeyUsageClientAuth) {
		return nil, errTLSIdentity
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{credentials.certificate},
		RootCAs: credentials.roots.Clone(), NextProtos: []string{"http/1.1"},
		VerifyConnection: func(state tls.ConnectionState) error { return verifyPeer(state, uri) },
	}, nil
}

// ValidateEnrollment authenticates both installation-issued roles and server
// addresses before the installer writes state or starts either service.
// The node needs client auth for its collector and self-readiness, not a
// controller certificate. Each chain is checked for its exact required EKU.
func ValidateEnrollment(node, collector Credentials, identity nodev1.Identity, nodeAddress, collectorAddress string) error {
	// The collector can read its own key. Sharing that key with the privileged
	// node would defeat process/credential isolation despite distinct SAN roles.
	if node.certificate.Leaf == nil || collector.certificate.Leaf == nil ||
		bytes.Equal(node.certificate.Leaf.RawSubjectPublicKeyInfo, collector.certificate.Leaf.RawSubjectPublicKeyInfo) {
		return errTLSIdentity
	}
	nodeURI, err := nodev1.NodeURI(identity)
	if err != nil {
		return errTLSIdentity
	}
	collectorURI, err := nodev1.CollectorURI(identity)
	if err != nil {
		return errTLSIdentity
	}
	for _, check := range []struct {
		credentials Credentials
		roots       *x509.CertPool
		uri         string
		address     string
		purpose     x509.ExtKeyUsage
	}{
		{node, node.roots, nodeURI, nodeAddress, x509.ExtKeyUsageServerAuth},
		{node, collector.roots, nodeURI, nodeAddress, x509.ExtKeyUsageClientAuth},
		{collector, node.roots, collectorURI, collectorAddress, x509.ExtKeyUsageServerAuth},
	} {
		if check.roots == nil || !check.credentials.validFor(check.uri, check.purpose) {
			return errTLSIdentity
		}
		host, _, err := net.SplitHostPort(check.address)
		if err != nil || net.ParseIP(host) == nil {
			return errTLSIdentity
		}
		intermediates := x509.NewCertPool()
		for _, encoded := range check.credentials.certificate.Certificate[1:] {
			certificate, err := x509.ParseCertificate(encoded)
			if err != nil {
				return errTLSIdentity
			}
			intermediates.AddCert(certificate)
		}
		if _, err := check.credentials.certificate.Leaf.Verify(x509.VerifyOptions{
			Roots: check.roots, Intermediates: intermediates,
			DNSName: host, KeyUsages: []x509.ExtKeyUsage{check.purpose},
		}); err != nil {
			return errTLSIdentity
		}
	}
	return nil
}

func clientTLS(credentials Credentials, identity nodev1.Identity, controllerID string) (*tls.Config, error) {
	ownURI, err := nodev1.ControllerURI(identity.InstallationID, controllerID)
	if err != nil || !credentials.validFor(ownURI, x509.ExtKeyUsageClientAuth) {
		return nil, errTLSIdentity
	}
	peerURI, err := nodev1.NodeURI(identity)
	if err != nil {
		return nil, errTLSIdentity
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{credentials.certificate},
		RootCAs: credentials.roots.Clone(), NextProtos: []string{"http/1.1"},
		VerifyConnection: func(state tls.ConnectionState) error { return verifyPeer(state, peerURI) },
	}, nil
}

// CollectorClientTLS authenticates the node to its separately privileged local
// collector. A collector identity cannot impersonate a node or controller.
func CollectorClientTLS(credentials Credentials, identity nodev1.Identity) (*tls.Config, error) {
	ownURI, err := nodev1.NodeURI(identity)
	if err != nil || !credentials.validFor(ownURI, x509.ExtKeyUsageClientAuth) {
		return nil, errTLSIdentity
	}
	peerURI, err := nodev1.CollectorURI(identity)
	if err != nil {
		return nil, errTLSIdentity
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{credentials.certificate},
		RootCAs: credentials.roots.Clone(), NextProtos: []string{"http/1.1"},
		VerifyConnection: func(state tls.ConnectionState) error { return verifyPeer(state, peerURI) },
	}, nil
}

func (credentials Credentials) validFor(identity string, purpose x509.ExtKeyUsage) bool {
	leaf := credentials.certificate.Leaf
	now := time.Now()
	return credentials.roots != nil && leaf != nil && !leaf.IsCA &&
		!now.Before(leaf.NotBefore) && now.Before(leaf.NotAfter) &&
		slices.Contains(leaf.ExtKeyUsage, purpose) && nodev1.MatchesIdentity(leaf.URIs, identity)
}

func verifyPeer(state tls.ConnectionState, expected string) error {
	if len(state.VerifiedChains) == 0 || len(state.PeerCertificates) == 0 {
		return errTLSIdentity
	}
	leaf := state.PeerCertificates[0]
	now := time.Now()
	if leaf.IsCA || now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) ||
		!nodev1.MatchesIdentity(leaf.URIs, expected) {
		return errTLSIdentity
	}
	return nil
}
