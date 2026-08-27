package nodehttps

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
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
		remaining = bytes.TrimSpace(rest)
	}
	if count == 0 {
		return Credentials{}, errTLSIdentity
	}
	return Credentials{certificate: certificate, roots: roots}, nil
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
		VerifyConnection: func(state tls.ConnectionState) error { return verifyPeer(state, peerURI) },
	}, nil
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
