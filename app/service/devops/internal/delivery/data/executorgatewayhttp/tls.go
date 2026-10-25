package executorgatewayhttp

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
)

func NewAdminTLSConfig(
	serverCertificate tls.Certificate,
	clientRoots *x509.CertPool,
	clientIdentity string,
) (*tls.Config, error) {
	expectedIdentity, err := parseSPIFFEIdentity(clientIdentity)
	if err != nil || len(serverCertificate.Certificate) == 0 ||
		serverCertificate.PrivateKey == nil || clientRoots == nil ||
		len(clientRoots.Subjects()) == 0 {
		return nil, errors.New("executor admin TLS configuration is invalid")
	}
	return &tls.Config{
		MinVersion:             tls.VersionTLS13,
		MaxVersion:             tls.VersionTLS13,
		Certificates:           []tls.Certificate{serverCertificate},
		ClientAuth:             tls.RequireAndVerifyClientCert,
		ClientCAs:              clientRoots.Clone(),
		NextProtos:             []string{"http/1.1"},
		SessionTicketsDisabled: true,
		VerifyConnection: func(state tls.ConnectionState) error {
			return exactPeerIdentity(&state, expectedIdentity)
		},
	}, nil
}

func NewRunnerTLSConfig(
	serverCertificate tls.Certificate,
	clientRoots *x509.CertPool,
	runnerNamespace string,
) (*tls.Config, error) {
	namespace, err := parseSPIFFEIdentity(runnerNamespace)
	if err != nil || len(serverCertificate.Certificate) == 0 ||
		serverCertificate.PrivateKey == nil || clientRoots == nil ||
		len(clientRoots.Subjects()) == 0 {
		return nil, errors.New("executor runner TLS configuration is invalid")
	}
	return &tls.Config{
		MinVersion:             tls.VersionTLS13,
		MaxVersion:             tls.VersionTLS13,
		Certificates:           []tls.Certificate{serverCertificate},
		ClientAuth:             tls.RequireAndVerifyClientCert,
		ClientCAs:              clientRoots.Clone(),
		NextProtos:             []string{"http/1.1"},
		SessionTicketsDisabled: true,
		VerifyConnection: func(state tls.ConnectionState) error {
			_, identityErr := runnerPeerIdentity(&state, namespace)
			return identityErr
		},
	}, nil
}
