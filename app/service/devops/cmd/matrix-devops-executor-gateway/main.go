// matrix-devops-executor-gateway is the isolated durable rendezvous between a
// table-blind build worker and outbound-only dedicated runners. It owns no
// database, product, provider, Docker, source-store, or reporting authority.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/xiak/matrix/app/service/devops/internal/delivery/data/executorgatewayhttp"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/data/executorspoolfile"
	"github.com/xiak/matrix/app/service/internal/processconfig"
)

const (
	spoolRootEnvironment       = "MATRIX_DEVOPS_EXECUTOR_GATEWAY_SPOOL_ROOT"
	adminAddressEnvironment    = "MATRIX_DEVOPS_EXECUTOR_GATEWAY_ADMIN_LISTEN_ADDRESS"
	runnerAddressEnvironment   = "MATRIX_DEVOPS_EXECUTOR_GATEWAY_RUNNER_LISTEN_ADDRESS"
	serverCertEnvironment      = "MATRIX_DEVOPS_EXECUTOR_GATEWAY_SERVER_CERT_FILE"
	serverKeyEnvironment       = "MATRIX_DEVOPS_EXECUTOR_GATEWAY_SERVER_KEY_FILE"
	adminCAEnvironment         = "MATRIX_DEVOPS_EXECUTOR_GATEWAY_ADMIN_CLIENT_CA_FILE"
	adminIdentityEnvironment   = "MATRIX_DEVOPS_EXECUTOR_GATEWAY_ADMIN_CLIENT_IDENTITY"
	runnerCAEnvironment        = "MATRIX_DEVOPS_EXECUTOR_GATEWAY_RUNNER_CLIENT_CA_FILE"
	runnerNamespaceEnvironment = "MATRIX_DEVOPS_EXECUTOR_GATEWAY_RUNNER_NAMESPACE"

	maximumCertificateBytes = 1024 * 1024
	maximumPrivateKeyBytes  = 256 * 1024
	maximumClientRoots      = 8
	maximumRequestHeaders   = 16 * 1024
)

type configuration struct {
	spoolRoot       string
	adminAddress    string
	runnerAddress   string
	serverCertFile  string
	serverKeyFile   string
	adminCAFile     string
	adminIdentity   string
	runnerCAFile    string
	runnerNamespace string
}

type clientRoots struct {
	pool         *x509.CertPool
	fingerprints map[[sha256.Size]byte]struct{}
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "matrix DevOps executor gateway failed")
		os.Exit(1)
	}
}

func run(ctx context.Context) (runErr error) {
	if ctx == nil {
		return errors.New("executor gateway context is required")
	}
	config, err := loadConfiguration()
	if err != nil {
		return err
	}
	ownership, err := executorspoolfile.AcquireOwnership(config.spoolRoot)
	if err != nil {
		return errors.New("executor gateway spool ownership is unavailable")
	}
	defer func() { runErr = errors.Join(runErr, ownership.Close()) }()
	spool, err := executorspoolfile.New(config.spoolRoot)
	if err != nil {
		return errors.New("executor gateway spool is unavailable")
	}

	certificate, err := loadServerCertificate(
		config.serverCertFile, config.serverKeyFile, time.Now(),
	)
	if err != nil {
		return err
	}
	adminRoots, err := loadClientRoots(config.adminCAFile, time.Now())
	if err != nil {
		return errors.New("executor gateway admin client roots are invalid")
	}
	runnerRoots, err := loadClientRoots(config.runnerCAFile, time.Now())
	if err != nil {
		return errors.New("executor gateway runner client roots are invalid")
	}
	if rootsOverlap(adminRoots, runnerRoots) {
		return errors.New("executor gateway client trust boundaries overlap")
	}
	adminTLS, err := executorgatewayhttp.NewAdminTLSConfig(
		certificate, adminRoots.pool, config.adminIdentity,
	)
	if err != nil {
		return errors.New("executor gateway admin TLS policy is invalid")
	}
	runnerTLS, err := executorgatewayhttp.NewRunnerTLSConfig(
		certificate, runnerRoots.pool, config.runnerNamespace,
	)
	if err != nil {
		return errors.New("executor gateway runner TLS policy is invalid")
	}
	adminHandler, err := executorgatewayhttp.NewAdminHandler(spool, config.adminIdentity)
	if err != nil {
		return errors.New("executor gateway admin handler is invalid")
	}
	runnerHandler, err := executorgatewayhttp.NewRunnerHandler(spool, config.runnerNamespace)
	if err != nil {
		return errors.New("executor gateway runner handler is invalid")
	}

	adminListener, err := net.Listen("tcp", config.adminAddress)
	if err != nil {
		return errors.New("executor gateway admin listener cannot start")
	}
	runnerListener, err := net.Listen("tcp", config.runnerAddress)
	if err != nil {
		_ = adminListener.Close()
		return errors.New("executor gateway runner listener cannot start")
	}
	return serveGatewayListeners(
		ctx,
		adminListener,
		adminHandler,
		adminTLS,
		runnerListener,
		runnerHandler,
		runnerTLS,
	)
}

func loadConfiguration() (configuration, error) {
	config := configuration{
		spoolRoot:       os.Getenv(spoolRootEnvironment),
		adminAddress:    os.Getenv(adminAddressEnvironment),
		runnerAddress:   os.Getenv(runnerAddressEnvironment),
		serverCertFile:  os.Getenv(serverCertEnvironment),
		serverKeyFile:   os.Getenv(serverKeyEnvironment),
		adminCAFile:     os.Getenv(adminCAEnvironment),
		adminIdentity:   os.Getenv(adminIdentityEnvironment),
		runnerCAFile:    os.Getenv(runnerCAEnvironment),
		runnerNamespace: os.Getenv(runnerNamespaceEnvironment),
	}
	if config.spoolRoot == "" || config.adminAddress == "" ||
		config.runnerAddress == "" || config.serverCertFile == "" ||
		config.serverKeyFile == "" || config.adminCAFile == "" ||
		config.adminIdentity == "" || config.runnerCAFile == "" ||
		config.runnerNamespace == "" {
		return configuration{}, errors.New("executor gateway configuration is incomplete")
	}
	if !validListenAddress(config.adminAddress) ||
		!validListenAddress(config.runnerAddress) ||
		config.adminAddress == config.runnerAddress {
		return configuration{}, errors.New("executor gateway listener configuration is invalid")
	}
	return config, nil
}

func validListenAddress(value string) bool {
	host, portText, err := net.SplitHostPort(value)
	if err != nil || host == "" || portText == "" {
		return false
	}
	address := net.ParseIP(host)
	port, portErr := strconv.Atoi(portText)
	return address != nil && address.String() == host && portErr == nil &&
		port >= 1 && port <= 65535 && strconv.Itoa(port) == portText &&
		net.JoinHostPort(host, portText) == value
}

func loadServerCertificate(
	certificatePath string,
	privateKeyPath string,
	now time.Time,
) (tls.Certificate, error) {
	certificatePEM, err := processconfig.ReadFile(
		certificatePath, maximumCertificateBytes, false,
	)
	if err != nil {
		return tls.Certificate{}, errors.New("executor gateway server certificate is unavailable")
	}
	privateKeyPEM, err := processconfig.ReadFile(
		privateKeyPath, maximumPrivateKeyBytes, true,
	)
	if err != nil {
		return tls.Certificate{}, errors.New("executor gateway server private key is unavailable")
	}
	defer clear(privateKeyPEM)
	certificateBlocks, err := decodeCanonicalPEM(certificatePEM, "CERTIFICATE")
	if err != nil || len(certificateBlocks) == 0 {
		return tls.Certificate{}, errors.New("executor gateway server certificate is invalid")
	}
	keyBlocks, err := decodeCanonicalPrivateKeyPEM(privateKeyPEM)
	if err != nil || len(keyBlocks) != 1 {
		return tls.Certificate{}, errors.New("executor gateway server private key is invalid")
	}
	certificate, err := tls.X509KeyPair(certificatePEM, privateKeyPEM)
	if err != nil || len(certificate.Certificate) != len(certificateBlocks) {
		return tls.Certificate{}, errors.New("executor gateway server key pair is invalid")
	}
	chain := make([]*x509.Certificate, len(certificate.Certificate))
	seen := make(map[[sha256.Size]byte]struct{}, len(chain))
	for index, encoded := range certificate.Certificate {
		parsed, parseErr := x509.ParseCertificate(encoded)
		fingerprint := sha256.Sum256(encoded)
		_, duplicate := seen[fingerprint]
		if parseErr != nil || duplicate {
			return tls.Certificate{}, errors.New("executor gateway server certificate is invalid")
		}
		chain[index] = parsed
		seen[fingerprint] = struct{}{}
	}
	for index := 0; index+1 < len(chain); index++ {
		issuer := chain[index+1]
		if !issuer.IsCA || !issuer.BasicConstraintsValid ||
			issuer.KeyUsage&x509.KeyUsageCertSign == 0 ||
			chain[index].CheckSignatureFrom(issuer) != nil {
			return tls.Certificate{}, errors.New("executor gateway server certificate is invalid")
		}
	}
	leaf := chain[0]
	if leaf.IsCA || !now.After(leaf.NotBefore) || !now.Before(leaf.NotAfter) ||
		leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 ||
		len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
		return tls.Certificate{}, errors.New("executor gateway server certificate is invalid")
	}
	certificate.Leaf = leaf
	return certificate, nil
}

func loadClientRoots(path string, now time.Time) (clientRoots, error) {
	content, err := processconfig.ReadFile(path, maximumCertificateBytes, false)
	if err != nil {
		return clientRoots{}, err
	}
	blocks, err := decodeCanonicalPEM(content, "CERTIFICATE")
	if err != nil || len(blocks) == 0 || len(blocks) > maximumClientRoots {
		return clientRoots{}, errors.New("client root bundle is invalid")
	}
	result := clientRoots{
		pool: x509.NewCertPool(), fingerprints: make(map[[sha256.Size]byte]struct{}),
	}
	for _, block := range blocks {
		certificate, parseErr := x509.ParseCertificate(block.Bytes)
		var fingerprint [sha256.Size]byte
		if parseErr == nil {
			fingerprint = sha256.Sum256(certificate.RawSubjectPublicKeyInfo)
		}
		_, duplicate := result.fingerprints[fingerprint]
		if parseErr != nil || duplicate || !certificate.IsCA ||
			!certificate.BasicConstraintsValid ||
			certificate.KeyUsage&x509.KeyUsageCertSign == 0 ||
			!now.After(certificate.NotBefore) || !now.Before(certificate.NotAfter) ||
			certificate.CheckSignatureFrom(certificate) != nil {
			return clientRoots{}, errors.New("client root certificate is invalid")
		}
		result.pool.AddCert(certificate)
		result.fingerprints[fingerprint] = struct{}{}
	}
	return result, nil
}

func decodeCanonicalPEM(content []byte, blockType string) ([]*pem.Block, error) {
	if len(content) == 0 || blockType == "" {
		return nil, errors.New("PEM input is invalid")
	}
	remaining := content
	blocks := make([]*pem.Block, 0, 2)
	for len(remaining) > 0 {
		block, rest := pem.Decode(remaining)
		if block == nil || block.Type != blockType || len(block.Headers) != 0 ||
			!bytes.HasPrefix(remaining, pem.EncodeToMemory(block)) {
			return nil, errors.New("PEM input is not canonical")
		}
		blocks = append(blocks, block)
		remaining = rest
	}
	return blocks, nil
}

func decodeCanonicalPrivateKeyPEM(content []byte) ([]*pem.Block, error) {
	for _, blockType := range []string{"PRIVATE KEY", "EC PRIVATE KEY", "RSA PRIVATE KEY"} {
		blocks, err := decodeCanonicalPEM(content, blockType)
		if err == nil {
			return blocks, nil
		}
	}
	return nil, errors.New("private key PEM is invalid")
}

func rootsOverlap(left, right clientRoots) bool {
	if left.pool == nil || right.pool == nil || len(left.fingerprints) == 0 ||
		len(right.fingerprints) == 0 {
		return true
	}
	for fingerprint := range left.fingerprints {
		if _, found := right.fingerprints[fingerprint]; found {
			return true
		}
	}
	return false
}

func serveGatewayListeners(
	ctx context.Context,
	adminListener net.Listener,
	adminHandler http.Handler,
	adminTLS *tls.Config,
	runnerListener net.Listener,
	runnerHandler http.Handler,
	runnerTLS *tls.Config,
) error {
	if ctx == nil || adminListener == nil || adminHandler == nil || adminTLS == nil ||
		runnerListener == nil || runnerHandler == nil || runnerTLS == nil {
		return errors.New("executor gateway listeners are invalid")
	}
	serveContext, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan error, 2)
	go func() {
		results <- serveTLSListener(serveContext, adminListener, adminHandler, adminTLS)
	}()
	go func() {
		results <- serveTLSListener(serveContext, runnerListener, runnerHandler, runnerTLS)
	}()
	first := <-results
	cancel()
	second := <-results
	if ctx.Err() != nil {
		return nil
	}
	if first != nil {
		return first
	}
	if second != nil {
		return second
	}
	return errors.New("executor gateway listeners stopped unexpectedly")
}

func serveTLSListener(
	ctx context.Context,
	listener net.Listener,
	handler http.Handler,
	tlsConfig *tls.Config,
) error {
	server := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       2 * time.Minute,
		WriteTimeout:      2 * time.Minute,
		IdleTimeout:       time.Minute,
		MaxHeaderBytes:    maximumRequestHeaders,
		TLSConfig:         tlsConfig.Clone(),
		BaseContext: func(net.Listener) context.Context {
			return ctx
		},
	}
	result := make(chan error, 1)
	go func() {
		result <- server.Serve(tls.NewListener(listener, tlsConfig.Clone()))
	}()
	select {
	case err := <-result:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return errors.New("executor gateway TLS listener stopped unexpectedly")
	case <-ctx.Done():
		shutdownContext, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownContext); err != nil {
			return errors.New("executor gateway TLS listener cannot stop gracefully")
		}
		err := <-result
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return errors.New("executor gateway TLS listener stopped unexpectedly")
		}
		return nil
	}
}
