package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"

	nodev1 "github.com/xiak/matrix/api/adapter/node/v1"
	"github.com/xiak/matrix/api/contractjson"
	paasv1 "github.com/xiak/matrix/api/paas/v1"
	"github.com/xiak/matrix/app/adapter/infrastructure/localmachine"
	"github.com/xiak/matrix/app/adapter/infrastructure/nodeexporter"
	nodehttps "github.com/xiak/matrix/app/adapter/node/https"
	"github.com/xiak/matrix/app/service/internal/processconfig"
	"github.com/xiak/matrix/app/service/internal/processhttp"
	"github.com/xiak/matrix/app/service/nodeagent/internal/service/nethttp"
	"github.com/xiak/matrix/app/service/nodeagent/internal/usecase/observehost"
)

const configurationEnvironment = "MATRIX_NODE_CONFIGURATION_FILE"

type configuration struct {
	APIVersion          string          `json:"apiVersion"`
	Kind                string          `json:"kind"`
	Identity            nodev1.Identity `json:"identity"`
	ControllerID        string          `json:"controllerId"`
	BindingRef          string          `json:"bindingRef"`
	ExpectedFingerprint string          `json:"expectedFingerprint"`
	ListenAddress       string          `json:"listenAddress"`
	CollectorEndpoint   string          `json:"collectorEndpoint"`
	StoragePath         string          `json:"storagePath"`
	CertificateFile     string          `json:"certificateFile"`
	PrivateKeyFile      string          `json:"privateKeyFile"`
	TrustFile           string          `json:"trustFile"`
	SystemReserve       paasv1.Capacity `json:"systemReserve"`
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "matrix node agent failed")
		os.Exit(1)
	}
}

func run(ctx context.Context) error {
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		return errors.New("node host platform is unsupported")
	}
	config, err := loadConfiguration(os.Getenv(configurationEnvironment))
	if err != nil {
		return err
	}
	credentials, err := loadCredentials(config)
	if err != nil {
		return err
	}
	security, err := nodehttps.ServerTLS(credentials, config.Identity, config.ControllerID)
	if err != nil {
		return err
	}
	// An inherited CLI context must not redirect this node's probe to another
	// engine. The Phase 3 host profile uses the local Unix socket exclusively.
	if os.Setenv("DOCKER_HOST", "unix:///var/run/docker.sock") != nil || os.Unsetenv("DOCKER_CONTEXT") != nil {
		return errors.New("node local runtime cannot be configured")
	}
	binding, err := localmachine.NewMachineBinding(localmachine.MachineBindingSpec{
		ID: config.BindingRef, Kind: localmachine.BindingLocal, StoragePath: config.StoragePath,
		ExpectedMachineFingerprint: config.ExpectedFingerprint,
		AllowedIsolationGuarantees: []paasv1.IsolationGuarantee{paasv1.IsolationWorkload},
	})
	if err != nil {
		return errors.New("node local binding is invalid")
	}
	bindings, err := localmachine.NewStaticBindingResolver(binding)
	if err != nil {
		return errors.New("node local binding is invalid")
	}
	adapter, err := localmachine.New(localmachine.Config{Bindings: bindings, LocalProbe: localmachine.NewLocalHostProbe()})
	if err != nil {
		return err
	}
	collector, err := nodeexporter.New(nodeexporter.Config{
		Endpoint: config.CollectorEndpoint, Identity: config.Identity, Credentials: credentials,
	})
	if err != nil {
		return err
	}
	defer collector.Close()
	sampler, err := observehost.New(adapter, collector, observehost.Config{
		Identity: config.Identity, BindingRef: config.BindingRef,
		ExpectedFingerprint: config.ExpectedFingerprint, SystemReserve: config.SystemReserve,
	})
	if err != nil {
		return err
	}
	handler, err := nethttp.New(sampler, nethttp.Config{
		Identity: config.Identity, ControllerID: config.ControllerID, BindingRef: config.BindingRef,
	})
	if err != nil {
		return err
	}
	return processhttp.ServeTLSWithBackground(ctx, config.ListenAddress, handler, security, sampler.Run)
}

func loadConfiguration(path string) (configuration, error) {
	empty := configuration{}
	source, err := processconfig.ReadFile(path, 64*1024, true)
	if err != nil {
		return empty, errors.New("node configuration is unavailable")
	}
	defer clear(source)
	var value configuration
	if contractjson.DecodeObjectBytes(source, 64*1024, &value) != nil ||
		value.APIVersion != "node.installation.matrix.xiak.com/v1" || value.Kind != "NodeConfiguration" ||
		nodev1.ValidateIdentity(value.Identity) != nil ||
		paasv1.ValidateID("controllerId", value.ControllerID) != nil ||
		paasv1.ValidateID("bindingRef", value.BindingRef) != nil ||
		paasv1.ValidateDigest("expectedFingerprint", value.ExpectedFingerprint) != nil ||
		!privateListenAddress(value.ListenAddress) {
		return empty, errors.New("node configuration is invalid")
	}
	for _, name := range []string{value.StoragePath, value.CertificateFile, value.PrivateKeyFile, value.TrustFile} {
		if !filepath.IsAbs(name) || filepath.Clean(name) != name {
			return empty, errors.New("node configuration is invalid")
		}
	}
	return value, nil
}

func privateListenAddress(address string) bool {
	host, portText, err := net.SplitHostPort(address)
	port, portErr := strconv.ParseUint(portText, 10, 16)
	addressIP := net.ParseIP(host)
	return err == nil && portErr == nil && port > 0 && addressIP != nil &&
		(addressIP.IsLoopback() || addressIP.IsPrivate())
}

func loadCredentials(config configuration) (nodehttps.Credentials, error) {
	empty := nodehttps.Credentials{}
	certificate, err := processconfig.ReadFile(config.CertificateFile, 64*1024, false)
	if err != nil {
		return empty, err
	}
	defer clear(certificate)
	key, err := processconfig.ReadFile(config.PrivateKeyFile, 64*1024, true)
	if err != nil {
		return empty, err
	}
	defer clear(key)
	trust, err := processconfig.ReadFile(config.TrustFile, 256*1024, false)
	if err != nil {
		return empty, err
	}
	defer clear(trust)
	return nodehttps.NewCredentials(certificate, key, trust)
}
