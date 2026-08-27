package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	paasv1 "github.com/xiak/matrix/api/paas/v1"
	"github.com/xiak/matrix/app/adapter/infrastructure/localmachine"
	"github.com/xiak/matrix/app/adapter/infrastructure/nodeexporter"
	nodehttps "github.com/xiak/matrix/app/adapter/node/https"
	"github.com/xiak/matrix/app/service/installation/nodeconfig"
	"github.com/xiak/matrix/app/service/internal/processconfig"
	"github.com/xiak/matrix/app/service/internal/processhttp"
	"github.com/xiak/matrix/app/service/nodeagent/internal/service/nethttp"
	"github.com/xiak/matrix/app/service/nodeagent/internal/usecase/observehost"
)

const configurationEnvironment = "MATRIX_NODE_CONFIGURATION_FILE"

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

func loadConfiguration(path string) (nodeconfig.Configuration, error) {
	source, err := processconfig.ReadFile(path, nodeconfig.MaximumBytes, true)
	if err != nil {
		return nodeconfig.Configuration{}, errors.New("node configuration is unavailable")
	}
	defer clear(source)
	return nodeconfig.DecodeConfiguration(source)
}

func loadCredentials(config nodeconfig.Configuration) (nodehttps.Credentials, error) {
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
