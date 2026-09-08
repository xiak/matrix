package main

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xiak/matrix/app/service/devops/internal/delivery/usecase/buildexecution"
)

func TestLoadConfigurationRequiresClosedEnvironment(t *testing.T) {
	for _, name := range []string{
		databaseDSNFileEnvironment,
		archiveRootEnvironment,
		workerIDEnvironment,
		listenAddressEnvironment,
		gatewayOriginEnvironment,
		gatewayNameEnvironment,
		clientCertEnvironment,
		clientKeyEnvironment,
		serverCAEnvironment,
		clientIdentityEnvironment,
	} {
		t.Setenv(name, "")
	}
	if _, err := loadConfiguration(); err == nil {
		t.Fatal("loadConfiguration() accepted an incomplete environment")
	}

	t.Setenv(databaseDSNFileEnvironment, "/run/matrix/build-worker-dsn")
	t.Setenv(archiveRootEnvironment, "/var/lib/matrix/source-archives")
	t.Setenv(workerIDEnvironment, "devops-build-worker-test")
	t.Setenv(listenAddressEnvironment, "0.0.0.0:8080")
	t.Setenv(gatewayOriginEnvironment, "https://executor-gateway:9443")
	t.Setenv(gatewayNameEnvironment, "executor-gateway")
	t.Setenv(clientCertEnvironment, "/run/matrix/build-worker.crt")
	t.Setenv(clientKeyEnvironment, "/run/matrix/build-worker.key")
	t.Setenv(serverCAEnvironment, "/run/matrix/executor-server-ca.crt")
	t.Setenv(clientIdentityEnvironment, "spiffe://matrix.internal/devops/build-worker")
	config, err := loadConfiguration()
	if err != nil {
		t.Fatalf("loadConfiguration() error = %v", err)
	}
	if config.workerID != "devops-build-worker-test" ||
		config.archiveRoot != "/var/lib/matrix/source-archives" ||
		config.gatewayOrigin != "https://executor-gateway:9443" ||
		config.clientIdentity != "spiffe://matrix.internal/devops/build-worker" {
		t.Fatalf("loadConfiguration() = %#v", config)
	}

	t.Setenv(workerIDEnvironment, "invalid worker")
	if _, err := loadConfiguration(); err == nil {
		t.Fatal("loadConfiguration() accepted an invalid worker identity")
	}
}

func TestBuildLoopHeartbeatsDuringExecutionAndStops(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started := make(chan struct{})
	var builds atomic.Int64
	err := runBuildLoop(
		ctx,
		func(buildContext context.Context) (buildexecution.Result, error) {
			if builds.Add(1) == 1 {
				close(started)
			}
			<-buildContext.Done()
			return buildexecution.Result{}, buildContext.Err()
		},
		func(context.Context) (time.Time, error) {
			select {
			case <-started:
				cancel()
			default:
				t.Fatal("heartbeat ran before build began")
			}
			return time.Now().UTC().Truncate(time.Microsecond), nil
		},
		5*time.Millisecond,
		5*time.Millisecond,
	)
	if err != nil || builds.Load() != 1 {
		t.Fatalf("runBuildLoop() builds=%d error=%v", builds.Load(), err)
	}
}

func TestBuildLoopDrainsClaimsAndFailsClosed(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	builds := 0
	err := runBuildLoop(
		ctx,
		func(context.Context) (buildexecution.Result, error) {
			builds++
			if builds == 1 {
				return buildexecution.Result{Claimed: true}, nil
			}
			return buildexecution.Result{}, errors.New("database unavailable")
		},
		func(context.Context) (time.Time, error) {
			return time.Now().UTC().Truncate(time.Microsecond), nil
		},
		time.Hour,
		time.Hour,
	)
	if err == nil || err.Error() != "DevOps build execution cycle failed" || builds != 2 {
		t.Fatalf("runBuildLoop() builds=%d error=%v", builds, err)
	}

	if err := runBuildLoop(
		context.Background(),
		nil,
		func(context.Context) (time.Time, error) { return time.Time{}, nil },
		time.Second,
		time.Second,
	); err == nil {
		t.Fatal("runBuildLoop() accepted a nil build boundary")
	}
}
