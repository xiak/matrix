package main

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xiak/matrix/app/service/devops/internal/delivery/usecase/sourceacquisition"
)

func TestLoadConfigurationRequiresClosedEnvironment(t *testing.T) {
	for _, name := range []string{
		databaseDSNFileEnvironment,
		fetchRootEnvironment,
		archiveRootEnvironment,
		workerIDEnvironment,
		listenAddressEnvironment,
	} {
		t.Setenv(name, "")
	}
	if _, err := loadConfiguration(); err == nil {
		t.Fatal("loadConfiguration() accepted an incomplete environment")
	}

	t.Setenv(databaseDSNFileEnvironment, "/run/matrix/source-fetcher-dsn")
	t.Setenv(fetchRootEnvironment, "/run/matrix/source-fetch")
	t.Setenv(archiveRootEnvironment, "/var/lib/matrix/source-archives")
	t.Setenv(workerIDEnvironment, "devops-source-fetcher-test")
	t.Setenv(listenAddressEnvironment, "0.0.0.0:8080")
	config, err := loadConfiguration()
	if err != nil {
		t.Fatalf("loadConfiguration() error = %v", err)
	}
	if config.workerID != "devops-source-fetcher-test" ||
		config.fetchRoot != "/run/matrix/source-fetch" ||
		config.archiveRoot != "/var/lib/matrix/source-archives" {
		t.Fatalf("loadConfiguration() = %#v", config)
	}

	t.Setenv(workerIDEnvironment, "invalid worker")
	if _, err := loadConfiguration(); err == nil {
		t.Fatal("loadConfiguration() accepted an invalid worker identity")
	}
}

func TestAcquisitionLoopHeartbeatsDuringFetchAndStops(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started := make(chan struct{})
	var fetches atomic.Int64
	err := runAcquisitionLoop(
		ctx,
		func(fetchContext context.Context) (sourceacquisition.Result, error) {
			if fetches.Add(1) == 1 {
				close(started)
			}
			<-fetchContext.Done()
			return sourceacquisition.Result{}, fetchContext.Err()
		},
		func(context.Context) (time.Time, error) {
			select {
			case <-started:
				cancel()
			default:
				t.Fatal("heartbeat ran before acquisition began")
			}
			return time.Now().UTC().Truncate(time.Microsecond), nil
		},
		5*time.Millisecond,
		5*time.Millisecond,
	)
	if err != nil || fetches.Load() != 1 {
		t.Fatalf("runAcquisitionLoop() fetches=%d error=%v", fetches.Load(), err)
	}
}

func TestAcquisitionLoopDrainsClaimedWorkAndFailsClosed(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fetches := 0
	err := runAcquisitionLoop(
		ctx,
		func(context.Context) (sourceacquisition.Result, error) {
			fetches++
			if fetches == 1 {
				return sourceacquisition.Result{Claimed: true}, nil
			}
			return sourceacquisition.Result{}, errors.New("database unavailable")
		},
		func(context.Context) (time.Time, error) {
			return time.Now().UTC().Truncate(time.Microsecond), nil
		},
		time.Hour,
		time.Hour,
	)
	if err == nil || err.Error() != "DevOps source acquisition cycle failed" || fetches != 2 {
		t.Fatalf("runAcquisitionLoop() fetches=%d error=%v", fetches, err)
	}

	if err := runAcquisitionLoop(
		context.Background(),
		nil,
		func(context.Context) (time.Time, error) { return time.Time{}, nil },
		time.Second,
		time.Second,
	); err == nil {
		t.Fatal("runAcquisitionLoop() accepted a nil acquisition boundary")
	}
}

func TestAcquisitionLoopWaitsForActiveCycleCleanupBeforeShutdown(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	started := make(chan struct{})
	cleaning := make(chan struct{})
	releaseCleanup := make(chan struct{})
	result := make(chan error, 1)
	go func() {
		result <- runAcquisitionLoop(
			ctx,
			func(fetchContext context.Context) (sourceacquisition.Result, error) {
				close(started)
				<-fetchContext.Done()
				close(cleaning)
				<-releaseCleanup
				return sourceacquisition.Result{}, fetchContext.Err()
			},
			func(context.Context) (time.Time, error) {
				return time.Now().UTC().Truncate(time.Microsecond), nil
			},
			time.Hour,
			time.Hour,
		)
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("source acquisition cycle did not start")
	}
	cancel()
	select {
	case <-cleaning:
	case <-time.After(time.Second):
		t.Fatal("source acquisition cycle did not begin cancellation cleanup")
	}
	select {
	case err := <-result:
		t.Fatalf("source acquisition loop returned before cycle cleanup: %v", err)
	default:
	}
	close(releaseCleanup)
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("source acquisition loop shutdown error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("source acquisition loop did not stop after cycle cleanup")
	}
}
