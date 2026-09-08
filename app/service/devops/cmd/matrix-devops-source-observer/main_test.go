package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/xiak/matrix/app/service/devops/internal/delivery/usecase/sourceobservation"
)

func TestLoadConfigurationRequiresClosedEnvironment(t *testing.T) {
	for _, name := range []string{
		databaseDSNFileEnvironment,
		webhookRootEnvironment,
		fetchRootEnvironment,
		reportRootEnvironment,
		workerIDEnvironment,
		listenAddressEnvironment,
	} {
		t.Setenv(name, "")
	}
	if _, err := loadConfiguration(); err == nil {
		t.Fatal("loadConfiguration() accepted an incomplete environment")
	}

	t.Setenv(databaseDSNFileEnvironment, "/run/matrix/source-observer-dsn")
	t.Setenv(webhookRootEnvironment, "/run/matrix/source-webhooks")
	t.Setenv(fetchRootEnvironment, "/run/matrix/source-fetch")
	t.Setenv(reportRootEnvironment, "/run/matrix/source-report")
	t.Setenv(workerIDEnvironment, "devops-source-observer-test")
	t.Setenv(listenAddressEnvironment, "0.0.0.0:8080")
	config, err := loadConfiguration()
	if err != nil {
		t.Fatalf("loadConfiguration() error = %v", err)
	}
	if config.workerID != "devops-source-observer-test" ||
		config.fetchRoot != "/run/matrix/source-fetch" {
		t.Fatalf("loadConfiguration() = %#v", config)
	}

	t.Setenv(workerIDEnvironment, "invalid worker")
	if _, err := loadConfiguration(); err == nil {
		t.Fatal("loadConfiguration() accepted an invalid worker identity")
	}
}

func TestObservationLoopHeartbeatsAfterCompletion(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	observations := 0
	heartbeats := 0
	err := runObservationLoop(
		ctx,
		func(context.Context) (sourceobservation.Result, error) {
			observations++
			if observations == 1 {
				return sourceobservation.Result{Claimed: true}, nil
			}
			cancel()
			return sourceobservation.Result{}, context.Canceled
		},
		func(context.Context) (time.Time, error) {
			heartbeats++
			return time.Now().UTC().Truncate(time.Microsecond), nil
		},
		time.Now,
	)
	if err != nil {
		t.Fatalf("runObservationLoop() error = %v", err)
	}
	if observations != 2 || heartbeats != 1 {
		t.Fatalf("observations=%d heartbeats=%d", observations, heartbeats)
	}
}

func TestObservationLoopRejectsInvalidAndFailsClosed(t *testing.T) {
	if err := runObservationLoop(
		context.Background(), nil,
		func(context.Context) (time.Time, error) { return time.Time{}, nil },
		time.Now,
	); err == nil {
		t.Fatal("runObservationLoop() accepted a nil observation boundary")
	}
	want := errors.New("database unavailable")
	err := runObservationLoop(
		context.Background(),
		func(context.Context) (sourceobservation.Result, error) {
			return sourceobservation.Result{}, want
		},
		func(context.Context) (time.Time, error) { return time.Time{}, nil },
		time.Now,
	)
	if err == nil || err.Error() != "DevOps source observation cycle failed" {
		t.Fatalf("runObservationLoop() error = %v", err)
	}
}
