package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/xiak/matrix/app/service/devops/internal/delivery/usecase/checkreporting"
)

func TestLoadConfigurationRequiresClosedEnvironment(t *testing.T) {
	for _, name := range []string{
		databaseDSNFileEnvironment,
		reportRootEnvironment,
		trustRootEnvironment,
		workerIDEnvironment,
		listenAddressEnvironment,
	} {
		t.Setenv(name, "")
	}
	if _, err := loadConfiguration(); err == nil {
		t.Fatal("loadConfiguration() accepted an incomplete environment")
	}

	t.Setenv(databaseDSNFileEnvironment, "/run/matrix/check-reporter-dsn")
	t.Setenv(reportRootEnvironment, "/run/matrix/source-report")
	t.Setenv(trustRootEnvironment, "/run/matrix/source-trust")
	t.Setenv(workerIDEnvironment, "devops-check-reporter-test")
	t.Setenv(listenAddressEnvironment, "0.0.0.0:8080")
	config, err := loadConfiguration()
	if err != nil {
		t.Fatalf("loadConfiguration() error = %v", err)
	}
	if config.workerID != "devops-check-reporter-test" ||
		config.reportRoot != "/run/matrix/source-report" ||
		config.trustRoot != "/run/matrix/source-trust" {
		t.Fatalf("loadConfiguration() = %#v", config)
	}

	t.Setenv(workerIDEnvironment, "invalid worker")
	if _, err := loadConfiguration(); err == nil {
		t.Fatal("loadConfiguration() accepted an invalid worker identity")
	}
}

func TestReportLoopHeartbeatsAfterCompletion(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reports := 0
	heartbeats := 0
	err := runReportLoop(
		ctx,
		func(context.Context) (checkreporting.Result, error) {
			reports++
			if reports == 1 {
				return checkreporting.Result{Claimed: true}, nil
			}
			cancel()
			return checkreporting.Result{}, context.Canceled
		},
		func(context.Context) (time.Time, error) {
			heartbeats++
			return time.Now().UTC().Truncate(time.Microsecond), nil
		},
		time.Now,
	)
	if err != nil {
		t.Fatalf("runReportLoop() error = %v", err)
	}
	if reports != 2 || heartbeats != 1 {
		t.Fatalf("reports=%d heartbeats=%d", reports, heartbeats)
	}
}

func TestReportLoopRejectsInvalidAndFailsClosed(t *testing.T) {
	if err := runReportLoop(
		context.Background(), nil,
		func(context.Context) (time.Time, error) { return time.Time{}, nil },
		time.Now,
	); err == nil {
		t.Fatal("runReportLoop() accepted a nil reporting boundary")
	}
	want := errors.New("database unavailable")
	err := runReportLoop(
		context.Background(),
		func(context.Context) (checkreporting.Result, error) {
			return checkreporting.Result{}, want
		},
		func(context.Context) (time.Time, error) { return time.Time{}, nil },
		time.Now,
	)
	if err == nil || err.Error() != "DevOps check reporting cycle failed" {
		t.Fatalf("runReportLoop() error = %v", err)
	}
}
