package main

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xiak/matrix/app/service/devops/internal/delivery/usecase/runnerexecution"
)

func TestLoadConfigurationAcceptsOnlySeparatedPrivateRunnerInputs(t *testing.T) {
	values := runnerConfigurationFixture(t)
	setRunnerEnvironment(t, values)

	config, err := loadConfiguration()
	if err != nil || config.storageRoot != values[storageRootEnvironment] ||
		config.journalRoot != values[journalRootEnvironment] ||
		config.workspaceRoot != values[workspaceRootEnvironment] ||
		config.listenAddress != "127.0.0.1:8080" ||
		config.credentialDirectory != values[credentialsDirectoryEnvironment] ||
		config.clientIdentity != "spiffe://matrix.test/devops/runners/node-one" {
		t.Fatalf("runner configuration=%#v err=%v", config, err)
	}
}

func TestLoadConfigurationRejectsMissingOverlappingAndRemoteInputs(t *testing.T) {
	base := runnerConfigurationFixture(t)
	tests := []struct {
		name   string
		change func(map[string]string)
	}{
		{name: "missing", change: func(values map[string]string) {
			values[gatewayOriginEnvironment] = ""
		}},
		{name: "missing credential directory", change: func(values map[string]string) {
			values[credentialsDirectoryEnvironment] = ""
		}},
		{name: "relative root", change: func(values map[string]string) {
			values[journalRootEnvironment] = "journal"
		}},
		{name: "workspace outside storage", change: func(values map[string]string) {
			values[workspaceRootEnvironment] = filepath.Join(filepath.Dir(values[storageRootEnvironment]), "outside")
		}},
		{name: "same durable root", change: func(values map[string]string) {
			values[workspaceRootEnvironment] = values[journalRootEnvironment]
		}},
		{name: "nested durable roots", change: func(values map[string]string) {
			values[workspaceRootEnvironment] = filepath.Join(values[journalRootEnvironment], "workspace")
		}},
		{name: "credential in writable storage", change: func(values map[string]string) {
			values[credentialsDirectoryEnvironment] = filepath.Join(values[storageRootEnvironment], "credentials")
		}},
		{name: "credential directory contains writable storage", change: func(values map[string]string) {
			values[credentialsDirectoryEnvironment] = filepath.Dir(values[storageRootEnvironment])
		}},
		{name: "remote readiness", change: func(values map[string]string) {
			values[listenAddressEnvironment] = "0.0.0.0:8080"
		}},
		{name: "noncanonical readiness port", change: func(values map[string]string) {
			values[listenAddressEnvironment] = "127.0.0.1:08080"
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			values := make(map[string]string, len(base))
			for key, value := range base {
				values[key] = value
			}
			test.change(values)
			setRunnerEnvironment(t, values)
			if _, err := loadConfiguration(); err == nil {
				t.Fatal("unsafe runner configuration was accepted")
			}
		})
	}
}

func TestRunnerLoopBecomesReadyAfterPreflightCycleAndImmediatelyDrainsClaim(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	readiness := &runnerReadiness{}
	if err := readiness.check(context.Background()); err == nil {
		t.Fatal("runner was ready before its first proved cycle")
	}
	secondCycle := make(chan struct{})
	var calls atomic.Int32
	workOnce := func(context.Context) (runnerexecution.Result, error) {
		switch calls.Add(1) {
		case 1:
			return runnerexecution.Result{
				Claimed: true, ExecutionID: "sha256:" + strings.Repeat("1", 64),
				Acknowledged: true,
			}, nil
		case 2:
			close(secondCycle)
			return runnerexecution.Result{}, nil
		default:
			return runnerexecution.Result{}, errors.New("unexpected extra cycle")
		}
	}
	result := make(chan error, 1)
	go func() {
		result <- runRunnerLoop(ctx, workOnce, readiness, time.Hour)
	}()
	select {
	case <-secondCycle:
	case <-time.After(time.Second):
		t.Fatal("runner did not immediately continue after a claimed execution")
	}
	waitForRunnerReady(t, readiness)
	cancel()
	select {
	case err := <-result:
		if err != nil || calls.Load() != 2 {
			t.Fatalf("runner loop err=%v calls=%d", err, calls.Load())
		}
	case <-time.After(time.Second):
		t.Fatal("runner loop did not stop")
	}
	if err := readiness.check(context.Background()); err == nil {
		t.Fatal("stopped runner remained ready")
	}
}

func TestRunnerLoopFailsClosedAndRemovesReadiness(t *testing.T) {
	readiness := &runnerReadiness{}
	readiness.set(true)
	err := runRunnerLoop(
		context.Background(),
		func(context.Context) (runnerexecution.Result, error) {
			return runnerexecution.Result{}, errors.New("native error /secret/path")
		},
		readiness,
		time.Second,
	)
	if err == nil || strings.Contains(err.Error(), "native error") ||
		strings.Contains(err.Error(), "/secret/path") {
		t.Fatalf("runner loop error was not closed: %v", err)
	}
	if err := readiness.check(context.Background()); err == nil {
		t.Fatal("failed runner remained ready")
	}
}

func TestRunnerResultValidationIsClosed(t *testing.T) {
	valid := []runnerexecution.Result{
		{},
		{Claimed: true, ExecutionID: "sha256:" + strings.Repeat("2", 64), Acknowledged: true},
		{Claimed: true, ExecutionID: "sha256:" + strings.Repeat("3", 64), Deferred: true},
	}
	for _, result := range valid {
		if !validRunnerResult(result) {
			t.Fatalf("valid runner result rejected: %#v", result)
		}
	}
	invalid := []runnerexecution.Result{
		{ExecutionID: "sha256:" + strings.Repeat("4", 64)},
		{Claimed: true, ExecutionID: "execution-native", Acknowledged: true},
		{Claimed: true, ExecutionID: "sha256:" + strings.Repeat("5", 64)},
		{Claimed: true, ExecutionID: "sha256:" + strings.Repeat("6", 64), Deferred: true, Acknowledged: true},
	}
	for _, result := range invalid {
		if validRunnerResult(result) {
			t.Fatalf("invalid runner result accepted: %#v", result)
		}
	}
}

func TestRunRejectsNilContext(t *testing.T) {
	if err := run(nil); err == nil {
		t.Fatal("nil runner process context was accepted")
	}
}

func runnerConfigurationFixture(t *testing.T) map[string]string {
	t.Helper()
	root := t.TempDir()
	storage := filepath.Join(root, "storage")
	return map[string]string{
		journalRootEnvironment:          filepath.Join(storage, "journal"),
		workspaceRootEnvironment:        filepath.Join(storage, "workspaces"),
		storageRootEnvironment:          storage,
		dockerSocketEnvironment:         filepath.Join(root, "docker.sock"),
		listenAddressEnvironment:        "127.0.0.1:8080",
		gatewayOriginEnvironment:        "https://executor-gateway.matrix.test:8444",
		gatewayNameEnvironment:          "executor-gateway.matrix.test",
		credentialsDirectoryEnvironment: filepath.Join(root, "credentials"),
		clientIdentityEnvironment:       "spiffe://matrix.test/devops/runners/node-one",
		runnerNamespaceEnvironment:      "spiffe://matrix.test/devops/runners",
	}
}

func setRunnerEnvironment(t *testing.T, values map[string]string) {
	t.Helper()
	for _, key := range []string{
		journalRootEnvironment, workspaceRootEnvironment, storageRootEnvironment,
		dockerSocketEnvironment, listenAddressEnvironment, gatewayOriginEnvironment,
		gatewayNameEnvironment, clientIdentityEnvironment, runnerNamespaceEnvironment,
		credentialsDirectoryEnvironment,
	} {
		t.Setenv(key, values[key])
	}
}

func waitForRunnerReady(t *testing.T, readiness *runnerReadiness) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if readiness.check(context.Background()) == nil {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("runner did not become ready")
}
