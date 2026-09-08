package runnersandboxdocker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	devopsv1 "github.com/xiak/matrix/api/devops/v1"
)

func TestStepLifecycleRunsExactContainerAndNormalizesLogs(t *testing.T) {
	plan := testStepPlan(t)
	engine := newStepEngine(t, plan)
	engine.logs = dockerLogStream(
		logFrame{stream: stdoutStream, content: []byte("go test ./...\n")},
		logFrame{stream: stderrStream, content: []byte("warning\n")},
	)
	client := testStepClient(t, engine)

	if err := client.CreateStep(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	if state, err := client.ObserveStep(context.Background(), plan); err != nil || state != StepCreated {
		t.Fatalf("created state = %q / %v", state, err)
	}
	if err := client.StartStep(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	if state, err := client.ObserveStep(context.Background(), plan); err != nil || state != StepRunning {
		t.Fatalf("running state = %q / %v", state, err)
	}
	result, err := client.FollowStep(context.Background(), plan, NewLogBudget())
	if err != nil || result.State != StepPassed || len(result.Chunks) != 1 ||
		result.Chunks[0].Sequence != 1 ||
		result.Chunks[0].Content != "[stdout] go test ./...\n[stderr] warning\n" {
		t.Fatalf("result = %#v / %v", result, err)
	}
	if err := client.StartStep(context.Background(), plan); err != nil {
		t.Fatalf("terminal start replay = %v", err)
	}
	if err := client.DeleteStep(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	if err := client.DeleteStep(context.Background(), plan); err != nil {
		t.Fatalf("absent delete replay = %v", err)
	}
	if state, err := client.ObserveStep(context.Background(), plan); state != "" ||
		!errors.Is(err, ErrStepNotFound) {
		t.Fatalf("deleted state = %q / %v", state, err)
	}

	wantCalls := []string{
		"POST /v1.46/containers/create?name=" + plan.Name(),
		"GET /v1.46/containers/" + engine.id + "/json?size=false",
		"GET /v1.46/containers/" + plan.Name() + "/json?size=false",
		"GET /v1.46/containers/" + plan.Name() + "/json?size=false",
		"POST /v1.46/containers/" + engine.id + "/start",
		"GET /v1.46/containers/" + plan.Name() + "/json?size=false",
		"GET /v1.46/containers/" + plan.Name() + "/json?size=false",
		"GET /v1.46/containers/" + plan.Name() + "/json?size=false",
		"GET /v1.46/containers/" + engine.id + "/logs?follow=true&stderr=true&stdout=true&tail=all&timestamps=false",
		"POST /v1.46/containers/" + engine.id + "/wait?condition=not-running",
		"GET /v1.46/containers/" + plan.Name() + "/json?size=false",
		"GET /v1.46/containers/" + plan.Name() + "/json?size=false",
		"GET /v1.46/containers/" + plan.Name() + "/json?size=false",
		"DELETE /v1.46/containers/" + engine.id + "?force=false&v=true",
		"GET /v1.46/containers/" + plan.Name() + "/json?size=false",
		"GET /v1.46/containers/" + plan.Name() + "/json?size=false",
		"GET /v1.46/containers/" + plan.Name() + "/json?size=false",
	}
	if !equalStrings(engine.calls, wantCalls) {
		t.Fatalf("calls = %#v\n want = %#v", engine.calls, wantCalls)
	}
}

func TestStepLifecycleReturnsClosedFailureForExitAndOOM(t *testing.T) {
	tests := []struct {
		name     string
		exitCode int64
		oom      bool
	}{
		{name: "ordinary exit", exitCode: 1},
		{name: "memory limit", exitCode: 137, oom: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			plan := testStepPlan(t)
			engine := newStepEngine(t, plan)
			engine.nextExitCode = test.exitCode
			engine.oomOnExit = test.oom
			client := testStepClient(t, engine)
			if err := client.CreateStep(context.Background(), plan); err != nil {
				t.Fatal(err)
			}
			if err := client.StartStep(context.Background(), plan); err != nil {
				t.Fatal(err)
			}
			result, err := client.FollowStep(context.Background(), plan, NewLogBudget())
			if err != nil || result.State != StepFailed {
				t.Fatalf("result = %#v / %v", result, err)
			}
			state, err := client.ObserveStep(context.Background(), plan)
			if err != nil || state != StepFailed {
				t.Fatalf("observed state = %q / %v", state, err)
			}
		})
	}
}

func TestStepCancellationIsClosedBeforeAndDuringExecution(t *testing.T) {
	t.Run("before start", func(t *testing.T) {
		plan := testStepPlan(t)
		engine := newStepEngine(t, plan)
		client := testStepClient(t, engine)
		if err := client.CreateStep(context.Background(), plan); err != nil {
			t.Fatal(err)
		}
		state, err := client.CancelStep(context.Background(), plan)
		if err != nil || state != StepCancelled || engine.killed ||
			!engine.deleted || engine.present {
			t.Fatalf(
				"cancel = %q / %v, killed=%v deleted=%v present=%v",
				state, err, engine.killed, engine.deleted, engine.present,
			)
		}
		if observed, err := client.ObserveStep(context.Background(), plan); observed != "" ||
			!errors.Is(err, ErrStepNotFound) {
			t.Fatalf("container after cancellation = %q / %v", observed, err)
		}
	})

	t.Run("while running", func(t *testing.T) {
		plan := testStepPlan(t)
		engine := newStepEngine(t, plan)
		client := testStepClient(t, engine)
		if err := client.CreateStep(context.Background(), plan); err != nil {
			t.Fatal(err)
		}
		if err := client.StartStep(context.Background(), plan); err != nil {
			t.Fatal(err)
		}
		state, err := client.CancelStep(context.Background(), plan)
		if err != nil || state != StepCancelled || !engine.killed {
			t.Fatalf("cancel = %q / %v, killed = %v", state, err, engine.killed)
		}
		if observed, err := client.ObserveStep(context.Background(), plan); err != nil || observed != StepFailed {
			t.Fatalf("terminal container = %q / %v", observed, err)
		}
	})

	t.Run("start race after created observation", func(t *testing.T) {
		plan := testStepPlan(t)
		engine := newStepEngine(t, plan)
		engine.present = true
		engine.state = StepCreated
		engine.mutateInspection = func(*containerInspection) {
			engine.state = StepRunning
		}
		state, err := testStepClient(t, engine).CancelStep(context.Background(), plan)
		if err != nil || state != StepCancelled || !engine.deleted || engine.present {
			t.Fatalf("cancel = %q / %v, deleted=%v present=%v", state, err, engine.deleted, engine.present)
		}
		foundForcedDelete := false
		for _, call := range engine.calls {
			if strings.HasPrefix(call, "DELETE ") && strings.Contains(call, "force=true") {
				foundForcedDelete = true
			}
		}
		if !foundForcedDelete {
			t.Fatalf("calls = %#v", engine.calls)
		}
	})
}

func TestStepLifecycleRejectsChangedIdentityAndUnsafeState(t *testing.T) {
	tests := map[string]func(*containerInspection){
		"name":         func(value *containerInspection) { value.Name = "/foreign" },
		"image":        func(value *containerInspection) { value.Image = strings.Repeat("f", 64) },
		"command":      func(value *containerInspection) { value.Config.Cmd = []string{"sh"} },
		"environment":  func(value *containerInspection) { value.Config.Env = append(value.Config.Env, "TOKEN=secret") },
		"mount":        func(value *containerInspection) { value.HostConfig.Mounts[0].ReadOnly = false },
		"logging":      func(value *containerInspection) { value.HostConfig.LogConfig.Type = "json-file" },
		"runtime":      func(value *containerInspection) { value.HostConfig.Runtime = "runc" },
		"network":      func(value *containerInspection) { value.NetworkSettings.Networks["bridge"] = json.RawMessage(`{}`) },
		"restart":      func(value *containerInspection) { value.RestartCount = 1 },
		"paused":       func(value *containerInspection) { value.State.Paused = true },
		"native error": func(value *containerInspection) { value.State.Error = "native-secret" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			plan := testStepPlan(t)
			engine := newStepEngine(t, plan)
			engine.present = true
			engine.state = StepCreated
			engine.mutateInspection = mutate
			client := testStepClient(t, engine)
			state, err := client.ObserveStep(context.Background(), plan)
			if state != "" || !errors.Is(err, ErrStepConflict) ||
				strings.Contains(err.Error(), "native-secret") {
				t.Fatalf("state = %q / %v", state, err)
			}
			if engine.killed || engine.deleted {
				t.Fatalf("observe changed container: killed=%v deleted=%v", engine.killed, engine.deleted)
			}
		})
	}
}

func TestCreateCleansUpContainerThatCannotBeProvedExact(t *testing.T) {
	plan := testStepPlan(t)
	engine := newStepEngine(t, plan)
	engine.mutateInspection = func(value *containerInspection) {
		value.HostConfig.Runtime = "runc"
	}
	err := testStepClient(t, engine).CreateStep(context.Background(), plan)
	if !errors.Is(err, ErrStepOutcomeUnknown) || !errors.Is(err, ErrStepConflict) ||
		!engine.deleted || engine.present {
		t.Fatalf("error = %v, deleted = %v, present = %v", err, engine.deleted, engine.present)
	}
}

func TestStepLifecycleRejectsContainerReplacementAcrossEffect(t *testing.T) {
	tests := []struct {
		name    string
		initial StepState
		invoke  func(*Client, ContainerPlan) error
	}{
		{
			name: "start", initial: StepCreated,
			invoke: func(client *Client, plan ContainerPlan) error {
				return client.StartStep(context.Background(), plan)
			},
		},
		{
			name: "follow", initial: StepRunning,
			invoke: func(client *Client, plan ContainerPlan) error {
				_, err := client.FollowStep(context.Background(), plan, NewLogBudget())
				return err
			},
		},
		{
			name: "cancel", initial: StepRunning,
			invoke: func(client *Client, plan ContainerPlan) error {
				_, err := client.CancelStep(context.Background(), plan)
				return err
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			plan := testStepPlan(t)
			engine := newStepEngine(t, plan)
			engine.present = true
			engine.state = test.initial
			inspections := 0
			engine.mutateInspection = func(value *containerInspection) {
				inspections++
				if inspections == 2 {
					value.ID = strings.Repeat("b", 64)
				}
			}
			err := test.invoke(testStepClient(t, engine), plan)
			if !errors.Is(err, ErrStepOutcomeUnknown) {
				t.Fatalf("error = %v", err)
			}
		})
	}

	t.Run("delete", func(t *testing.T) {
		plan := testStepPlan(t)
		engine := newStepEngine(t, plan)
		engine.present = true
		engine.state = StepPassed
		engine.replaceAfterDelete = true
		err := testStepClient(t, engine).DeleteStep(context.Background(), plan)
		if !errors.Is(err, ErrStepOutcomeUnknown) || !engine.deleted || !engine.present {
			t.Fatalf("error = %v, deleted = %v, present = %v", err, engine.deleted, engine.present)
		}
	})
}

func TestStepMutationsPreserveAmbiguousTransportOutcome(t *testing.T) {
	tests := []struct {
		name    string
		initial StepState
		method  string
		path    func(ContainerPlan, string) string
		invoke  func(*Client, ContainerPlan) error
	}{
		{
			name: "create", method: http.MethodPost,
			path: func(plan ContainerPlan, _ string) string { return "/v1.46/containers/create" },
			invoke: func(client *Client, plan ContainerPlan) error {
				return client.CreateStep(context.Background(), plan)
			},
		},
		{
			name: "start", initial: StepCreated, method: http.MethodPost,
			path: func(_ ContainerPlan, id string) string { return startPath(id) },
			invoke: func(client *Client, plan ContainerPlan) error {
				return client.StartStep(context.Background(), plan)
			},
		},
		{
			name: "kill", initial: StepRunning, method: http.MethodPost,
			path: func(_ ContainerPlan, id string) string { return "/v1.46/containers/" + id + "/kill" },
			invoke: func(client *Client, plan ContainerPlan) error {
				_, err := client.CancelStep(context.Background(), plan)
				return err
			},
		},
		{
			name: "delete", initial: StepPassed, method: http.MethodDelete,
			path: func(_ ContainerPlan, id string) string { return "/v1.46/containers/" + id },
			invoke: func(client *Client, plan ContainerPlan) error {
				return client.DeleteStep(context.Background(), plan)
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			plan := testStepPlan(t)
			engine := newStepEngine(t, plan)
			if test.initial != "" {
				engine.present = true
				engine.state = test.initial
			}
			engine.failMethod = test.method
			engine.failPath = test.path(plan, engine.id)
			err := test.invoke(testStepClient(t, engine), plan)
			if !errors.Is(err, ErrStepOutcomeUnknown) ||
				strings.Contains(err.Error(), "daemon-native-secret") {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestStepLogsFailClosedAndPoisonPartialBudget(t *testing.T) {
	tests := []struct {
		name          string
		logs          []byte
		contentLength func([]byte) int64
		want          error
	}{
		{
			name:          "truncated multiplex frame",
			logs:          []byte{stdoutStream, 0, 0},
			contentLength: func(content []byte) int64 { return int64(len(content)) },
			want:          ErrLogInvalid,
		},
		{
			name:          "declared length mismatch",
			logs:          dockerLogStream(logFrame{stream: stdoutStream, content: []byte("safe\n")}),
			contentLength: func(content []byte) int64 { return int64(len(content) + 1) },
			want:          ErrUnavailable,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			plan := testStepPlan(t)
			engine := newStepEngine(t, plan)
			engine.present = true
			engine.state = StepPassed
			engine.logs = test.logs
			length := test.contentLength(test.logs)
			engine.logContentLength = &length
			budget := NewLogBudget()
			result, err := testStepClient(t, engine).FollowStep(context.Background(), plan, budget)
			if result.State != "" || result.Chunks != nil || !errors.Is(err, test.want) {
				t.Fatalf("result = %#v / %v", result, err)
			}
			if chunks, reuseErr := budget.DecodeDockerStream(bytes.NewReader(dockerLogStream(
				logFrame{stream: stdoutStream, content: []byte("must not resume\n")},
			))); len(chunks) != 0 || !errors.Is(reuseErr, ErrLogInvalid) {
				t.Fatalf("reused chunks = %#v / %v", chunks, reuseErr)
			}
		})
	}
}

func TestDeleteRejectsRunningContainerWithoutMutation(t *testing.T) {
	plan := testStepPlan(t)
	engine := newStepEngine(t, plan)
	engine.present = true
	engine.state = StepRunning
	err := testStepClient(t, engine).DeleteStep(context.Background(), plan)
	if !errors.Is(err, ErrStepConflict) || engine.deleted || !engine.present {
		t.Fatalf("error = %v, deleted = %v, present = %v", err, engine.deleted, engine.present)
	}
}

func TestDeleteDoesNotBecomeCancellationWhenContainerStartsAfterInspection(t *testing.T) {
	plan := testStepPlan(t)
	engine := newStepEngine(t, plan)
	engine.present = true
	engine.state = StepPassed
	engine.mutateInspection = func(*containerInspection) {
		engine.state = StepRunning
	}
	err := testStepClient(t, engine).DeleteStep(context.Background(), plan)
	if !errors.Is(err, ErrStepConflict) || engine.deleted || !engine.present {
		t.Fatalf("error = %v, deleted = %v, present = %v", err, engine.deleted, engine.present)
	}
	foundNonForcedDelete := false
	for _, call := range engine.calls {
		if strings.HasPrefix(call, "DELETE ") && strings.Contains(call, "force=false") {
			foundNonForcedDelete = true
		}
	}
	if !foundNonForcedDelete {
		t.Fatalf("calls = %#v", engine.calls)
	}
}

func TestFailureCleanupSurvivesCallerCancellationWithFixedDeadline(t *testing.T) {
	parent, cancelParent := context.WithCancel(context.Background())
	cancelParent()
	started := time.Now()
	cleanupContext, cancelCleanup := boundedCleanupContext(parent)
	defer cancelCleanup()
	deadline, bounded := cleanupContext.Deadline()
	if cleanupContext.Err() != nil || !bounded || deadline.Before(started) ||
		deadline.After(started.Add(cleanupTimeout+time.Second)) {
		t.Fatalf("cleanup context: error=%v bounded=%v deadline=%v", cleanupContext.Err(), bounded, deadline)
	}
}

type stepEngine struct {
	t                  *testing.T
	plan               ContainerPlan
	id                 string
	present            bool
	state              StepState
	exitCode           int64
	nextExitCode       int64
	oomKilled          bool
	oomOnExit          bool
	logs               []byte
	logContentLength   *int64
	mutateInspection   func(*containerInspection)
	failMethod         string
	failPath           string
	calls              []string
	killed             bool
	deleted            bool
	replaceAfterDelete bool
}

func newStepEngine(t *testing.T, plan ContainerPlan) *stepEngine {
	t.Helper()
	return &stepEngine{
		t: t, plan: plan, id: strings.Repeat("a", 64), state: StepCreated,
		logs: dockerLogStream(logFrame{stream: stdoutStream, content: []byte("ok\n")}),
	}
}

func (engine *stepEngine) RoundTrip(request *http.Request) (*http.Response, error) {
	engine.t.Helper()
	engine.assertRequest(request)
	engine.calls = append(engine.calls, request.Method+" "+request.URL.EscapedPath()+querySuffix(request))
	if request.Method == engine.failMethod && request.URL.Path == engine.failPath {
		return nil, errors.New("daemon-native-secret")
	}

	containerPrefix := "/v1.46/containers/"
	switch {
	case request.Method == http.MethodPost && request.URL.Path == "/v1.46/containers/create":
		if request.URL.Query().Get("name") != engine.plan.Name() || len(request.URL.Query()) != 1 {
			engine.t.Fatalf("create query = %q", request.URL.RawQuery)
		}
		content, err := io.ReadAll(request.Body)
		if err != nil {
			engine.t.Fatal(err)
		}
		want, err := engine.plan.MarshalJSON()
		if err != nil || !bytes.Equal(content, want) {
			engine.t.Fatalf("create content = %s / %v, want %s", content, err, want)
		}
		if engine.present {
			return jsonResponse(engine.t, http.StatusConflict, map[string]string{"message": "native-secret"}), nil
		}
		engine.present = true
		engine.state = StepCreated
		return jsonResponse(engine.t, http.StatusCreated, createResponse{ID: engine.id, Warnings: []string{}}), nil

	case request.Method == http.MethodGet && strings.HasSuffix(request.URL.Path, "/json"):
		if request.URL.Query().Get("size") != "false" || len(request.URL.Query()) != 1 {
			engine.t.Fatalf("inspect query = %q", request.URL.RawQuery)
		}
		reference := strings.TrimSuffix(strings.TrimPrefix(request.URL.Path, containerPrefix), "/json")
		if reference != engine.id && reference != engine.plan.Name() {
			engine.t.Fatalf("inspect reference = %q", reference)
		}
		if !engine.present {
			return jsonResponse(engine.t, http.StatusNotFound, map[string]string{"message": "native-secret"}), nil
		}
		return jsonResponse(engine.t, http.StatusOK, engine.inspection()), nil

	case request.Method == http.MethodPost && request.URL.Path == startPath(engine.id):
		if !engine.present {
			return jsonResponse(engine.t, http.StatusNotFound, map[string]string{"message": "native-secret"}), nil
		}
		if engine.state != StepCreated {
			return emptyResponse(http.StatusNotModified), nil
		}
		engine.state = StepRunning
		return emptyResponse(http.StatusNoContent), nil

	case request.Method == http.MethodGet && request.URL.Path == containerPrefix+engine.id+"/logs":
		query := request.URL.Query()
		if len(query) != 5 || query.Get("stderr") != "true" || query.Get("stdout") != "true" ||
			query.Get("tail") != "all" || query.Get("timestamps") != "false" ||
			(query.Get("follow") != "true" && query.Get("follow") != "false") {
			engine.t.Fatalf("logs query = %q", request.URL.RawQuery)
		}
		if !engine.present {
			return jsonResponse(engine.t, http.StatusNotFound, map[string]string{"message": "native-secret"}), nil
		}
		if query.Get("follow") == "true" {
			if engine.state != StepRunning {
				engine.t.Fatalf("followed state = %q", engine.state)
			}
			engine.exitCode = engine.nextExitCode
			engine.oomKilled = engine.oomOnExit
			if engine.exitCode == 0 {
				engine.state = StepPassed
			} else {
				engine.state = StepFailed
			}
		}
		length := int64(len(engine.logs))
		if engine.logContentLength != nil {
			length = *engine.logContentLength
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header: http.Header{
				"Content-Type": []string{"application/vnd.docker.raw-stream"},
			},
			Body: io.NopCloser(bytes.NewReader(engine.logs)), ContentLength: length,
		}, nil

	case request.Method == http.MethodPost && request.URL.Path == containerPrefix+engine.id+"/wait":
		if request.URL.Query().Get("condition") != "not-running" || len(request.URL.Query()) != 1 {
			engine.t.Fatalf("wait query = %q", request.URL.RawQuery)
		}
		if !engine.present {
			return jsonResponse(engine.t, http.StatusNotFound, map[string]string{"message": "native-secret"}), nil
		}
		if engine.state != StepPassed && engine.state != StepFailed {
			engine.t.Fatalf("waited state = %q", engine.state)
		}
		return jsonResponse(engine.t, http.StatusOK, waitResponse{StatusCode: engine.exitCode}), nil

	case request.Method == http.MethodPost && request.URL.Path == containerPrefix+engine.id+"/kill":
		if request.URL.Query().Get("signal") != "SIGKILL" || len(request.URL.Query()) != 1 {
			engine.t.Fatalf("kill query = %q", request.URL.RawQuery)
		}
		if !engine.present {
			return jsonResponse(engine.t, http.StatusNotFound, map[string]string{"message": "native-secret"}), nil
		}
		if engine.state != StepRunning {
			return jsonResponse(engine.t, http.StatusConflict, map[string]string{"message": "native-secret"}), nil
		}
		engine.killed = true
		engine.state = StepFailed
		engine.exitCode = 137
		return emptyResponse(http.StatusNoContent), nil

	case request.Method == http.MethodDelete && request.URL.Path == containerPrefix+engine.id:
		query := request.URL.Query()
		if (query.Get("force") != "true" && query.Get("force") != "false") ||
			query.Get("v") != "true" || len(query) != 2 {
			engine.t.Fatalf("delete query = %q", request.URL.RawQuery)
		}
		if !engine.present {
			return jsonResponse(engine.t, http.StatusNotFound, map[string]string{"message": "native-secret"}), nil
		}
		if engine.state == StepRunning && query.Get("force") == "false" {
			return jsonResponse(engine.t, http.StatusConflict, map[string]string{"message": "native-secret"}), nil
		}
		engine.present = false
		engine.deleted = true
		if engine.replaceAfterDelete {
			engine.id = strings.Repeat("b", 64)
			engine.present = true
			engine.state = StepCreated
			engine.exitCode = 0
		}
		return emptyResponse(http.StatusNoContent), nil
	default:
		engine.t.Fatalf("unexpected Docker request: %s %s", request.Method, request.URL.String())
		return nil, nil
	}
}

func (engine *stepEngine) assertRequest(request *http.Request) {
	engine.t.Helper()
	wantAccept := "application/json"
	if strings.HasSuffix(request.URL.Path, "/logs") {
		wantAccept = "application/vnd.docker.raw-stream"
	}
	if request.URL.Scheme != "http" || request.URL.Host != "matrix-docker-engine" ||
		request.Header.Get("Accept") != wantAccept ||
		request.Header.Get("User-Agent") != "matrix-devops-runner/v1" ||
		request.Header.Get("Authorization") != "" || request.Header.Get("Cookie") != "" {
		engine.t.Fatalf("unsafe request metadata: %#v", request)
	}
	if request.Method == http.MethodPost && request.URL.Path == "/v1.46/containers/create" {
		if request.Header.Get("Content-Type") != "application/json" || request.ContentLength <= 0 {
			engine.t.Fatalf("create headers = %#v", request.Header)
		}
	} else if request.Header.Get("Content-Type") != "" || request.ContentLength != 0 {
		engine.t.Fatalf("unexpected empty-request metadata: %#v", request.Header)
	}
}

func (engine *stepEngine) inspection() containerInspection {
	engine.t.Helper()
	content, err := json.Marshal(engine.plan.request)
	if err != nil {
		engine.t.Fatal(err)
	}
	var request containerCreateRequest
	if err := json.Unmarshal(content, &request); err != nil {
		engine.t.Fatal(err)
	}
	var value containerInspection
	if err := json.Unmarshal(content, &value.Config); err != nil {
		engine.t.Fatal(err)
	}
	value.ID = engine.id
	value.Name = "/" + engine.plan.Name()
	value.Image = ToolchainImageID
	value.HostConfig = request.HostConfig
	value.NetworkSettings.Networks = map[string]json.RawMessage{"none": json.RawMessage(`{}`)}
	value.State.ExitCode = engine.exitCode
	value.State.OOMKilled = engine.oomKilled
	switch engine.state {
	case StepCreated:
		value.State.Status = "created"
	case StepRunning:
		value.State.Status = "running"
		value.State.Running = true
		value.State.PID = 42
	case StepPassed, StepFailed:
		value.State.Status = "exited"
	default:
		engine.t.Fatalf("invalid fake state %q", engine.state)
	}
	if engine.mutateInspection != nil {
		engine.mutateInspection(&value)
	}
	return value
}

func testStepPlan(t *testing.T) ContainerPlan {
	t.Helper()
	plan, err := NewStepPlan(
		"matrix-build-"+strings.Repeat("1", 48),
		devopsv1.VerificationStep{Ordinal: 1, Kind: devopsv1.VerificationStepGoTest},
		"/var/lib/matrix/runner/work/source",
	)
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func testStepClient(t *testing.T, engine *stepEngine) *Client {
	t.Helper()
	client, err := newClient(
		&http.Client{Transport: engine}, "/var/lib/matrix/runner",
		func(string) (uint64, error) { return minimumStorageBytes, nil },
	)
	if err != nil {
		t.Fatal(err)
	}
	return client
}
