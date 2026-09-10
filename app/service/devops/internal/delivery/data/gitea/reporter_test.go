package gitea

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	devopsbuildv1 "github.com/xiak/matrix/api/adapter/devopsbuild/v1"
	devopsv1 "github.com/xiak/matrix/api/devops/v1"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/domain"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/usecase/checkreporting"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/usecase/runlifecycle"
	"github.com/xiak/matrix/app/service/devops/sourcecredential"
)

const checkReporterToken = "reporter-token-00000000000000000001"

func TestCheckReporterCreatesExactTerminalStatus(t *testing.T) {
	var command checkreporting.Command
	requests := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		requests++
		if request.Method != http.MethodPost || request.URL.Path != mustCheckStatusPath(t, command) ||
			request.URL.RawQuery != "" || request.Header.Get("Accept") != "application/json" ||
			request.Header.Get("Content-Type") != "application/json" ||
			request.Header.Get("Authorization") != "token "+checkReporterToken {
			t.Errorf("request method=%s url=%s headers=%v", request.Method, request.URL, request.Header)
		}
		content, err := io.ReadAll(io.LimitReader(request.Body, maximumResponseBody+1))
		if err != nil {
			t.Errorf("read request: %v", err)
		}
		expected, _ := checkStatusDocument(command)
		expectedContent, _ := json.Marshal(expected)
		if string(content) != string(expectedContent) {
			t.Errorf("body=%s want=%s", content, expectedContent)
		}
		writeCheckStatus(response, request, expected, 7)
	}))
	defer server.Close()
	command = reporterCommand(
		t, server.URL, runlifecycle.ClaimExecute, false,
		devopsbuildv1.ConclusionPassed,
	)
	reporter := checkReporterForServer(t, server, staticCredentialResolver{
		purpose: sourcecredential.PurposeReport, value: checkReporterToken,
	})

	receipt, err := reporter.Create(context.Background(), command)
	if err != nil || requests != 1 || receipt.ProviderStatusID != 7 ||
		checkreporting.ValidateReceipt(command, receipt) != nil {
		t.Fatalf("receipt=%#v err=%v requests=%d", receipt, err, requests)
	}
}

func TestCheckReporterObservesNewestFixedWindowWithoutCreating(t *testing.T) {
	var command checkreporting.Command
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet || request.URL.Path != mustCheckStatusPath(t, command) ||
			request.URL.RawQuery != "limit=50&page=1&sort=leastindex" ||
			request.Header.Get("Authorization") != "token "+checkReporterToken ||
			request.ContentLength != 0 {
			t.Errorf("request method=%s url=%s headers=%v", request.Method, request.URL, request.Header)
		}
		expected, _ := checkStatusDocument(command)
		writeCheckStatuses(response, request, []checkStatus{
			checkStatusFor(request, createCheckStatus{
				Context: "other/check", Description: "unrelated", State: checkreporting.CheckSuccess,
			}, 10),
			checkStatusFor(request, expected, 9),
		})
	}))
	defer server.Close()
	command = reporterCommand(
		t, server.URL, runlifecycle.ClaimObserve, false,
		devopsbuildv1.ConclusionPassed,
	)
	reporter := checkReporterForServer(t, server, staticCredentialResolver{
		purpose: sourcecredential.PurposeReport, value: checkReporterToken,
	})

	receipt, found, err := reporter.Observe(context.Background(), command)
	if err != nil || !found || receipt.ProviderStatusID != 9 ||
		checkreporting.ValidateReceipt(command, receipt) != nil {
		t.Fatalf("receipt=%#v found=%t err=%v", receipt, found, err)
	}
}

func TestCheckReporterObservationDistinguishesAbsenceAndConflict(t *testing.T) {
	tests := []struct {
		name      string
		statuses  func(*http.Request, createCheckStatus) []checkStatus
		wantFound bool
		wantErr   error
	}{
		{
			name: "absent",
			statuses: func(request *http.Request, _ createCheckStatus) []checkStatus {
				return []checkStatus{checkStatusFor(request, createCheckStatus{
					Context: "other/check", Description: "unrelated", State: checkreporting.CheckSuccess,
				}, 7)}
			},
		},
		{
			name: "changed",
			statuses: func(request *http.Request, expected createCheckStatus) []checkStatus {
				expected.Description = "changed"
				return []checkStatus{checkStatusFor(request, expected, 7)}
			},
			wantErr: checkreporting.ErrReportConflict,
		},
		{
			name: "duplicate",
			statuses: func(request *http.Request, expected createCheckStatus) []checkStatus {
				return []checkStatus{
					checkStatusFor(request, expected, 8),
					checkStatusFor(request, expected, 7),
				}
			},
			wantErr: checkreporting.ErrReportConflict,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var command checkreporting.Command
			server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				expected, _ := checkStatusDocument(command)
				writeCheckStatuses(response, request, test.statuses(request, expected))
			}))
			defer server.Close()
			command = reporterCommand(
				t, server.URL, runlifecycle.ClaimObserve, true,
				devopsbuildv1.ConclusionPassed,
			)
			reporter := checkReporterForServer(t, server, staticCredentialResolver{
				purpose: sourcecredential.PurposeReport, value: checkReporterToken,
			})

			receipt, found, err := reporter.Observe(context.Background(), command)
			if found != test.wantFound || !errors.Is(err, test.wantErr) ||
				!found && receipt != (checkreporting.Receipt{}) {
				t.Fatalf("receipt=%#v found=%t err=%v", receipt, found, err)
			}
		})
	}
}

func TestCheckReporterNormalizesDefinitiveAndUncertainCreateFailures(t *testing.T) {
	tests := []struct {
		name        string
		status      int
		body        string
		contentType string
		wantErr     error
	}{
		{"bad request", http.StatusBadRequest, `{}`, "application/json", checkreporting.ErrReportUnavailable},
		{"unauthorized", http.StatusUnauthorized, `{}`, "application/json", checkreporting.ErrReportUnavailable},
		{"forbidden", http.StatusForbidden, `{}`, "application/json", checkreporting.ErrReportUnavailable},
		{"missing", http.StatusNotFound, `{}`, "application/json", checkreporting.ErrReportUnavailable},
		{"unprocessable", http.StatusUnprocessableEntity, `{}`, "application/json", checkreporting.ErrReportUnavailable},
		{"server failure", http.StatusInternalServerError, `{}`, "application/json", checkreporting.ErrOutcomeUnknown},
		{"malformed success", http.StatusCreated, `{"id":7}`, "application/json", checkreporting.ErrOutcomeUnknown},
		{"wrong media", http.StatusCreated, `{}`, "text/plain", checkreporting.ErrOutcomeUnknown},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
				response.Header().Set("Content-Type", test.contentType)
				response.WriteHeader(test.status)
				_, _ = io.WriteString(response, test.body)
			}))
			defer server.Close()
			command := reporterCommand(
				t, server.URL, runlifecycle.ClaimExecute, false,
				devopsbuildv1.ConclusionPassed,
			)
			reporter := checkReporterForServer(t, server, staticCredentialResolver{
				purpose: sourcecredential.PurposeReport, value: checkReporterToken,
			})

			_, err := reporter.Create(context.Background(), command)
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("error=%v want=%v", err, test.wantErr)
			}
		})
	}
}

func TestCheckReporterContainsCredentialAndTransportFailures(t *testing.T) {
	requests := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		requests++
	}))
	defer server.Close()
	command := reporterCommand(
		t, server.URL, runlifecycle.ClaimExecute, false,
		devopsbuildv1.ConclusionPassed,
	)
	secret := "private-path-and-token-must-not-escape"
	reporter := checkReporterForServer(t, server, staticCredentialResolver{
		purpose: sourcecredential.PurposeReport, err: errors.New(secret),
	})
	if _, err := reporter.Create(context.Background(), command); !errors.Is(err, checkreporting.ErrReportUnavailable) ||
		strings.Contains(err.Error(), secret) || requests != 0 {
		t.Fatalf("credential error=%v requests=%d", err, requests)
	}

	redirected := 0
	redirectServer := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/redirected" {
			redirected++
			return
		}
		http.Redirect(response, request, "/redirected", http.StatusFound)
	}))
	defer redirectServer.Close()
	command = reporterCommand(
		t, redirectServer.URL, runlifecycle.ClaimExecute, false,
		devopsbuildv1.ConclusionPassed,
	)
	reporter = checkReporterForServer(t, redirectServer, staticCredentialResolver{
		purpose: sourcecredential.PurposeReport, value: checkReporterToken,
	})
	if _, err := reporter.Create(context.Background(), command); !errors.Is(err, checkreporting.ErrOutcomeUnknown) ||
		redirected != 0 {
		t.Fatalf("redirect error=%v redirected=%d", err, redirected)
	}
}

func TestCheckReporterDeadlineAndOperationModeFailClosed(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		timer := time.NewTimer(100 * time.Millisecond)
		defer timer.Stop()
		select {
		case <-request.Context().Done():
			return
		case <-timer.C:
			response.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer server.Close()
	reporter := checkReporterForServer(t, server, staticCredentialResolver{
		purpose: sourcecredential.PurposeReport, value: checkReporterToken,
	})
	command := reporterCommand(
		t, server.URL, runlifecycle.ClaimExecute, false,
		devopsbuildv1.ConclusionPassed,
	)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if _, err := reporter.Create(ctx, command); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("deadline error=%v", err)
	}

	observe := command
	observe.Lease.Mode = runlifecycle.ClaimObserve
	observe.Lease.FencingToken = 2
	if _, err := reporter.Create(context.Background(), observe); !errors.Is(err, checkreporting.ErrReportUnavailable) {
		t.Fatalf("observe create error=%v", err)
	}
	if _, _, err := reporter.Observe(context.Background(), command); !errors.Is(err, checkreporting.ErrReportUnavailable) {
		t.Fatalf("execute observe error=%v", err)
	}
}

func TestCheckReporterRejectsOpenConfiguration(t *testing.T) {
	client := &http.Client{
		Transport: http.DefaultTransport,
		Timeout:   checkreporting.ProviderDeadline,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("redirect rejected")
		},
	}
	resolver := staticCredentialResolver{
		purpose: sourcecredential.PurposeReport, value: checkReporterToken,
	}
	if _, err := NewCheckReporter(nil, staticTrustResolver{}); err == nil {
		t.Fatal("nil credential resolver was accepted")
	}
	client.Timeout++
	if _, err := newCheckReporter(resolver, client); err == nil {
		t.Fatal("open HTTP deadline was accepted")
	}
}

func checkReporterForServer(
	t *testing.T,
	server *httptest.Server,
	resolver CredentialResolver,
) *CheckReporter {
	t.Helper()
	client := server.Client()
	client.Timeout = checkreporting.ProviderDeadline
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return errors.New("redirect rejected")
	}
	reporter, err := newCheckReporter(resolver, client)
	if err != nil {
		t.Fatal(err)
	}
	return reporter
}

func writeCheckStatus(
	response http.ResponseWriter,
	request *http.Request,
	document createCheckStatus,
	id int64,
) {
	response.Header().Set("Content-Type", "application/json; charset=utf-8")
	response.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(response).Encode(checkStatusFor(request, document, id))
}

func writeCheckStatuses(
	response http.ResponseWriter,
	request *http.Request,
	statuses []checkStatus,
) {
	response.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(response).Encode(statuses)
}

func checkStatusFor(
	request *http.Request,
	document createCheckStatus,
	id int64,
) checkStatus {
	observedAt := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC).Format(time.RFC3339Nano)
	return checkStatus{
		ID: id, Status: string(document.State), TargetURL: document.TargetURL,
		Description: document.Description, URL: serverURL(request) + request.URL.Path,
		Context: document.Context, Creator: json.RawMessage(`{"id":1,"login":"matrix"}`),
		CreatedAt: observedAt, UpdatedAt: observedAt,
	}
}

func mustCheckStatusPath(t *testing.T, command checkreporting.Command) string {
	t.Helper()
	path, err := checkStatusPath(command)
	if err != nil {
		t.Fatal(err)
	}
	return path
}

func reporterCommand(
	t *testing.T,
	endpointOrigin string,
	mode runlifecycle.ClaimMode,
	reconciled bool,
	conclusion devopsbuildv1.Conclusion,
) checkreporting.Command {
	t.Helper()
	source := fetchCommand(
		t, endpointOrigin, strings.Repeat("1", 40), strings.Repeat("2", 40),
	)
	run := source.Lease.Run
	var err error
	for _, state := range []devopsv1.PipelineRunState{
		devopsv1.PipelineRunVerifying,
		devopsv1.PipelineRunReporting,
	} {
		run, err = domain.AdvancePipelineRun(run, state, "", run.UpdatedAt.Add(time.Microsecond))
		if err != nil {
			t.Fatal(err)
		}
	}
	if reconciled {
		run, err = domain.AdvancePipelineRun(
			run,
			devopsv1.PipelineRunReconciling,
			devopsv1.PipelineRunReasonExternalEffectUncertain,
			run.UpdatedAt.Add(time.Microsecond),
		)
		if err != nil {
			t.Fatal(err)
		}
	}
	steps := devopsv1.FixedVerificationSteps()
	stepConclusions := [2]devopsbuildv1.StepConclusion{
		devopsbuildv1.StepConclusionPassed,
		devopsbuildv1.StepConclusionPassed,
	}
	if conclusion == devopsbuildv1.ConclusionFailed {
		stepConclusions[1] = devopsbuildv1.StepConclusionFailed
	}
	buildReceipt := devopsbuildv1.Receipt{
		TenantID: run.Scope.TenantID, RunID: run.ID,
		CommandID:              runlifecycle.TaskCommandID(run.ID, devopsv1.PipelineRunStageVerify, 1),
		InputDigest:            run.InputDigest,
		SourceArchiveDigest:    "sha256:" + strings.Repeat("6", 64),
		PipelineRevisionID:     source.Revision.ID,
		PipelineRevisionDigest: source.Revision.ContentDigest,
		ExecutorID:             "executor-one",
		ExecutorProfile:        devopsv1.ExecutorMatrixNativeIsolatedV1,
		ToolchainImageDigest:   devopsv1.Go126OfflineToolchainImageDigest,
		Conclusion:             conclusion,
		Steps: [2]devopsbuildv1.StepReceipt{
			{Ordinal: steps[0].Ordinal, Kind: steps[0].Kind, Conclusion: stepConclusions[0]},
			{Ordinal: steps[1].Ordinal, Kind: steps[1].Kind, Conclusion: stepConclusions[1]},
		},
	}
	buildReceipt.ContentDigest = devopsbuildv1.DigestReceipt(buildReceipt)
	intent := runlifecycle.TaskIntent{
		RunID: run.ID, InputDigest: run.InputDigest,
		Stage: devopsv1.PipelineRunStageReport, Attempt: 1,
	}
	intent.CommandID = runlifecycle.TaskCommandID(intent.RunID, intent.Stage, intent.Attempt)
	fence := uint64(1)
	if mode == runlifecycle.ClaimObserve {
		fence = 2
	}
	attempts := uint64(0)
	if reconciled {
		attempts = 1
	}
	command := checkreporting.Command{
		Lease: runlifecycle.Lease{
			TenantID: run.Scope.TenantID, Run: run, Intent: intent, Mode: mode,
			WorkerID: "check-reporter-one", FencingToken: fence,
			LeaseExpiresAt:         run.UpdatedAt.Add(checkreporting.LeaseDuration),
			ReconciliationAttempts: attempts,
		},
		Connection: source.Connection, BindingRevision: source.BindingRevision,
		Revision: source.Revision, BuildReceipt: buildReceipt,
	}
	if err := checkreporting.ValidateCommand(command); err != nil {
		t.Fatal(err)
	}
	return command
}
