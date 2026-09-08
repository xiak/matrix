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
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func TestPreflightProvesPinnedHostAndIsolationBeforeEligibility(t *testing.T) {
	containerID := strings.Repeat("a", 64)
	var calls []string
	var probeRequest containerCreateRequest
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		assertEngineHeaders(t, request)
		calls = append(calls, request.Method+" "+request.URL.EscapedPath()+querySuffix(request))
		switch {
		case request.Method == http.MethodGet && request.URL.Path == versionPath():
			return jsonResponse(t, http.StatusOK, map[string]any{
				"Version": "29.6.2", "ApiVersion": "1.55", "MinAPIVersion": "1.40",
				"Os": "linux", "Arch": "amd64", "FutureField": true,
			}), nil
		case request.Method == http.MethodGet && request.URL.Path == infoPath():
			return jsonResponse(t, http.StatusOK, eligibleInfo()), nil
		case request.Method == http.MethodGet && strings.HasPrefix(request.URL.Path, "/v1.46/images/"):
			return jsonResponse(t, http.StatusOK, imageInspection{
				ID: devopsImageID(), RepoTags: []string{ToolchainImage}, RepoDigests: []string{ToolchainLocalDigest},
				OS: "linux", Architecture: "amd64",
			}), nil
		case request.Method == http.MethodPost && request.URL.Path == "/v1.46/containers/create":
			name := request.URL.Query().Get("name")
			plan, err := newProbePlan(name)
			if err != nil {
				t.Fatal(err)
			}
			want, err := plan.MarshalJSON()
			if err != nil {
				t.Fatal(err)
			}
			got, err := io.ReadAll(request.Body)
			if err != nil || !bytes.Equal(got, want) {
				t.Fatalf("create request mismatch: %v\nwant %s\n got %s", err, want, got)
			}
			if err := json.Unmarshal(got, &probeRequest); err != nil {
				t.Fatal(err)
			}
			return jsonResponse(t, http.StatusCreated, createResponse{ID: containerID, Warnings: []string{}}), nil
		case request.Method == http.MethodPost && request.URL.Path == startPath(containerID):
			return emptyResponse(http.StatusNoContent), nil
		case request.Method == http.MethodPost && request.URL.Path == "/v1.46/containers/"+containerID+"/wait":
			if request.URL.Query().Get("condition") != "not-running" {
				t.Fatalf("wait query = %q", request.URL.RawQuery)
			}
			return jsonResponse(t, http.StatusOK, waitResponse{StatusCode: 0}), nil
		case request.Method == http.MethodGet && request.URL.Path == "/v1.46/containers/"+containerID+"/json":
			if request.URL.Query().Get("size") != "false" {
				t.Fatalf("inspect query = %q", request.URL.RawQuery)
			}
			return jsonResponse(t, http.StatusOK, successfulProbeInspection(containerID, probeRequest)), nil
		case request.Method == http.MethodDelete && request.URL.Path == "/v1.46/containers/"+containerID:
			if request.URL.Query().Get("force") != "true" || request.URL.Query().Get("v") != "true" {
				t.Fatalf("delete query = %q", request.URL.RawQuery)
			}
			return emptyResponse(http.StatusNoContent), nil
		default:
			t.Fatalf("unexpected Docker request: %s %s", request.Method, request.URL.String())
			return nil, nil
		}
	})
	client, err := newClient(
		&http.Client{Transport: transport},
		"/var/lib/matrix/runner",
		func(root string) (uint64, error) {
			if root != "/var/lib/matrix/runner" {
				t.Fatalf("storage root = %q", root)
			}
			return minimumStorageBytes + 1, nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	report, err := client.Preflight(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !report.Eligible || report.Reason != "" || report.DockerVersion != "29.6.2" ||
		report.EngineAPIVersion != "1.55" || report.LogicalCPUs != 8 ||
		report.MemoryBytes != 16*1024*1024*1024 ||
		report.StorageFreeBytes != minimumStorageBytes+1 || report.ImageID != devopsImageID() {
		t.Fatalf("report = %#v", report)
	}
	if len(calls) != 8 || !strings.HasPrefix(calls[2], "GET /v1.46/images/") ||
		!strings.HasPrefix(calls[3], "POST /v1.46/containers/create?name=") ||
		calls[len(calls)-1] != "DELETE /v1.46/containers/"+containerID+"?force=true&v=true" {
		t.Fatalf("calls = %#v", calls)
	}
}

func TestToolchainImageAcceptsOnlyInstalledOfflineIdentity(t *testing.T) {
	tests := []struct {
		name  string
		value imageInspection
		want  bool
	}{
		{
			name: "Docker 29 containerd store",
			value: imageInspection{
				ID: ToolchainSourceID, RepoTags: []string{ToolchainImage}, RepoDigests: []string{ToolchainLocalDigest},
				OS: "linux", Architecture: "amd64",
			},
			want: true,
		},
		{
			name: "Docker 29 classic store",
			value: imageInspection{
				ID: ToolchainArchiveConfigID, RepoTags: []string{ToolchainImage}, RepoDigests: []string{},
				OS: "linux", Architecture: "amd64",
			},
			want: true,
		},
		{
			name: "remote source reference",
			value: imageInspection{
				ID:          ToolchainSourceID,
				RepoTags:    []string{"golang:1.26"},
				RepoDigests: []string{"golang@" + ToolchainSourceID},
				OS:          "linux", Architecture: "amd64",
			},
		},
		{
			name: "additional mutable tag",
			value: imageInspection{
				ID: ToolchainSourceID, RepoTags: []string{ToolchainImage, "matrix.local/extra:latest"},
				RepoDigests: []string{}, OS: "linux", Architecture: "amd64",
			},
		},
		{
			name: "untrusted image identity",
			value: imageInspection{
				ID: "sha256:" + strings.Repeat("f", 64), RepoTags: []string{ToolchainImage}, RepoDigests: []string{},
				OS: "linux", Architecture: "amd64",
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := validToolchainImage(test.value); got != test.want {
				t.Fatalf("validToolchainImage(%#v) = %v, want %v", test.value, got, test.want)
			}
		})
	}
}

func TestPreflightFailsClosedBeforeProbeWhenRunscIsMissing(t *testing.T) {
	callCount := 0
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		callCount++
		switch request.URL.Path {
		case versionPath():
			return jsonResponse(t, http.StatusOK, daemonVersion{
				Version: "29.6.2", APIVersion: "1.55", MinAPIVersion: "1.40",
				OS: "linux", Arch: "amd64",
			}), nil
		case infoPath():
			info := eligibleInfo()
			delete(info.Runtimes, RuntimeName)
			return jsonResponse(t, http.StatusOK, info), nil
		default:
			t.Fatalf("request crossed missing-runtime fence: %s", request.URL.String())
			return nil, nil
		}
	})
	client, err := newClient(
		&http.Client{Transport: transport},
		"/var/lib/matrix/runner",
		func(string) (uint64, error) { t.Fatal("storage checked after missing runtime"); return 0, nil },
	)
	if err != nil {
		t.Fatal(err)
	}
	report, err := client.Preflight(context.Background())
	if !errors.Is(err, ErrIneligible) || report.Eligible || report.Reason != ReasonRuntime ||
		callCount != 2 {
		t.Fatalf("report = %#v, error = %v, calls = %d", report, err, callCount)
	}
}

func TestPreflightRejectsFailedIsolationAndStillDeletesProbe(t *testing.T) {
	containerID := strings.Repeat("b", 64)
	deleted := false
	var probeRequest containerCreateRequest
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		switch {
		case request.Method == http.MethodGet && request.URL.Path == versionPath():
			return jsonResponse(t, http.StatusOK, daemonVersion{Version: "29.6.2", APIVersion: "1.55", MinAPIVersion: "1.40", OS: "linux", Arch: "amd64"}), nil
		case request.Method == http.MethodGet && request.URL.Path == infoPath():
			return jsonResponse(t, http.StatusOK, eligibleInfo()), nil
		case request.Method == http.MethodGet && strings.HasPrefix(request.URL.Path, "/v1.46/images/"):
			return jsonResponse(t, http.StatusOK, imageInspection{ID: devopsImageID(), RepoTags: []string{ToolchainImage}, RepoDigests: []string{ToolchainLocalDigest}, OS: "linux", Architecture: "amd64"}), nil
		case request.Method == http.MethodPost && request.URL.Path == "/v1.46/containers/create":
			if err := json.NewDecoder(request.Body).Decode(&probeRequest); err != nil {
				t.Fatal(err)
			}
			return jsonResponse(t, http.StatusCreated, createResponse{ID: containerID, Warnings: []string{}}), nil
		case request.Method == http.MethodPost && request.URL.Path == startPath(containerID):
			return emptyResponse(http.StatusNoContent), nil
		case request.Method == http.MethodPost && request.URL.Path == "/v1.46/containers/"+containerID+"/wait":
			return jsonResponse(t, http.StatusOK, waitResponse{StatusCode: 0}), nil
		case request.Method == http.MethodGet && request.URL.Path == "/v1.46/containers/"+containerID+"/json":
			inspection := successfulProbeInspection(containerID, probeRequest)
			inspection.HostConfig.Runtime = "runc"
			return jsonResponse(t, http.StatusOK, inspection), nil
		case request.Method == http.MethodDelete && request.URL.Path == "/v1.46/containers/"+containerID:
			deleted = true
			return emptyResponse(http.StatusNoContent), nil
		default:
			t.Fatalf("unexpected request: %s %s", request.Method, request.URL.String())
			return nil, nil
		}
	})
	client, err := newClient(
		&http.Client{Transport: transport}, "/var/lib/matrix/runner",
		func(string) (uint64, error) { return minimumStorageBytes, nil },
	)
	if err != nil {
		t.Fatal(err)
	}
	report, err := client.Preflight(context.Background())
	if !errors.Is(err, ErrIneligible) || report.Reason != ReasonIsolation || !deleted {
		t.Fatalf("report = %#v, error = %v, deleted = %v", report, err, deleted)
	}
}

func TestIsolationProbeInspectionRejectsUnsafeTerminalMetadata(t *testing.T) {
	plan, err := newProbePlan("matrix-runner-isolation-probe-0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	containerID := strings.Repeat("c", 64)
	tests := map[string]func(*containerInspection){
		"restart count": func(value *containerInspection) { value.RestartCount = 1 },
		"restarting":    func(value *containerInspection) { value.State.Restarting = true },
		"out of memory": func(value *containerInspection) { value.State.OOMKilled = true },
		"live process":  func(value *containerInspection) { value.State.PID = 42 },
		"native error":  func(value *containerInspection) { value.State.Error = "native-secret" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			inspection := successfulProbeInspection(containerID, plan.request)
			mutate(&inspection)
			if validProbeInspection(inspection, containerID, plan.request) {
				t.Fatalf("unsafe probe inspection accepted: %#v", inspection.State)
			}
		})
	}
}

func TestIsolationProbeAcceptsBothAuthenticatedDockerStoreIdentities(t *testing.T) {
	plan, err := newProbePlan("matrix-runner-isolation-probe-0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	containerID := strings.Repeat("d", 64)
	for _, imageID := range []string{ToolchainSourceID, ToolchainArchiveConfigID} {
		inspection := successfulProbeInspection(containerID, plan.request)
		inspection.Image = imageID
		if !validProbeInspection(inspection, containerID, plan.request) {
			t.Fatalf("authenticated Docker image identity %q was rejected", imageID)
		}
	}
}

func TestEngineResponseValidationIsBoundedAndSanitized(t *testing.T) {
	transport := roundTripFunc(func(*http.Request) (*http.Response, error) {
		response := jsonResponse(t, http.StatusOK, daemonVersion{})
		response.Header.Set("Content-Type", "text/plain")
		return response, nil
	})
	client, err := newClient(
		&http.Client{Transport: transport}, "/var/lib/matrix/runner",
		func(string) (uint64, error) { return minimumStorageBytes, nil },
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Preflight(context.Background()); !errors.Is(err, ErrUnavailable) ||
		strings.Contains(err.Error(), "text/plain") {
		t.Fatalf("error = %v", err)
	}
}

func TestIsolationProbeCleansUpByRandomNameAfterCreateOutcomeAmbiguity(t *testing.T) {
	createdName := ""
	deletedName := ""
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		switch {
		case request.Method == http.MethodPost && request.URL.Path == "/v1.46/containers/create":
			createdName = request.URL.Query().Get("name")
			content := []byte("{")
			return &http.Response{
				StatusCode:    http.StatusCreated,
				Header:        http.Header{"Content-Type": []string{"application/json"}},
				Body:          io.NopCloser(bytes.NewReader(content)),
				ContentLength: int64(len(content)),
			}, nil
		case request.Method == http.MethodDelete:
			deletedName = strings.TrimPrefix(request.URL.Path, "/v1.46/containers/")
			return emptyResponse(http.StatusNoContent), nil
		default:
			t.Fatalf("unexpected request: %s %s", request.Method, request.URL.String())
			return nil, nil
		}
	})
	client, err := newClient(
		&http.Client{Transport: transport}, "/var/lib/matrix/runner",
		func(string) (uint64, error) { return minimumStorageBytes, nil },
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.runIsolationProbe(context.Background()); !errors.Is(err, ErrUnavailable) ||
		!validProbeName(createdName) || deletedName != createdName {
		t.Fatalf("created = %q, deleted = %q, error = %v", createdName, deletedName, err)
	}
}

func eligibleInfo() daemonInfo {
	return daemonInfo{
		NCPU: 8, MemTotal: 16 * 1024 * 1024 * 1024,
		MemoryLimit: true, SwapLimit: true, CPUCFSQuota: true, PidsLimit: true,
		OSType: "linux", Architecture: "x86_64",
		Runtimes: map[string]json.RawMessage{RuntimeName: json.RawMessage(`{"path":"runsc"}`)},
	}
}

func successfulProbeInspection(
	containerID string,
	request containerCreateRequest,
) containerInspection {
	var value containerInspection
	value.ID = containerID
	value.Image = devopsImageID()
	value.Config.Image = request.Image
	value.Config.Cmd = append([]string(nil), request.Cmd...)
	value.Config.Entrypoint = []string{}
	value.Config.Env = append([]string(nil), request.Env...)
	value.Config.User = request.User
	value.Config.WorkingDir = request.WorkingDir
	value.Config.NetworkDisabled = request.NetworkDisabled
	value.Config.AttachStdin = request.AttachStdin
	value.Config.AttachStdout = request.AttachStdout
	value.Config.AttachStderr = request.AttachStderr
	value.Config.OpenStdin = request.OpenStdin
	value.Config.StdinOnce = request.StdinOnce
	value.Config.Tty = request.Tty
	value.Config.Labels = request.Labels
	value.HostConfig = request.HostConfig
	value.State.Status = "exited"
	value.State.ExitCode = 0
	value.NetworkSettings.Networks = map[string]json.RawMessage{"none": json.RawMessage(`{}`)}
	return value
}

func assertEngineHeaders(t *testing.T, request *http.Request) {
	t.Helper()
	if request.URL.Scheme != "http" || request.URL.Host != "matrix-docker-engine" ||
		request.Header.Get("Accept") != "application/json" ||
		request.Header.Get("User-Agent") != "matrix-devops-runner/v1" ||
		request.Header.Get("Authorization") != "" || request.Header.Get("Cookie") != "" {
		t.Fatalf("unsafe request metadata: %#v", request)
	}
	if request.Method == http.MethodPost && request.URL.Path == "/v1.46/containers/create" {
		if request.Header.Get("Content-Type") != "application/json" || request.ContentLength <= 0 {
			t.Fatalf("create headers = %#v", request.Header)
		}
	} else if request.Header.Get("Content-Type") != "" || request.ContentLength != 0 {
		t.Fatalf("unexpected empty-request metadata: %#v", request.Header)
	}
}

func jsonResponse(t *testing.T, status int, value any) *http.Response {
	t.Helper()
	content, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Response{
		StatusCode:    status,
		Header:        http.Header{"Content-Type": []string{"application/json"}},
		Body:          io.NopCloser(bytes.NewReader(content)),
		ContentLength: int64(len(content)),
	}
}

func emptyResponse(status int) *http.Response {
	return &http.Response{
		StatusCode:    status,
		Header:        make(http.Header),
		Body:          io.NopCloser(strings.NewReader("")),
		ContentLength: 0,
	}
}

func querySuffix(request *http.Request) string {
	if request.URL.RawQuery == "" {
		return ""
	}
	return "?" + request.URL.RawQuery
}

func devopsImageID() string {
	return ToolchainSourceID
}
