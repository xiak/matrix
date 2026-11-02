package compose

import (
	"bytes"
	"context"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestContainerHTTPUsesOnlyExactContainerLoopbackAndPrivateStdin(t *testing.T) {
	request := ContainerHTTPRequest{ContainerID: strings.Repeat("a", 64), Port: 9200, Method: "POST",
		Path: "/_security/service/elastic/kibana/credential/token/matrix-owned", Authorization: "Basic dXNlcjpwYXNzd29yZA=="}
	status, body, err := requestContainerHTTP(t.Context(), request,
		func(ctx context.Context, input io.Reader, output io.Writer, arguments ...string) (bool, error) {
			if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > 10*time.Second {
				t.Fatal("native request is unbounded")
			}
			args := strings.Join(arguments, " ")
			if !strings.HasPrefix(args, "exec --interactive "+request.ContainerID+" curl --disable ") ||
				!strings.Contains(args, "--url http://127.0.0.1:9200"+request.Path) ||
				strings.Contains(args, request.Authorization) || strings.Contains(args, "--location") {
				t.Fatal("native request escaped its fixed loopback or disclosed authorization")
			}
			configuration, err := io.ReadAll(input)
			if err != nil || string(configuration) != "header = \"Authorization: "+request.Authorization+"\"\n" {
				t.Fatal("authorization was not supplied on private stdin")
			}
			clear(configuration)
			_, err = io.WriteString(output, "{\"created\":true}\n200")
			return true, err
		})
	if err != nil || status != 200 || string(body) != "{\"created\":true}" {
		t.Fatal("native response was not preserved")
	}
}

func TestContainerHTTPRejectsUnboundedSelectorsAndResponseLeaks(t *testing.T) {
	valid := ContainerHTTPRequest{ContainerID: strings.Repeat("a", 64), Port: 9200, Method: "GET", Path: "/_security/_authenticate", Authorization: "Bearer bounded-token"}
	for _, mutate := range []func(*ContainerHTTPRequest){
		func(r *ContainerHTTPRequest) { r.ContainerID = "--privileged" },
		func(r *ContainerHTTPRequest) { r.ContainerID = strings.Repeat("A", 64) },
		func(r *ContainerHTTPRequest) { r.Port = 0 },
		func(r *ContainerHTTPRequest) { r.Method = "CONNECT" },
		func(r *ContainerHTTPRequest) { r.Path = "http://other" },
		func(r *ContainerHTTPRequest) { r.Path = "//other" },
		func(r *ContainerHTTPRequest) { r.Path = "/bad\nheader" },
		func(r *ContainerHTTPRequest) { r.Path = "/" + strings.Repeat("a", 2048) },
		func(r *ContainerHTTPRequest) { r.Authorization = "Bearer token\"\nurl=\"http://other" },
		func(r *ContainerHTTPRequest) { r.Authorization = "Bearer " },
	} {
		request := valid
		mutate(&request)
		if _, _, err := requestContainerHTTP(t.Context(), request, func(context.Context, io.Reader, io.Writer, ...string) (bool, error) {
			t.Fatal("invalid request reached Docker")
			return false, nil
		}); !errors.Is(err, ErrRuntimeOutputInvalid) {
			t.Fatal("invalid request was accepted")
		}
	}
	for _, response := range []string{"private-native-error", "secret\n000", strings.Repeat("x", 65537) + "\n200"} {
		_, body, err := requestContainerHTTP(t.Context(), valid, func(_ context.Context, _ io.Reader, output io.Writer, _ ...string) (bool, error) {
			_, err := io.Copy(output, bytes.NewBufferString(response))
			return true, err
		})
		if err == nil || len(body) != 0 || strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "private-native") {
			t.Fatal("invalid native response escaped its bounded error")
		}
	}
}

func TestResolveImageIDPinsEitherAuthenticatedDockerStoreIdentity(t *testing.T) {
	manifestID := "sha256:" + strings.Repeat("a", 64)
	configID := "sha256:" + strings.Repeat("b", 64)
	for _, available := range []string{manifestID, configID} {
		t.Run(available, func(t *testing.T) {
			actual, err := resolveImageID(context.Background(), []string{manifestID, configID},
				func(_ context.Context, output io.Writer, args ...string) (bool, error) {
					if len(args) != 5 || !reflect.DeepEqual(args[:4], []string{"image", "inspect", "--format", "{{.Id}}|{{.Os}}|{{.Architecture}}"}) {
						t.Fatalf("unexpected image resolution effect: %v", args)
					}
					if args[4] != available {
						return true, errors.New("image absent")
					}
					_, err := io.WriteString(output, available+"|linux|amd64\n")
					return true, err
				})
			if err != nil || actual != available {
				t.Fatalf("resolve authenticated identity = %q, %v", actual, err)
			}
		})
	}
}

func TestResolveImageIDRejectsUntrustedSelectorsBeforeDocker(t *testing.T) {
	id := "sha256:" + strings.Repeat("a", 64)
	for _, identities := range [][]string{
		nil, {""}, {"postgres:18"}, {"matrix.local/matrix/postgres:sha256-" + strings.Repeat("a", 64)},
		{id, id}, {id, "--help"}, {"sha256:" + strings.Repeat("A", 64)}, {id, id, id},
	} {
		_, err := resolveImageID(context.Background(), identities, func(context.Context, io.Writer, ...string) (bool, error) {
			t.Fatal("invalid image selectors reached Docker")
			return false, nil
		})
		if !errors.Is(err, ErrRuntimeOutputInvalid) {
			t.Fatalf("invalid image selectors %v: %v", identities, err)
		}
	}
}

func TestResolveImageIDRejectsUnexpectedDaemonEvidence(t *testing.T) {
	id := "sha256:" + strings.Repeat("a", 64)
	for _, response := range []string{
		"sha256:" + strings.Repeat("b", 64) + "|linux|amd64",
		id + "|windows|amd64", id + "|linux|arm64", "", strings.Repeat("x", 1025),
	} {
		actual, err := resolveImageID(context.Background(), []string{id}, func(_ context.Context, output io.Writer, _ ...string) (bool, error) {
			_, err := io.WriteString(output, response)
			return true, err
		})
		if actual != "" || !errors.Is(err, ErrRuntimeOutputInvalid) {
			t.Fatalf("unexpected daemon identity accepted: %q, %v", actual, err)
		}
	}
}

func TestResolveImageIDFailsClosedWhenUnavailableOrCanceled(t *testing.T) {
	id := "sha256:" + strings.Repeat("a", 64)
	for _, started := range []bool{false, true} {
		actual, err := resolveImageID(context.Background(), []string{id}, func(context.Context, io.Writer, ...string) (bool, error) {
			return started, errors.New("unavailable")
		})
		if actual != "" || !errors.Is(err, ErrRuntimeUnavailable) {
			t.Fatalf("unavailable image = %q, %v", actual, err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := resolveImageID(ctx, []string{id}, func(context.Context, io.Writer, ...string) (bool, error) {
		t.Fatal("canceled image resolution reached Docker")
		return false, nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled image resolution: %v", err)
	}
}

func TestLocalRuntimeReadyProofRunsOneLiveProbePerRequest(t *testing.T) {
	calls := 0
	runtime := &LocalRuntime{readiness: func(context.Context) error {
		calls++
		return nil
	}}

	baseContext, cancel := context.WithCancel(context.Background())
	requestContext, err := runtime.ProveReady(baseContext)
	if err != nil {
		t.Fatalf("prove runtime ready: %v", err)
	}
	for attempt := 0; attempt < 5; attempt++ {
		if err := runtime.Ready(requestContext); err != nil {
			t.Fatalf("reuse runtime readiness proof: %v", err)
		}
	}
	if calls != 1 {
		t.Fatalf("live runtime readiness probes in one request = %d, want 1", calls)
	}
	cancel()
	if err := runtime.Ready(requestContext); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled readiness proof = %v, want context cancellation", err)
	}

	if err := runtime.Ready(context.Background()); err != nil {
		t.Fatalf("probe runtime for next request: %v", err)
	}
	if calls != 2 {
		t.Fatalf("live runtime readiness probes across two requests = %d, want 2", calls)
	}
}

func TestLocalRuntimeReadyProofIsBoundToSuccessfulRuntime(t *testing.T) {
	unavailable := &LocalRuntime{readiness: func(context.Context) error {
		return ErrRuntimeUnavailable
	}}
	if requestContext, err := unavailable.ProveReady(context.Background()); requestContext != nil || !errors.Is(err, ErrRuntimeUnavailable) {
		t.Fatalf("failed runtime proof: context=%v error=%v", requestContext, err)
	}

	readyCalls := 0
	ready := &LocalRuntime{readiness: func(context.Context) error {
		readyCalls++
		return nil
	}}
	requestContext, err := ready.ProveReady(context.Background())
	if err != nil {
		t.Fatalf("prove first runtime ready: %v", err)
	}
	otherCalls := 0
	other := &LocalRuntime{readiness: func(context.Context) error {
		otherCalls++
		return nil
	}}
	if err := other.Ready(requestContext); err != nil {
		t.Fatalf("probe other runtime: %v", err)
	}
	if readyCalls != 1 || otherCalls != 1 {
		t.Fatalf("runtime-bound proof calls = %d/%d, want 1/1", readyCalls, otherCalls)
	}
}
