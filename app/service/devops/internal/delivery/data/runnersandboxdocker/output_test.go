package runnersandboxdocker

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
	"unicode"
	"unicode/utf8"

	devopsv1 "github.com/xiak/matrix/api/devops/v1"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/runnerlog"
)

func TestLogBudgetDecodesSplitMultiplexedOutputIntoRunSequence(t *testing.T) {
	budget := NewLogBudget()
	first := dockerLogStream(
		logFrame{stream: stdoutStream, content: []byte("go te")},
		logFrame{stream: stderrStream, content: []byte("warning\n")},
		logFrame{stream: stdoutStream, content: []byte("st ./...\n")},
	)
	chunks, err := budget.DecodeDockerStream(bytes.NewReader(first))
	if err != nil || len(chunks) != 1 || chunks[0].Sequence != 1 ||
		chunks[0].Content != "[stderr] warning\n[stdout] go test ./...\n" {
		t.Fatalf("chunks = %#v, error = %v", chunks, err)
	}
	second := dockerLogStream(logFrame{stream: stdoutStream, content: []byte("done")})
	chunks, err = budget.DecodeDockerStream(bytes.NewReader(second))
	if err != nil || len(chunks) != 1 || chunks[0].Sequence != 2 ||
		chunks[0].Content != "[stdout] done" {
		t.Fatalf("second chunks = %#v, error = %v", chunks, err)
	}
}

func TestLogBudgetRestoresRunWideCursorAcrossRestart(t *testing.T) {
	budget := NewLogBudget()
	firstContent := []byte("first\n")
	firstChunks, err := budget.DecodeDockerStream(bytes.NewReader(dockerLogStream(
		logFrame{stream: stdoutStream, content: firstContent},
	)))
	if err != nil || len(firstChunks) != 1 {
		t.Fatalf("first chunks = %#v, error = %v", firstChunks, err)
	}
	first, err := budget.Progress()
	if err != nil || first != (runnerlog.Progress{
		NativeBytes: int64(len(firstContent)), NormalizedBytes: int64(len("[stdout] first\n")),
		LastSequence: 1,
	}) {
		t.Fatalf("first progress = %#v, error = %v", first, err)
	}

	restarted, err := ResumeLogBudget(first)
	if err != nil {
		t.Fatalf("resume budget: %v", err)
	}
	secondContent := []byte("second\n")
	secondChunks, err := restarted.DecodeDockerStream(bytes.NewReader(dockerLogStream(
		logFrame{stream: stderrStream, content: secondContent},
	)))
	if err != nil || len(secondChunks) != 1 || secondChunks[0].Sequence != 2 {
		t.Fatalf("second chunks = %#v, error = %v", secondChunks, err)
	}
	second, err := restarted.Progress()
	if err != nil || second.NativeBytes != first.NativeBytes+int64(len(secondContent)) ||
		second.NormalizedBytes != first.NormalizedBytes+int64(len("[stderr] second\n")) ||
		second.LastSequence != 2 {
		t.Fatalf("second progress = %#v, error = %v", second, err)
	}
}

func TestLogBudgetRejectsInvalidOrExhaustedRestoredCursor(t *testing.T) {
	if budget, err := ResumeLogBudget(runnerlog.Progress{NativeBytes: 1}); budget != nil || !errors.Is(err, ErrLogInvalid) {
		t.Fatalf("invalid restored budget = %#v / %v", budget, err)
	}

	tests := []struct {
		name     string
		progress runnerlog.Progress
	}{
		{
			name: "native",
			progress: runnerlog.Progress{
				NativeBytes:     devopsv1.FixedMaxLogBytes - 1,
				NormalizedBytes: devopsv1.FixedMaxLogBytes - 100,
				LastSequence:    1,
			},
		},
		{
			name: "normalized",
			progress: runnerlog.Progress{
				NativeBytes:     devopsv1.FixedMaxLogBytes - 100,
				NormalizedBytes: devopsv1.FixedMaxLogBytes - 1,
				LastSequence:    1,
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			budget, err := ResumeLogBudget(test.progress)
			if err != nil {
				t.Fatal(err)
			}
			chunks, err := budget.DecodeDockerStream(bytes.NewReader(dockerLogStream(
				logFrame{stream: stdoutStream, content: []byte("xx\n")},
			)))
			if len(chunks) != 0 || !errors.Is(err, ErrLogLimit) {
				t.Fatalf("chunks = %#v, error = %v", chunks, err)
			}
			if progress, err := budget.Progress(); progress != (runnerlog.Progress{}) ||
				!errors.Is(err, ErrLogInvalid) {
				t.Fatalf("poisoned progress = %#v / %v", progress, err)
			}
		})
	}
}

func TestLogBudgetReplacesUnsafeLinesWithoutLeakingContent(t *testing.T) {
	tests := []struct {
		name    string
		content []byte
		marker  string
	}{
		{name: "invalid UTF-8", content: []byte{0xff, '\n'}, marker: "[matrix:invalid-utf8]"},
		{name: "ANSI", content: []byte("\x1b[31mred\x1b[0m\n"), marker: "[matrix:ansi-escape]"},
		{name: "control", content: []byte("left\x00right\n"), marker: "[matrix:control-bytes]"},
		{name: "secret", content: []byte("GITHUB_TOKEN=top-secret\n"), marker: "[matrix:secret-shaped]"},
		{name: "JSON secret", content: []byte(`{"token":"top-secret"}` + "\n"), marker: "[matrix:secret-shaped]"},
		{name: "spaced secret", content: []byte("password  = top-secret\n"), marker: "[matrix:secret-shaped]"},
		{name: "credential URL", content: []byte("clone https://user:top-secret@example.invalid/repo\n"), marker: "[matrix:secret-shaped]"},
		{name: "AWS key", content: []byte("AKIAIOSFODNN7EXAMPLE\n"), marker: "[matrix:secret-shaped]"},
		{name: "JWT", content: []byte("eyJhbGciOiJIUzI1NiJ9.payload.signature\n"), marker: "[matrix:secret-shaped]"},
		{name: "Unix path", content: []byte("open /var/lib/matrix/private\n"), marker: "[matrix:absolute-path]"},
		{name: "attached Unix path", content: []byte("error:/var/lib/matrix/private\n"), marker: "[matrix:absolute-path]"},
		{name: "file URL", content: []byte("open file:///var/lib/matrix/private\n"), marker: "[matrix:absolute-path]"},
		{name: "Windows path", content: []byte("open C:\\matrix\\private\n"), marker: "[matrix:absolute-path]"},
		{name: "UNC path", content: []byte("open \\\\server\\private\n"), marker: "[matrix:absolute-path]"},
		{name: "long", content: append(bytes.Repeat([]byte("x"), maximumLogLineBytes+1), '\n'), marker: "[matrix:line-too-long]"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			budget := NewLogBudget()
			chunks, err := budget.DecodeDockerStream(bytes.NewReader(dockerLogStream(
				logFrame{stream: stdoutStream, content: test.content},
			)))
			if err != nil || len(chunks) != 1 ||
				chunks[0].Content != "[stdout] "+test.marker+"\n" ||
				!utf8.ValidString(chunks[0].Content) {
				t.Fatalf("chunks = %#v, error = %v", chunks, err)
			}
		})
	}
}

func TestLogBudgetPreservesSafeUTF8AndRemoteURL(t *testing.T) {
	content := "通过 github.com/xiak/matrix，详情 https://example.invalid/runs/42\n"
	chunks, err := NewLogBudget().DecodeDockerStream(bytes.NewReader(dockerLogStream(
		logFrame{stream: stdoutStream, content: []byte(content)},
	)))
	if err != nil || len(chunks) != 1 || chunks[0].Content != "[stdout] "+content {
		t.Fatalf("chunks = %#v, error = %v", chunks, err)
	}
}

func TestLogBudgetRejectsMalformedOrOverBudgetNativeStreams(t *testing.T) {
	tests := map[string][]byte{
		"bad stream":      dockerLogStream(logFrame{stream: 3, content: []byte("x")}),
		"reserved header": []byte{stdoutStream, 1, 0, 0, 0, 0, 0, 1, 'x'},
		"zero frame":      []byte{stdoutStream, 0, 0, 0, 0, 0, 0, 0},
		"partial header":  []byte{stdoutStream, 0, 0},
		"partial payload": []byte{stdoutStream, 0, 0, 0, 0, 0, 0, 2, 'x'},
	}
	for name, content := range tests {
		t.Run(name, func(t *testing.T) {
			if chunks, err := NewLogBudget().DecodeDockerStream(bytes.NewReader(content)); len(chunks) != 0 || !errors.Is(err, ErrLogInvalid) {
				t.Fatalf("chunks = %#v, error = %v", chunks, err)
			}
		})
	}
	budget, err := ResumeLogBudget(runnerlog.Progress{
		NativeBytes: devopsv1.FixedMaxLogBytes - 1, NormalizedBytes: 1, LastSequence: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if chunks, err := budget.DecodeDockerStream(bytes.NewReader(dockerLogStream(
		logFrame{stream: stdoutStream, content: []byte("xx")},
	))); len(chunks) != 0 || !errors.Is(err, ErrLogLimit) {
		t.Fatalf("chunks = %#v, error = %v", chunks, err)
	}
}

func TestLogBudgetFailsClosedAfterPartialInvalidStream(t *testing.T) {
	budget := NewLogBudget()
	stream := append(
		dockerLogStream(logFrame{stream: stdoutStream, content: []byte("accepted\n")}),
		[]byte{stdoutStream, 0, 0}...,
	)
	if chunks, err := budget.DecodeDockerStream(bytes.NewReader(stream)); len(chunks) != 0 || !errors.Is(err, ErrLogInvalid) {
		t.Fatalf("partial chunks = %#v, error = %v", chunks, err)
	}
	if chunks, err := budget.DecodeDockerStream(bytes.NewReader(dockerLogStream(
		logFrame{stream: stdoutStream, content: []byte("must-not-resume\n")},
	))); len(chunks) != 0 || !errors.Is(err, ErrLogInvalid) {
		t.Fatalf("reused chunks = %#v, error = %v", chunks, err)
	}
	if progress, err := budget.Progress(); progress != (runnerlog.Progress{}) ||
		!errors.Is(err, ErrLogInvalid) {
		t.Fatalf("poisoned progress = %#v / %v", progress, err)
	}
}

func TestLogBudgetBoundsNormalizedBytesAcrossSteps(t *testing.T) {
	budget, err := ResumeLogBudget(runnerlog.Progress{
		NativeBytes: 1, NormalizedBytes: devopsv1.FixedMaxLogBytes - 1, LastSequence: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if chunks, err := budget.DecodeDockerStream(bytes.NewReader(dockerLogStream(
		logFrame{stream: stdoutStream, content: []byte("x\n")},
	))); len(chunks) != 0 || !errors.Is(err, ErrLogLimit) {
		t.Fatalf("chunks = %#v, error = %v", chunks, err)
	}
	if !budget.failed {
		t.Fatal("over-budget run remained reusable")
	}
}

func TestLogChunksStayBoundedUnderLargeAlternatingOutput(t *testing.T) {
	var frames []logFrame
	for index := 0; index < 8_000; index++ {
		stream := stdoutStream
		if index%2 == 1 {
			stream = stderrStream
		}
		frames = append(frames, logFrame{stream: stream, content: []byte("line\n")})
	}
	chunks, err := NewLogBudget().DecodeDockerStream(bytes.NewReader(dockerLogStream(frames...)))
	if err != nil || len(chunks) == 0 || len(chunks) > 4 {
		t.Fatalf("chunk count = %d, error = %v", len(chunks), err)
	}
	for index, chunk := range chunks {
		if chunk.Sequence != uint64(index+1) || len(chunk.Content) > runnerlog.MaximumChunkBytes ||
			!utf8.ValidString(chunk.Content) {
			t.Fatalf("chunk %d = %#v", index, chunk)
		}
	}
}

func FuzzLogBudgetDockerStream(f *testing.F) {
	f.Add([]byte{})
	f.Add(dockerLogStream(logFrame{stream: stdoutStream, content: []byte("safe\n")}))
	f.Add([]byte{stdoutStream, 0, 0})
	f.Fuzz(func(t *testing.T, content []byte) {
		chunks, err := NewLogBudget().DecodeDockerStream(bytes.NewReader(content))
		if err != nil {
			if len(chunks) != 0 ||
				(!errors.Is(err, ErrLogInvalid) && !errors.Is(err, ErrLogLimit)) {
				t.Fatalf("chunks = %#v, error = %v", chunks, err)
			}
			return
		}
		total := 0
		for index, chunk := range chunks {
			total += len(chunk.Content)
			if chunk.Sequence != uint64(index+1) || len(chunk.Content) == 0 ||
				len(chunk.Content) > runnerlog.MaximumChunkBytes || !utf8.ValidString(chunk.Content) {
				t.Fatalf("chunk %d = %#v", index, chunk)
			}
			for _, character := range chunk.Content {
				if character != '\n' && character != '\t' && unicode.IsControl(character) {
					t.Fatalf("unsafe control character %U in %#v", character, chunk)
				}
			}
		}
		if int64(total) > devopsv1.FixedMaxLogBytes {
			t.Fatalf("normalized bytes = %d", total)
		}
	})
}

type logFrame struct {
	stream  byte
	content []byte
}

func dockerLogStream(frames ...logFrame) []byte {
	var output bytes.Buffer
	for _, frame := range frames {
		var header [8]byte
		header[0] = frame.stream
		binary.BigEndian.PutUint32(header[4:], uint32(len(frame.content)))
		_, _ = output.Write(header[:])
		_, _ = output.Write(frame.content)
	}
	return output.Bytes()
}
