package devopsbuildv1

import (
	"bytes"
	"strings"
	"testing"

	devopsv1 "github.com/xiak/matrix/api/devops/v1"
)

func TestLogDocumentsAreCanonicalAndFenceIndependent(t *testing.T) {
	request := requestFixture([]byte("canonical source archive"))
	batch := logBatchFixture(request, []string{"[stdout] test ok\n", "[stdout] vet next\n"})
	appendDocument, err := EncodeLogAppend(request, 7, batch)
	if err != nil {
		t.Fatal(err)
	}
	appendValue, err := DecodeLogAppend(request, appendDocument)
	if err != nil || appendValue.FencingToken != 7 ||
		appendValue.Batch.ContentDigest != batch.ContentDigest {
		t.Fatalf("append = %#v / %v", appendValue, err)
	}
	recoveredDocument, err := EncodeLogAppend(request, 8, batch)
	if err != nil || bytes.Equal(appendDocument, recoveredDocument) ||
		batch.ContentDigest != appendValue.Batch.ContentDigest {
		t.Fatalf("recovered append = %q / %v", recoveredDocument, err)
	}

	batchDocument, err := EncodeLogBatch(request, batch)
	if err != nil {
		t.Fatal(err)
	}
	decodedBatch, err := DecodeLogBatch(request, batchDocument)
	if err != nil || decodedBatch.ContentDigest != batch.ContentDigest ||
		len(decodedBatch.Chunks) != len(batch.Chunks) {
		t.Fatalf("batch = %#v / %v", decodedBatch, err)
	}

	readDocument, err := EncodeLogRead(request, batch.Next.LastSequence)
	if err != nil {
		t.Fatal(err)
	}
	readRequest, after, err := DecodeLogRead(readDocument)
	if err != nil || readRequest != request || after != batch.Next.LastSequence {
		t.Fatalf("read = %#v / %d / %v", readRequest, after, err)
	}
}

func TestLogBatchRejectsChangedSequenceContentProgressAndStep(t *testing.T) {
	request := requestFixture([]byte("canonical source archive"))
	valid := logBatchFixture(request, []string{"[stdout] ok\n", "[stderr] next\n"})
	tests := map[string]func(*LogBatch){
		"execution": func(value *LogBatch) { value.ExecutionID = digestOf('9') },
		"step":      func(value *LogBatch) { value.Step.Ordinal = 3 },
		"previous":  func(value *LogBatch) { value.Previous.NativeBytes = 1 },
		"native":    func(value *LogBatch) { value.Next.NativeBytes = 0 },
		"normalized": func(value *LogBatch) {
			value.Next.NormalizedBytes++
		},
		"last sequence": func(value *LogBatch) { value.Next.LastSequence++ },
		"chunk sequence": func(value *LogBatch) {
			value.Chunks[0].Sequence++
		},
		"empty content": func(value *LogBatch) { value.Chunks[0].Content = "" },
		"control content": func(value *LogBatch) {
			value.Chunks[0].Content = "unsafe\x00"
		},
		"chunk digest": func(value *LogBatch) {
			value.Chunks[0].ContentDigest = digestOf('8')
		},
		"batch digest": func(value *LogBatch) { value.ContentDigest = digestOf('7') },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			candidate := cloneLogBatch(valid)
			mutate(&candidate)
			if ValidateLogBatch(request, candidate) == nil {
				t.Fatal("changed log batch was accepted")
			}
		})
	}

	empty := cloneLogBatch(valid)
	empty.Chunks = nil
	if ValidateLogBatch(request, empty) == nil {
		t.Fatal("empty log batch was accepted")
	}
	tooMany := cloneLogBatch(valid)
	tooMany.Chunks = make([]LogChunk, MaximumLogChunksPerBatch+1)
	if ValidateLogBatch(request, tooMany) == nil {
		t.Fatal("oversized chunk inventory was accepted")
	}
}

func TestLogDocumentsRejectUnknownNoncanonicalAndOversizedInput(t *testing.T) {
	request := requestFixture([]byte("canonical source archive"))
	batch := logBatchFixture(request, []string{"[stdout] ok\n"})
	content, err := EncodeLogAppend(request, 1, batch)
	if err != nil {
		t.Fatal(err)
	}
	for name, candidate := range map[string][]byte{
		"leading whitespace": append([]byte(" "), content...),
		"trailing document":  append(append([]byte(nil), content...), []byte(`{}`)...),
		"unknown field": bytes.Replace(
			content, []byte(`"batch":`), []byte(`"native":"secret","batch":`), 1,
		),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeLogAppend(request, candidate); err == nil {
				t.Fatal("noncanonical log append was accepted")
			}
		})
	}
	if _, err := DecodeLogAppend(
		request, bytes.Repeat([]byte("x"), int(MaximumLogDocumentBytes)+1),
	); err == nil {
		t.Fatal("oversized log document was accepted")
	}
	if _, err := EncodeLogRead(request, uint64(request.Limits.MaxLogBytes)+1); err == nil {
		t.Fatal("oversized log cursor was accepted")
	}
}

func TestLogDocumentCarriesMaximumChunkWithoutHTMLEscapeExpansion(t *testing.T) {
	request := requestFixture([]byte("canonical source archive"))
	content := strings.Repeat(
		"[stdout] "+strings.Repeat("<", int(devopsv1.FixedMaxLogLineBytes))+"\n",
		3,
	) + "[stdout] " + strings.Repeat("<", 16345)
	if int64(len(content)) != 64*1024 {
		t.Fatalf("fixture bytes = %d", len(content))
	}
	batch := logBatchFixture(request, []string{content})
	encoded, err := EncodeLogAppend(request, 1, batch)
	if err != nil || int64(len(encoded)) > MaximumLogDocumentBytes ||
		bytes.Contains(encoded, []byte(`\u003c`)) {
		t.Fatalf("maximum chunk bytes=%d escaped=%t error=%v", len(encoded), bytes.Contains(encoded, []byte(`\u003c`)), err)
	}
	if _, err := DecodeLogAppend(request, encoded); err != nil {
		t.Fatalf("decode maximum chunk: %v", err)
	}
}

func TestLogBatchRequiresCompleteNormalizedStreamLines(t *testing.T) {
	request := requestFixture([]byte("canonical source archive"))
	for name, content := range map[string]string{
		"unlabeled":        "native output\n",
		"empty line":       "\n",
		"oversized line":   "[stdout] " + strings.Repeat("x", int(devopsv1.FixedMaxLogLineBytes)+1),
		"unknown stream":   "[system] safe\n",
		"embedded control": "[stdout] unsafe\x1b[31m\n",
	} {
		t.Run(name, func(t *testing.T) {
			if ValidateLogBatch(request, logBatchFixture(request, []string{content})) == nil {
				t.Fatal("non-normalized log content was accepted")
			}
		})
	}
	valid := "[stderr] " + strings.Repeat(
		"x", int(devopsv1.FixedMaxLogLineBytes),
	) + "\n"
	if err := ValidateLogBatch(
		request, logBatchFixture(request, []string{valid}),
	); err != nil {
		t.Fatalf("maximum normalized line rejected: %v", err)
	}
}

func logBatchFixture(request Request, content []string) LogBatch {
	executionID, err := ExecutionID(request)
	if err != nil {
		panic(err)
	}
	batch := LogBatch{
		ExecutionID: executionID,
		Step:        request.Steps[0],
		Previous:    LogProgress{},
		Chunks:      make([]LogChunk, len(content)),
	}
	var bytesCount int64
	for index, value := range content {
		chunk := LogChunk{Sequence: uint64(index + 1), Content: value}
		chunk.ContentDigest = DigestLogChunk(executionID, batch.Step, chunk)
		batch.Chunks[index] = chunk
		bytesCount += int64(len(value))
	}
	batch.Next = LogProgress{
		NativeBytes:     bytesCount,
		NormalizedBytes: bytesCount,
		LastSequence:    uint64(len(content)),
	}
	batch.ContentDigest = DigestLogBatch(batch)
	return batch
}

func cloneLogBatch(value LogBatch) LogBatch {
	value.Chunks = append([]LogChunk(nil), value.Chunks...)
	return value
}
