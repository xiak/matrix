package devopsv1

import (
	"strings"
	"testing"
	"time"
)

func TestPipelineRunLogPageContract(t *testing.T) {
	readAt := time.Date(2026, 9, 9, 3, 4, 5, 123_456_000, time.UTC)
	page := PipelineRunLogPage{
		APIVersion: APIVersion, Kind: "PipelineRunLogPage",
		RunID:         "pipeline-run-" + ResourceID(strings.Repeat("a", 48)),
		AfterSequence: 0, NextSequence: 2,
		Chunks: []PipelineRunLogChunk{
			{
				Sequence: 1,
				Step:     VerificationStep{Ordinal: 1, Kind: VerificationStepGoTest},
				Content:  "[stdout] test ok\n", ExpiresAt: readAt.Add(14 * 24 * time.Hour),
			},
			{
				Sequence: 2,
				Step:     VerificationStep{Ordinal: 1, Kind: VerificationStepGoTest},
				Content:  "[stderr] warning\n", ExpiresAt: readAt.Add(14 * 24 * time.Hour),
			},
		},
		ReadAt: readAt,
	}
	if err := ValidatePipelineRunLogPage(page); err != nil {
		t.Fatalf("validate PipelineRun log page: %v", err)
	}

	for name, mutate := range map[string]func(*PipelineRunLogPage){
		"metadata":       func(value *PipelineRunLogPage) { value.Kind = "BuildLogBatch" },
		"run identity":   func(value *PipelineRunLogPage) { value.RunID = "run-one" },
		"cursor":         func(value *PipelineRunLogPage) { value.NextSequence = 1 },
		"sequence order": func(value *PipelineRunLogPage) { value.Chunks[1].Sequence = 1 },
		"step order": func(value *PipelineRunLogPage) {
			value.Chunks[0].Step = VerificationStep{Ordinal: 2, Kind: VerificationStepGoVet}
		},
		"native content": func(value *PipelineRunLogPage) { value.Chunks[0].Content = "test ok\n" },
		"control content": func(value *PipelineRunLogPage) {
			value.Chunks[0].Content = "[stdout] unsafe\x1b[31m\n"
		},
		"expired":            func(value *PipelineRunLogPage) { value.Chunks[0].ExpiresAt = value.ReadAt },
		"nil chunks":         func(value *PipelineRunLogPage) { value.Chunks = nil },
		"false continuation": func(value *PipelineRunLogPage) { value.HasMore = true },
	} {
		t.Run(name, func(t *testing.T) {
			value := page
			value.Chunks = append([]PipelineRunLogChunk(nil), page.Chunks...)
			mutate(&value)
			if err := ValidatePipelineRunLogPage(value); err == nil {
				t.Fatal("invalid PipelineRun log page was accepted")
			}
		})
	}
}

func TestPipelineRunLogPageAllowsEmptyAndRetentionTruncation(t *testing.T) {
	readAt := time.Date(2026, 9, 9, 3, 4, 5, 0, time.UTC)
	page := PipelineRunLogPage{
		APIVersion: APIVersion, Kind: "PipelineRunLogPage",
		RunID:         "pipeline-run-" + ResourceID(strings.Repeat("b", 48)),
		AfterSequence: 7, NextSequence: 7,
		Chunks: []PipelineRunLogChunk{}, Truncated: true, ReadAt: readAt,
	}
	if err := ValidatePipelineRunLogPage(page); err != nil {
		t.Fatalf("validate empty truncated log page: %v", err)
	}
	page.Chunks = make([]PipelineRunLogChunk, FixedLogPageChunkCount)
	for index := range page.Chunks {
		page.Chunks[index] = PipelineRunLogChunk{
			Sequence: uint64(index + 9),
			Step:     VerificationStep{Ordinal: 2, Kind: VerificationStepGoVet},
			Content:  "[stdout] retained\n", ExpiresAt: readAt.Add(time.Hour),
		}
	}
	page.NextSequence = page.Chunks[len(page.Chunks)-1].Sequence
	page.HasMore = true
	if err := ValidatePipelineRunLogPage(page); err != nil {
		t.Fatalf("validate continued truncated log page: %v", err)
	}
}
