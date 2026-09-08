package runnerlog

import (
	"errors"
	"testing"

	devopsv1 "github.com/xiak/matrix/api/devops/v1"
)

func TestProgressAcceptsOnlyProducerReachableState(t *testing.T) {
	valid := []Progress{
		{},
		{NativeBytes: 1, NormalizedBytes: 10, LastSequence: 1},
		{
			NativeBytes:     devopsv1.FixedMaxLogBytes,
			NormalizedBytes: devopsv1.FixedMaxLogBytes,
			LastSequence:    1,
		},
	}
	for _, value := range valid {
		if err := Validate(value); err != nil {
			t.Fatalf("valid progress %#v: %v", value, err)
		}
	}

	invalid := []Progress{
		{NativeBytes: -1},
		{NativeBytes: 1},
		{NativeBytes: 1, NormalizedBytes: 1},
		{NativeBytes: 1, NormalizedBytes: 1, LastSequence: 2},
		{NativeBytes: devopsv1.FixedMaxLogBytes + 1, NormalizedBytes: 1, LastSequence: 1},
		{NativeBytes: 1, NormalizedBytes: devopsv1.FixedMaxLogBytes + 1, LastSequence: 1},
	}
	for _, value := range invalid {
		if err := Validate(value); !errors.Is(err, ErrInvalid) {
			t.Fatalf("invalid progress %#v: %v", value, err)
		}
	}
}

func TestProgressAdvanceIsAtomicAndMonotonic(t *testing.T) {
	previous := Progress{NativeBytes: 10, NormalizedBytes: 20, LastSequence: 1}
	if err := ValidateAdvance(previous, previous); err != nil {
		t.Fatalf("empty advance: %v", err)
	}
	if err := ValidateAdvance(previous, Progress{
		NativeBytes: 20, NormalizedBytes: 40, LastSequence: 2,
	}); err != nil {
		t.Fatalf("strict advance: %v", err)
	}
	for _, next := range []Progress{
		{NativeBytes: 9, NormalizedBytes: 40, LastSequence: 2},
		{NativeBytes: 20, NormalizedBytes: 20, LastSequence: 2},
		{NativeBytes: 20, NormalizedBytes: 40, LastSequence: 1},
	} {
		if err := ValidateAdvance(previous, next); !errors.Is(err, ErrInvalid) {
			t.Fatalf("partial or backwards advance %#v: %v", next, err)
		}
	}
}

func TestLogBatchExactlyAccountsForCursorAdvance(t *testing.T) {
	previous := Progress{NativeBytes: 10, NormalizedBytes: 20, LastSequence: 2}
	next := Progress{NativeBytes: 20, NormalizedBytes: 24, LastSequence: 4}
	chunks := []Chunk{{Sequence: 3, Content: "ok\n"}, {Sequence: 4, Content: "x"}}
	if err := ValidateBatch(previous, next, chunks); err != nil {
		t.Fatalf("valid batch: %v", err)
	}
	if err := ValidateBatch(previous, previous, nil); err != nil {
		t.Fatalf("empty batch: %v", err)
	}
	invalid := [][]Chunk{
		nil,
		{{Sequence: 4, Content: "ok\n"}, {Sequence: 5, Content: "x"}},
		{{Sequence: 3, Content: "ok\n"}},
		{{Sequence: 3, Content: "ok\x00"}, {Sequence: 4, Content: "x"}},
		{{Sequence: 3, Content: ""}, {Sequence: 4, Content: "ok\nx"}},
	}
	for _, batch := range invalid {
		if err := ValidateBatch(previous, next, batch); !errors.Is(err, ErrInvalid) {
			t.Fatalf("invalid batch %#v: %v", batch, err)
		}
	}
}
