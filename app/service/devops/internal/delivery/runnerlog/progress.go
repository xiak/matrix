// Package runnerlog owns recovery-safe invariants for normalized runner logs.
package runnerlog

import (
	"errors"

	devopsv1 "github.com/xiak/matrix/api/devops/v1"
)

var ErrInvalid = errors.New("runner log progress is invalid")

// Progress is the smallest durable cursor needed to resume the run-wide log
// budget. Native log content is deliberately not part of runner-local state.
type Progress struct {
	NativeBytes     int64  `json:"nativeBytes"`
	NormalizedBytes int64  `json:"normalizedBytes"`
	LastSequence    uint64 `json:"lastSequence"`
}

func Validate(value Progress) error {
	if value.NativeBytes < 0 || value.NormalizedBytes < 0 ||
		value.NativeBytes > devopsv1.FixedMaxLogBytes ||
		value.NormalizedBytes > devopsv1.FixedMaxLogBytes ||
		value.LastSequence > uint64(devopsv1.FixedMaxLogBytes) {
		return ErrInvalid
	}
	if value.NativeBytes == 0 || value.NormalizedBytes == 0 || value.LastSequence == 0 {
		if value != (Progress{}) {
			return ErrInvalid
		}
		return nil
	}
	if value.LastSequence > uint64(value.NormalizedBytes) {
		return ErrInvalid
	}
	return nil
}

// ValidateAdvance accepts no output or a strict advance of all three values.
// A successful non-empty Docker stream always consumes native bytes, emits
// normalized bytes, and closes at least one sequenced chunk together.
func ValidateAdvance(previous, next Progress) error {
	if Validate(previous) != nil || Validate(next) != nil {
		return ErrInvalid
	}
	if previous == next {
		return nil
	}
	if next.NativeBytes <= previous.NativeBytes ||
		next.NormalizedBytes <= previous.NormalizedBytes ||
		next.LastSequence <= previous.LastSequence {
		return ErrInvalid
	}
	return nil
}
