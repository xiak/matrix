package runnerlog

import (
	"unicode"
	"unicode/utf8"
)

const MaximumChunkBytes = 64 * 1024

// Chunk is sanitized UTF-8 output with a run-wide monotonic sequence.
type Chunk struct {
	Sequence uint64
	Content  string
}

// ValidateBatch proves that chunks exactly account for one cursor advance.
// Content has already been normalized by the sandbox, but this boundary still
// rejects malformed UTF-8 and unsafe controls before publication.
func ValidateBatch(previous, next Progress, chunks []Chunk) error {
	if ValidateAdvance(previous, next) != nil {
		return ErrInvalid
	}
	if len(chunks) == 0 {
		if previous != next {
			return ErrInvalid
		}
		return nil
	}
	if previous == next || uint64(len(chunks)) > next.LastSequence ||
		next.LastSequence-uint64(len(chunks)) != previous.LastSequence {
		return ErrInvalid
	}
	var normalizedBytes int64
	for index, chunk := range chunks {
		if chunk.Sequence != previous.LastSequence+uint64(index)+1 ||
			len(chunk.Content) == 0 || len(chunk.Content) > MaximumChunkBytes ||
			!utf8.ValidString(chunk.Content) {
			return ErrInvalid
		}
		for _, character := range chunk.Content {
			if character != '\n' && character != '\t' && unicode.IsControl(character) {
				return ErrInvalid
			}
		}
		normalizedBytes += int64(len(chunk.Content))
	}
	if normalizedBytes != next.NormalizedBytes-previous.NormalizedBytes {
		return ErrInvalid
	}
	return nil
}
