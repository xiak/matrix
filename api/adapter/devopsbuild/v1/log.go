package devopsbuildv1

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"hash"
	"io"
	"strings"
	"unicode"
	"unicode/utf8"

	devopsv1 "github.com/xiak/matrix/api/devops/v1"
)

const (
	LogAppendKind = "BuildLogAppend"
	LogBatchKind  = "BuildLogBatch"
	LogReadKind   = "BuildLogRead"

	LogDocumentMediaType     = "application/vnd.matrix.devops.build-log.v1+json"
	MaximumLogChunksPerBatch = 1024
	MaximumLogDocumentBytes  = 2*devopsv1.FixedMaxLogBytes + MaximumDocumentBytes
)

type LogProgress struct {
	NativeBytes     int64  `json:"nativeBytes"`
	NormalizedBytes int64  `json:"normalizedBytes"`
	LastSequence    uint64 `json:"lastSequence"`
}

type LogChunk struct {
	Sequence      uint64 `json:"sequence"`
	Content       string `json:"content"`
	ContentDigest string `json:"contentDigest"`
}

// LogBatch is normalized runner output for one fixed verification step. Its
// digest deliberately excludes lease authority so an equal batch can replay
// under a later same-runner fencing token.
type LogBatch struct {
	ExecutionID   string                    `json:"executionId"`
	Step          devopsv1.VerificationStep `json:"step"`
	Previous      LogProgress               `json:"previous"`
	Next          LogProgress               `json:"next"`
	Chunks        []LogChunk                `json:"chunks"`
	ContentDigest string                    `json:"contentDigest"`
}

type LogAppend struct {
	APIVersion   string   `json:"apiVersion"`
	Kind         string   `json:"kind"`
	FencingToken uint64   `json:"fencingToken"`
	Batch        LogBatch `json:"batch"`
}

type LogBatchDocument struct {
	APIVersion string   `json:"apiVersion"`
	Kind       string   `json:"kind"`
	Batch      LogBatch `json:"batch"`
}

type LogRead struct {
	APIVersion    string  `json:"apiVersion"`
	Kind          string  `json:"kind"`
	ExecutionID   string  `json:"executionId"`
	AfterSequence uint64  `json:"afterSequence"`
	Request       Request `json:"request"`
}

func ValidateLogBatch(request Request, value LogBatch) error {
	if ValidateRequest(request) != nil || len(value.Chunks) == 0 ||
		len(value.Chunks) > MaximumLogChunksPerBatch ||
		validateLogProgress(value.Previous, request.Limits.MaxLogBytes) != nil ||
		validateLogProgress(value.Next, request.Limits.MaxLogBytes) != nil ||
		value.Next.NativeBytes <= value.Previous.NativeBytes ||
		value.Next.NormalizedBytes <= value.Previous.NormalizedBytes ||
		value.Next.LastSequence <= value.Previous.LastSequence {
		return ErrInvalidDocument
	}
	executionID, err := ExecutionID(request)
	if err != nil || value.ExecutionID != executionID || !requestHasStep(request, value.Step) ||
		uint64(len(value.Chunks)) > value.Next.LastSequence ||
		value.Next.LastSequence-uint64(len(value.Chunks)) != value.Previous.LastSequence {
		return ErrInvalidDocument
	}
	var normalizedBytes int64
	for index, chunk := range value.Chunks {
		if chunk.Sequence != value.Previous.LastSequence+uint64(index)+1 ||
			validateLogContent(chunk.Content) != nil ||
			chunk.ContentDigest != DigestLogChunk(value.ExecutionID, value.Step, chunk) {
			return ErrInvalidDocument
		}
		normalizedBytes += int64(len(chunk.Content))
	}
	if normalizedBytes != value.Next.NormalizedBytes-value.Previous.NormalizedBytes ||
		value.ContentDigest != DigestLogBatch(value) {
		return ErrInvalidDocument
	}
	return nil
}

func DigestLogChunk(
	executionID string,
	step devopsv1.VerificationStep,
	chunk LogChunk,
) string {
	digest := sha256.New()
	writeString(digest, "matrix-devops-build-log-chunk-v1")
	writeString(digest, executionID)
	writeUint64(digest, uint64(step.Ordinal))
	writeString(digest, string(step.Kind))
	writeUint64(digest, chunk.Sequence)
	writeString(digest, chunk.Content)
	return "sha256:" + hex.EncodeToString(digest.Sum(nil))
}

func DigestLogBatch(value LogBatch) string {
	digest := sha256.New()
	writeString(digest, "matrix-devops-build-log-batch-v1")
	writeString(digest, value.ExecutionID)
	writeUint64(digest, uint64(value.Step.Ordinal))
	writeString(digest, string(value.Step.Kind))
	writeLogProgress(digest, value.Previous)
	writeLogProgress(digest, value.Next)
	writeUint64(digest, uint64(len(value.Chunks)))
	for _, chunk := range value.Chunks {
		writeUint64(digest, chunk.Sequence)
		writeString(digest, chunk.ContentDigest)
	}
	return "sha256:" + hex.EncodeToString(digest.Sum(nil))
}

func EncodeLogAppend(
	request Request,
	fencingToken uint64,
	batch LogBatch,
) ([]byte, error) {
	if !validRunnerFence(batch.ExecutionID, fencingToken) ||
		ValidateLogBatch(request, batch) != nil {
		return nil, ErrInvalidDocument
	}
	return encodeLogDocument(LogAppend{
		APIVersion: APIVersion, Kind: LogAppendKind,
		FencingToken: fencingToken, Batch: batch,
	})
}

func DecodeLogAppend(request Request, content []byte) (LogAppend, error) {
	var document LogAppend
	if decodeLogDocument(content, &document) != nil ||
		document.APIVersion != APIVersion || document.Kind != LogAppendKind ||
		!validRunnerFence(document.Batch.ExecutionID, document.FencingToken) ||
		ValidateLogBatch(request, document.Batch) != nil {
		return LogAppend{}, ErrInvalidDocument
	}
	canonical, err := EncodeLogAppend(request, document.FencingToken, document.Batch)
	if err != nil || !bytes.Equal(canonical, content) {
		return LogAppend{}, ErrInvalidDocument
	}
	return document, nil
}

func EncodeLogBatch(request Request, batch LogBatch) ([]byte, error) {
	if ValidateLogBatch(request, batch) != nil {
		return nil, ErrInvalidDocument
	}
	return encodeLogDocument(LogBatchDocument{
		APIVersion: APIVersion, Kind: LogBatchKind, Batch: batch,
	})
}

func DecodeLogBatch(request Request, content []byte) (LogBatch, error) {
	var document LogBatchDocument
	if decodeLogDocument(content, &document) != nil ||
		document.APIVersion != APIVersion || document.Kind != LogBatchKind ||
		ValidateLogBatch(request, document.Batch) != nil {
		return LogBatch{}, ErrInvalidDocument
	}
	canonical, err := EncodeLogBatch(request, document.Batch)
	if err != nil || !bytes.Equal(canonical, content) {
		return LogBatch{}, ErrInvalidDocument
	}
	return document.Batch, nil
}

func EncodeLogRead(request Request, afterSequence uint64) ([]byte, error) {
	executionID, err := ExecutionID(request)
	if err != nil || afterSequence > uint64(request.Limits.MaxLogBytes) {
		return nil, ErrInvalidDocument
	}
	return encodeDocument(LogRead{
		APIVersion: APIVersion, Kind: LogReadKind, ExecutionID: executionID,
		AfterSequence: afterSequence, Request: request,
	})
}

func DecodeLogRead(content []byte) (Request, uint64, error) {
	var document LogRead
	if decodeDocument(content, &document) != nil || document.APIVersion != APIVersion ||
		document.Kind != LogReadKind || document.AfterSequence > uint64(devopsv1.FixedMaxLogBytes) {
		return Request{}, 0, ErrInvalidDocument
	}
	executionID, err := ExecutionID(document.Request)
	if err != nil || document.ExecutionID != executionID ||
		document.AfterSequence > uint64(document.Request.Limits.MaxLogBytes) {
		return Request{}, 0, ErrInvalidDocument
	}
	canonical, err := EncodeLogRead(document.Request, document.AfterSequence)
	if err != nil || !bytes.Equal(canonical, content) {
		return Request{}, 0, ErrInvalidDocument
	}
	return document.Request, document.AfterSequence, nil
}

func validateLogProgress(value LogProgress, maximum int64) error {
	if maximum != devopsv1.FixedMaxLogBytes || value.NativeBytes < 0 ||
		value.NormalizedBytes < 0 || value.NativeBytes > maximum ||
		value.NormalizedBytes > maximum ||
		value.LastSequence > uint64(maximum) {
		return ErrInvalidDocument
	}
	if value.NativeBytes == 0 || value.NormalizedBytes == 0 || value.LastSequence == 0 {
		if value != (LogProgress{}) {
			return ErrInvalidDocument
		}
		return nil
	}
	if value.LastSequence > uint64(value.NormalizedBytes) {
		return ErrInvalidDocument
	}
	return nil
}

func validateLogContent(value string) error {
	if len(value) == 0 || int64(len(value)) > devopsv1.FixedMaxLogChunkBytes ||
		!utf8.ValidString(value) {
		return ErrInvalidDocument
	}
	for _, character := range value {
		if character != '\n' && character != '\t' && unicode.IsControl(character) {
			return ErrInvalidDocument
		}
	}
	lines := strings.Split(value, "\n")
	for index, line := range lines {
		if line == "" && index == len(lines)-1 {
			continue
		}
		if (!strings.HasPrefix(line, "[stdout] ") &&
			!strings.HasPrefix(line, "[stderr] ")) ||
			int64(len(line)) > int64(len("[stdout] "))+devopsv1.FixedMaxLogLineBytes {
			return ErrInvalidDocument
		}
	}
	return nil
}

func requestHasStep(request Request, step devopsv1.VerificationStep) bool {
	return request.Steps[0] == step || request.Steps[1] == step
}

func writeLogProgress(destination hash.Hash, value LogProgress) {
	writeUint64(destination, uint64(value.NativeBytes))
	writeUint64(destination, uint64(value.NormalizedBytes))
	writeUint64(destination, value.LastSequence)
}

func encodeLogDocument(value any) ([]byte, error) {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, ErrInvalidDocument
	}
	content := buffer.Bytes()
	if len(content) == 0 || content[len(content)-1] != '\n' {
		return nil, ErrInvalidDocument
	}
	content = content[:len(content)-1]
	if len(content) == 0 || int64(len(content)) > MaximumLogDocumentBytes {
		return nil, ErrInvalidDocument
	}
	return append([]byte(nil), content...), nil
}

func decodeLogDocument(content []byte, destination any) error {
	if len(content) == 0 || int64(len(content)) > MaximumLogDocumentBytes {
		return ErrInvalidDocument
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return errors.Join(ErrInvalidDocument, err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return ErrInvalidDocument
	}
	return nil
}
