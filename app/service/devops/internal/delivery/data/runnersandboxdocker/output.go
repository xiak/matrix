package runnersandboxdocker

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"

	devopsv1 "github.com/xiak/matrix/api/devops/v1"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/runnerlog"
)

const (
	maximumLogLineBytes  = 16 * 1024
	maximumLogChunkBytes = 64 * 1024

	stdoutStream = byte(1)
	stderrStream = byte(2)
)

var (
	ErrLogInvalid = errors.New("runner sandbox log stream is invalid")
	ErrLogLimit   = errors.New("runner sandbox log limit was exceeded")
)

type LogChunk struct {
	Sequence uint64
	Content  string
}

// LogBudget is shared by both fixed verification steps. It bounds native bytes
// before normalization and normalized bytes after stream labels and markers.
type LogBudget struct {
	mutex           sync.Mutex
	rawBytes        int64
	normalizedBytes int64
	sequence        uint64
	failed          bool
}

func NewLogBudget() *LogBudget {
	return &LogBudget{}
}

// ResumeLogBudget restores only validated counters from the private runner
// journal. Native output never crosses this boundary.
func ResumeLogBudget(progress runnerlog.Progress) (*LogBudget, error) {
	if runnerlog.Validate(progress) != nil {
		return nil, ErrLogInvalid
	}
	return &LogBudget{
		rawBytes:        progress.NativeBytes,
		normalizedBytes: progress.NormalizedBytes,
		sequence:        progress.LastSequence,
	}, nil
}

// Progress returns a durable cursor only while every decoded stream remains
// valid. A poisoned partial stream cannot become restart state.
func (budget *LogBudget) Progress() (runnerlog.Progress, error) {
	if budget == nil {
		return runnerlog.Progress{}, ErrLogInvalid
	}
	budget.mutex.Lock()
	defer budget.mutex.Unlock()
	progress := budget.progress()
	if budget.failed || runnerlog.Validate(progress) != nil {
		return runnerlog.Progress{}, ErrLogInvalid
	}
	return progress, nil
}

func (budget *LogBudget) progress() runnerlog.Progress {
	return runnerlog.Progress{
		NativeBytes:     budget.rawBytes,
		NormalizedBytes: budget.normalizedBytes,
		LastSequence:    budget.sequence,
	}
}

func (budget *LogBudget) invalidate() {
	if budget == nil {
		return
	}
	budget.mutex.Lock()
	budget.failed = true
	budget.mutex.Unlock()
}

func (budget *LogBudget) DecodeDockerStream(source io.Reader) ([]LogChunk, error) {
	if budget == nil || source == nil {
		return nil, ErrInvalid
	}
	budget.mutex.Lock()
	defer budget.mutex.Unlock()
	if budget.failed || runnerlog.Validate(budget.progress()) != nil {
		return nil, ErrLogInvalid
	}
	decoder := logDecoder{budget: budget}
	if err := decoder.decode(source); err != nil {
		// A native stream can fail after some bytes have already influenced the
		// run-wide counters. Reusing that budget would make retry behavior depend
		// on an untrusted partial parse, so the complete run fails closed.
		budget.failed = true
		return nil, err
	}
	return decoder.chunks, nil
}

type logDecoder struct {
	budget   *LogBudget
	stdout   logLine
	stderr   logLine
	order    uint64
	chunks   []LogChunk
	buffered []byte
}

type logLine struct {
	content   []byte
	overflow  bool
	lastOrder uint64
}

func (decoder *logDecoder) decode(source io.Reader) error {
	reader := bufio.NewReaderSize(source, 32*1024)
	var header [8]byte
	for {
		read, err := io.ReadFull(reader, header[:])
		if errors.Is(err, io.EOF) && read == 0 {
			break
		}
		if err != nil || read != len(header) ||
			(header[0] != stdoutStream && header[0] != stderrStream) ||
			header[1] != 0 || header[2] != 0 || header[3] != 0 {
			return ErrLogInvalid
		}
		length := int64(binary.BigEndian.Uint32(header[4:]))
		if length == 0 {
			return ErrLogInvalid
		}
		if length > devopsv1.FixedMaxLogBytes-decoder.budget.rawBytes {
			return ErrLogLimit
		}
		line := &decoder.stdout
		label := "[stdout] "
		if header[0] == stderrStream {
			line = &decoder.stderr
			label = "[stderr] "
		}
		decoder.order++
		line.lastOrder = decoder.order
		limited := &io.LimitedReader{R: reader, N: length}
		if err := decoder.consumeFrame(line, label, limited); err != nil {
			return err
		}
		if limited.N != 0 {
			return ErrLogInvalid
		}
		decoder.budget.rawBytes += length
	}
	if err := decoder.flushPending(); err != nil {
		return err
	}
	return decoder.flushChunk()
}

func (decoder *logDecoder) consumeFrame(
	line *logLine,
	label string,
	source io.Reader,
) error {
	buffer := make([]byte, 32*1024)
	for {
		read, err := source.Read(buffer)
		for _, value := range buffer[:read] {
			if value == '\n' {
				if emitErr := decoder.emitLine(line, label, true); emitErr != nil {
					return emitErr
				}
				continue
			}
			if line.overflow {
				continue
			}
			line.content = append(line.content, value)
			if len(line.content) > maximumLogLineBytes {
				line.content = line.content[:0]
				line.overflow = true
			}
		}
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return ErrLogInvalid
		}
		if read == 0 {
			return ErrLogInvalid
		}
	}
}

func (decoder *logDecoder) flushPending() error {
	type pending struct {
		line  *logLine
		label string
	}
	values := []pending{
		{line: &decoder.stdout, label: "[stdout] "},
		{line: &decoder.stderr, label: "[stderr] "},
	}
	if values[0].line.lastOrder > values[1].line.lastOrder {
		values[0], values[1] = values[1], values[0]
	}
	for _, value := range values {
		if len(value.line.content) == 0 && !value.line.overflow {
			continue
		}
		if err := decoder.emitLine(value.line, value.label, false); err != nil {
			return err
		}
	}
	return nil
}

func (decoder *logDecoder) emitLine(line *logLine, label string, newline bool) error {
	content := normalizeLogLine(line.content, line.overflow)
	line.content = line.content[:0]
	line.overflow = false
	line.lastOrder = 0
	output := make([]byte, 0, len(label)+len(content)+1)
	output = append(output, label...)
	output = append(output, content...)
	if newline {
		output = append(output, '\n')
	}
	if int64(len(output)) > devopsv1.FixedMaxLogBytes-decoder.budget.normalizedBytes {
		return ErrLogLimit
	}
	decoder.budget.normalizedBytes += int64(len(output))
	if len(decoder.buffered) > 0 && len(decoder.buffered)+len(output) > maximumLogChunkBytes {
		if err := decoder.flushChunk(); err != nil {
			return err
		}
	}
	decoder.buffered = append(decoder.buffered, output...)
	if len(decoder.buffered) == maximumLogChunkBytes {
		return decoder.flushChunk()
	}
	return nil
}

func (decoder *logDecoder) flushChunk() error {
	if len(decoder.buffered) == 0 {
		return nil
	}
	if decoder.budget.sequence == ^uint64(0) {
		return ErrLogInvalid
	}
	decoder.chunks = append(decoder.chunks, LogChunk{
		Sequence: decoder.budget.sequence + 1,
		Content:  string(decoder.buffered),
	})
	decoder.budget.sequence++
	decoder.buffered = nil
	return nil
}

func normalizeLogLine(content []byte, overflow bool) []byte {
	if overflow {
		return []byte("[matrix:line-too-long]")
	}
	if len(content) > 0 && content[len(content)-1] == '\r' {
		content = content[:len(content)-1]
	}
	if !utf8.Valid(content) {
		return []byte("[matrix:invalid-utf8]")
	}
	if bytes.Contains(content, []byte{0x1b}) {
		return []byte("[matrix:ansi-escape]")
	}
	for _, character := range string(content) {
		if unicode.IsControl(character) && character != '\t' {
			return []byte("[matrix:control-bytes]")
		}
	}
	text := string(content)
	if secretShaped(text) {
		return []byte("[matrix:secret-shaped]")
	}
	if containsAbsolutePath(text) {
		return []byte("[matrix:absolute-path]")
	}
	return append([]byte(nil), content...)
}

func secretShaped(value string) bool {
	lower := strings.ToLower(value)
	for _, marker := range []string{
		"bearer ", "-----begin private key-----", "-----begin rsa private key-----",
		"-----begin ec private key-----", "-----begin openssh private key-----",
	} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	for _, key := range []string{
		"authorization", "proxy_authorization", "proxy-authorization",
		"token", "access_token", "access-token", "refresh_token", "refresh-token",
		"id_token", "id-token", "private_token", "private-token", "deploy_token",
		"deploy-token", "password", "passwd", "secret", "client_secret",
		"client-secret", "credential", "credentials", "api_key", "api-key", "apikey",
		"github_token", "gitlab_token", "ci_job_token", "aws_access_key_id",
		"aws_secret_access_key", "aws_session_token",
	} {
		if sensitiveAssignment(lower, key) {
			return true
		}
	}
	if authorityContainsUserInfo(value) {
		return true
	}
	for _, field := range strings.Fields(value) {
		trimmed := strings.Trim(field, "\"'`[](){}<>,;:")
		lowerTrimmed := strings.ToLower(trimmed)
		if strings.HasPrefix(lowerTrimmed, "ghp_") ||
			strings.HasPrefix(lowerTrimmed, "gho_") ||
			strings.HasPrefix(lowerTrimmed, "ghu_") ||
			strings.HasPrefix(lowerTrimmed, "ghs_") ||
			strings.HasPrefix(lowerTrimmed, "ghr_") ||
			strings.HasPrefix(lowerTrimmed, "github_pat_") ||
			strings.HasPrefix(lowerTrimmed, "glpat-") ||
			strings.HasPrefix(lowerTrimmed, "xoxb-") ||
			strings.HasPrefix(lowerTrimmed, "xoxp-") ||
			strings.HasPrefix(lowerTrimmed, "xoxa-") ||
			strings.HasPrefix(lowerTrimmed, "xoxr-") ||
			strings.HasPrefix(lowerTrimmed, "xoxs-") ||
			awsAccessKey(trimmed) ||
			(strings.HasPrefix(trimmed, "eyJ") && strings.Count(trimmed, ".") == 2) {
			return true
		}
	}
	return false
}

func sensitiveAssignment(value, key string) bool {
	for offset := 0; offset < len(value); {
		index := strings.Index(value[offset:], key)
		if index < 0 {
			return false
		}
		index += offset
		end := index + len(key)
		if (index == 0 || !identifierByte(value[index-1])) &&
			(end == len(value) || !identifierByte(value[end])) {
			for end < len(value) && (value[end] == '\'' || value[end] == '"' || isSpace(value[end])) {
				end++
			}
			if end < len(value) && (value[end] == '=' || value[end] == ':') {
				return true
			}
		}
		offset = index + len(key)
	}
	return false
}

func authorityContainsUserInfo(value string) bool {
	for offset := 0; offset < len(value); {
		marker := strings.Index(value[offset:], "://")
		if marker < 0 {
			return false
		}
		marker += offset
		authority := value[marker+3:]
		if end := strings.IndexAny(authority, "/?# \t"); end >= 0 {
			authority = authority[:end]
		}
		if strings.Contains(authority, "@") {
			return true
		}
		offset = marker + 3
	}
	return false
}

func awsAccessKey(value string) bool {
	if len(value) != 20 || (!strings.HasPrefix(value, "AKIA") && !strings.HasPrefix(value, "ASIA")) {
		return false
	}
	for _, character := range value[4:] {
		if (character < 'A' || character > 'Z') && (character < '0' || character > '9') {
			return false
		}
	}
	return true
}

func identifierByte(value byte) bool {
	return asciiLetter(value) || (value >= '0' && value <= '9') || value == '_'
}

func containsAbsolutePath(value string) bool {
	for index := 0; index < len(value); index++ {
		if value[index] == '/' && pathBoundary(value, index) &&
			index+1 < len(value) && !isSpace(value[index+1]) && value[index+1] != '/' {
			return true
		}
		if value[index] == '/' && index > 0 && value[index-1] == ':' &&
			!remoteURLSchemeBefore(value, index-1) {
			return true
		}
		if index+1 < len(value) && value[index] == '\\' && value[index+1] == '\\' &&
			pathBoundary(value, index) {
			return true
		}
		if index+2 < len(value) && asciiLetter(value[index]) && value[index+1] == ':' &&
			(value[index+2] == '\\' || value[index+2] == '/') && pathBoundary(value, index) {
			return true
		}
	}
	return false
}

func remoteURLSchemeBefore(value string, colon int) bool {
	if colon+2 >= len(value) || value[colon+1] != '/' || value[colon+2] != '/' {
		return false
	}
	start := colon
	for start > 0 && (identifierByte(value[start-1]) ||
		value[start-1] == '+' || value[start-1] == '-' || value[start-1] == '.') {
		start--
	}
	return start < colon && asciiLetter(value[start]) &&
		!strings.EqualFold(value[start:colon], "file")
}

func pathBoundary(value string, index int) bool {
	return index == 0 || isSpace(value[index-1]) || strings.ContainsRune("=([{<\"'", rune(value[index-1]))
}

func isSpace(value byte) bool {
	return value == ' ' || value == '\t'
}

func asciiLetter(value byte) bool {
	return (value >= 'a' && value <= 'z') || (value >= 'A' && value <= 'Z')
}
