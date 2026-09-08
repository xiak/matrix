package executorspoolfile

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"

	devopsbuildv1 "github.com/xiak/matrix/api/adapter/devopsbuild/v1"
	devopsv1 "github.com/xiak/matrix/api/devops/v1"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/sourcearchive"
)

const (
	submissionName     = "submission.json"
	archiveName        = "source.tar.gz"
	ownershipLockName  = ".gateway.lock"
	maximumRootEntries = 256
	maximumStateFiles  = 512
	stagingAttempts    = 16
)

type storedExecution struct {
	key     string
	request devopsbuildv1.Request
	state   stateRecord
}

func (spool *Spool) openRoot() (*os.Root, error) {
	cleaned, err := validateRoot(spool.rootPath)
	if err != nil || cleaned != spool.rootPath {
		return nil, errors.Join(ErrUnavailable, err)
	}
	root, err := os.OpenRoot(cleaned)
	if err != nil {
		return nil, errors.Join(ErrUnavailable, err)
	}
	return root, nil
}

func recoverTemporaryEntries(root *os.Root) error {
	directory, err := root.Open(".")
	if err != nil {
		return err
	}
	entries, readErr := directory.ReadDir(maximumRootEntries + 2)
	closeErr := directory.Close()
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		return errors.Join(readErr, closeErr)
	}
	if closeErr != nil || len(entries) > maximumRootEntries+1 {
		return errors.Join(closeErr, ErrUnavailable)
	}
	removed := false
	for _, entry := range entries {
		name := entry.Name()
		if name == ownershipLockName {
			info, infoErr := entry.Info()
			if infoErr != nil || !validOwnershipFile(info) {
				return errors.Join(ErrUnavailable, infoErr)
			}
			continue
		}
		if validStagingName(name) {
			if entry.Type()&os.ModeSymlink != 0 || !entry.IsDir() {
				return ErrUnavailable
			}
			if err := root.RemoveAll(name); err != nil {
				return err
			}
			removed = true
			continue
		}
		if validStateTemporaryName(name) {
			if entry.Type()&os.ModeSymlink != 0 || !entry.Type().IsRegular() {
				return ErrUnavailable
			}
			if err := root.Remove(name); err != nil {
				return err
			}
			removed = true
		}
	}
	if removed {
		return syncDirectory(root, ".")
	}
	return nil
}

func listExecutionKeys(root *os.Root) ([]string, error) {
	directory, err := root.Open(".")
	if err != nil {
		return nil, err
	}
	entries, readErr := directory.ReadDir(maximumRootEntries + 2)
	closeErr := directory.Close()
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		return nil, errors.Join(readErr, closeErr)
	}
	if closeErr != nil || len(entries) > maximumRootEntries+1 {
		return nil, errors.Join(closeErr, ErrUnavailable)
	}
	keys := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.Name() == ownershipLockName {
			info, infoErr := entry.Info()
			if infoErr != nil || !validOwnershipFile(info) {
				return nil, errors.Join(ErrUnavailable, infoErr)
			}
			continue
		}
		if !validExecutionKey(entry.Name()) || entry.Type()&os.ModeSymlink != 0 || !entry.IsDir() {
			return nil, ErrUnavailable
		}
		info, err := entry.Info()
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() ||
			!privateMode(info.Mode(), 0o700) {
			return nil, errors.Join(ErrUnavailable, err)
		}
		keys = append(keys, entry.Name())
	}
	if len(keys) > maximumRootEntries {
		return nil, ErrUnavailable
	}
	sort.Strings(keys)
	return keys, nil
}

func readExecution(
	ctx context.Context,
	root *os.Root,
	key string,
	expected *devopsbuildv1.Request,
	verifySource bool,
) (storedExecution, bool, error) {
	if ctx == nil || !validExecutionKey(key) {
		return storedExecution{}, false, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return storedExecution{}, false, err
	}
	info, err := root.Lstat(key)
	if errors.Is(err, os.ErrNotExist) {
		return storedExecution{}, false, nil
	}
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() ||
		!privateMode(info.Mode(), 0o700) {
		return storedExecution{}, false, errors.Join(ErrUnavailable, err)
	}

	entries, err := readExecutionEntries(root, key)
	if err != nil {
		return storedExecution{}, false, err
	}
	submission, err := readPrivateFile(
		root, key+"/"+submissionName, devopsbuildv1.MaximumDocumentBytes,
	)
	if err != nil {
		return storedExecution{}, false, err
	}
	request, err := devopsbuildv1.DecodeSubmission(submission)
	if err != nil {
		return storedExecution{}, false, errors.Join(ErrUnavailable, err)
	}
	executionID, err := devopsbuildv1.ExecutionID(request)
	if err != nil || executionKey(executionID) != key {
		return storedExecution{}, false, errors.Join(ErrUnavailable, err)
	}
	if expected != nil && *expected != request {
		return storedExecution{}, false, ErrConflict
	}

	var current stateRecord
	for index, name := range entries.stateNames {
		content, readErr := readPrivateFile(
			root, key+"/"+name, devopsbuildv1.MaximumDocumentBytes,
		)
		if readErr != nil {
			return storedExecution{}, false, readErr
		}
		state, decodeErr := decodeState(request, content)
		if decodeErr != nil || stateFileName(state.Version) != name ||
			state.Version != uint64(index+1) {
			return storedExecution{}, false, errors.Join(ErrUnavailable, decodeErr)
		}
		if index > 0 && validateTransition(request, current, state) != nil {
			return storedExecution{}, false, ErrUnavailable
		}
		current = state
	}
	if verifySource {
		file, openErr := openVerifiedArchive(ctx, root, key+"/"+archiveName, request)
		if openErr != nil {
			return storedExecution{}, false, openErr
		}
		if closeErr := file.Close(); closeErr != nil {
			return storedExecution{}, false, errors.Join(ErrUnavailable, closeErr)
		}
	}
	return storedExecution{key: key, request: request, state: current}, true, nil
}

type executionEntries struct {
	stateNames []string
}

func readExecutionEntries(root *os.Root, key string) (executionEntries, error) {
	directory, err := root.Open(key)
	if err != nil {
		return executionEntries{}, errors.Join(ErrUnavailable, err)
	}
	entries, readErr := directory.ReadDir(maximumStateFiles + 3)
	closeErr := directory.Close()
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		return executionEntries{}, errors.Join(ErrUnavailable, readErr, closeErr)
	}
	if closeErr != nil || len(entries) > maximumStateFiles+2 {
		return executionEntries{}, errors.Join(ErrUnavailable, closeErr)
	}
	foundSubmission := false
	foundArchive := false
	stateNames := make([]string, 0, len(entries)-2)
	for _, entry := range entries {
		if entry.Type()&os.ModeSymlink != 0 || !entry.Type().IsRegular() {
			return executionEntries{}, ErrUnavailable
		}
		switch entry.Name() {
		case submissionName:
			if foundSubmission {
				return executionEntries{}, ErrUnavailable
			}
			foundSubmission = true
		case archiveName:
			if foundArchive {
				return executionEntries{}, ErrUnavailable
			}
			foundArchive = true
		default:
			if _, ok := stateVersion(entry.Name()); !ok {
				return executionEntries{}, ErrUnavailable
			}
			stateNames = append(stateNames, entry.Name())
		}
	}
	if !foundSubmission || !foundArchive || len(stateNames) == 0 ||
		len(stateNames) > maximumStateFiles {
		return executionEntries{}, ErrUnavailable
	}
	sort.Strings(stateNames)
	return executionEntries{stateNames: stateNames}, nil
}

func openVerifiedArchive(
	ctx context.Context,
	root *os.Root,
	path string,
	request devopsbuildv1.Request,
) (*os.File, error) {
	info, err := root.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() ||
		!privateMode(info.Mode(), 0o600) || info.Size() != request.SourceArchiveBytes ||
		info.Size() <= 0 || info.Size() > devopsv1.MaximumSourceArchiveBytes {
		return nil, errors.Join(ErrUnavailable, err)
	}
	file, err := root.Open(path)
	if err != nil {
		return nil, errors.Join(ErrUnavailable, err)
	}
	actual, statErr := file.Stat()
	if statErr != nil || !actual.Mode().IsRegular() || actual.Size() != request.SourceArchiveBytes {
		_ = file.Close()
		return nil, errors.Join(ErrUnavailable, statErr)
	}
	digest := sha256.New()
	content, inspectErr := sourcearchive.Inspect(ctx, io.TeeReader(file, digest))
	if err := ctx.Err(); err != nil {
		_ = file.Close()
		return nil, err
	}
	actualDigest := "sha256:" + hex.EncodeToString(digest.Sum(nil))
	if inspectErr != nil || actualDigest != request.SourceArchiveDigest ||
		content.ExpandedBytes != request.SourceExpandedBytes ||
		content.PathCount != request.SourcePathCount {
		_ = file.Close()
		return nil, errors.Join(ErrUnavailable, inspectErr)
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		_ = file.Close()
		return nil, errors.Join(ErrUnavailable, err)
	}
	return file, nil
}

func readPrivateFile(root *os.Root, path string, maximum int) ([]byte, error) {
	info, err := root.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() ||
		!privateMode(info.Mode(), 0o600) || info.Size() <= 0 ||
		info.Size() > int64(maximum) {
		return nil, errors.Join(ErrUnavailable, err)
	}
	file, err := root.Open(path)
	if err != nil {
		return nil, errors.Join(ErrUnavailable, err)
	}
	actual, statErr := file.Stat()
	if statErr != nil || !actual.Mode().IsRegular() ||
		!privateMode(actual.Mode(), 0o600) || actual.Size() != info.Size() {
		_ = file.Close()
		return nil, errors.Join(ErrUnavailable, statErr)
	}
	content, readErr := io.ReadAll(io.LimitReader(file, int64(maximum)+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || int64(len(content)) != info.Size() {
		return nil, errors.Join(ErrUnavailable, readErr, closeErr)
	}
	return content, nil
}

func writePrivateFile(root *os.Root, path string, content []byte) error {
	if len(content) == 0 || len(content) > devopsbuildv1.MaximumDocumentBytes {
		return ErrUnavailable
	}
	file, err := root.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	written, writeErr := file.Write(content)
	if writeErr == nil && written != len(content) {
		writeErr = io.ErrShortWrite
	}
	if writeErr == nil {
		writeErr = file.Sync()
	}
	closeErr := file.Close()
	return errors.Join(writeErr, closeErr)
}

func appendState(
	root *os.Root,
	execution storedExecution,
	next stateRecord,
) error {
	if validateTransition(execution.request, execution.state, next) != nil {
		return ErrInvalid
	}
	content, err := encodeState(execution.request, next)
	if err != nil {
		return err
	}
	temporary, file, err := createStateTemporary(root, execution.key, next.Version)
	if err != nil {
		return errors.Join(ErrUnavailable, err)
	}
	published := false
	defer func() {
		if !published {
			_ = root.Remove(temporary)
		}
	}()
	written, writeErr := file.Write(content)
	if writeErr == nil && written != len(content) {
		writeErr = io.ErrShortWrite
	}
	if writeErr == nil {
		writeErr = file.Sync()
	}
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		return errors.Join(ErrUnavailable, writeErr, closeErr)
	}
	if err := root.Rename(temporary, execution.key+"/"+stateFileName(next.Version)); err != nil {
		return errors.Join(ErrUnavailable, err)
	}
	published = true
	if err := syncDirectory(root, execution.key); err != nil {
		return errors.Join(ErrOutcomeUnknown, err)
	}
	return nil
}

func createStaging(root *os.Root) (string, error) {
	for attempt := 0; attempt < stagingAttempts; attempt++ {
		random, err := randomHex(8)
		if err != nil {
			return "", err
		}
		name := ".staging-" + random
		if err := root.Mkdir(name, 0o700); err == nil {
			return name, nil
		} else if !errors.Is(err, os.ErrExist) {
			return "", err
		}
	}
	return "", ErrUnavailable
}

func createStateTemporary(
	root *os.Root,
	key string,
	version uint64,
) (string, *os.File, error) {
	for attempt := 0; attempt < stagingAttempts; attempt++ {
		random, err := randomHex(8)
		if err != nil {
			return "", nil, err
		}
		name := fmt.Sprintf(".state-%s-%020d-%s.tmp", key, version, random)
		file, err := root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			return name, file, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return "", nil, err
		}
	}
	return "", nil, ErrUnavailable
}

func stateFileName(version uint64) string {
	return fmt.Sprintf("state-%020d.json", version)
}

func stateVersion(name string) (uint64, bool) {
	if len(name) != len("state-")+20+len(".json") ||
		!strings.HasPrefix(name, "state-") || !strings.HasSuffix(name, ".json") {
		return 0, false
	}
	value := strings.TrimSuffix(strings.TrimPrefix(name, "state-"), ".json")
	version, err := strconv.ParseUint(value, 10, 64)
	return version, err == nil && version > 0 && stateFileName(version) == name
}

func executionKey(executionID string) string {
	if devopsv1.ValidateDigest("executionId", executionID) != nil ||
		!strings.HasPrefix(executionID, "sha256:") {
		return ""
	}
	return strings.TrimPrefix(executionID, "sha256:")
}

func validExecutionKey(value string) bool {
	return len(value) == sha256.Size*2 && lowerHex(value)
}

func validStagingName(value string) bool {
	return len(value) == len(".staging-")+16 && strings.HasPrefix(value, ".staging-") &&
		lowerHex(strings.TrimPrefix(value, ".staging-"))
}

func validStateTemporaryName(value string) bool {
	if !strings.HasPrefix(value, ".state-") || !strings.HasSuffix(value, ".tmp") {
		return false
	}
	parts := strings.Split(strings.TrimSuffix(strings.TrimPrefix(value, ".state-"), ".tmp"), "-")
	if len(parts) != 3 || !validExecutionKey(parts[0]) || len(parts[1]) != 20 ||
		len(parts[2]) != 16 || !lowerHex(parts[2]) {
		return false
	}
	_, err := strconv.ParseUint(parts[1], 10, 64)
	return err == nil
}

func lowerHex(value string) bool {
	if value == "" {
		return false
	}
	for _, character := range value {
		if (character < '0' || character > '9') &&
			(character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func randomHex(bytesCount int) (string, error) {
	value := make([]byte, bytesCount)
	if _, err := io.ReadFull(rand.Reader, value); err != nil {
		return "", err
	}
	return hex.EncodeToString(value), nil
}

func validateRoot(rootPath string) (string, error) {
	if rootPath == "" || !filepath.IsAbs(rootPath) {
		return "", errors.New("executor spool root must be absolute")
	}
	cleaned := filepath.Clean(rootPath)
	info, err := os.Lstat(cleaned)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() ||
		!privateMode(info.Mode(), 0o700) {
		return "", errors.New("executor spool root must be a private directory")
	}
	resolved, err := filepath.EvalSymlinks(cleaned)
	if err != nil || !samePath(cleaned, resolved) {
		return "", errors.New("executor spool root cannot traverse a symbolic link")
	}
	return cleaned, nil
}

func samePath(left, right string) bool {
	if runtime.GOOS == "windows" {
		return strings.EqualFold(filepath.Clean(left), filepath.Clean(right))
	}
	return filepath.Clean(left) == filepath.Clean(right)
}

func privateMode(actual os.FileMode, expected os.FileMode) bool {
	return runtime.GOOS == "windows" || actual.Perm() == expected
}

func validOwnershipFile(info os.FileInfo) bool {
	return info != nil && info.Mode()&os.ModeSymlink == 0 && info.Mode().IsRegular() &&
		info.Size() == 0 && privateMode(info.Mode(), 0o600)
}

func syncDirectory(root *os.Root, name string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	directory, err := root.Open(name)
	if err != nil {
		return err
	}
	syncErr := directory.Sync()
	return errors.Join(syncErr, directory.Close())
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (reader *contextReader) Read(value []byte) (int, error) {
	if err := reader.ctx.Err(); err != nil {
		return 0, err
	}
	return reader.reader.Read(value)
}

type errorTrackingWriter struct {
	destination io.Writer
	err         error
}

func (writer *errorTrackingWriter) Write(value []byte) (int, error) {
	written, err := writer.destination.Write(value)
	if err != nil {
		writer.err = err
	}
	return written, err
}
