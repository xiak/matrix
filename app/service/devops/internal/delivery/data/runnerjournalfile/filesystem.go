package runnerjournalfile

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
	identityName             = "runner.json"
	identityTemporaryName    = ".runner.tmp"
	ownershipLockName        = ".runner.lock"
	assignmentName           = "assignment.json"
	archiveName              = "source.tar.gz"
	maximumJournalExecutions = 64
	maximumStateFiles        = 512
	maximumRootEntries       = maximumJournalExecutions + 10
	stagingAttempts          = 16
)

type storedExecution struct {
	key        string
	assignment devopsbuildv1.Assignment
	state      stateRecord
}

type executionEntries struct {
	stateNames []string
}

func validateRoot(rootPath string) (string, error) {
	if rootPath == "" || !filepath.IsAbs(rootPath) {
		return "", errors.New("runner journal root must be absolute")
	}
	cleaned := filepath.Clean(rootPath)
	info, err := os.Lstat(cleaned)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() ||
		!privateMode(info.Mode(), 0o700) {
		return "", errors.New("runner journal root must be a private directory")
	}
	resolved, err := filepath.EvalSymlinks(cleaned)
	if err != nil || !samePath(cleaned, resolved) {
		return "", errors.New("runner journal root cannot traverse a symbolic link")
	}
	return cleaned, nil
}

func (journal *Journal) openRoot() (*os.Root, error) {
	cleaned, err := validateRoot(journal.rootPath)
	if err != nil || cleaned != journal.rootPath {
		return nil, errors.Join(ErrUnavailable, err)
	}
	root, err := os.OpenRoot(cleaned)
	if err != nil {
		return nil, errors.Join(ErrUnavailable, err)
	}
	return root, nil
}

func recoverStaging(root *os.Root) error {
	directory, err := root.Open(".")
	if err != nil {
		return err
	}
	entries, readErr := directory.ReadDir(maximumRootEntries + 1)
	closeErr := directory.Close()
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		return errors.Join(readErr, closeErr)
	}
	if closeErr != nil || len(entries) > maximumRootEntries {
		return errors.Join(closeErr, ErrUnavailable)
	}
	removed := false
	for _, entry := range entries {
		if entry.Name() == ownershipLockName {
			info, infoErr := entry.Info()
			if infoErr != nil || !validOwnershipFile(info) {
				return errors.Join(ErrUnavailable, infoErr)
			}
			continue
		}
		if entry.Name() == identityTemporaryName || validStateTemporaryName(entry.Name()) {
			info, infoErr := entry.Info()
			if infoErr != nil || info.Mode()&os.ModeSymlink != 0 ||
				!info.Mode().IsRegular() || !privateMode(info.Mode(), 0o600) {
				return errors.Join(ErrUnavailable, infoErr)
			}
			if err := root.Remove(entry.Name()); err != nil {
				return err
			}
			removed = true
			continue
		}
		if !validStagingName(entry.Name()) {
			continue
		}
		if entry.Type()&os.ModeSymlink != 0 || !entry.IsDir() {
			return ErrUnavailable
		}
		if err := root.RemoveAll(entry.Name()); err != nil {
			return err
		}
		removed = true
	}
	if removed {
		return syncDirectory(root, ".")
	}
	return nil
}

func countExecutionDirectories(root *os.Root) (int, error) {
	directory, err := root.Open(".")
	if err != nil {
		return 0, err
	}
	entries, readErr := directory.ReadDir(maximumRootEntries + 1)
	closeErr := directory.Close()
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		return 0, errors.Join(readErr, closeErr)
	}
	if closeErr != nil || len(entries) > maximumRootEntries {
		return 0, errors.Join(closeErr, ErrUnavailable)
	}
	count := 0
	foundIdentity := false
	for _, entry := range entries {
		name := entry.Name()
		if name == ownershipLockName {
			info, infoErr := entry.Info()
			if infoErr != nil || !validOwnershipFile(info) {
				return 0, errors.Join(ErrUnavailable, infoErr)
			}
			continue
		}
		if name == identityName {
			if foundIdentity || entry.Type()&os.ModeSymlink != 0 ||
				!entry.Type().IsRegular() {
				return 0, ErrUnavailable
			}
			foundIdentity = true
			continue
		}
		if validStagingName(name) {
			if entry.Type()&os.ModeSymlink != 0 || !entry.IsDir() {
				return 0, ErrUnavailable
			}
			info, infoErr := entry.Info()
			if infoErr != nil || !info.IsDir() || !privateMode(info.Mode(), 0o700) {
				return 0, errors.Join(ErrUnavailable, infoErr)
			}
			continue
		}
		if !validExecutionKey(name) || entry.Type()&os.ModeSymlink != 0 ||
			!entry.IsDir() {
			return 0, ErrUnavailable
		}
		count++
	}
	if !foundIdentity || count > maximumJournalExecutions {
		return 0, ErrUnavailable
	}
	return count, nil
}

func validateStagingShape(
	root *os.Root,
	name string,
	wantArchive bool,
	stateName string,
) error {
	if !validStagingName(name) {
		return ErrUnavailable
	}
	directory, err := root.Open(name)
	if err != nil {
		return errors.Join(ErrUnavailable, err)
	}
	entries, readErr := directory.ReadDir(4)
	closeErr := directory.Close()
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		return errors.Join(ErrUnavailable, readErr, closeErr)
	}
	wantEntries := 1
	if wantArchive {
		wantEntries = 3
	}
	if closeErr != nil || len(entries) != wantEntries {
		return errors.Join(ErrUnavailable, closeErr)
	}
	foundAssignment := false
	foundArchive := false
	foundState := false
	for _, entry := range entries {
		info, infoErr := entry.Info()
		if infoErr != nil || entry.Type()&os.ModeSymlink != 0 ||
			!info.Mode().IsRegular() || !privateMode(info.Mode(), 0o600) {
			return errors.Join(ErrUnavailable, infoErr)
		}
		switch entry.Name() {
		case assignmentName:
			foundAssignment = true
		case archiveName:
			foundArchive = true
		case stateName:
			foundState = stateName != ""
		default:
			return ErrUnavailable
		}
	}
	if !foundAssignment || foundArchive != wantArchive || foundState != wantArchive {
		return ErrUnavailable
	}
	return nil
}

func listExecutionKeys(root *os.Root) ([]string, error) {
	directory, err := root.Open(".")
	if err != nil {
		return nil, err
	}
	entries, readErr := directory.ReadDir(maximumJournalExecutions + 3)
	closeErr := directory.Close()
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		return nil, errors.Join(readErr, closeErr)
	}
	if closeErr != nil || len(entries) > maximumJournalExecutions+2 {
		return nil, errors.Join(closeErr, ErrUnavailable)
	}
	keys := make([]string, 0, len(entries)-1)
	foundIdentity := false
	for _, entry := range entries {
		if entry.Name() == ownershipLockName {
			info, infoErr := entry.Info()
			if infoErr != nil || !validOwnershipFile(info) {
				return nil, errors.Join(ErrUnavailable, infoErr)
			}
			continue
		}
		if entry.Name() == identityName {
			if foundIdentity || entry.Type()&os.ModeSymlink != 0 ||
				!entry.Type().IsRegular() {
				return nil, ErrUnavailable
			}
			foundIdentity = true
			continue
		}
		if !validExecutionKey(entry.Name()) || entry.Type()&os.ModeSymlink != 0 ||
			!entry.IsDir() {
			return nil, ErrUnavailable
		}
		info, infoErr := entry.Info()
		if infoErr != nil || !info.IsDir() || !privateMode(info.Mode(), 0o700) {
			return nil, errors.Join(ErrUnavailable, infoErr)
		}
		keys = append(keys, entry.Name())
	}
	if !foundIdentity || len(keys) > maximumJournalExecutions {
		return nil, ErrUnavailable
	}
	sort.Strings(keys)
	return keys, nil
}

func readExecution(
	ctx context.Context,
	root *os.Root,
	key string,
	runnerID string,
	verifyArchive bool,
) (storedExecution, bool, error) {
	if ctx == nil || !validExecutionKey(key) || !validRunnerID(runnerID) {
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
	content, err := readPrivateFile(
		root, key+"/"+assignmentName, devopsbuildv1.MaximumDocumentBytes,
	)
	if err != nil {
		return storedExecution{}, false, err
	}
	assignment, err := devopsbuildv1.DecodeAssignment(content)
	if err != nil || assignment.Mode != devopsbuildv1.AssignmentExecute ||
		assignment.FencingToken != 1 || executionKey(assignment.ExecutionID) != key {
		return storedExecution{}, false, errors.Join(ErrUnavailable, err)
	}
	if verifyArchive {
		archive, archiveErr := openVerifiedArchive(
			ctx, root, key+"/"+archiveName, assignment.Request,
		)
		if archiveErr != nil {
			return storedExecution{}, false, archiveErr
		}
		if closeErr := archive.Close(); closeErr != nil {
			return storedExecution{}, false, errors.Join(ErrUnavailable, closeErr)
		}
	}
	var current stateRecord
	for index, name := range entries.stateNames {
		stateContent, readErr := readPrivateFile(
			root, key+"/"+name, devopsbuildv1.MaximumDocumentBytes,
		)
		if readErr != nil {
			return storedExecution{}, false, readErr
		}
		state, decodeErr := decodeState(assignment.Request, stateContent)
		if decodeErr != nil || state.Version != uint64(index+1) ||
			stateFileName(state.Version) != name || state.RunnerID != runnerID {
			return storedExecution{}, false, errors.Join(ErrUnavailable, decodeErr)
		}
		if index == 0 {
			if state.Mode != assignment.Mode ||
				state.FencingToken != assignment.FencingToken ||
				!state.LeaseExpiresAt.Equal(assignment.LeaseExpiresAt) {
				return storedExecution{}, false, ErrUnavailable
			}
		} else if validateTransition(current, state) != nil {
			return storedExecution{}, false, ErrUnavailable
		}
		current = state
	}
	return storedExecution{key: key, assignment: assignment, state: current}, true, nil
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
	if closeErr != nil || len(entries) < 3 || len(entries) > maximumStateFiles+2 {
		return executionEntries{}, errors.Join(ErrUnavailable, closeErr)
	}
	foundAssignment := false
	foundArchive := false
	stateNames := make([]string, 0, len(entries)-2)
	for _, entry := range entries {
		if entry.Type()&os.ModeSymlink != 0 || !entry.Type().IsRegular() {
			return executionEntries{}, ErrUnavailable
		}
		switch entry.Name() {
		case assignmentName:
			if foundAssignment {
				return executionEntries{}, ErrUnavailable
			}
			foundAssignment = true
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
	if !foundAssignment || !foundArchive || len(stateNames) == 0 ||
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
	if statErr != nil || !os.SameFile(info, actual) || !actual.Mode().IsRegular() ||
		!privateMode(actual.Mode(), 0o600) || actual.Size() != request.SourceArchiveBytes {
		_ = file.Close()
		return nil, errors.Join(ErrUnavailable, statErr)
	}
	digest := sha256.New()
	content, inspectErr := sourcearchive.Inspect(ctx, io.TeeReader(file, digest))
	if ctxErr := ctx.Err(); ctxErr != nil {
		_ = file.Close()
		return nil, ctxErr
	}
	actualDigest := "sha256:" + hex.EncodeToString(digest.Sum(nil))
	after, afterErr := file.Stat()
	if inspectErr != nil || afterErr != nil || !os.SameFile(actual, after) ||
		after.Size() != actual.Size() || after.ModTime() != actual.ModTime() ||
		actualDigest != request.SourceArchiveDigest ||
		content.ExpandedBytes != request.SourceExpandedBytes ||
		content.PathCount != request.SourcePathCount {
		_ = file.Close()
		return nil, errors.Join(ErrUnavailable, inspectErr, afterErr)
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
	if statErr != nil || !os.SameFile(info, actual) || !actual.Mode().IsRegular() ||
		!privateMode(actual.Mode(), 0o600) || actual.Size() != info.Size() {
		_ = file.Close()
		return nil, errors.Join(ErrUnavailable, statErr)
	}
	content, readErr := io.ReadAll(io.LimitReader(file, int64(maximum)+1))
	after, afterErr := file.Stat()
	closeErr := file.Close()
	if readErr != nil || afterErr != nil || closeErr != nil ||
		int64(len(content)) != info.Size() || !os.SameFile(actual, after) ||
		after.Size() != actual.Size() || after.ModTime() != actual.ModTime() {
		return nil, errors.Join(ErrUnavailable, readErr, afterErr, closeErr)
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

func appendState(root *os.Root, execution storedExecution, next stateRecord) error {
	if validateTransition(execution.state, next) != nil {
		return ErrInvalid
	}
	content, err := encodeState(execution.assignment.Request, next)
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
		name := ".claim-" + random
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
	return len(value) == len(".claim-")+16 && strings.HasPrefix(value, ".claim-") &&
		lowerHex(strings.TrimPrefix(value, ".claim-"))
}

func validStateTemporaryName(value string) bool {
	if !strings.HasPrefix(value, ".state-") || !strings.HasSuffix(value, ".tmp") {
		return false
	}
	parts := strings.Split(strings.TrimSuffix(strings.TrimPrefix(value, ".state-"), ".tmp"), "-")
	if len(parts) != 3 || !validExecutionKey(parts[0]) || len(parts[1]) != 20 ||
		len(parts[2]) != 16 || !lowerHex(parts[1]) || !lowerHex(parts[2]) {
		return false
	}
	_, err := strconv.ParseUint(parts[1], 10, 64)
	return err == nil
}

func randomHex(bytesCount int) (string, error) {
	value := make([]byte, bytesCount)
	if _, err := io.ReadFull(rand.Reader, value); err != nil {
		return "", err
	}
	return hex.EncodeToString(value), nil
}

func privateMode(actual os.FileMode, expected os.FileMode) bool {
	return runtime.GOOS == "windows" || actual.Perm() == expected
}

func samePath(left, right string) bool {
	if runtime.GOOS == "windows" {
		return strings.EqualFold(filepath.Clean(left), filepath.Clean(right))
	}
	return filepath.Clean(left) == filepath.Clean(right)
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
