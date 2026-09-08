// Package runnerworkspacefile owns the private, immutable source workspaces
// consumed by the dedicated Matrix DevOps runner's sandbox adapter.
package runnerworkspacefile

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"

	devopsbuildv1 "github.com/xiak/matrix/api/adapter/devopsbuild/v1"
	devopsv1 "github.com/xiak/matrix/api/devops/v1"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/sourcearchive"
)

const (
	rootIdentityName         = "runner.json"
	rootIdentityTemporary    = ".runner.tmp"
	ownershipLockName        = ".workspace.lock"
	manifestName             = "workspace.json"
	sourceDirectoryName      = "source"
	maximumWorkspaces        = 64
	maximumWorkspaceEntries  = maximumWorkspaces + 8
	maximumWorkspaceChildren = 3
	stagingAttempts          = 16
)

var (
	ErrInvalid        = errors.New("runner workspace input is invalid")
	ErrUnavailable    = errors.New("runner workspace is unavailable")
	ErrConflict       = errors.New("runner workspace conflicts")
	ErrOutcomeUnknown = errors.New("runner workspace outcome is unknown")
)

type Workspace struct {
	ExecutionID string
	TreeDigest  string
	SourceRoot  string
}

type Store struct {
	rootPath  string
	runnerID  string
	ownership *ownership
	mutex     sync.Mutex
	closed    bool
}

type rootIdentity struct {
	SchemaVersion uint32 `json:"schemaVersion"`
	RunnerID      string `json:"runnerId"`
	ContentDigest string `json:"contentDigest"`
}

// New opens one runner-owned workspace root and holds its operating-system
// lock until Close. Another process cannot recover, publish, or reuse this root
// concurrently.
func New(rootPath, runnerID string) (*Store, error) {
	cleaned, err := validateRoot(rootPath)
	if err != nil || !validRunnerID(runnerID) {
		return nil, ErrInvalid
	}
	owner, err := acquireOwnership(cleaned)
	if err != nil {
		return nil, err
	}
	store := &Store{rootPath: cleaned, runnerID: runnerID, ownership: owner}
	valid := false
	defer func() {
		if !valid {
			_ = owner.Close()
		}
	}()
	root, err := store.openRoot()
	if err != nil {
		return nil, err
	}
	defer root.Close()
	if err := recoverStaging(root); err != nil {
		return nil, err
	}
	if err := ensureRootIdentity(root, runnerID); err != nil {
		return nil, err
	}
	keys, err := listWorkspaceKeys(root)
	if err != nil {
		return nil, err
	}
	for _, key := range keys {
		value, readErr := readManifest(root, key)
		if readErr != nil || value.RunnerID != runnerID || value.ExecutionID != "sha256:"+key {
			return nil, errors.Join(ErrUnavailable, readErr)
		}
	}
	valid = true
	return store, nil
}

func (store *Store) Close() error {
	if store == nil {
		return nil
	}
	store.mutex.Lock()
	defer store.mutex.Unlock()
	if store.closed {
		return nil
	}
	store.closed = true
	return store.ownership.Close()
}

// Ensure consumes and closes archive. It either atomically publishes a new
// immutable source tree or fully re-proves the archive, manifest, and existing
// tree before returning an equal workspace.
func (store *Store) Ensure(
	ctx context.Context,
	executionID string,
	request devopsbuildv1.Request,
	archive io.ReadCloser,
) (workspace Workspace, result error) {
	if archive == nil {
		return Workspace{}, ErrInvalid
	}
	defer func() {
		if closeErr := archive.Close(); closeErr != nil {
			if workspace.SourceRoot != "" {
				result = errors.Join(result, ErrOutcomeUnknown, closeErr)
			} else {
				result = errors.Join(result, ErrUnavailable, closeErr)
			}
			workspace = Workspace{}
		}
	}()
	if store == nil || ctx == nil || devopsbuildv1.ValidateRequest(request) != nil {
		return Workspace{}, ErrInvalid
	}
	wantExecutionID, err := devopsbuildv1.ExecutionID(request)
	if err != nil || executionID != wantExecutionID {
		return Workspace{}, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return Workspace{}, err
	}
	store.mutex.Lock()
	defer store.mutex.Unlock()
	if store.closed || store.ownership == nil {
		return Workspace{}, ErrUnavailable
	}
	root, err := store.openRoot()
	if err != nil {
		return Workspace{}, err
	}
	defer root.Close()
	key := executionKey(executionID)
	info, err := root.Lstat(key)
	if err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || !privateMode(info.Mode(), 0o700) {
			return Workspace{}, ErrUnavailable
		}
		return store.reuse(ctx, root, key, executionID, request, archive)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return Workspace{}, errors.Join(ErrUnavailable, err)
	}
	return store.publish(ctx, root, key, executionID, request, archive)
}

func (store *Store) reuse(
	ctx context.Context,
	root *os.Root,
	key string,
	executionID string,
	request devopsbuildv1.Request,
	archive io.Reader,
) (Workspace, error) {
	value, err := readManifest(root, key)
	if err != nil {
		return Workspace{}, err
	}
	if value.RunnerID != store.runnerID ||
		validateManifestRequest(value, executionID, request) != nil {
		return Workspace{}, ErrConflict
	}
	archiveTree, err := consumeArchive(ctx, archive, request, nil)
	if err != nil {
		return Workspace{}, err
	}
	publishedTree, err := scanPublishedTree(ctx, root, key)
	if err != nil || archiveTree != publishedTree || !manifestMatchesTree(value, publishedTree) {
		return Workspace{}, errors.Join(ErrUnavailable, err)
	}
	return store.workspace(root, key, value)
}

func (store *Store) publish(
	ctx context.Context,
	root *os.Root,
	key string,
	executionID string,
	request devopsbuildv1.Request,
	archive io.Reader,
) (workspace Workspace, result error) {
	keys, err := listWorkspaceKeys(root)
	if err != nil || len(keys) >= maximumWorkspaces {
		return Workspace{}, errors.Join(ErrUnavailable, err)
	}
	staging, err := createStaging(root, key)
	if err != nil {
		return Workspace{}, errors.Join(ErrUnavailable, err)
	}
	published := false
	defer func() {
		if !published {
			if cleanupErr := discardStaging(root, staging); cleanupErr != nil {
				workspace = Workspace{}
				result = errors.Join(result, ErrUnavailable, cleanupErr)
			}
		}
	}()
	sourceRoot := staging + "/" + sourceDirectoryName
	if err := root.Mkdir(sourceRoot, 0o700); err != nil {
		return Workspace{}, errors.Join(ErrUnavailable, err)
	}
	tree, err := consumeArchive(
		ctx,
		archive,
		request,
		func(member sourcearchive.Member, body io.Reader, digest io.Writer) error {
			return writeMember(root, sourceRoot, member, body, digest)
		},
	)
	if err != nil {
		return Workspace{}, err
	}
	if err := sealSourceTree(root, sourceRoot); err != nil {
		return Workspace{}, err
	}
	value, err := newManifest(store.runnerID, executionID, request, tree)
	if err != nil {
		return Workspace{}, err
	}
	content, err := encodeManifest(value)
	if err != nil || writePrivateFile(root, staging+"/"+manifestName, content) != nil {
		return Workspace{}, errors.Join(ErrUnavailable, err)
	}
	if err := syncDirectory(root, staging); err != nil {
		return Workspace{}, errors.Join(ErrUnavailable, err)
	}
	if err := validateWorkspaceShape(root, staging); err != nil {
		return Workspace{}, err
	}
	confirmed, err := scanTree(ctx, root, sourceRoot)
	if err != nil || confirmed != tree || !manifestMatchesTree(value, confirmed) {
		return Workspace{}, errors.Join(ErrUnavailable, err)
	}
	if err := root.Rename(staging, key); err != nil {
		return Workspace{}, errors.Join(ErrUnavailable, err)
	}
	published = true
	if err := syncDirectory(root, "."); err != nil {
		return Workspace{}, errors.Join(ErrOutcomeUnknown, err)
	}
	return store.workspace(root, key, value)
}

func (store *Store) workspace(
	root *os.Root,
	key string,
	value manifest,
) (Workspace, error) {
	sourceRoot := filepath.Join(store.rootPath, key, sourceDirectoryName)
	info, err := root.Lstat(key + "/" + sourceDirectoryName)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() ||
		!privateMode(info.Mode(), 0o555) {
		return Workspace{}, errors.Join(ErrUnavailable, err)
	}
	return Workspace{
		ExecutionID: value.ExecutionID,
		TreeDigest:  value.TreeDigest,
		SourceRoot:  sourceRoot,
	}, nil
}

func (store *Store) openRoot() (*os.Root, error) {
	cleaned, err := validateRoot(store.rootPath)
	if err != nil || cleaned != store.rootPath {
		return nil, errors.Join(ErrUnavailable, err)
	}
	root, err := os.OpenRoot(cleaned)
	if err != nil {
		return nil, errors.Join(ErrUnavailable, err)
	}
	return root, nil
}

func consumeArchive(
	ctx context.Context,
	archive io.Reader,
	request devopsbuildv1.Request,
	write func(sourcearchive.Member, io.Reader, io.Writer) error,
) (treeEvidence, error) {
	digest := startTreeDigest()
	archiveDigest := sha256.New()
	counted := &countingReader{reader: io.LimitReader(archive, request.SourceArchiveBytes+1)}
	directories := make(map[string]struct{})
	content, err := sourcearchive.Visit(
		ctx,
		io.TeeReader(counted, archiveDigest),
		func(member sourcearchive.Member, body io.Reader) error {
			if err := addParentDirectories(directories, member.Path); err != nil {
				return err
			}
			writeTreeHeader(digest, member.Path, member.Executable, member.Size)
			if write != nil {
				return write(member, body, digest)
			}
			copied, copyErr := io.Copy(digest, body)
			if copyErr != nil || copied != member.Size {
				return errors.Join(ErrUnavailable, copyErr)
			}
			return nil
		},
	)
	if ctxErr := ctx.Err(); ctxErr != nil {
		return treeEvidence{}, ctxErr
	}
	if err != nil || counted.bytes != request.SourceArchiveBytes ||
		"sha256:"+hex.EncodeToString(archiveDigest.Sum(nil)) != request.SourceArchiveDigest ||
		content.ExpandedBytes != request.SourceExpandedBytes ||
		content.PathCount != request.SourcePathCount {
		return treeEvidence{}, errors.Join(ErrUnavailable, err)
	}
	return treeEvidence{
		ExpandedBytes:  content.ExpandedBytes,
		PathCount:      content.PathCount,
		DirectoryCount: uint64(len(directories)),
		TreeDigest:     finishTreeDigest(digest),
	}, nil
}

type countingReader struct {
	reader io.Reader
	bytes  int64
}

func (reader *countingReader) Read(buffer []byte) (int, error) {
	read, err := reader.reader.Read(buffer)
	reader.bytes += int64(read)
	return read, err
}

func writeMember(
	root *os.Root,
	sourceRoot string,
	member sourcearchive.Member,
	body io.Reader,
	digest io.Writer,
) error {
	if err := ensureMemberDirectories(root, sourceRoot, member.Path); err != nil {
		return err
	}
	memberPath := sourceRoot + "/" + member.Path
	file, err := root.OpenFile(memberPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return errors.Join(ErrUnavailable, err)
	}
	copied, copyErr := io.Copy(io.MultiWriter(file, digest), body)
	if copyErr == nil && copied != member.Size {
		copyErr = io.ErrUnexpectedEOF
	}
	if copyErr == nil {
		copyErr = file.Sync()
	}
	closeErr := file.Close()
	if copyErr != nil || closeErr != nil {
		return errors.Join(ErrUnavailable, copyErr, closeErr)
	}
	mode := os.FileMode(0o444)
	if member.Executable {
		mode = 0o555
	}
	if err := root.Chmod(memberPath, mode); err != nil {
		return errors.Join(ErrUnavailable, err)
	}
	if err := syncFile(root, memberPath); err != nil {
		return errors.Join(ErrUnavailable, err)
	}
	return nil
}

func addParentDirectories(directories map[string]struct{}, memberPath string) error {
	for parent := filepath.ToSlash(filepath.Dir(memberPath)); parent != "."; parent = filepath.ToSlash(filepath.Dir(parent)) {
		if _, found := directories[parent]; found {
			continue
		}
		if len(directories) >= int(sourcearchive.MaximumPathCount) {
			return ErrUnavailable
		}
		directories[parent] = struct{}{}
	}
	return nil
}

func ensureMemberDirectories(root *os.Root, sourceRoot, memberPath string) error {
	parents := make([]string, 0, 8)
	for parent := filepath.ToSlash(filepath.Dir(memberPath)); parent != "."; parent = filepath.ToSlash(filepath.Dir(parent)) {
		parents = append(parents, parent)
	}
	for index := len(parents) - 1; index >= 0; index-- {
		name := sourceRoot + "/" + parents[index]
		if err := root.Mkdir(name, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
			return errors.Join(ErrUnavailable, err)
		}
		info, err := root.Lstat(name)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() ||
			!privateMode(info.Mode(), 0o700) {
			return errors.Join(ErrUnavailable, err)
		}
	}
	return nil
}

func sealSourceTree(root *os.Root, sourceRoot string) error {
	directories := []string{sourceRoot}
	err := walkRoot(root, sourceRoot, func(name string, info os.FileInfo) error {
		if info.IsDir() && name != sourceRoot {
			directories = append(directories, name)
		}
		return nil
	})
	if err != nil {
		return err
	}
	sort.Slice(directories, func(left, right int) bool {
		return strings.Count(directories[left], "/") > strings.Count(directories[right], "/")
	})
	for _, directory := range directories {
		if err := root.Chmod(directory, 0o555); err != nil {
			return errors.Join(ErrUnavailable, err)
		}
		if err := syncDirectory(root, directory); err != nil {
			return errors.Join(ErrUnavailable, err)
		}
	}
	return nil
}

func createStaging(root *os.Root, key string) (string, error) {
	for attempt := 0; attempt < stagingAttempts; attempt++ {
		var random [8]byte
		if _, err := io.ReadFull(rand.Reader, random[:]); err != nil {
			return "", err
		}
		name := ".workspace-" + key + "-" + hex.EncodeToString(random[:])
		if err := root.Mkdir(name, 0o700); err == nil {
			if syncErr := syncDirectory(root, "."); syncErr != nil {
				_ = root.Remove(name)
				return "", syncErr
			}
			return name, nil
		} else if !errors.Is(err, os.ErrExist) {
			return "", err
		}
	}
	return "", ErrUnavailable
}

func executionKey(executionID string) string {
	if devopsv1.ValidateDigest("runnerWorkspace.executionId", executionID) != nil ||
		!strings.HasPrefix(executionID, "sha256:") {
		return ""
	}
	return strings.TrimPrefix(executionID, "sha256:")
}

func validWorkspaceKey(value string) bool {
	return len(value) == sha256.Size*2 && lowerHex(value)
}

func validStagingName(value string) bool {
	if !strings.HasPrefix(value, ".workspace-") || len(value) != len(".workspace-")+64+1+16 {
		return false
	}
	parts := strings.Split(strings.TrimPrefix(value, ".workspace-"), "-")
	return len(parts) == 2 && validWorkspaceKey(parts[0]) && len(parts[1]) == 16 && lowerHex(parts[1])
}

func validateRoot(rootPath string) (string, error) {
	if rootPath == "" || !filepath.IsAbs(rootPath) {
		return "", ErrInvalid
	}
	cleaned := filepath.Clean(rootPath)
	info, err := os.Lstat(cleaned)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() ||
		!privateMode(info.Mode(), 0o700) {
		return "", errors.Join(ErrInvalid, err)
	}
	resolved, err := filepath.EvalSymlinks(cleaned)
	if err != nil || !samePath(cleaned, resolved) {
		return "", errors.Join(ErrInvalid, err)
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

func ensureRootIdentity(root *os.Root, runnerID string) error {
	content, err := readPrivateFile(root, rootIdentityName, maximumManifestBytes)
	if err == nil {
		value, decodeErr := decodeRootIdentity(content)
		if decodeErr != nil || value.RunnerID != runnerID {
			return errors.Join(ErrConflict, decodeErr)
		}
		return nil
	}
	if _, statErr := root.Lstat(rootIdentityName); !errors.Is(statErr, os.ErrNotExist) {
		return errors.Join(ErrUnavailable, err, statErr)
	}
	value := rootIdentity{SchemaVersion: 1, RunnerID: runnerID}
	value.ContentDigest = digestRootIdentity(value)
	encoded, err := json.Marshal(value)
	if err != nil {
		return errors.Join(ErrUnavailable, err)
	}
	if err := writePrivateFile(root, rootIdentityTemporary, encoded); err != nil {
		return err
	}
	if err := root.Rename(rootIdentityTemporary, rootIdentityName); err != nil {
		_ = root.Remove(rootIdentityTemporary)
		return errors.Join(ErrUnavailable, err)
	}
	if err := syncDirectory(root, "."); err != nil {
		return errors.Join(ErrUnavailable, err)
	}
	return nil
}

func decodeRootIdentity(content []byte) (rootIdentity, error) {
	var value rootIdentity
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		return rootIdentity{}, ErrUnavailable
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) ||
		value.SchemaVersion != 1 || !validRunnerID(value.RunnerID) ||
		value.ContentDigest != digestRootIdentity(value) {
		return rootIdentity{}, ErrUnavailable
	}
	canonical, err := json.Marshal(value)
	if err != nil || !bytes.Equal(canonical, content) {
		return rootIdentity{}, ErrUnavailable
	}
	return value, nil
}

func digestRootIdentity(value rootIdentity) string {
	digest := sha256.New()
	writeString(digest, "matrix-devops-runner-workspace-root-v1")
	writeUint64(digest, uint64(value.SchemaVersion))
	writeString(digest, value.RunnerID)
	return "sha256:" + hex.EncodeToString(digest.Sum(nil))
}
