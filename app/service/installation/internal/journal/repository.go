// Package journal owns the protected durable representation and exclusive
// process lock for the installation lifecycle journal.
package journal

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/xiak/matrix/app/service/installation/internal/lifecycle"
)

const (
	stateDirectoryName = "state"
	lockFilename       = "installation.lock"
	keyFilename        = "journal.key"
	journalFilename    = "journal.json"
	sealKeyBytes       = 32
)

var (
	ErrNotInitialized     = errors.New("installation journal is not initialized")
	ErrAlreadyInitialized = errors.New("installation journal is already initialized")
	ErrOwnershipConflict  = errors.New("installation root contains objects Matrix does not own")
	ErrIntegrity          = errors.New("installation journal integrity verification failed")
)

type Session struct {
	root     string
	state    string
	lockFile *os.File
}

// Acquire validates or creates the protected root and holds its exclusive OS
// lock until Session.Close. The caller must authenticate and verify a release
// bundle before calling Acquire for a fresh installation.
func Acquire(ctx context.Context, root string) (*Session, error) {
	if ctx == nil {
		return nil, errors.New("installation lock context is nil")
	}
	cleanRoot, err := prepareRoot(root)
	if err != nil {
		return nil, err
	}
	state, err := prepareStateDirectory(cleanRoot)
	if err != nil {
		return nil, err
	}
	lockPath := filepath.Join(state, lockFilename)
	_, statErr := os.Lstat(lockPath)
	createdLock := errors.Is(statErr, os.ErrNotExist)
	if statErr != nil && !createdLock {
		return nil, errors.New("inspect installation lock failed")
	}
	lockFile, err := openLockFileNoFollow(lockPath)
	if err != nil {
		return nil, errors.New("open installation lock failed")
	}
	if createdLock {
		err = securePermissions(lockPath, false)
	} else {
		err = verifySecurePermissions(lockPath, false)
	}
	if err != nil {
		_ = lockFile.Close()
		return nil, errors.New("installation lock permissions are unsafe")
	}
	if err := acquireOSFileLock(ctx, lockFile); err != nil {
		_ = lockFile.Close()
		return nil, fmt.Errorf("acquire installation lock: %w", err)
	}
	return &Session{root: cleanRoot, state: state, lockFile: lockFile}, nil
}

func (session *Session) Root() string {
	if session == nil {
		return ""
	}
	return session.root
}

func (session *Session) Initialized() (bool, error) {
	if err := session.validateOpen(); err != nil {
		return false, err
	}
	journalExists, err := regularFileExists(filepath.Join(session.state, journalFilename))
	if err != nil {
		return false, ErrIntegrity
	}
	keyExists, err := regularFileExists(filepath.Join(session.state, keyFilename))
	if err != nil {
		return false, ErrIntegrity
	}
	if journalExists && !keyExists {
		return false, ErrIntegrity
	}
	return journalExists, nil
}

func (session *Session) Initialize(value lifecycle.Journal) error {
	if err := session.validateOpen(); err != nil {
		return err
	}
	if err := lifecycle.ValidateJournal(value); err != nil {
		return fmt.Errorf("initialize invalid installation journal: %w", err)
	}
	initialized, err := session.Initialized()
	if err != nil {
		return err
	}
	if initialized {
		return ErrAlreadyInitialized
	}
	if err := validateUninitializedInventory(session.root, session.state); err != nil {
		return err
	}
	keyPath := filepath.Join(session.state, keyFilename)
	key, err := readOrCreateKey(keyPath, session.state)
	if err != nil {
		return err
	}
	defer wipe(key)
	content, err := encodeSealed(value, key)
	if err != nil {
		return err
	}
	return writeManagedFile(session.root, filepath.Join(session.state, journalFilename), content)
}

func (session *Session) Read() (lifecycle.Journal, error) {
	if err := session.validateOpen(); err != nil {
		return lifecycle.Journal{}, err
	}
	initialized, err := session.Initialized()
	if err != nil {
		return lifecycle.Journal{}, err
	}
	if !initialized {
		return lifecycle.Journal{}, ErrNotInitialized
	}
	key, err := readKey(filepath.Join(session.state, keyFilename))
	if err != nil {
		return lifecycle.Journal{}, ErrIntegrity
	}
	defer wipe(key)
	content, err := readManagedFile(
		session.root,
		filepath.Join(session.state, journalFilename),
		maximumJournalBytes,
	)
	if err != nil {
		return lifecycle.Journal{}, ErrIntegrity
	}
	value, err := decodeSealed(content, key)
	if err != nil {
		return lifecycle.Journal{}, ErrIntegrity
	}
	return value, nil
}

func (session *Session) Write(value lifecycle.Journal) error {
	if err := session.validateOpen(); err != nil {
		return err
	}
	if err := lifecycle.ValidateJournal(value); err != nil {
		return fmt.Errorf("write invalid installation journal: %w", err)
	}
	current, err := session.Read()
	if err != nil {
		return err
	}
	if value.InstallationID != current.InstallationID || value.Version != current.Version+1 {
		return errors.New("installation journal version or identity is stale")
	}
	key, err := readKey(filepath.Join(session.state, keyFilename))
	if err != nil {
		return ErrIntegrity
	}
	defer wipe(key)
	content, err := encodeSealed(value, key)
	if err != nil {
		return err
	}
	return writeManagedFile(session.root, filepath.Join(session.state, journalFilename), content)
}

func (session *Session) Close() error {
	if session == nil || session.lockFile == nil {
		return nil
	}
	file := session.lockFile
	session.lockFile = nil
	return errors.Join(releaseOSFileLock(file), file.Close())
}

func (session *Session) validateOpen() error {
	if session == nil || session.lockFile == nil || session.root == "" || session.state == "" {
		return errors.New("installation journal session is closed")
	}
	return nil
}

func prepareRoot(root string) (string, error) {
	if root == "" || len(root) > 4096 || !filepath.IsAbs(root) || filepath.Clean(root) != root ||
		isVolumeRoot(root) {
		return "", errors.New("installation root must be a clean absolute non-volume-root path")
	}
	info, err := os.Lstat(root)
	switch {
	case errors.Is(err, os.ErrNotExist):
		parent := filepath.Dir(root)
		parentInfo, parentErr := validateExistingPath(parent)
		if parentErr != nil || !parentInfo.IsDir() {
			return "", errors.New("installation root parent is unsafe")
		}
		if err := os.Mkdir(root, managedDirectoryMode); err != nil {
			return "", errors.New("create installation root failed")
		}
		if err := securePermissions(root, true); err != nil {
			return "", errors.New("protect installation root failed")
		}
	case err != nil:
		return "", errors.New("inspect installation root failed")
	case pathComponentIsLink(root, info) || !info.IsDir():
		return "", errors.New("installation root is unsafe")
	}
	info, err = validateExistingPath(root)
	if err != nil || !info.IsDir() || verifySecurePermissions(root, true) != nil {
		return "", errors.New("installation root permissions or path are unsafe")
	}
	return root, nil
}

func prepareStateDirectory(root string) (string, error) {
	state := filepath.Join(root, stateDirectoryName)
	info, err := os.Lstat(state)
	switch {
	case errors.Is(err, os.ErrNotExist):
		entries, readErr := os.ReadDir(root)
		if readErr != nil || len(entries) != 0 {
			return "", ErrOwnershipConflict
		}
		if err := os.Mkdir(state, managedDirectoryMode); err != nil {
			return "", errors.New("create installation state directory failed")
		}
		if err := securePermissions(state, true); err != nil {
			return "", errors.New("protect installation state directory failed")
		}
	case err != nil:
		return "", errors.New("inspect installation state directory failed")
	case pathComponentIsLink(state, info) || !info.IsDir():
		return "", errors.New("installation state directory is unsafe")
	}
	if _, err := validateExistingPath(state); err != nil || verifySecurePermissions(state, true) != nil {
		return "", errors.New("installation state directory permissions or path are unsafe")
	}
	return state, nil
}

func validateUninitializedInventory(root, state string) error {
	rootEntries, err := os.ReadDir(root)
	if err != nil || len(rootEntries) != 1 || rootEntries[0].Name() != stateDirectoryName || !rootEntries[0].IsDir() {
		return ErrOwnershipConflict
	}
	entries, err := os.ReadDir(state)
	if err != nil {
		return ErrOwnershipConflict
	}
	for _, entry := range entries {
		if entry.Name() != lockFilename && entry.Name() != keyFilename {
			return ErrOwnershipConflict
		}
	}
	return nil
}

func readOrCreateKey(target, parent string) ([]byte, error) {
	key, err := readKey(target)
	if err == nil {
		return key, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, ErrIntegrity
	}
	key = make([]byte, sealKeyBytes)
	if _, err := rand.Read(key); err != nil {
		wipe(key)
		return nil, errors.New("generate installation journal key failed")
	}
	if err := writeNewManagedFile(target, parent, key); err != nil {
		wipe(key)
		return nil, err
	}
	return key, nil
}

func readKey(target string) ([]byte, error) {
	content, err := readExactRegularFile(target, sealKeyBytes)
	if err != nil {
		return nil, err
	}
	return content, nil
}

func regularFileExists(target string) (bool, error) {
	info, err := os.Lstat(target)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil || pathComponentIsLink(target, info) || !info.Mode().IsRegular() ||
		verifySecurePermissions(target, false) != nil {
		return false, ErrIntegrity
	}
	return true, nil
}

func wipe(content []byte) {
	for index := range content {
		content[index] = 0
	}
}
