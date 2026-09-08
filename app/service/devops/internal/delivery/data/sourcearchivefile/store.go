// Package sourcearchivefile publishes source archives atomically below one
// private installation-owned filesystem root.
package sourcearchivefile

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"hash"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	devopsv1 "github.com/xiak/matrix/api/devops/v1"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/sourcearchive"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/usecase/sourceacquisition"
)

const (
	receiptName        = "receipt.json"
	archiveTemporary   = "archive.tmp"
	receiptTemporary   = "receipt.tmp"
	maximumReceiptSize = int64(16 * 1024)
	stagingAttempts    = 16
)

type Store struct {
	rootPath string
}

func New(rootPath string) (*Store, error) {
	cleaned, err := validateRoot(rootPath)
	if err != nil {
		return nil, err
	}
	return &Store{rootPath: cleaned}, nil
}

func (store *Store) Publish(
	ctx context.Context,
	command sourceacquisition.Command,
	write sourceacquisition.ArchiveWriter,
) (sourcearchive.Receipt, error) {
	if store == nil || ctx == nil || write == nil ||
		sourceacquisition.ValidateCommand(command) != nil {
		return sourcearchive.Receipt{}, sourceacquisition.ErrSourceUnavailable
	}
	root, err := store.openRoot()
	if err != nil {
		return sourcearchive.Receipt{}, err
	}
	defer root.Close()
	key := commandKey(command)
	if receipt, found, observeErr := observe(ctx, root, key, command); observeErr != nil || found {
		return receipt, observeErr
	}

	stagingName, err := createStaging(root, key)
	if err != nil {
		return sourcearchive.Receipt{}, sourceUnavailable(err)
	}
	published := false
	defer func() {
		if !published {
			cleanupStaging(root, key, stagingName)
		}
	}()

	archivePath := stagingName + "/" + archiveTemporary
	archiveFile, err := root.OpenFile(archivePath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return sourcearchive.Receipt{}, sourceUnavailable(err)
	}
	bounded := &boundedWriter{destination: archiveFile, digest: sha256.New()}
	content, writeErr := write(bounded)
	if writeErr == nil {
		writeErr = sourceacquisition.ValidateArchiveContent(content)
	}
	if writeErr == nil && bounded.written == 0 {
		writeErr = sourcearchive.ErrInvalid
	}
	if writeErr == nil {
		writeErr = archiveFile.Sync()
	}
	closeErr := archiveFile.Close()
	if writeErr != nil || closeErr != nil {
		return sourcearchive.Receipt{}, sourceUnavailable(errors.Join(writeErr, closeErr))
	}

	digestHex := hex.EncodeToString(bounded.digest.Sum(nil))
	archiveName := digestHex + ".tar.gz"
	receipt := sourcearchive.Receipt{
		TenantID: command.Lease.TenantID, RunID: command.Lease.Run.ID,
		CommandID: command.Lease.Intent.CommandID, InputDigest: command.Lease.Run.InputDigest,
		HeadCommit:        command.Lease.Run.Input.Change.HeadCommit,
		TrustedBaseCommit: command.Lease.Run.Input.Change.TrustedBaseCommit,
		MediaType:         sourcearchive.MediaType, ArchiveDigest: "sha256:" + digestHex,
		ArchiveBytes: bounded.written, ExpandedBytes: content.ExpandedBytes,
		PathCount: content.PathCount,
	}
	if err := sourceacquisition.ValidateReceipt(command, receipt); err != nil {
		return sourcearchive.Receipt{}, sourceUnavailable(err)
	}
	if err := root.Rename(archivePath, stagingName+"/"+archiveName); err != nil {
		return sourcearchive.Receipt{}, sourceUnavailable(err)
	}
	if err := verifyArchive(ctx, root, stagingName+"/"+archiveName, receipt); err != nil {
		return sourcearchive.Receipt{}, err
	}

	receiptDocument, err := json.Marshal(receipt)
	if err != nil || int64(len(receiptDocument)) > maximumReceiptSize {
		return sourcearchive.Receipt{}, sourceUnavailable(err)
	}
	receiptPath := stagingName + "/" + receiptTemporary
	receiptFile, err := root.OpenFile(receiptPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return sourcearchive.Receipt{}, sourceUnavailable(err)
	}
	written, writeErr := receiptFile.Write(receiptDocument)
	if writeErr == nil && written != len(receiptDocument) {
		writeErr = io.ErrShortWrite
	}
	if writeErr == nil {
		writeErr = receiptFile.Sync()
	}
	closeErr = receiptFile.Close()
	if writeErr != nil || closeErr != nil {
		return sourcearchive.Receipt{}, sourceUnavailable(errors.Join(writeErr, closeErr))
	}
	if err := root.Rename(receiptPath, stagingName+"/"+receiptName); err != nil {
		return sourcearchive.Receipt{}, sourceUnavailable(err)
	}
	if err := syncDirectory(root, stagingName); err != nil {
		return sourcearchive.Receipt{}, sourceUnavailable(err)
	}
	if err := root.Rename(stagingName, key); err != nil {
		if existing, found, observeErr := observe(ctx, root, key, command); observeErr == nil && found {
			return existing, nil
		}
		return sourcearchive.Receipt{}, sourceUnavailable(err)
	}
	published = true
	if err := syncDirectory(root, "."); err != nil {
		// The final directory is already visible. Return no receipt so the
		// current fence cannot claim durability; a takeover will re-observe it.
		return sourcearchive.Receipt{}, errors.Join(
			sourceacquisition.ErrArchiveUncertain, err,
		)
	}
	return receipt, nil
}

func (store *Store) Observe(
	ctx context.Context,
	command sourceacquisition.Command,
) (sourcearchive.Receipt, bool, error) {
	if store == nil || ctx == nil || sourceacquisition.ValidateCommand(command) != nil {
		return sourcearchive.Receipt{}, false, sourceacquisition.ErrSourceUnavailable
	}
	root, err := store.openRoot()
	if err != nil {
		return sourcearchive.Receipt{}, false, err
	}
	defer root.Close()
	return observe(ctx, root, commandKey(command), command)
}

// Open re-proves the stored receipt and archive before returning a stream that
// also verifies complete, unchanged consumption at the executor boundary.
func (store *Store) Open(
	ctx context.Context,
	expected sourcearchive.Receipt,
) (io.ReadCloser, error) {
	if store == nil || ctx == nil || sourcearchive.ValidateReceipt(expected) != nil {
		return nil, sourceUnavailable(sourcearchive.ErrInvalid)
	}
	root, err := store.openRoot()
	if err != nil {
		return nil, err
	}
	defer root.Close()
	key := receiptKey(expected)
	stored, found, err := readPublishedReceipt(ctx, root, key)
	if err != nil || !found || stored != expected {
		if err == nil {
			err = sourcearchive.ErrInvalid
		}
		return nil, sourceUnavailable(err)
	}
	name, err := archiveName(stored.ArchiveDigest)
	if err != nil {
		return nil, sourceUnavailable(err)
	}
	file, err := openVerifiedArchive(ctx, root, key+"/"+name, stored)
	if err != nil {
		return nil, err
	}
	return &verifiedArchiveReader{
		file:           file,
		digest:         sha256.New(),
		expectedBytes:  stored.ArchiveBytes,
		expectedDigest: stored.ArchiveDigest,
	}, nil
}

func (store *Store) openRoot() (*os.Root, error) {
	cleaned, err := validateRoot(store.rootPath)
	if err != nil || cleaned != store.rootPath {
		return nil, sourceUnavailable(err)
	}
	root, err := os.OpenRoot(cleaned)
	if err != nil {
		return nil, sourceUnavailable(err)
	}
	return root, nil
}

func observe(
	ctx context.Context,
	root *os.Root,
	key string,
	command sourceacquisition.Command,
) (sourcearchive.Receipt, bool, error) {
	receipt, found, err := readPublishedReceipt(ctx, root, key)
	if err != nil || !found {
		return sourcearchive.Receipt{}, found, err
	}
	if sourceacquisition.ValidateReceipt(command, receipt) != nil {
		return sourcearchive.Receipt{}, false, sourceUnavailable(sourcearchive.ErrInvalid)
	}
	name, err := archiveName(receipt.ArchiveDigest)
	if err != nil {
		return sourcearchive.Receipt{}, false, sourceUnavailable(err)
	}
	if err := verifyArchive(ctx, root, key+"/"+name, receipt); err != nil {
		return sourcearchive.Receipt{}, false, err
	}
	return receipt, true, nil
}

func readPublishedReceipt(
	ctx context.Context,
	root *os.Root,
	key string,
) (sourcearchive.Receipt, bool, error) {
	if err := ctx.Err(); err != nil {
		return sourcearchive.Receipt{}, false, err
	}
	directory, err := root.Lstat(key)
	if errors.Is(err, os.ErrNotExist) {
		return sourcearchive.Receipt{}, false, nil
	}
	if err != nil || directory.Mode()&os.ModeSymlink != 0 || !directory.IsDir() ||
		!privateMode(directory.Mode(), 0o700) {
		return sourcearchive.Receipt{}, false, sourceUnavailable(err)
	}

	receiptPath := key + "/" + receiptName
	receiptInfo, err := root.Lstat(receiptPath)
	if err != nil || receiptInfo.Mode()&os.ModeSymlink != 0 || !receiptInfo.Mode().IsRegular() ||
		!privateMode(receiptInfo.Mode(), 0o600) || receiptInfo.Size() <= 0 ||
		receiptInfo.Size() > maximumReceiptSize {
		return sourcearchive.Receipt{}, false, sourceUnavailable(err)
	}
	receiptFile, err := root.Open(receiptPath)
	if err != nil {
		return sourcearchive.Receipt{}, false, sourceUnavailable(err)
	}
	receiptDocument, readErr := io.ReadAll(io.LimitReader(receiptFile, maximumReceiptSize+1))
	closeErr := receiptFile.Close()
	if readErr != nil || closeErr != nil || int64(len(receiptDocument)) != receiptInfo.Size() {
		return sourcearchive.Receipt{}, false, sourceUnavailable(errors.Join(readErr, closeErr))
	}
	receipt, err := decodeReceipt(receiptDocument)
	if err != nil || sourcearchive.ValidateReceipt(receipt) != nil {
		return sourcearchive.Receipt{}, false, sourceUnavailable(err)
	}
	name, err := archiveName(receipt.ArchiveDigest)
	if err != nil {
		return sourcearchive.Receipt{}, false, sourceUnavailable(err)
	}
	directoryFile, err := root.Open(key)
	if err != nil {
		return sourcearchive.Receipt{}, false, sourceUnavailable(err)
	}
	entries, readDirectoryErr := directoryFile.ReadDir(3)
	closeErr = directoryFile.Close()
	if readDirectoryErr != nil && !errors.Is(readDirectoryErr, io.EOF) {
		return sourcearchive.Receipt{}, false, sourceUnavailable(errors.Join(readDirectoryErr, closeErr))
	}
	if closeErr != nil || len(entries) != 2 || !containsEntry(entries, receiptName) ||
		!containsEntry(entries, name) {
		return sourcearchive.Receipt{}, false, sourceUnavailable(closeErr)
	}
	return receipt, true, nil
}

func verifyArchive(
	ctx context.Context,
	root *os.Root,
	archivePath string,
	receipt sourcearchive.Receipt,
) error {
	file, err := openVerifiedArchive(ctx, root, archivePath, receipt)
	if err != nil {
		return err
	}
	return sourceUnavailableOnError(file.Close())
}

func openVerifiedArchive(
	ctx context.Context,
	root *os.Root,
	archivePath string,
	receipt sourcearchive.Receipt,
) (*os.File, error) {
	info, err := root.Lstat(archivePath)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() ||
		!privateMode(info.Mode(), 0o600) || info.Size() != receipt.ArchiveBytes ||
		info.Size() <= 0 || info.Size() > sourcearchive.MaximumArchiveBytes {
		return nil, sourceUnavailable(err)
	}
	file, err := root.Open(archivePath)
	if err != nil {
		return nil, sourceUnavailable(err)
	}
	actualInfo, statErr := file.Stat()
	if statErr != nil || !actualInfo.Mode().IsRegular() ||
		actualInfo.Size() != receipt.ArchiveBytes {
		_ = file.Close()
		return nil, sourceUnavailable(statErr)
	}
	digest := sha256.New()
	content, inspectErr := sourcearchive.Inspect(ctx, io.TeeReader(file, digest))
	if inspectErr != nil ||
		"sha256:"+hex.EncodeToString(digest.Sum(nil)) != receipt.ArchiveDigest ||
		content.ExpandedBytes != receipt.ExpandedBytes || content.PathCount != receipt.PathCount {
		_ = file.Close()
		return nil, sourceUnavailable(inspectErr)
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		_ = file.Close()
		return nil, sourceUnavailable(err)
	}
	return file, nil
}

func decodeReceipt(document []byte) (sourcearchive.Receipt, error) {
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	var receipt sourcearchive.Receipt
	if err := decoder.Decode(&receipt); err != nil {
		return sourcearchive.Receipt{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return sourcearchive.Receipt{}, sourcearchive.ErrInvalid
	}
	canonical, err := json.Marshal(receipt)
	if err != nil || !bytes.Equal(canonical, document) {
		return sourcearchive.Receipt{}, sourcearchive.ErrInvalid
	}
	return receipt, nil
}

func archiveName(digest string) (string, error) {
	if devopsv1.ValidateDigest("sourceArchive.archiveDigest", digest) != nil ||
		!strings.HasPrefix(digest, "sha256:") {
		return "", sourcearchive.ErrInvalid
	}
	value := strings.TrimPrefix(digest, "sha256:")
	if len(value) != sha256.Size*2 {
		return "", sourcearchive.ErrInvalid
	}
	return value + ".tar.gz", nil
}

func commandKey(command sourceacquisition.Command) string {
	return archiveKey(
		command.Lease.TenantID,
		command.Lease.Run.ID,
		command.Lease.Intent.CommandID,
		command.Lease.Run.InputDigest,
	)
}

func receiptKey(receipt sourcearchive.Receipt) string {
	return archiveKey(
		receipt.TenantID,
		receipt.RunID,
		receipt.CommandID,
		receipt.InputDigest,
	)
}

func archiveKey(
	tenantID devopsv1.TenantID,
	runID devopsv1.ResourceID,
	commandID string,
	inputDigest string,
) string {
	digest := sha256.New()
	_, _ = digest.Write([]byte("matrix-devops-source-archive-command-v1"))
	for _, value := range []string{
		string(tenantID), string(runID), commandID, inputDigest,
	} {
		var size [8]byte
		binary.BigEndian.PutUint64(size[:], uint64(len(value)))
		_, _ = digest.Write(size[:])
		_, _ = digest.Write([]byte(value))
	}
	return hex.EncodeToString(digest.Sum(nil))
}

func sourceUnavailableOnError(err error) error {
	if err == nil {
		return nil
	}
	return sourceUnavailable(err)
}

type verifiedArchiveReader struct {
	file           *os.File
	digest         hash.Hash
	expectedBytes  int64
	expectedDigest string
	readBytes      int64
	completed      bool
	closed         bool
	validationErr  error
}

func (reader *verifiedArchiveReader) Read(value []byte) (int, error) {
	if reader == nil || reader.file == nil || reader.closed {
		return 0, os.ErrClosed
	}
	if reader.validationErr != nil {
		return 0, reader.validationErr
	}
	if reader.completed {
		return 0, io.EOF
	}
	read, err := reader.file.Read(value)
	if read > 0 {
		_, _ = reader.digest.Write(value[:read])
		reader.readBytes += int64(read)
		if reader.readBytes > reader.expectedBytes {
			reader.validationErr = sourceUnavailable(sourcearchive.ErrInvalid)
			return read, reader.validationErr
		}
	}
	if err != nil && !errors.Is(err, io.EOF) {
		reader.validationErr = sourceUnavailable(err)
		return read, reader.validationErr
	}
	if errors.Is(err, io.EOF) {
		return read, reader.finish()
	}
	return read, nil
}

func (reader *verifiedArchiveReader) Close() error {
	if reader == nil || reader.file == nil || reader.closed {
		return os.ErrClosed
	}
	if reader.validationErr == nil && !reader.completed {
		if reader.readBytes == reader.expectedBytes {
			var trailing [1]byte
			read, err := reader.file.Read(trailing[:])
			if read > 0 {
				_, _ = reader.digest.Write(trailing[:read])
				reader.readBytes += int64(read)
				reader.validationErr = sourceUnavailable(sourcearchive.ErrInvalid)
			} else if errors.Is(err, io.EOF) {
				_ = reader.finish()
			} else if err != nil {
				reader.validationErr = sourceUnavailable(err)
			}
		} else {
			reader.validationErr = sourceUnavailable(io.ErrUnexpectedEOF)
		}
	}
	reader.closed = true
	return errors.Join(reader.validationErr, sourceUnavailableOnError(reader.file.Close()))
}

func (reader *verifiedArchiveReader) finish() error {
	if reader.readBytes != reader.expectedBytes ||
		"sha256:"+hex.EncodeToString(reader.digest.Sum(nil)) != reader.expectedDigest {
		reader.validationErr = sourceUnavailable(sourcearchive.ErrInvalid)
		return reader.validationErr
	}
	reader.completed = true
	return io.EOF
}

func createStaging(root *os.Root, key string) (string, error) {
	for attempt := 0; attempt < stagingAttempts; attempt++ {
		var random [8]byte
		if _, err := io.ReadFull(rand.Reader, random[:]); err != nil {
			return "", err
		}
		name := ".staging-" + key + "-" + hex.EncodeToString(random[:])
		if err := root.Mkdir(name, 0o700); err == nil {
			return name, nil
		} else if !errors.Is(err, os.ErrExist) {
			return "", err
		}
	}
	return "", errors.New("source archive staging identity is exhausted")
}

func cleanupStaging(root *os.Root, key, name string) {
	prefix := ".staging-" + key + "-"
	if root == nil || !strings.HasPrefix(name, prefix) || len(name) != len(prefix)+16 ||
		strings.ContainsAny(name, "/\\") {
		return
	}
	_ = root.RemoveAll(name)
}

func validateRoot(rootPath string) (string, error) {
	if rootPath == "" || !filepath.IsAbs(rootPath) {
		return "", errors.New("source archive root must be absolute")
	}
	cleaned := filepath.Clean(rootPath)
	info, err := os.Lstat(cleaned)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() ||
		!privateMode(info.Mode(), 0o700) {
		return "", errors.New("source archive root must be a private directory")
	}
	resolved, err := filepath.EvalSymlinks(cleaned)
	if err != nil || !samePath(cleaned, resolved) {
		return "", errors.New("source archive root cannot traverse a symbolic link")
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

func containsEntry(entries []os.DirEntry, name string) bool {
	for _, entry := range entries {
		if entry.Name() == name && entry.Type()&os.ModeSymlink == 0 {
			return true
		}
	}
	return false
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

func sourceUnavailable(err error) error {
	if err == nil {
		return errors.Join(sourceacquisition.ErrSourceUnavailable, sourcearchive.ErrInvalid)
	}
	return errors.Join(sourceacquisition.ErrSourceUnavailable, err)
}

type boundedWriter struct {
	destination io.Writer
	digest      hash.Hash
	written     int64
}

func (writer *boundedWriter) Write(value []byte) (int, error) {
	if int64(len(value)) > sourcearchive.MaximumArchiveBytes-writer.written {
		return 0, sourceacquisition.ErrSourceUnavailable
	}
	written, err := writer.destination.Write(value)
	if written > 0 {
		_, _ = writer.digest.Write(value[:written])
		writer.written += int64(written)
	}
	if written != len(value) && err == nil {
		err = io.ErrShortWrite
	}
	return written, err
}
