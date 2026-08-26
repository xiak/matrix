package localmachine

import (
	"archive/tar"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/xiak/matrix/api/contractjson"
	paasv1 "github.com/xiak/matrix/api/paas/v1"
	"github.com/xiak/matrix/app/service/installation/internal/layout"
	"github.com/xiak/matrix/app/service/installation/internal/platformcommand"
)

const (
	backupAPIVersion                 = "installation.matrix.xiak.com/v1"
	backupKind                       = "PlatformBackup"
	backupSealAlgorithm              = "HMAC-SHA256"
	backupSealKeyID                  = "installation-backup-v1"
	backupSealDomain                 = "matrix-platform-backup-v1\x00"
	backupManifestFilename           = "backup.json"
	databaseDumpFilename             = "database.dump"
	workloadSecretsFilename          = "workload-secrets.tar"
	maximumBackupManifestBytes       = int64(64 * 1024)
	maximumDatabaseDumpBytes         = uint64(64 * 1024 * 1024 * 1024)
	databaseDumpReserveBytes         = uint64(64 * 1024 * 1024)
	maximumWorkloadSecretFiles       = 4096
	maximumWorkloadSecretBytes       = uint64(1024 * 1024 * 1024)
	maximumWorkloadSecretArchiveSize = maximumWorkloadSecretBytes + 8*1024*1024
)

var backupIDPattern = regexp.MustCompile(`^backup-[0-9a-f]{32}$`)

type backupManifest struct {
	APIVersion     string           `json:"apiVersion"`
	Kind           string           `json:"kind"`
	BackupID       string           `json:"backupId"`
	InstallationID string           `json:"installationId"`
	ReleaseID      string           `json:"releaseId"`
	ReleaseDigest  string           `json:"releaseDigest"`
	SchemaVersion  uint64           `json:"schemaVersion"`
	CreatedAt      time.Time        `json:"createdAt"`
	Artifacts      []backupArtifact `json:"artifacts"`
	Seal           *backupSeal      `json:"seal,omitempty"`
}

type backupArtifact struct {
	Path      string `json:"path"`
	MediaType string `json:"mediaType"`
	Size      uint64 `json:"size"`
	SHA256    string `json:"sha256"`
}

type backupSeal struct {
	Algorithm string `json:"algorithm"`
	KeyID     string `json:"keyId"`
	Value     string `json:"value"`
}

func (effects *Effects) InspectBackup(
	ctx context.Context,
	installed platformcommand.InstalledPlan,
	backupID string,
) (platformcommand.RecoverySource, error) {
	if effects == nil || ctx == nil {
		return platformcommand.RecoverySource{}, errors.Join(
			platformcommand.ErrEffectUnavailable,
			errors.New("local-machine backup inspection is unavailable"),
		)
	}
	if err := ctx.Err(); err != nil {
		return platformcommand.RecoverySource{}, err
	}
	if !backupIDPattern.MatchString(backupID) {
		return platformcommand.RecoverySource{}, errors.Join(
			platformcommand.ErrEffectPrecondition,
			errors.New("selected backup identity is invalid"),
		)
	}
	current, err := authenticateInstalledPlan(installed)
	if err != nil {
		return platformcommand.RecoverySource{}, errors.Join(
			platformcommand.ErrEffectVerification, err,
		)
	}
	defer clear(current.TrustBytes)
	key, err := loadBackupSealKey(installed.Root, nil, false)
	if err != nil {
		return platformcommand.RecoverySource{}, err
	}
	defer clear(key)
	relative := filepath.Join(filepath.FromSlash(layout.BackupDirectory), backupID)
	manifest, manifestDigest, err := readVerifiedBackupDirectory(
		installed.Root, installed.InstallationID, backupID, relative, key,
	)
	if err != nil {
		return platformcommand.RecoverySource{}, err
	}
	targetIdentity := installed
	targetIdentity.ReleaseID = manifest.ReleaseID
	targetIdentity.ReleaseDigest = manifest.ReleaseDigest
	targetIdentity.PreviousID = ""
	targetIdentity.PreviousDigest = ""
	target, err := authenticateInstalledPlan(targetIdentity)
	if err != nil || target.Bundle.Manifest.Database.SchemaVersion != manifest.SchemaVersion {
		clear(target.TrustBytes)
		return platformcommand.RecoverySource{}, errors.Join(
			platformcommand.ErrEffectVerification,
			errors.New("backup release is unavailable or incompatible"),
		)
	}
	clear(target.TrustBytes)
	if err := verifyWorkloadSecretRestore(
		installed.Root, filepath.Join(relative, workloadSecretsFilename), false,
	); err != nil {
		return platformcommand.RecoverySource{}, errors.Join(
			platformcommand.ErrEffectConflict, err,
		)
	}
	return platformcommand.RecoverySource{
		InstallationID: installed.InstallationID,
		BackupID:       backupID,
		BackupDigest:   manifestDigest,
		ReleaseID:      manifest.ReleaseID,
		ReleaseDigest:  manifest.ReleaseDigest,
		SchemaVersion:  manifest.SchemaVersion,
	}, nil
}

func (effects *Effects) CreateBackup(
	ctx context.Context,
	request platformcommand.BackupPlan,
) error {
	if effects == nil || effects.runtime == nil || effects.entropy == nil ||
		ctx == nil {
		return errors.Join(
			platformcommand.ErrEffectUnavailable,
			errors.New("local-machine backup is unavailable"),
		)
	}
	streaming, ok := effects.runtime.(streamingDockerRuntime)
	if !ok {
		return errors.Join(
			platformcommand.ErrEffectUnavailable,
			errors.New("local-machine backup streaming is unavailable"),
		)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if !backupIDPattern.MatchString(request.BackupID) ||
		request.CreatedAt.IsZero() || request.CreatedAt.Location() != time.UTC ||
		request.CreatedAt != request.CreatedAt.Truncate(time.Microsecond) {
		return errors.Join(
			platformcommand.ErrEffectVerification,
			errors.New("backup identity or time is invalid"),
		)
	}
	finalRelative := filepath.Join(
		filepath.FromSlash(layout.BackupDirectory), request.BackupID,
	)
	finalExists, err := managedDirectoryExists(request.Root, finalRelative)
	if err != nil {
		return errors.Join(platformcommand.ErrEffectConflict, err)
	}
	plan, err := authenticateInstalledPlan(request.InstalledPlan)
	if err != nil {
		if finalExists {
			return errors.Join(platformcommand.ErrEffectOutcomeUnknown, err)
		}
		return errors.Join(platformcommand.ErrEffectVerification, err)
	}
	defer clear(plan.TrustBytes)
	installation, _, observation, err := inspectReadyInstalledPlatform(
		ctx, effects.runtime, plan,
	)
	if err != nil {
		if finalExists {
			return errors.Join(platformcommand.ErrEffectOutcomeUnknown, err)
		}
		return err
	}
	if err := verifyInstallationMigrations(
		ctx, effects.runtime, plan, installation,
	); err != nil {
		if finalExists && errors.Is(err, platformcommand.ErrEffectUnavailable) {
			return errors.Join(platformcommand.ErrEffectOutcomeUnknown, err)
		}
		return err
	}
	postgres, found := observation.Containers["postgres"]
	if !found || postgres.ID == "" {
		return errors.Join(
			platformcommand.ErrEffectVerification,
			errors.New("owned PostgreSQL service is unavailable for backup"),
		)
	}
	return createBackup(
		ctx, effects.runtime, streaming, effects.entropy, plan,
		installation, postgres.ID, request.BackupID, request.CreatedAt,
	)
}

func createBackup(
	ctx context.Context,
	runtimeBoundary dockerRuntime,
	streaming streamingDockerRuntime,
	entropy io.Reader,
	plan platformcommand.InstallPlan,
	installation verifiedInstallation,
	postgresID string,
	backupID string,
	createdAt time.Time,
) error {
	if _, err := ensureManagedDirectory(
		plan.Root, filepath.FromSlash(layout.BackupDirectory),
	); err != nil {
		return errors.Join(platformcommand.ErrEffectConflict, err)
	}
	finalRelative := filepath.Join(filepath.FromSlash(layout.BackupDirectory), backupID)
	partialRelative := filepath.Join(
		filepath.FromSlash(layout.BackupDirectory), "."+backupID+".partial",
	)
	finalExists, err := managedDirectoryExists(plan.Root, finalRelative)
	if err != nil {
		return errors.Join(platformcommand.ErrEffectConflict, err)
	}
	key, err := loadBackupSealKey(plan.Root, entropy, !finalExists)
	if err != nil {
		return err
	}
	defer clear(key)
	if finalExists {
		err := verifyBackupDirectory(
			ctx, streaming, plan, installation, postgresID,
			backupID, createdAt, finalRelative, key,
		)
		if errors.Is(err, platformcommand.ErrEffectUnavailable) {
			return errors.Join(platformcommand.ErrEffectOutcomeUnknown, err)
		}
		return err
	}
	if err := removeManagedTree(plan.Root, partialRelative); err != nil {
		return errors.Join(platformcommand.ErrEffectConflict, err)
	}
	if _, err := ensureManagedDirectory(plan.Root, partialRelative); err != nil {
		return errors.Join(platformcommand.ErrEffectConflict, err)
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = removeManagedTree(plan.Root, partialRelative)
		}
	}()

	secretsRelative := filepath.Join(partialRelative, workloadSecretsFilename)
	if err := writeWorkloadSecretsArchive(plan.Root, secretsRelative); err != nil {
		return errors.Join(platformcommand.ErrEffectVerification, err)
	}
	databaseSize, err := observeDatabaseSize(ctx, runtimeBoundary, postgresID)
	if err != nil {
		return err
	}
	dumpLimit, err := backupDumpLimit(plan.Root, databaseSize)
	if err != nil {
		return err
	}
	dumpRelative := filepath.Join(partialRelative, databaseDumpFilename)
	if err := streamDatabaseDump(
		ctx, streaming, plan.Root, dumpRelative, postgresID, dumpLimit,
	); err != nil {
		if ctx.Err() != nil {
			cleanup = false
		}
		return err
	}
	if err := verifyDatabaseDump(ctx, streaming, plan.Root, dumpRelative, postgresID); err != nil {
		if ctx.Err() != nil {
			cleanup = false
		}
		return err
	}

	dumpArtifact, err := inspectBackupArtifact(plan.Root, dumpRelative, maximumDatabaseDumpBytes)
	if err != nil {
		return errors.Join(platformcommand.ErrEffectVerification, err)
	}
	dumpArtifact.Path = databaseDumpFilename
	dumpArtifact.MediaType = "application/vnd.postgresql.custom"
	secretsArtifact, err := inspectBackupArtifact(
		plan.Root, secretsRelative, maximumWorkloadSecretArchiveSize,
	)
	if err != nil {
		return errors.Join(platformcommand.ErrEffectVerification, err)
	}
	secretsArtifact.Path = workloadSecretsFilename
	secretsArtifact.MediaType = "application/vnd.xiak.matrix.workload-secrets.tar"
	manifest := backupManifest{
		APIVersion: backupAPIVersion, Kind: backupKind,
		BackupID: backupID, InstallationID: plan.InstallationID,
		ReleaseID:     plan.Bundle.Manifest.Release.ID,
		ReleaseDigest: plan.Bundle.ManifestSHA256,
		SchemaVersion: plan.Bundle.Manifest.Database.SchemaVersion,
		CreatedAt:     createdAt,
		Artifacts:     []backupArtifact{dumpArtifact, secretsArtifact},
	}
	content, err := sealBackupManifest(manifest, key)
	if err != nil {
		return errors.Join(platformcommand.ErrEffectVerification, err)
	}
	defer clear(content)
	if err := writeManagedOnce(
		plan.Root, filepath.Join(partialRelative, backupManifestFilename), content,
	); err != nil {
		return errors.Join(platformcommand.ErrEffectConflict, err)
	}
	if err := verifyBackupDirectory(
		ctx, streaming, plan, installation, postgresID,
		backupID, createdAt, partialRelative, key,
	); err != nil {
		return err
	}
	if err := publishBackupDirectory(plan.Root, partialRelative, finalRelative); err != nil {
		cleanup = false
		return err
	}
	cleanup = false
	if err := verifyBackupDirectory(
		ctx, streaming, plan, installation, postgresID,
		backupID, createdAt, finalRelative, key,
	); err != nil {
		return errors.Join(platformcommand.ErrEffectOutcomeUnknown, err)
	}
	return nil
}

func observeDatabaseSize(
	ctx context.Context,
	runtimeBoundary dockerRuntime,
	postgresID string,
) (uint64, error) {
	output, started, err := runtimeBoundary.Run(
		ctx, nil, "exec", "--user", "postgres", postgresID,
		"psql", "--no-password", "--no-psqlrc", "--no-align", "--tuples-only",
		"--set", "ON_ERROR_STOP=1", "--username", "matrix", "--dbname", "matrix",
		"--command", "SELECT pg_catalog.pg_database_size(current_database())",
	)
	if err != nil {
		if !started {
			return 0, errors.Join(platformcommand.ErrEffectUnavailable, err)
		}
		return 0, errors.Join(
			platformcommand.ErrEffectVerification,
			errors.New("PostgreSQL backup size observation failed"),
		)
	}
	size, err := strconv.ParseUint(strings.TrimSpace(string(output)), 10, 64)
	if err != nil || size == 0 || size > maximumDatabaseDumpBytes-databaseDumpReserveBytes {
		return 0, errors.Join(
			platformcommand.ErrEffectPrecondition,
			errors.New("PostgreSQL database size is outside the backup bound"),
		)
	}
	return size, nil
}

func backupDumpLimit(root string, databaseSize uint64) (uint64, error) {
	backupRoot, err := managedPath(root, filepath.FromSlash(layout.BackupDirectory))
	if err != nil {
		return 0, errors.Join(platformcommand.ErrEffectConflict, err)
	}
	limit := databaseSize + databaseDumpReserveBytes
	available, err := availableFilesystemBytes(backupRoot)
	if err != nil {
		return 0, errors.Join(platformcommand.ErrEffectUnavailable, err)
	}
	if available < limit {
		return 0, errors.Join(
			platformcommand.ErrEffectPrecondition,
			errors.New("backup filesystem capacity is insufficient"),
		)
	}
	return limit, nil
}

func streamDatabaseDump(
	ctx context.Context,
	runtimeBoundary streamingDockerRuntime,
	root string,
	relative string,
	postgresID string,
	maximum uint64,
) error {
	file, err := createBackupFile(root, relative)
	if err != nil {
		return errors.Join(platformcommand.ErrEffectConflict, err)
	}
	writer := &boundedBackupWriter{writer: file, maximum: maximum}
	started, runErr := runtimeBoundary.RunTo(
		ctx, nil, writer, "exec", "--user", "postgres", postgresID,
		"pg_dump", "--format=custom", "--no-owner", "--no-privileges",
		"--no-password", "--lock-wait-timeout=5s", "--username=matrix", "--dbname=matrix",
	)
	syncErr := file.Sync()
	closeErr := file.Close()
	if runErr != nil || writer.exceeded || syncErr != nil || closeErr != nil {
		if ctx.Err() != nil && started {
			return errors.Join(platformcommand.ErrEffectOutcomeUnknown, ctx.Err())
		}
		if !started {
			return errors.Join(platformcommand.ErrEffectUnavailable, runErr)
		}
		return errors.Join(
			platformcommand.ErrEffectVerification,
			errors.New("PostgreSQL logical backup failed"),
		)
	}
	return nil
}

func verifyDatabaseDump(
	ctx context.Context,
	runtimeBoundary streamingDockerRuntime,
	root string,
	relative string,
	postgresID string,
) error {
	target, err := managedPath(root, relative)
	if err != nil {
		return errors.Join(platformcommand.ErrEffectVerification, err)
	}
	file, err := openManagedRegularNoFollow(target)
	if err != nil {
		return errors.Join(platformcommand.ErrEffectVerification, err)
	}
	defer file.Close()
	started, err := runtimeBoundary.RunTo(
		ctx, file, io.Discard, "exec", "--interactive", "--user", "postgres", postgresID,
		"pg_restore", "--list",
	)
	if err != nil {
		if ctx.Err() != nil && started {
			return errors.Join(platformcommand.ErrEffectOutcomeUnknown, ctx.Err())
		}
		if !started {
			return errors.Join(platformcommand.ErrEffectUnavailable, err)
		}
		return errors.Join(
			platformcommand.ErrEffectVerification,
			errors.New("PostgreSQL backup verification failed"),
		)
	}
	return nil
}

func writeWorkloadSecretsArchive(root string, relative string) error {
	file, err := createBackupFile(root, relative)
	if err != nil {
		return err
	}
	writer := &boundedBackupWriter{writer: file, maximum: maximumWorkloadSecretArchiveSize}
	archive := tar.NewWriter(writer)
	secretRoot, err := managedPath(root, filepath.FromSlash(layout.WorkloadSecretRoot))
	if err != nil {
		_ = file.Close()
		return err
	}
	files := 0
	total := uint64(0)
	walkErr := filepath.WalkDir(secretRoot, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		contained, err := filepath.Rel(secretRoot, path)
		if err != nil {
			return errManagedConflict
		}
		info, err := os.Lstat(path)
		if err != nil || managedPathIsLink(path, info) ||
			verifyManagedPermissions(path, info.IsDir()) != nil {
			return errManagedConflict
		}
		if contained == "." {
			return nil
		}
		parts := strings.Split(filepath.ToSlash(contained), "/")
		if info.IsDir() {
			if len(parts) != 1 || paasv1.ValidateID("secretId", parts[0]) != nil {
				return errManagedConflict
			}
			return nil
		}
		if !info.Mode().IsRegular() || len(parts) != 2 ||
			paasv1.ValidateID("secretId", parts[0]) != nil ||
			paasv1.ValidateID("version", parts[1]) != nil || info.Size() < 0 ||
			info.Size() > 1024*1024 || files >= maximumWorkloadSecretFiles {
			return errManagedConflict
		}
		files++
		total += uint64(info.Size())
		if total > maximumWorkloadSecretBytes {
			return errors.New("workload secret backup exceeds its bound")
		}
		content, err := readManagedFile(
			root, filepath.Join(filepath.FromSlash(layout.WorkloadSecretRoot), contained),
			1024*1024,
		)
		if err != nil {
			return err
		}
		defer clear(content)
		header := &tar.Header{
			Name: filepath.ToSlash(contained), Mode: 0o600, Size: int64(len(content)),
			ModTime: time.Unix(0, 0).UTC(), Format: tar.FormatPAX,
		}
		if err := archive.WriteHeader(header); err != nil {
			return err
		}
		_, err = archive.Write(content)
		return err
	})
	archiveErr := archive.Close()
	syncErr := file.Sync()
	closeErr := file.Close()
	if walkErr != nil || archiveErr != nil || writer.exceeded || syncErr != nil || closeErr != nil {
		return errors.Join(
			walkErr, archiveErr, syncErr, closeErr,
			errors.New("workload secret backup failed"),
		)
	}
	return nil
}

func verifyWorkloadSecretsArchive(root string, relative string) error {
	return walkWorkloadSecretsArchive(root, relative, nil)
}

func verifyWorkloadSecretRestore(root string, relative string, apply bool) error {
	return walkWorkloadSecretsArchive(root, relative, func(name string, content []byte) error {
		parts := strings.Split(name, "/")
		directoryRelative := filepath.Join(
			filepath.FromSlash(layout.WorkloadSecretRoot), filepath.FromSlash(parts[0]),
		)
		_, err := managedDirectoryExists(root, directoryRelative)
		if err != nil {
			return errors.New("workload secret restore directory conflicts")
		}
		fileRelative := filepath.Join(directoryRelative, filepath.FromSlash(parts[1]))
		exists, err := managedFileExists(root, fileRelative)
		if err != nil {
			return errors.New("workload secret restore target conflicts")
		}
		if exists {
			existing, readErr := readManagedFile(root, fileRelative, 1024*1024)
			if readErr != nil || subtle.ConstantTimeCompare(existing, content) != 1 {
				clear(existing)
				return errors.New("workload secret restore content conflicts")
			}
			clear(existing)
			return nil
		}
		if !apply {
			return nil
		}
		if _, err := ensureManagedDirectory(root, directoryRelative); err != nil {
			return errors.New("workload secret restore directory is unsafe")
		}
		return writeRecoveredSecretVersion(root, fileRelative, content)
	})
}

func walkWorkloadSecretsArchive(
	root string,
	relative string,
	visit func(string, []byte) error,
) error {
	target, err := managedPath(root, relative)
	if err != nil {
		return err
	}
	file, err := openManagedRegularNoFollow(target)
	if err != nil {
		return err
	}
	defer file.Close()
	archive := tar.NewReader(io.LimitReader(file, int64(maximumWorkloadSecretArchiveSize)+1))
	seen := make(map[string]struct{})
	total := uint64(0)
	for {
		header, err := archive.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil || header == nil || header.Typeflag != tar.TypeReg ||
			header.Size < 0 || header.Size > 1024*1024 || header.Mode != 0o600 ||
			filepath.IsAbs(header.Name) || filepath.Clean(header.Name) != header.Name ||
			strings.Contains(header.Name, "\\") {
			return errors.New("workload secret backup archive is invalid")
		}
		parts := strings.Split(header.Name, "/")
		if len(parts) != 2 || paasv1.ValidateID("secretId", parts[0]) != nil ||
			paasv1.ValidateID("version", parts[1]) != nil {
			return errors.New("workload secret backup path is invalid")
		}
		if _, duplicate := seen[header.Name]; duplicate || len(seen) >= maximumWorkloadSecretFiles {
			return errors.New("workload secret backup inventory is invalid")
		}
		seen[header.Name] = struct{}{}
		total += uint64(header.Size)
		if total > maximumWorkloadSecretBytes {
			return errors.New("workload secret backup exceeds its bound")
		}
		if visit == nil {
			if copied, err := io.Copy(io.Discard, archive); err != nil || copied != header.Size {
				return errors.New("workload secret backup content is invalid")
			}
			continue
		}
		content, readErr := io.ReadAll(io.LimitReader(archive, header.Size+1))
		if readErr != nil || int64(len(content)) != header.Size {
			clear(content)
			return errors.New("workload secret backup content is invalid")
		}
		visitErr := visit(header.Name, content)
		clear(content)
		if visitErr != nil {
			return visitErr
		}
	}
	return nil
}

func writeRecoveredSecretVersion(root string, relative string, content []byte) (returnErr error) {
	if len(content) > 1024*1024 {
		return errors.New("recovered workload secret exceeds its bound")
	}
	target, err := managedPath(root, relative)
	if err != nil {
		return err
	}
	if _, err := ensureManagedDirectory(root, filepath.Dir(relative)); err != nil {
		return err
	}
	if info, statErr := os.Lstat(target); statErr == nil {
		if managedPathIsLink(target, info) || !info.Mode().IsRegular() ||
			verifyManagedPermissions(target, false) != nil {
			return errManagedConflict
		}
		existing, readErr := readManagedFile(root, relative, 1024*1024)
		defer clear(existing)
		if readErr != nil || subtle.ConstantTimeCompare(existing, content) != 1 {
			return errManagedConflict
		}
		return nil
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return errManagedConflict
	}
	partial := target + ".recovery-partial"
	if info, statErr := os.Lstat(partial); statErr == nil {
		if managedPathIsLink(partial, info) || !info.Mode().IsRegular() ||
			verifyManagedPermissions(partial, false) != nil || os.Remove(partial) != nil {
			return errManagedConflict
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return errManagedConflict
	}
	file, err := os.OpenFile(partial, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return errors.New("create recovered workload secret failed")
	}
	removePartial := true
	defer func() {
		if file != nil {
			returnErr = errors.Join(returnErr, file.Close())
		}
		if removePartial {
			_ = os.Remove(partial)
		}
	}()
	if err := protectManagedPath(partial, false); err != nil {
		return errors.New("protect recovered workload secret failed")
	}
	if _, err := file.Write(content); err != nil {
		return errors.New("write recovered workload secret failed")
	}
	if err := file.Sync(); err != nil {
		return errors.New("write recovered workload secret failed")
	}
	if err := file.Close(); err != nil {
		file = nil
		return errors.New("write recovered workload secret failed")
	}
	file = nil
	if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
		return errManagedConflict
	}
	if err := durableReplaceManaged(partial, target, filepath.Dir(target)); err != nil {
		return errors.Join(errManagedOutcomeUnknown, err)
	}
	removePartial = false
	if err := verifyManagedPermissions(target, false); err != nil {
		return errors.Join(errManagedOutcomeUnknown, err)
	}
	observed, err := readManagedFile(root, relative, 1024*1024)
	defer clear(observed)
	if err != nil || subtle.ConstantTimeCompare(observed, content) != 1 {
		return errManagedOutcomeUnknown
	}
	return nil
}

func sealBackupManifest(value backupManifest, key []byte) ([]byte, error) {
	if len(key) != sha256.Size {
		return nil, errors.New("backup seal key is invalid")
	}
	value.Seal = nil
	canonical, err := json.Marshal(value)
	if err != nil {
		return nil, errors.New("encode backup commitment failed")
	}
	defer clear(canonical)
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(backupSealDomain))
	_, _ = mac.Write(canonical)
	value.Seal = &backupSeal{
		Algorithm: backupSealAlgorithm, KeyID: backupSealKeyID,
		Value: "sha256:" + hex.EncodeToString(mac.Sum(nil)),
	}
	content, err := json.Marshal(value)
	if err != nil {
		return nil, errors.New("encode sealed backup manifest failed")
	}
	return append(content, '\n'), nil
}

func verifyBackupDirectory(
	ctx context.Context,
	runtimeBoundary streamingDockerRuntime,
	plan platformcommand.InstallPlan,
	installation verifiedInstallation,
	postgresID string,
	backupID string,
	createdAt time.Time,
	relative string,
	key []byte,
) error {
	manifest, _, err := readVerifiedBackupDirectory(
		plan.Root, plan.InstallationID, backupID, relative, key,
	)
	if err != nil {
		return err
	}
	if manifest.ReleaseID != plan.Bundle.Manifest.Release.ID ||
		manifest.ReleaseDigest != plan.Bundle.ManifestSHA256 ||
		manifest.SchemaVersion != installation.bundle.Manifest.Database.SchemaVersion ||
		manifest.CreatedAt != createdAt {
		return errors.Join(
			platformcommand.ErrEffectVerification,
			errors.New("backup manifest identity is invalid"),
		)
	}
	return verifyDatabaseDump(
		ctx, runtimeBoundary, plan.Root,
		filepath.Join(relative, databaseDumpFilename), postgresID,
	)
}

func readVerifiedBackupDirectory(
	root string,
	installationID string,
	backupID string,
	relative string,
	key []byte,
) (backupManifest, string, error) {
	target, err := managedPath(root, relative)
	if err != nil {
		return backupManifest{}, "", errors.Join(platformcommand.ErrEffectVerification, err)
	}
	info, err := validateManagedExistingPath(target)
	if err != nil || !info.IsDir() || verifyManagedPermissions(target, true) != nil {
		return backupManifest{}, "", errors.Join(
			platformcommand.ErrEffectVerification,
			errors.New("backup directory is unsafe"),
		)
	}
	entries, err := os.ReadDir(target)
	wantNames := []string{backupManifestFilename, databaseDumpFilename, workloadSecretsFilename}
	if err != nil || len(entries) != len(wantNames) {
		return backupManifest{}, "", errors.Join(
			platformcommand.ErrEffectVerification,
			errors.New("backup inventory is invalid"),
		)
	}
	actualNames := make([]string, 0, len(entries))
	for _, entry := range entries {
		actualNames = append(actualNames, entry.Name())
	}
	slices.Sort(actualNames)
	slices.Sort(wantNames)
	if !slices.Equal(actualNames, wantNames) {
		return backupManifest{}, "", errors.Join(
			platformcommand.ErrEffectVerification,
			errors.New("backup inventory is invalid"),
		)
	}
	content, err := readManagedFile(
		root, filepath.Join(relative, backupManifestFilename), maximumBackupManifestBytes,
	)
	if err != nil {
		return backupManifest{}, "", errors.Join(platformcommand.ErrEffectVerification, err)
	}
	defer clear(content)
	manifestDigestValue := sha256.Sum256(content)
	manifestDigest := "sha256:" + hex.EncodeToString(manifestDigestValue[:])
	var manifest backupManifest
	if contractjson.DecodeObjectBytes(content, maximumBackupManifestBytes, &manifest) != nil ||
		manifest.APIVersion != backupAPIVersion || manifest.Kind != backupKind ||
		manifest.BackupID != backupID || manifest.InstallationID != installationID ||
		manifest.ReleaseID == "" || !validSHA256(manifest.ReleaseDigest) ||
		manifest.SchemaVersion == 0 || manifest.CreatedAt.IsZero() ||
		manifest.CreatedAt.Location() != time.UTC ||
		manifest.CreatedAt != manifest.CreatedAt.Truncate(time.Microsecond) ||
		len(manifest.Artifacts) != 2 || manifest.Seal == nil ||
		manifest.Seal.Algorithm != backupSealAlgorithm ||
		manifest.Seal.KeyID != backupSealKeyID || !validSHA256(manifest.Seal.Value) {
		return backupManifest{}, "", errors.Join(
			platformcommand.ErrEffectVerification,
			errors.New("backup manifest identity is invalid"),
		)
	}
	sealValue := manifest.Seal.Value
	manifest.Seal = nil
	canonical, err := json.Marshal(manifest)
	if err != nil {
		return backupManifest{}, "", errors.Join(platformcommand.ErrEffectVerification, err)
	}
	defer clear(canonical)
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(backupSealDomain))
	_, _ = mac.Write(canonical)
	wantSeal := "sha256:" + hex.EncodeToString(mac.Sum(nil))
	if subtle.ConstantTimeCompare([]byte(sealValue), []byte(wantSeal)) != 1 {
		return backupManifest{}, "", errors.Join(
			platformcommand.ErrEffectVerification,
			errors.New("backup manifest seal is invalid"),
		)
	}
	manifest.Seal = &backupSeal{
		Algorithm: backupSealAlgorithm, KeyID: backupSealKeyID, Value: sealValue,
	}
	wantArtifacts := []struct {
		path      string
		mediaType string
		maximum   uint64
	}{
		{databaseDumpFilename, "application/vnd.postgresql.custom", maximumDatabaseDumpBytes},
		{workloadSecretsFilename, "application/vnd.xiak.matrix.workload-secrets.tar", maximumWorkloadSecretArchiveSize},
	}
	for index, want := range wantArtifacts {
		artifact := manifest.Artifacts[index]
		if artifact.Path != want.path || artifact.MediaType != want.mediaType ||
			artifact.Size == 0 || artifact.Size > want.maximum || !validSHA256(artifact.SHA256) {
			return backupManifest{}, "", errors.Join(
				platformcommand.ErrEffectVerification,
				errors.New("backup artifact commitment is invalid"),
			)
		}
		observed, err := inspectBackupArtifact(
			root, filepath.Join(relative, want.path), want.maximum,
		)
		if err != nil || observed.Size != artifact.Size || observed.SHA256 != artifact.SHA256 {
			return backupManifest{}, "", errors.Join(
				platformcommand.ErrEffectVerification,
				errors.New("backup artifact differs from its commitment"),
			)
		}
	}
	if err := verifyWorkloadSecretsArchive(
		root, filepath.Join(relative, workloadSecretsFilename),
	); err != nil {
		return backupManifest{}, "", errors.Join(platformcommand.ErrEffectVerification, err)
	}
	return manifest, manifestDigest, nil
}

func publishBackupDirectory(root, partialRelative, finalRelative string) error {
	partial, err := managedPath(root, partialRelative)
	if err != nil {
		return errors.Join(platformcommand.ErrEffectConflict, err)
	}
	final, err := managedPath(root, finalRelative)
	if err != nil {
		return errors.Join(platformcommand.ErrEffectConflict, err)
	}
	if _, err := os.Lstat(final); !errors.Is(err, os.ErrNotExist) {
		return errors.Join(
			platformcommand.ErrEffectConflict,
			errors.New("backup destination already exists"),
		)
	}
	if err := os.Rename(partial, final); err != nil {
		return errors.Join(platformcommand.ErrEffectOutcomeUnknown, err)
	}
	if err := syncManagedDirectory(filepath.Dir(final)); err != nil {
		return errors.Join(platformcommand.ErrEffectOutcomeUnknown, err)
	}
	return nil
}

func loadBackupSealKey(root string, entropy io.Reader, create bool) ([]byte, error) {
	path := filepath.FromSlash(layout.BackupSealKey)
	var content []byte
	var err error
	if create {
		content, err = ensureRandomHex(root, layout.BackupSealKey, entropy)
	} else {
		content, err = readManagedFile(root, path, 64)
	}
	if err != nil {
		clear(content)
		return nil, errors.Join(platformcommand.ErrEffectVerification, err)
	}
	defer clear(content)
	key, err := hex.DecodeString(string(content))
	if err != nil || len(key) != 32 {
		clear(key)
		return nil, errors.Join(
			platformcommand.ErrEffectVerification,
			errors.New("backup seal key is invalid"),
		)
	}
	return key, nil
}

func managedDirectoryExists(root, relative string) (bool, error) {
	target, err := managedPath(root, relative)
	if err != nil {
		return false, err
	}
	info, err := os.Lstat(target)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil || managedPathIsLink(target, info) || !info.IsDir() ||
		verifyManagedPermissions(target, true) != nil {
		return false, errManagedConflict
	}
	return true, nil
}

func createBackupFile(root, relative string) (*os.File, error) {
	target, err := managedPath(root, relative)
	if err != nil {
		return nil, err
	}
	if _, err := ensureManagedDirectory(root, filepath.Dir(relative)); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, errors.New("create backup artifact failed")
	}
	if err := protectManagedPath(target, false); err != nil {
		_ = file.Close()
		return nil, errors.New("protect backup artifact failed")
	}
	return file, nil
}

func inspectBackupArtifact(root, relative string, maximum uint64) (backupArtifact, error) {
	if maximum == 0 || maximum > maximumDatabaseDumpBytes {
		return backupArtifact{}, errors.New("backup artifact bound is invalid")
	}
	target, err := managedPath(root, relative)
	if err != nil {
		return backupArtifact{}, err
	}
	before, err := validateManagedExistingPath(target)
	if err != nil || !before.Mode().IsRegular() || before.Size() <= 0 ||
		uint64(before.Size()) > maximum || verifyManagedPermissions(target, false) != nil {
		return backupArtifact{}, errors.New("backup artifact is unsafe")
	}
	file, err := openManagedRegularNoFollow(target)
	if err != nil {
		return backupArtifact{}, errors.New("open backup artifact failed")
	}
	defer file.Close()
	digest := sha256.New()
	written, err := io.Copy(digest, io.LimitReader(file, int64(maximum)+1))
	after, statErr := file.Stat()
	if err != nil || statErr != nil || written != before.Size() || written <= 0 ||
		uint64(written) > maximum || !os.SameFile(before, after) {
		return backupArtifact{}, errors.New("read backup artifact failed")
	}
	return backupArtifact{
		Size: uint64(written), SHA256: "sha256:" + hex.EncodeToString(digest.Sum(nil)),
	}, nil
}

func validSHA256(value string) bool {
	if len(value) != len("sha256:")+sha256.Size*2 || !strings.HasPrefix(value, "sha256:") ||
		strings.ToLower(value) != value {
		return false
	}
	decoded, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil && len(decoded) == sha256.Size
}

type boundedBackupWriter struct {
	writer   io.Writer
	maximum  uint64
	written  uint64
	exceeded bool
}

func (writer *boundedBackupWriter) Write(content []byte) (int, error) {
	if writer == nil || writer.writer == nil || writer.exceeded ||
		writer.written > writer.maximum || uint64(len(content)) > writer.maximum-writer.written {
		if writer != nil {
			writer.exceeded = true
		}
		return 0, errors.New("backup artifact exceeds its bound")
	}
	written, err := writer.writer.Write(content)
	writer.written += uint64(written)
	return written, err
}
