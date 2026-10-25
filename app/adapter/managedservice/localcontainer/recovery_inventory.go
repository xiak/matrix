package localcontainer

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

const (
	maximumRecoveryProviders = 64
	maximumRecoveryProjects  = 4096
)

var (
	recoveryProviderPattern = regexp.MustCompile(`^managed-[a-z][a-z0-9-]{0,62}$`)
	recoveryProjectPattern  = regexp.MustCompile(`^matrix-[0-9a-f]{24}$`)
)

// ProviderDirectoryName is the shared installation directory contract for a
// local managed-service product. The product adapter still owns its runtime
// semantics; this name only makes every provider's installation identities
// visible to the backup/recovery inventory witness.
func ProviderDirectoryName(serviceName string) (string, error) {
	if !serviceNamePattern.MatchString(serviceName) {
		return "", errors.New("local managed-service name is invalid")
	}
	return "managed-" + serviceName, nil
}

// InspectRecoveryInventory commits only provider and installation identities.
// It never reads database contents, credentials, endpoints, or Compose files.
// A prepared project participates before its first runtime effect, so an old
// backup cannot silently orphan a newly requested managed service.
func InspectRecoveryInventory(bindingRoot string) (string, error) {
	if !filepath.IsAbs(bindingRoot) || filepath.Clean(bindingRoot) != bindingRoot {
		return "", errors.New("local managed-service recovery root is invalid")
	}
	before, err := os.Lstat(bindingRoot)
	if err != nil || !before.IsDir() || before.Mode()&os.ModeSymlink != 0 ||
		(os.PathSeparator == '/' && before.Mode().Perm()&0o077 != 0) {
		return "", errors.New("local managed-service recovery root is unavailable")
	}
	root, err := os.Open(bindingRoot)
	if err != nil {
		return "", errors.New("local managed-service recovery inventory is unavailable")
	}
	defer root.Close()
	opened, err := root.Stat()
	if err != nil || !os.SameFile(before, opened) {
		return "", errors.New("local managed-service recovery root changed")
	}
	entries, err := root.ReadDir(maximumRecoveryProviders + maximumRecoveryProjects + 1)
	if (err != nil && !errors.Is(err, io.EOF)) ||
		len(entries) > maximumRecoveryProviders+maximumRecoveryProjects {
		return "", errors.New("local managed-service recovery inventory is unavailable")
	}
	witnesses := make([]string, 0)
	providers := 0
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), "managed-") {
			continue
		}
		providers++
		if providers > maximumRecoveryProviders || !recoveryProviderPattern.MatchString(entry.Name()) {
			return "", errors.New("local managed-service provider inventory exceeds its bound")
		}
		providerPath := filepath.Join(bindingRoot, entry.Name())
		providerInfo, statErr := os.Lstat(providerPath)
		if statErr != nil || !providerInfo.IsDir() || providerInfo.Mode()&os.ModeSymlink != 0 ||
			(os.PathSeparator == '/' && providerInfo.Mode().Perm()&0o077 != 0) {
			return "", errors.New("local managed-service provider inventory is unproved")
		}
		provider, openErr := os.Open(providerPath)
		if openErr != nil {
			return "", errors.New("local managed-service provider inventory is unavailable")
		}
		projects, readErr := provider.ReadDir(maximumRecoveryProjects - len(witnesses) + 1)
		closeErr := provider.Close()
		if (readErr != nil && !errors.Is(readErr, io.EOF)) || closeErr != nil ||
			len(projects)+len(witnesses) > maximumRecoveryProjects {
			return "", errors.New("local managed-service project inventory exceeds its bound")
		}
		for _, project := range projects {
			projectPath := filepath.Join(providerPath, project.Name())
			projectInfo, statErr := os.Lstat(projectPath)
			if statErr != nil || !recoveryProjectPattern.MatchString(project.Name()) ||
				!projectInfo.IsDir() || projectInfo.Mode()&os.ModeSymlink != 0 ||
				(os.PathSeparator == '/' && projectInfo.Mode().Perm()&0o077 != 0) {
				return "", errors.New("local managed-service project inventory is unproved")
			}
			witnesses = append(witnesses, entry.Name()+"\x00"+project.Name())
		}
	}
	after, err := os.Lstat(bindingRoot)
	if err != nil || !os.SameFile(before, after) {
		return "", errors.New("local managed-service recovery root changed")
	}
	slices.Sort(witnesses)
	digest := sha256.New()
	_, _ = digest.Write([]byte("matrix-managed-service-recovery-inventory-v2\x00"))
	for _, witness := range witnesses {
		_, _ = digest.Write([]byte(witness))
		_, _ = digest.Write([]byte{0})
	}
	return "sha256:" + hex.EncodeToString(digest.Sum(nil)), nil
}
