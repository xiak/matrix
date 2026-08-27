package releasebuild

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"

	nodev1 "github.com/xiak/matrix/api/adapter/node/v1"
	"github.com/xiak/matrix/app/service/installation/nodeconfig"
	installationrelease "github.com/xiak/matrix/app/service/installation/release"
)

// The build accepts this fixed upstream archive, never a caller-selected
// executable or a download/pull instruction in the installed release.
const NodeExporterArchiveSHA256 = "b51d8a76aa2a9156a55d501aca6276fae09e262259a5e4e831d2c2222f084e63"

var nodeBinarySpecifications = []binarySpecification{
	{name: "mx", packagePath: "./app/service/installation/cmd/mx"},
	{name: "matrix-node-agent", packagePath: "./app/service/nodeagent/cmd/matrix-node-agent"},
}

func nodeManifest(value installationrelease.Manifest) installationrelease.Manifest {
	value.Kind = installationrelease.NodeManifestKind
	value.Database = installationrelease.DatabaseProfile{}
	value.Node = &installationrelease.NodeProfile{ProtocolAPIVersion: nodev1.APIVersion,
		RuntimeRevision: nodeconfig.RuntimeRevision, CollectorVersion: nodeconfig.CollectorVersion}
	value.Host.MinimumSystemd = nodeconfig.MinimumSystemd
	value.Host.MinimumDocker = nodeconfig.MinimumDocker
	value.Host.MinimumCompose = nodeconfig.MinimumCompose
	value.TopologyDigest = nodeconfig.ContractDigest()
	value.MinimumFreeBytes = 1024 * 1024 * 1024
	return value
}

func assembleNodePayloads(ctx context.Context, config Config, effects Effects, bundle string) ([]installationrelease.File, error) {
	if err := unpackNodeCollector(config.CollectorArchive, bundle); err != nil {
		return nil, err
	}
	for _, specification := range nodeBinarySpecifications {
		if err := effects.BuildGoBinary(ctx, config.RepositoryRoot, specification.packagePath, filepath.Join(bundle, "bin", specification.name)); err != nil {
			return nil, errors.New("build node release executable failed")
		}
	}
	files := nodePlaceholderPayloads()
	for index := range files {
		size, digest, err := hashRegularFile(filepath.Join(bundle, filepath.FromSlash(files[index].Path)))
		if err != nil {
			return nil, err
		}
		files[index].Size, files[index].SHA256 = size, digest
	}
	return files, nil
}

func nodePlaceholderPayloads() []installationrelease.File {
	files := []installationrelease.File{}
	for _, name := range []string{"bin/matrix-node-agent", "bin/mx", "bin/node-exporter", "licenses/node-exporter-license.txt", "licenses/node-exporter-notice.txt"} {
		executable := filepath.Ext(name) != ".txt"
		mediaType := "text/plain"
		if executable {
			mediaType = "application/vnd.matrix.executable"
		}
		files = append(files, installationrelease.File{Path: name, Size: 1, SHA256: placeholderDigest(name), MediaType: mediaType, Executable: executable})
	}
	return files
}

func unpackNodeCollector(archivePath, bundle string) error {
	const maximumArchive = 64 * 1024 * 1024
	info, err := os.Lstat(archivePath)
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maximumArchive {
		return errors.New("pinned collector archive is invalid")
	}
	file, err := os.Open(archivePath)
	if err != nil {
		return errors.New("pinned collector archive is unavailable")
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return errors.New("pinned collector archive changed")
	}
	content, err := io.ReadAll(io.LimitReader(file, maximumArchive+1))
	if err != nil || len(content) != int(info.Size()) || len(content) > maximumArchive {
		return errors.New("pinned collector archive is outside its bound")
	}
	digest := sha256.Sum256(content)
	if hex.EncodeToString(digest[:]) != NodeExporterArchiveSHA256 {
		return errors.New("pinned collector archive digest changed")
	}
	reader, err := gzip.NewReader(bytes.NewReader(content))
	if err != nil {
		return errors.New("pinned collector compression is invalid")
	}
	defer reader.Close()
	if err := extractNodeCollector(io.LimitReader(reader, 96*1024*1024), bundle); err != nil {
		return err
	}
	// Drain to validate the compressed stream checksum as well as its archive.
	if count, err := io.Copy(io.Discard, io.LimitReader(reader, 1024*1024+1)); err != nil || count > 1024*1024 {
		return errors.New("pinned collector compression is invalid")
	}
	return nil
}

func extractNodeCollector(source io.Reader, bundle string) error {
	prefix := "node_exporter-" + nodeconfig.CollectorVersion + ".linux-amd64/"
	required := map[string]string{
		prefix + "node_exporter": "bin/node-exporter",
		prefix + "LICENSE":       "licenses/node-exporter-license.txt",
		prefix + "NOTICE":        "licenses/node-exporter-notice.txt",
	}
	if err := os.Mkdir(filepath.Join(bundle, "licenses"), 0o700); err != nil {
		return errors.New("create node license directory failed")
	}
	reader := tar.NewReader(source)
	seen := make([]string, 0, 4)
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil || len(seen) >= 4 || slices.Contains(seen, header.Name) {
			return errors.New("collector archive inventory is invalid")
		}
		seen = append(seen, header.Name)
		if header.Name == prefix && header.Typeflag == tar.TypeDir && header.Size == 0 {
			continue
		}
		target, found := required[header.Name]
		if !found || header.Typeflag != tar.TypeReg || header.Linkname != "" || header.Size <= 0 || header.Size > 64*1024*1024 {
			return errors.New("collector archive payload is invalid")
		}
		if target != "bin/node-exporter" && header.Size > 1024*1024 {
			return errors.New("collector license is oversized")
		}
		mode := os.FileMode(0o600)
		if target == "bin/node-exporter" {
			mode = 0o700
		}
		file, err := os.OpenFile(filepath.Join(bundle, filepath.FromSlash(target)), os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
		if err != nil {
			return errors.New("create collector payload failed")
		}
		_, copyErr := io.CopyN(file, reader, header.Size)
		closeErr := errors.Join(file.Sync(), file.Close())
		if copyErr != nil || closeErr != nil {
			return errors.New("write collector payload failed")
		}
		delete(required, header.Name)
	}
	if len(required) != 0 {
		return errors.New("collector archive is incomplete")
	}
	return nil
}
