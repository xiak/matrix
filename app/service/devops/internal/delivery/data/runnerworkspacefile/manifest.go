package runnerworkspacefile

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"hash"
	"io"
	"strings"

	devopsbuildv1 "github.com/xiak/matrix/api/adapter/devopsbuild/v1"
	devopsv1 "github.com/xiak/matrix/api/devops/v1"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/sourcearchive"
)

const (
	manifestSchemaVersion = 1
	maximumManifestBytes  = 16 * 1024
)

type manifest struct {
	SchemaVersion       uint32 `json:"schemaVersion"`
	ExecutionID         string `json:"executionId"`
	RequestDigest       string `json:"requestDigest"`
	RunnerID            string `json:"runnerId"`
	SourceArchiveDigest string `json:"sourceArchiveDigest"`
	ExpandedBytes       int64  `json:"expandedBytes"`
	PathCount           uint64 `json:"pathCount"`
	DirectoryCount      uint64 `json:"directoryCount"`
	TreeDigest          string `json:"treeDigest"`
	ContentDigest       string `json:"contentDigest"`
}

type treeEvidence struct {
	ExpandedBytes  int64
	PathCount      uint64
	DirectoryCount uint64
	TreeDigest     string
}

func newManifest(
	runnerID string,
	executionID string,
	request devopsbuildv1.Request,
	tree treeEvidence,
) (manifest, error) {
	requestDigest, err := devopsbuildv1.DigestRequest(request)
	if err != nil {
		return manifest{}, ErrInvalid
	}
	value := manifest{
		SchemaVersion:       manifestSchemaVersion,
		ExecutionID:         executionID,
		RequestDigest:       requestDigest,
		RunnerID:            runnerID,
		SourceArchiveDigest: request.SourceArchiveDigest,
		ExpandedBytes:       tree.ExpandedBytes,
		PathCount:           tree.PathCount,
		DirectoryCount:      tree.DirectoryCount,
		TreeDigest:          tree.TreeDigest,
	}
	value.ContentDigest = digestManifest(value)
	if validateManifest(value) != nil || validateManifestRequest(value, executionID, request) != nil {
		return manifest{}, ErrInvalid
	}
	return value, nil
}

func encodeManifest(value manifest) ([]byte, error) {
	if validateManifest(value) != nil {
		return nil, ErrInvalid
	}
	content, err := json.Marshal(value)
	if err != nil || len(content) == 0 || len(content) > maximumManifestBytes {
		return nil, errors.Join(ErrUnavailable, err)
	}
	return content, nil
}

func decodeManifest(content []byte) (manifest, error) {
	if len(content) == 0 || len(content) > maximumManifestBytes {
		return manifest{}, ErrUnavailable
	}
	var value manifest
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		return manifest{}, errors.Join(ErrUnavailable, err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) ||
		validateManifest(value) != nil {
		return manifest{}, ErrUnavailable
	}
	canonical, err := json.Marshal(value)
	if err != nil || !bytes.Equal(canonical, content) {
		return manifest{}, errors.Join(ErrUnavailable, err)
	}
	return value, nil
}

func validateManifest(value manifest) error {
	if value.SchemaVersion != manifestSchemaVersion ||
		devopsv1.ValidateDigest("runnerWorkspace.executionId", value.ExecutionID) != nil ||
		devopsv1.ValidateDigest("runnerWorkspace.requestDigest", value.RequestDigest) != nil ||
		!validRunnerID(value.RunnerID) ||
		devopsv1.ValidateDigest("runnerWorkspace.sourceArchiveDigest", value.SourceArchiveDigest) != nil ||
		value.ExpandedBytes < 0 || value.ExpandedBytes > sourcearchive.MaximumExpandedBytes ||
		value.PathCount > sourcearchive.MaximumPathCount ||
		value.DirectoryCount > sourcearchive.MaximumPathCount ||
		devopsv1.ValidateDigest("runnerWorkspace.treeDigest", value.TreeDigest) != nil ||
		devopsv1.ValidateDigest("runnerWorkspace.contentDigest", value.ContentDigest) != nil ||
		value.ContentDigest != digestManifest(value) {
		return ErrUnavailable
	}
	return nil
}

func validateManifestRequest(
	value manifest,
	executionID string,
	request devopsbuildv1.Request,
) error {
	wantExecutionID, err := devopsbuildv1.ExecutionID(request)
	wantRequestDigest, requestErr := devopsbuildv1.DigestRequest(request)
	if err != nil || requestErr != nil || executionID != wantExecutionID ||
		value.ExecutionID != executionID || value.RequestDigest != wantRequestDigest ||
		value.SourceArchiveDigest != request.SourceArchiveDigest ||
		value.ExpandedBytes != request.SourceExpandedBytes ||
		value.PathCount != request.SourcePathCount {
		return ErrConflict
	}
	return nil
}

func manifestMatchesTree(value manifest, tree treeEvidence) bool {
	return value.ExpandedBytes == tree.ExpandedBytes &&
		value.PathCount == tree.PathCount &&
		value.DirectoryCount == tree.DirectoryCount &&
		value.TreeDigest == tree.TreeDigest
}

func digestManifest(value manifest) string {
	digest := sha256.New()
	writeString(digest, "matrix-devops-runner-workspace-manifest-v1")
	writeUint64(digest, uint64(value.SchemaVersion))
	for _, field := range []string{
		value.ExecutionID,
		value.RequestDigest,
		value.RunnerID,
		value.SourceArchiveDigest,
		value.TreeDigest,
	} {
		writeString(digest, field)
	}
	writeUint64(digest, uint64(value.ExpandedBytes))
	writeUint64(digest, value.PathCount)
	writeUint64(digest, value.DirectoryCount)
	return "sha256:" + hex.EncodeToString(digest.Sum(nil))
}

func startTreeDigest() hash.Hash {
	digest := sha256.New()
	writeString(digest, "matrix-devops-runner-source-tree-v1")
	return digest
}

func writeTreeHeader(destination hash.Hash, path string, executable bool, size int64) {
	writeString(destination, path)
	if executable {
		writeUint64(destination, 1)
	} else {
		writeUint64(destination, 0)
	}
	writeUint64(destination, uint64(size))
}

func finishTreeDigest(digest hash.Hash) string {
	return "sha256:" + hex.EncodeToString(digest.Sum(nil))
}

func writeString(destination hash.Hash, value string) {
	writeUint64(destination, uint64(len(value)))
	_, _ = destination.Write([]byte(value))
}

func writeUint64(destination hash.Hash, value uint64) {
	var framed [8]byte
	binary.BigEndian.PutUint64(framed[:], value)
	_, _ = destination.Write(framed[:])
}

func validRunnerID(value string) bool {
	return len(value) == len("runner-")+sha256.Size*2 &&
		strings.HasPrefix(value, "runner-") && lowerHex(strings.TrimPrefix(value, "runner-"))
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
