package devopsv1

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"hash"
)

// PipelineDraftSpecDigest seals every tenant-selectable field without relying
// on JSON field order or ambiguous delimiter escaping.
func PipelineDraftSpecDigest(value PipelineDraftSpec) string {
	digest := newContractDigest("matrix-devops-pipeline-draft-v1")
	writeString(digest, string(value.RepositoryBindingID))
	writeString(digest, string(value.TriggerPolicy))
	writeString(digest, string(value.VerificationProfile))
	writeString(digest, string(value.DependencyEgress))
	writeString(digest, string(value.ReporterPolicy))
	return digest.sum()
}

// PipelineRevisionSpecDigest seals the resolved immutable execution contract.
func PipelineRevisionSpecDigest(value PipelineRevisionSpec) string {
	digest := newContractDigest("matrix-devops-pipeline-revision-v1")
	writeString(digest, string(value.RepositoryBindingID))
	writeString(digest, string(value.TriggerPolicy))
	writeString(digest, string(value.VerificationProfile))
	writeString(digest, string(value.ExecutorProfile))
	writeString(digest, value.ToolchainImageDigest)
	writeString(digest, string(value.DependencyEgress))
	writeString(digest, string(value.ReporterPolicy))
	writeUint64(digest, uint64(len(value.Steps)))
	for _, step := range value.Steps {
		writeUint64(digest, uint64(step.Ordinal))
		writeString(digest, string(step.Kind))
	}
	writeUint64(digest, uint64(value.Limits.StepTimeoutSeconds))
	writeUint64(digest, uint64(value.Limits.RunTimeoutSeconds))
	writeInt64(digest, value.Limits.CPUMillis)
	writeInt64(digest, value.Limits.MemoryBytes)
	writeInt64(digest, value.Limits.WritableBytes)
	writeUint64(digest, uint64(value.Limits.ProcessLimit))
	writeInt64(digest, value.Limits.MaxLogBytes)
	return digest.sum()
}

// PipelineRevisionID returns the deterministic identity of one immutable
// revision. It includes tenant authority so equal local pipeline IDs in two
// tenants cannot converge on one identity.
func PipelineRevisionID(
	scope ResourceScope,
	pipelineID ResourceID,
	revision uint64,
	contentDigest string,
) (ResourceID, error) {
	if ValidateResourceScope(scope) != nil ||
		ValidateID("pipelineId", string(pipelineID)) != nil ||
		revision == 0 || ValidateDigest("contentDigest", contentDigest) != nil {
		return "", errors.New("pipeline revision identity input is invalid")
	}
	digest := newContractDigest("matrix-devops-pipeline-revision-identity-v1")
	writeString(digest, string(scope.TenantID))
	writeString(digest, string(pipelineID))
	writeUint64(digest, revision)
	writeString(digest, contentDigest)
	sum := digest.hash.Sum(nil)
	return ResourceID("pipeline-revision-" + hex.EncodeToString(sum[:24])), nil
}

type contractDigest struct {
	hash hash.Hash
}

func newContractDigest(stream string) *contractDigest {
	digest := &contractDigest{hash: sha256.New()}
	writeString(digest, stream)
	return digest
}

func (digest *contractDigest) sum() string {
	return "sha256:" + hex.EncodeToString(digest.hash.Sum(nil))
}

func writeString(target *contractDigest, value string) {
	writeBytes(target.hash, []byte(value))
}

func writeInt64(target *contractDigest, value int64) {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], uint64(value))
	writeBytes(target.hash, encoded[:])
}

func writeUint64(target *contractDigest, value uint64) {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], value)
	writeBytes(target.hash, encoded[:])
}

func writeBytes(target hash.Hash, value []byte) {
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(value)))
	_, _ = target.Write(length[:])
	_, _ = target.Write(value)
}
