package devopsv1

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"hash"
)

// RepositoryBindingSpecDigest seals the normalized repository identity without
// relying on JSON field order or provider-specific serialization.
func RepositoryBindingSpecDigest(value RepositoryBindingSpec) string {
	digest := newContractDigest("matrix-devops-repository-binding-v1")
	writeString(digest, string(value.SourceConnectionID))
	writeString(digest, string(value.ExternalRepositoryID))
	writeString(digest, value.RepositoryPath)
	writeString(digest, value.TrustedDefaultBranch)
	return digest.sum()
}

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
	writeString(digest, value.RepositoryBindingDigest)
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
		revision == 0 || revision > MaximumContractInteger ||
		ValidateDigest("contentDigest", contentDigest) != nil {
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

// SourceEventSpecDigest seals every normalized event field independently of
// JSON serialization. It intentionally includes the raw-payload digest rather
// than the raw provider document.
func SourceEventSpecDigest(value SourceEventSpec) string {
	digest := newContractDigest("matrix-devops-source-event-v1")
	writeString(digest, string(value.ProjectID))
	writeString(digest, string(value.SourceConnectionID))
	writeString(digest, string(value.RepositoryBindingID))
	writeString(digest, value.RepositoryBindingDigest)
	writeString(digest, string(value.ExternalRepositoryID))
	writeString(digest, value.DeliveryID)
	writeString(digest, value.CanonicalPayloadDigest)
	writeChangeIdentity(digest, value.Change)
	return digest.sum()
}

// SourceEventID binds replay identity to the authenticated tenant and source
// endpoint. Content is excluded so a changed replay collides instead of
// silently producing a second SourceEvent.
func SourceEventID(
	scope ResourceScope,
	sourceConnectionID ResourceID,
	deliveryID string,
) (ResourceID, error) {
	if ValidateResourceScope(scope) != nil ||
		ValidateID("sourceConnectionId", string(sourceConnectionID)) != nil ||
		validateDeliveryID(deliveryID) != nil {
		return "", errors.New("source event identity input is invalid")
	}
	digest := newContractDigest("matrix-devops-source-event-identity-v1")
	writeString(digest, string(scope.TenantID))
	writeString(digest, string(sourceConnectionID))
	writeString(digest, deliveryID)
	sum := digest.hash.Sum(nil)
	return ResourceID("source-event-" + hex.EncodeToString(sum[:24])), nil
}

// PipelineRunInputDigest seals all immutable inputs required after admission.
func PipelineRunInputDigest(value PipelineRunInput) string {
	digest := newContractDigest("matrix-devops-pipeline-run-input-v1")
	writeString(digest, string(value.SourceEventID))
	writeString(digest, value.SourceEventDigest)
	writeString(digest, string(value.PipelineRevisionID))
	writeString(digest, value.PipelineRevisionDigest)
	writeString(digest, string(value.RepositoryBindingID))
	writeString(digest, value.RepositoryBindingDigest)
	writeChangeIdentity(digest, value.Change)
	return digest.sum()
}

func PipelineRunID(
	scope ResourceScope,
	sourceEventID ResourceID,
	pipelineRevisionID ResourceID,
	inputDigest string,
) (ResourceID, error) {
	if ValidateResourceScope(scope) != nil ||
		ValidateID("sourceEventId", string(sourceEventID)) != nil ||
		ValidateID("pipelineRevisionId", string(pipelineRevisionID)) != nil ||
		ValidateDigest("inputDigest", inputDigest) != nil {
		return "", errors.New("PipelineRun identity input is invalid")
	}
	digest := newContractDigest("matrix-devops-pipeline-run-identity-v1")
	writeString(digest, string(scope.TenantID))
	writeString(digest, string(sourceEventID))
	writeString(digest, string(pipelineRevisionID))
	writeString(digest, inputDigest)
	sum := digest.hash.Sum(nil)
	return ResourceID("pipeline-run-" + hex.EncodeToString(sum[:24])), nil
}

func writeChangeIdentity(digest *contractDigest, value ChangeIdentity) {
	writeUint64(digest, value.Number)
	writeString(digest, string(value.Action))
	writeString(digest, value.HeadCommit)
	writeString(digest, value.TrustedBaseCommit)
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
