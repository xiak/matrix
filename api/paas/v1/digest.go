package paasv1

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"hash"
	"slices"
	"strconv"
)

// InstallationVerificationDeploymentID returns the stable Deployment identity
// shared by the fixed PaaS probe and the authenticated installation lifecycle.
// Keeping this derivation in the wire-contract package prevents lifecycle
// recovery from copying an internal PaaS resource algorithm.
func InstallationVerificationDeploymentID(installationID string) (ResourceID, error) {
	if ValidateID("installationId", installationID) != nil {
		return "", errors.New("installation verification identity is invalid")
	}
	digest := sha256.Sum256([]byte(
		"matrix.installation.verification.v1\x00installation\x00" + installationID,
	))
	identity := ResourceID(
		"installation-verification-deploy-" + hex.EncodeToString(digest[:12]),
	)
	if ValidateID("deploymentId", string(identity)) != nil {
		return "", errors.New("installation verification identity is invalid")
	}
	return identity, nil
}

// ConfigurationValuesDigest returns a deterministic digest without relying
// on map iteration or ambiguous delimiter escaping.
func ConfigurationValuesDigest(values map[string]string) string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	slices.Sort(keys)

	digest := sha256.New()
	writeDigestLength(digest, uint64(len(keys)))
	for _, key := range keys {
		writeDigestBytes(digest, []byte(key))
		writeDigestBytes(digest, []byte(values[key]))
	}
	return digestString(digest)
}

// DeploymentSpecContentDigest seals only desired content. A rollback that
// copies the same content into a later generation therefore retains the same
// content digest while receiving a new generation identity.
func DeploymentSpecContentDigest(value DeploymentSpec) string {
	digest := newContractDigest("matrix-deployment-spec-v1")
	writeDeploymentSpec(digest, value)
	return digest.sum()
}

// DeploymentExecutionRequestDigest seals every semantic input that may
// change an executor effect. Retry bookkeeping and deadlines are deliberately
// excluded so observation and replay retain one command payload identity.
func DeploymentExecutionRequestDigest(value DeploymentExecutionRequest) string {
	digest := newContractDigest("matrix-deployment-execution-request-v1")
	writeString(digest, string(value.Command.Action))
	writeScope(digest, value.Command.Scope)
	writeString(digest, string(value.Command.ApplicationID))
	writeString(digest, string(value.Command.ApplicationRevisionID))
	writeString(digest, string(value.Command.DeploymentID))
	writeString(digest, string(value.Command.ExecutionTargetID))
	writeString(digest, value.Command.BindingRef)

	writeScope(digest, value.Generation.Scope)
	writeString(digest, string(value.Generation.DeploymentID))
	writeUint64(digest, value.Generation.Generation)
	writeString(digest, value.Generation.ContentDigest)
	writeDeploymentSpec(digest, value.Generation.Spec)

	writeApplicationRevision(digest, value.ApplicationRevision)

	revisions := append([]ConfigurationRevision(nil), value.ConfigurationRevisions...)
	slices.SortFunc(revisions, func(left, right ConfigurationRevision) int {
		return compareStrings(string(left.Metadata.ID), string(right.Metadata.ID))
	})
	writeUint64(digest, uint64(len(revisions)))
	for _, revision := range revisions {
		writeScope(digest, revision.Metadata.Scope)
		writeString(digest, string(revision.Metadata.ID))
		writeUint64(digest, revision.Metadata.ResourceVersion)
		writeString(digest, string(revision.Spec.ConfigurationID))
		writeString(digest, revision.Spec.ContentDigest)
		writeStringMap(digest, revision.Spec.Values)
	}

	writePlacementDecision(digest, value.Placement)
	return digest.sum()
}

func ObserveDeploymentRequestDigest(value ObserveDeploymentRequest) string {
	digest := newContractDigest("matrix-observe-deployment-request-v1")
	writeString(digest, string(value.Command.Action))
	writeScope(digest, value.Command.Scope)
	writeString(digest, string(value.Command.ApplicationID))
	writeString(digest, string(value.Command.ApplicationRevisionID))
	writeString(digest, string(value.Command.DeploymentID))
	writeString(digest, string(value.Command.ExecutionTargetID))
	writeString(digest, value.Command.BindingRef)
	writeUint64(digest, value.Generation)
	writeString(digest, value.ExpectedContentDigest)
	return digest.sum()
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
	return digestString(digest.hash)
}

func writeDeploymentSpec(digest *contractDigest, value DeploymentSpec) {
	writeString(digest, string(value.ApplicationRevisionID))
	writeString(digest, string(value.PlacementPolicyID))
	writeString(digest, string(value.DesiredState))

	components := append([]DeploymentComponent(nil), value.Components...)
	slices.SortFunc(components, func(left, right DeploymentComponent) int {
		return compareStrings(left.Name, right.Name)
	})
	writeUint64(digest, uint64(len(components)))
	for _, component := range components {
		writeString(digest, component.Name)
		writeUint64(digest, uint64(component.Replicas))
		bindings := append([]ComponentBinding(nil), component.Bindings...)
		slices.SortFunc(bindings, compareBindings)
		writeUint64(digest, uint64(len(bindings)))
		for _, binding := range bindings {
			writeString(digest, binding.Name)
			writeString(digest, string(binding.ConfigurationRevisionID))
			if binding.SecretVersion == nil {
				writeBool(digest, false)
				continue
			}
			writeBool(digest, true)
			writeString(digest, string(binding.SecretVersion.SecretID))
			writeString(digest, binding.SecretVersion.Version)
		}
	}
}

func writeApplicationRevision(digest *contractDigest, value ApplicationRevision) {
	writeScope(digest, value.Metadata.Scope)
	writeString(digest, string(value.Metadata.ID))
	writeUint64(digest, value.Metadata.ResourceVersion)
	writeString(digest, string(value.Spec.ApplicationID))
	writeString(digest, value.Spec.Revision)
	writeString(digest, value.Spec.ContentDigest)

	components := append([]ApplicationRevisionComponent(nil), value.Spec.Components...)
	slices.SortFunc(components, func(left, right ApplicationRevisionComponent) int {
		return compareStrings(left.Name, right.Name)
	})
	writeUint64(digest, uint64(len(components)))
	for _, component := range components {
		writeString(digest, component.Name)
		writeString(digest, string(component.Artifact.Kind))
		writeString(digest, component.Artifact.Locator)
		writeString(digest, component.Artifact.Digest)
		writeInt64(digest, component.Resources.CPUMillis)
		writeInt64(digest, component.Resources.MemoryBytes)

		endpoints := append([]ApplicationEndpoint(nil), component.Endpoints...)
		slices.SortFunc(endpoints, compareEndpoints)
		writeUint64(digest, uint64(len(endpoints)))
		for _, endpoint := range endpoints {
			writeString(digest, endpoint.Name)
			writeUint64(digest, uint64(endpoint.Port))
			writeString(digest, string(endpoint.Protocol))
			writeString(digest, string(endpoint.Visibility))
		}

		inputs := append([]ComponentInput(nil), component.Inputs...)
		slices.SortFunc(inputs, compareInputs)
		writeUint64(digest, uint64(len(inputs)))
		for _, input := range inputs {
			writeString(digest, input.Name)
			writeString(digest, string(input.Kind))
			writeString(digest, string(input.Injection))
			writeBool(digest, input.Required)
		}
	}
}

func writePlacementDecision(digest *contractDigest, value PlacementDecision) {
	writeScope(digest, value.Metadata.Scope)
	writeString(digest, string(value.Metadata.ID))
	writeUint64(digest, value.Metadata.ResourceVersion)
	writeString(digest, string(value.DeploymentID))
	writeUint64(digest, value.DeploymentGeneration)
	writeUint64(digest, value.DeploymentResourceVersion)
	writeString(digest, string(value.ApplicationRevisionID))
	writeString(digest, string(value.PlacementPolicyID))
	writeUint64(digest, value.PolicyResourceVersion)
	writeString(digest, string(value.RequestedIsolationGuarantee))
	writeString(digest, string(value.Outcome))
	writeString(digest, string(value.ExecutionTargetID))
	writeUint64(digest, value.ExecutionTargetResourceVersion)
	writeString(digest, string(value.GrantedIsolationGuarantee))
	writeString(digest, value.CandidateSetDigest)
	writeInt64(digest, value.DecidedAt.UnixMicro())
}

func writeScope(digest *contractDigest, value ResourceScope) {
	writeString(digest, string(value.Kind))
	writeString(digest, string(value.TenantID))
}

func writeStringMap(digest *contractDigest, values map[string]string) {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	writeUint64(digest, uint64(len(keys)))
	for _, key := range keys {
		writeString(digest, key)
		writeString(digest, values[key])
	}
}

func compareBindings(left, right ComponentBinding) int {
	if result := compareStrings(left.Name, right.Name); result != 0 {
		return result
	}
	if result := compareStrings(string(left.ConfigurationRevisionID), string(right.ConfigurationRevisionID)); result != 0 {
		return result
	}
	leftSecret := ""
	rightSecret := ""
	if left.SecretVersion != nil {
		leftSecret = string(left.SecretVersion.SecretID) + "\x00" + left.SecretVersion.Version
	}
	if right.SecretVersion != nil {
		rightSecret = string(right.SecretVersion.SecretID) + "\x00" + right.SecretVersion.Version
	}
	return compareStrings(leftSecret, rightSecret)
}

func compareEndpoints(left, right ApplicationEndpoint) int {
	leftKey := left.Name + "\x00" + string(left.Protocol) + "\x00" + strconv.FormatUint(uint64(left.Port), 10)
	rightKey := right.Name + "\x00" + string(right.Protocol) + "\x00" + strconv.FormatUint(uint64(right.Port), 10)
	return compareStrings(leftKey, rightKey)
}

func compareInputs(left, right ComponentInput) int {
	leftKey := left.Name + "\x00" + string(left.Kind) + "\x00" + string(left.Injection)
	rightKey := right.Name + "\x00" + string(right.Kind) + "\x00" + string(right.Injection)
	return compareStrings(leftKey, rightKey)
}

func compareStrings(left, right string) int {
	if left < right {
		return -1
	}
	if left > right {
		return 1
	}
	return 0
}

func writeString(target *contractDigest, value string) {
	writeDigestBytes(target.hash, []byte(value))
}

func writeBool(target *contractDigest, value bool) {
	if value {
		writeDigestBytes(target.hash, []byte{1})
		return
	}
	writeDigestBytes(target.hash, []byte{0})
}

func writeInt64(target *contractDigest, value int64) {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], uint64(value))
	writeDigestBytes(target.hash, encoded[:])
}

func writeUint64(target *contractDigest, value uint64) {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], value)
	writeDigestBytes(target.hash, encoded[:])
}

func writeDigestBytes(target hash.Hash, value []byte) {
	writeDigestLength(target, uint64(len(value)))
	_, _ = target.Write(value)
}

func writeDigestLength(target hash.Hash, value uint64) {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], value)
	_, _ = target.Write(encoded[:])
}

func digestString(target hash.Hash) string {
	return "sha256:" + hex.EncodeToString(target.Sum(nil))
}
