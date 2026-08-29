package placement

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"hash"
	"sort"
	"time"

	paasv1 "github.com/xiak/matrix/api/paas/v1"
)

type canonicalEncoder struct {
	hash hash.Hash
}

func newCanonicalEncoder() *canonicalEncoder {
	return &canonicalEncoder{hash: sha256.New()}
}

func (encoder *canonicalEncoder) token(name string, value []byte) {
	encoder.lengthPrefixed([]byte(name))
	encoder.lengthPrefixed(value)
}

func (encoder *canonicalEncoder) lengthPrefixed(value []byte) {
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(value)))
	_, _ = encoder.hash.Write(size[:])
	_, _ = encoder.hash.Write(value)
}

func (encoder *canonicalEncoder) string(name, value string) {
	encoder.token(name, []byte(value))
}

func (encoder *canonicalEncoder) int64(name string, value int64) {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], uint64(value))
	encoder.token(name, encoded[:])
}

func (encoder *canonicalEncoder) uint64(name string, value uint64) {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], value)
	encoder.token(name, encoded[:])
}

func (encoder *canonicalEncoder) timestamp(name string, value time.Time) {
	encoder.int64(name, value.UnixMicro())
}

func (encoder *canonicalEncoder) digest() string {
	return "sha256:" + hex.EncodeToString(encoder.hash.Sum(nil))
}

func (planner *Planner) candidateSetDigest(
	input Input,
	requirements Resources,
	evaluations []candidateEvaluation,
	claims []CapacityClaim,
) string {
	encoder := newCanonicalEncoder()
	encoder.string("stream", "matrix-placement-candidate-set")
	encoder.string("algorithm", AlgorithmVersion)
	encoder.int64("max-observation-age-micros", planner.maxObservationAge.Microseconds())
	encoder.string("tenant-id", string(input.TenantID))

	deployment := input.Snapshot.Deployment
	encoder.string("deployment-id", string(deployment.Metadata.ID))
	encoder.uint64("deployment-generation", deployment.Generation)
	encoder.uint64("deployment-resource-version", deployment.Metadata.ResourceVersion)
	if active := input.Snapshot.ActivePlacement; active != nil {
		encoder.string("active-placement-decision-id", string(active.DecisionID))
		encoder.string("active-placement-target-id", string(active.ExecutionTargetID))
		encoder.string("active-placement-capacity-claim-id", string(active.CapacityClaimID))
	} else {
		encoder.string("active-placement-decision-id", "")
		encoder.string("active-placement-target-id", "")
		encoder.string("active-placement-capacity-claim-id", "")
	}

	revision := input.Snapshot.ApplicationRevision
	encoder.string("application-revision-id", string(revision.Metadata.ID))
	encoder.uint64("application-revision-resource-version", revision.Metadata.ResourceVersion)
	encoder.string("application-id", string(revision.Spec.ApplicationID))
	encoder.string("application-revision", revision.Spec.Revision)
	encoder.string("application-revision-content-digest", revision.Spec.ContentDigest)
	writeResources(encoder, "requirements", requirements)

	policy := input.Snapshot.Policy
	encoder.string("policy-id", string(policy.Metadata.ID))
	encoder.uint64("policy-resource-version", policy.Metadata.ResourceVersion)
	encoder.string("required-isolation", string(policy.Spec.RequiredIsolationGuarantee))
	encoder.string("strategy", string(policy.Spec.Strategy))
	writeResourceIDs(encoder, "eligible-pools", policy.Spec.EligibleExecutionPoolIDs)
	writeLabels(encoder, "policy-selector", policy.Spec.ExecutionTargetSelector.MatchLabels)
	policyVersion := ""
	if isolationPolicy := planner.policies[policy.Spec.RequiredIsolationGuarantee]; isolationPolicy != nil {
		policyVersion = isolationPolicy.Version()
	}
	encoder.string("isolation-policy-version", policyVersion)

	pools := append([]paasv1.ExecutionPool(nil), input.Snapshot.Pools...)
	sort.Slice(pools, func(left, right int) bool {
		return pools[left].Metadata.ID < pools[right].Metadata.ID
	})
	encoder.uint64("pool-count", uint64(len(pools)))
	for _, pool := range pools {
		encoder.string("pool-id", string(pool.Metadata.ID))
		encoder.uint64("pool-resource-version", pool.Metadata.ResourceVersion)
		encoder.string("pool-phase", string(pool.Status.Phase))
		writeLabels(encoder, "pool-selector", pool.Spec.ExecutionTargetSelector.MatchLabels)
		writeIsolationGuarantees(
			encoder,
			"pool-isolation",
			pool.Spec.AllowedIsolationGuarantees,
		)
	}

	encoder.uint64("target-count", uint64(len(evaluations)))
	for _, evaluation := range evaluations {
		target := evaluation.target
		encoder.string("target-id", string(target.Metadata.ID))
		encoder.uint64("target-resource-version", target.Metadata.ResourceVersion)
		encoder.string("target-pool-id", string(target.Spec.ExecutionPoolID))
		encoder.string("target-desired-state", string(target.Spec.DesiredState))
		encoder.string("target-health", string(target.Status.Health))
		encoder.timestamp("target-observed-at", target.Status.ObservedAt)
		writeLabels(encoder, "target-labels", target.Metadata.Labels)
		writeCapacity(encoder, "target-allocatable", target.Status.Allocatable)
		writeIsolationGuarantees(
			encoder,
			"target-isolation",
			target.Status.SupportedIsolationGuarantees,
		)
		encoder.string("target-evaluation", string(evaluation.rejection))
	}

	encoder.uint64("capacity-claim-count", uint64(len(claims)))
	for _, claim := range claims {
		encoder.string("capacity-claim-id", string(claim.ID))
		encoder.string("capacity-claim-target-id", string(claim.ExecutionTargetID))
		encoder.string("capacity-claim-isolation", string(claim.Isolation))
		writeResources(encoder, "capacity-claim-resources", claim.Resources)
		encoder.string("capacity-claim-state", string(claim.State))
		if claim.State == CapacityClaimPending {
			encoder.timestamp("capacity-claim-lease-expires-at", claim.LeaseExpiresAt)
		} else {
			encoder.int64("capacity-claim-lease-expires-at", 0)
		}
		encoder.uint64("capacity-claim-resource-version", claim.ResourceVersion)
	}
	return encoder.digest()
}

func writeResources(encoder *canonicalEncoder, prefix string, value Resources) {
	encoder.int64(prefix+"-cpu-millis", value.CPUMillis)
	encoder.int64(prefix+"-memory-bytes", value.MemoryBytes)
	encoder.int64(prefix+"-workload-slots", value.WorkloadSlots)
}

func writeCapacity(encoder *canonicalEncoder, prefix string, value paasv1.Capacity) {
	encoder.int64(prefix+"-cpu-millis", value.CPUMillis)
	encoder.int64(prefix+"-memory-bytes", value.MemoryBytes)
	encoder.int64(prefix+"-storage-bytes", value.StorageBytes)
	encoder.int64(prefix+"-workload-slots", value.WorkloadSlots)
}

func writeLabels(encoder *canonicalEncoder, prefix string, values map[string]string) {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	encoder.uint64(prefix+"-count", uint64(len(keys)))
	for _, key := range keys {
		encoder.string(prefix+"-key", key)
		encoder.string(prefix+"-value", values[key])
	}
}

func writeResourceIDs(
	encoder *canonicalEncoder,
	prefix string,
	values []paasv1.ResourceID,
) {
	items := make([]string, len(values))
	for index, value := range values {
		items[index] = string(value)
	}
	sort.Strings(items)
	encoder.uint64(prefix+"-count", uint64(len(items)))
	for _, item := range items {
		encoder.string(prefix+"-item", item)
	}
}

func writeIsolationGuarantees(
	encoder *canonicalEncoder,
	prefix string,
	values []paasv1.IsolationGuarantee,
) {
	items := make([]string, len(values))
	for index, value := range values {
		items[index] = string(value)
	}
	sort.Strings(items)
	encoder.uint64(prefix+"-count", uint64(len(items)))
	for _, item := range items {
		encoder.string(prefix+"-item", item)
	}
}
