package placement

import (
	"math/big"

	paasv1 "matrix/api/paas/v1"
)

type utilization struct {
	numerator   uint64
	denominator uint64
	infinite    bool
}

func selectCandidate(
	strategy paasv1.PlacementStrategy,
	candidates []candidateEvaluation,
	requirements Resources,
) candidateEvaluation {
	selected := candidates[0]
	for _, candidate := range candidates[1:] {
		if candidateBetter(strategy, candidate, selected, requirements) {
			selected = candidate
		}
	}
	return selected
}

func candidateBetter(
	strategy paasv1.PlacementStrategy,
	left candidateEvaluation,
	right candidateEvaluation,
	requirements Resources,
) bool {
	if strategy == paasv1.PlacementFirstFit {
		return left.target.Metadata.ID < right.target.Metadata.ID
	}
	leftUsage := left.reserved
	rightUsage := right.reserved
	if strategy == paasv1.PlacementBinPack {
		leftUsage = addResources(leftUsage, requirements)
		rightUsage = addResources(rightUsage, requirements)
	}
	leftScore := dominantUtilization(leftUsage, left.target.Status.Allocatable)
	rightScore := dominantUtilization(rightUsage, right.target.Status.Allocatable)
	comparison := compareUtilization(leftScore, rightScore)
	if comparison == 0 {
		return left.target.Metadata.ID < right.target.Metadata.ID
	}
	if strategy == paasv1.PlacementSpread {
		return comparison < 0
	}
	return comparison > 0
}

func addResources(left, right Resources) Resources {
	return Resources{
		CPUMillis:     left.CPUMillis + right.CPUMillis,
		MemoryBytes:   left.MemoryBytes + right.MemoryBytes,
		WorkloadSlots: left.WorkloadSlots + right.WorkloadSlots,
	}
}

func dominantUtilization(usage Resources, capacity paasv1.Capacity) utilization {
	result := utilizationFor(usage.CPUMillis, capacity.CPUMillis)
	for _, candidate := range []utilization{
		utilizationFor(usage.MemoryBytes, capacity.MemoryBytes),
		utilizationFor(usage.WorkloadSlots, capacity.WorkloadSlots),
	} {
		if compareUtilization(candidate, result) > 0 {
			result = candidate
		}
	}
	return result
}

func utilizationFor(usage, capacity int64) utilization {
	if capacity == 0 {
		if usage == 0 {
			return utilization{denominator: 1}
		}
		return utilization{infinite: true}
	}
	return utilization{
		numerator:   uint64(usage),
		denominator: uint64(capacity),
	}
}

func compareUtilization(left, right utilization) int {
	if left.infinite {
		if right.infinite {
			return 0
		}
		return 1
	}
	if right.infinite {
		return -1
	}
	leftProduct := new(big.Int).Mul(
		new(big.Int).SetUint64(left.numerator),
		new(big.Int).SetUint64(right.denominator),
	)
	rightProduct := new(big.Int).Mul(
		new(big.Int).SetUint64(right.numerator),
		new(big.Int).SetUint64(left.denominator),
	)
	return leftProduct.Cmp(rightProduct)
}
