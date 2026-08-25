package placement

import (
	"errors"
	"fmt"
	"time"

	paasv1 "github.com/xiak/matrix/api/paas/v1"
)

type workloadIsolationPolicy struct {
	version string
}

func (workloadIsolationPolicy) IsolationGuarantee() paasv1.IsolationGuarantee {
	return paasv1.IsolationWorkload
}

func (policy workloadIsolationPolicy) Version() string {
	return policy.version
}

func (workloadIsolationPolicy) Admit(IsolationContext) bool {
	return true
}

// NewV1Planner registers exactly the isolation capabilities delivered by the
// Local Compose Runtime v0.1 release.
func NewV1Planner(maxObservationAge time.Duration) (*Planner, error) {
	if maxObservationAge <= 0 {
		return nil, errors.New("maximum observation age must be positive")
	}
	if maxObservationAge%time.Microsecond != 0 {
		return nil, errors.New("maximum observation age must use whole microseconds")
	}

	policies := []IsolationPolicy{
		workloadIsolationPolicy{
			version: "compose-workload-v1",
		},
	}
	registered := make(map[paasv1.IsolationGuarantee]IsolationPolicy, len(policies))
	for _, policy := range policies {
		if policy == nil {
			return nil, errors.New("isolation policy cannot be nil")
		}
		class := policy.IsolationGuarantee()
		if class != paasv1.IsolationWorkload {
			return nil, fmt.Errorf("isolation policy %q is outside Compose v0.1", class)
		}
		if err := paasv1.ValidateID("isolation policy version", policy.Version()); err != nil {
			return nil, err
		}
		if _, duplicate := registered[class]; duplicate {
			return nil, fmt.Errorf("isolation policy %q is duplicated", class)
		}
		registered[class] = policy
	}

	return &Planner{
		maxObservationAge: maxObservationAge,
		policies:          registered,
	}, nil
}
