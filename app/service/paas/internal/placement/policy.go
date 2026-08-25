package placement

import (
	"errors"
	"fmt"
	"time"

	paasv1 "matrix/api/paas/v1"
)

type composeIsolationPolicy struct {
	class   paasv1.IsolationClass
	version string
}

func (policy composeIsolationPolicy) IsolationClass() paasv1.IsolationClass {
	return policy.class
}

func (policy composeIsolationPolicy) Version() string {
	return policy.version
}

func (composeIsolationPolicy) Admit(IsolationContext) bool {
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
		composeIsolationPolicy{
			class:   paasv1.IsolationSharedCompose,
			version: "shared-compose-v1",
		},
		composeIsolationPolicy{
			class:   paasv1.IsolationDedicatedCompose,
			version: "dedicated-compose-v1",
		},
	}
	registered := make(map[paasv1.IsolationClass]IsolationPolicy, len(policies))
	for _, policy := range policies {
		if policy == nil {
			return nil, errors.New("isolation policy cannot be nil")
		}
		class := policy.IsolationClass()
		if class != paasv1.IsolationSharedCompose &&
			class != paasv1.IsolationDedicatedCompose {
			return nil, fmt.Errorf("isolation policy %q is outside runtime v0.1", class)
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
