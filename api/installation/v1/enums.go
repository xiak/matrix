package installationv1

type ProductID string
type ProductState string
type ProductReason string
type ReadinessState string

const (
	ProductApplicationPaaS ProductID = "APPLICATION_PAAS"
	ProductDevOps          ProductID = "DEVOPS"
)

const (
	ProductReady       ProductState = "READY"
	ProductDegraded    ProductState = "DEGRADED"
	ProductUnavailable ProductState = "UNAVAILABLE"
)

const (
	ReasonDependencyUnavailable ProductReason = "DEPENDENCY_UNAVAILABLE"
	ReasonObservationStale      ProductReason = "OBSERVATION_STALE"
)

const (
	ReadinessReady    ReadinessState = "READY"
	ReadinessNotReady ReadinessState = "NOT_READY"
)

func AllProductIDs() []ProductID {
	return []ProductID{ProductApplicationPaaS, ProductDevOps}
}

func AllProductStates() []ProductState {
	return []ProductState{ProductReady, ProductDegraded, ProductUnavailable}
}

func AllProductReasons() []ProductReason {
	return []ProductReason{ReasonDependencyUnavailable, ReasonObservationStale}
}

func ProductRoute(id ProductID) (string, bool) {
	switch id {
	case ProductApplicationPaaS:
		return "paas", true
	case ProductDevOps:
		return "devops", true
	default:
		return "", false
	}
}
