package managedserviceadapterv1

import (
	"context"

	managedservicev1 "github.com/xiak/matrix/api/managedservice/v1"
)

// Provisioner is the product-team implementation boundary. It is composed by
// the trusted worker, not registered by a tenant or called over a public HTTP
// endpoint. The authority owns authorization, quota, durable Operations and
// fencing; implementations own only their exact installation's effects.
type Provisioner interface {
	// Ready checks provider prerequisites without creating customer resources.
	// It is not an observation of every previously provisioned instance.
	Ready(context.Context) error
	// Ensure observes before applying. Equal retries, including after restart
	// or an uncertain response, converge to one installation with stable
	// endpoint and credential references. A nil error proves actual readiness.
	Ensure(context.Context, ProvisionRequest) (ProvisionResult, error)
	// Delete removes only resources proved to belong to this exact identity.
	// Equal retries are safe; an error does not prove effects were rolled back.
	Delete(context.Context, DeprovisionRequest) error
}

// ProvisionRequest contains authority-derived facts, not caller-selected
// runtime configuration. Product-specific configuration must have a closed,
// versioned owner and be resolved by trusted composition before any effect.
type ProvisionRequest struct {
	TenantID       string
	InstallationID string
	OperationID    string
	OfferingID     string
	EngineVersion  string
	RegionID       string
	QuotaShape     managedservicev1.QuotaShape
	// Elasticsearch is the exact dependency accepted by the authority. Its
	// tenant is always this request's TenantID; it contains no native selector.
	Elasticsearch *ElasticsearchDependency "json:\"elasticsearch,omitempty\""
}

// ElasticsearchDependency binds a Kibana installation to an immutable current
// object observation. The authority owns permission, existence and delete
// protection; the provider cannot infer those facts from an endpoint.
type ElasticsearchDependency struct {
	InstallationID  string
	ResourceVersion uint64
	EngineVersion   string
	RegionID        string
}

type ProvisionResult struct {
	Endpoint            string
	CredentialReference string
}

// DeprovisionRequest contains only authority-derived resource identity. A
// provider never accepts an arbitrary path, project name, endpoint or
// credential selector from the northbound request.
type DeprovisionRequest struct {
	TenantID       string
	InstallationID string
	OperationID    string
	OfferingID     string
	EngineVersion  string
	RegionID       string
	Elasticsearch  *ElasticsearchDependency "json:\"elasticsearch,omitempty\""
}
