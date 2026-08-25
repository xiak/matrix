# APISIX gateway adapter

This adapter manages customer-workload routes through the internal APISIX
Admin API. It is separate from `deploy/compose/apisix`, which configures the
PaaS control plane's own northbound ingress.

The Admin API is never exposed to browsers or customer API clients.
