# Control-plane APISIX

APISIX is the default northbound gateway for the PaaS distribution. It owns
TLS termination, route selection, request limits, trusted identity-header
handling, request IDs, and gateway access audit.

Stable APIs remain owned by PaaS, IAM, and Audit. APISIX is replaceable and is
not a control-plane domain authority.
