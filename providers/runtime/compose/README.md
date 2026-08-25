# Compose runtime provider

The first runtime provider applies immutable WorkloadRelease identities to a
selected RuntimeTarget using controlled Compose delivery capabilities.

The initial implementation may delegate execution to a GitLab-backed delivery
adapter. It must observe deployment evidence and expose explicit rollback
outcomes; it must not run caller-supplied shell commands.
