# Services

Every directory below this path is an independently buildable and releasable
service boundary. Services may share versioned APIs and SDKs from `api/` and
`platform/`; they must not import another service's `internal/` packages or
access another service's database.
