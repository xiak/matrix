# Services

Every directory below this path is an independently buildable and releasable
service boundary. Services may share versioned contracts from `api/`; they
must not import another service's `internal/` packages or access another
service's database.

New reusable code starts in the service that owns the capability. It is
extracted only after multiple real consumers and a compatibility contract
exist.
