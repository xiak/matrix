// Package createplacement owns the idempotent placement application use case.
// Persistence implements transaction isolation, tenant context, and target
// locking; placement selection remains a pure domain rule.
package createplacement
