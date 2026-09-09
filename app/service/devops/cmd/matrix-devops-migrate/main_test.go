package main

import (
	"slices"
	"testing"
)

func TestMigrationProcessUsesTheClosedSortedDevOpsIdentityInventory(t *testing.T) {
	want := []string{
		"MATRIX_MIGRATION_DATABASE_DSN_FILE",
		"MATRIX_MIGRATION_DEVOPS_API_DSN_FILE",
		"MATRIX_MIGRATION_DEVOPS_CHECK_REPORTER_DSN_FILE",
		"MATRIX_MIGRATION_DEVOPS_SOURCE_FETCHER_DSN_FILE",
		"MATRIX_MIGRATION_DEVOPS_SOURCE_OBSERVER_DSN_FILE",
		"MATRIX_MIGRATION_DEVOPS_WORKER_DSN_FILE",
	}
	if !slices.Equal(dsnFileEnvironments, want) || !slices.IsSorted(dsnFileEnvironments) {
		t.Fatalf("DevOps migration identity inventory = %v, want %v", dsnFileEnvironments, want)
	}
}
