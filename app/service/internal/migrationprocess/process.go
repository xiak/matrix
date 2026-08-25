// Package migrationprocess owns the fixed, non-interactive process contract
// shared by service-specific PostgreSQL migration binaries.
package migrationprocess

import (
	"context"
	"errors"
	"os"
	"regexp"
	"slices"

	"github.com/xiak/matrix/app/service/internal/processconfig"
)

const maximumMigrationDSN = 16 * 1024

var environmentPattern = regexp.MustCompile(`^MATRIX_MIGRATION_[A-Z0-9_]+_DSN_FILE$`)

type Action func(context.Context, []string) error

type Configuration struct {
	DSNFileEnvironments []string
	Apply               Action
	Verify              Action
}

func Run(ctx context.Context, arguments []string, configuration Configuration) error {
	if ctx == nil || len(arguments) != 1 || validateConfiguration(configuration) != nil {
		return errors.New("migration process invocation is invalid")
	}
	dsns := make([]string, len(configuration.DSNFileEnvironments))
	defer func() {
		for index := range dsns {
			dsns[index] = ""
		}
	}()
	for index, environment := range configuration.DSNFileEnvironments {
		path := os.Getenv(environment)
		if path == "" {
			return errors.New("migration process configuration is incomplete")
		}
		value, err := processconfig.ReadText(path, maximumMigrationDSN, true)
		if err != nil {
			return errors.New("migration process configuration is invalid")
		}
		dsns[index] = value
	}
	switch arguments[0] {
	case "apply":
		return configuration.Apply(ctx, dsns)
	case "verify":
		return configuration.Verify(ctx, dsns)
	default:
		return errors.New("migration process action is unsupported")
	}
}

func validateConfiguration(configuration Configuration) error {
	if len(configuration.DSNFileEnvironments) < 2 ||
		len(configuration.DSNFileEnvironments) > 4 ||
		configuration.Apply == nil || configuration.Verify == nil {
		return errors.New("migration process configuration is invalid")
	}
	seen := make(map[string]struct{}, len(configuration.DSNFileEnvironments))
	for _, environment := range configuration.DSNFileEnvironments {
		if !environmentPattern.MatchString(environment) {
			return errors.New("migration process environment is invalid")
		}
		seen[environment] = struct{}{}
	}
	if len(seen) != len(configuration.DSNFileEnvironments) ||
		!slices.IsSorted(configuration.DSNFileEnvironments) {
		return errors.New("migration process environments are duplicated or not sorted")
	}
	return nil
}
