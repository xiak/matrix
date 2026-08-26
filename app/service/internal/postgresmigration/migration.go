// Package postgresmigration owns the small shared execution boundary for
// service-owned PostgreSQL migrations. Migration content remains embedded by
// its bounded context; this package provides locking, role confinement, exact
// runtime-login provisioning, and normalized failures.
package postgresmigration

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

const (
	maximumMigrationSQL  = 4 * 1024 * 1024
	maximumDSNBytes      = 16 * 1024
	maximumApplyAttempts = 3
)

var (
	migrationContextPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{1,62}[a-z0-9]$`)
	roleNamePattern         = regexp.MustCompile(`^matrix_[a-z][a-z0-9_]{2,62}$`)
	retryableApplyFailure   = errors.New("PostgreSQL migration apply failed")
)

type Executor interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}

type Source struct {
	Context       string
	BootstrapSQL  string
	UpSQL         string
	VerifySQL     string
	ExecutionRole string
}

type Login struct {
	Name  string
	Group string
	DSN   string
}

func Bootstrap(ctx context.Context, executor Executor, source Source) error {
	if err := validateSource(source); err != nil || executor == nil || ctx == nil {
		return errors.New("PostgreSQL migration bootstrap input is invalid")
	}
	if source.BootstrapSQL == "" {
		return nil
	}
	if _, err := executor.Exec(ctx, source.BootstrapSQL); err != nil {
		return errors.New("PostgreSQL migration bootstrap failed")
	}
	return nil
}

func Up(ctx context.Context, executor Executor, source Source) error {
	if err := validateSource(source); err != nil || executor == nil || ctx == nil {
		return errors.New("PostgreSQL migration apply input is invalid")
	}
	if _, err := executor.Exec(ctx, source.UpSQL); err != nil {
		if retryableMigrationConflict(err) {
			return retryableApplyFailure
		}
		return errors.New("PostgreSQL migration apply failed")
	}
	return nil
}

func Verify(ctx context.Context, executor Executor, source Source) error {
	if err := validateSource(source); err != nil || executor == nil || ctx == nil {
		return errors.New("PostgreSQL migration verification input is invalid")
	}
	if _, err := executor.Exec(ctx, source.VerifySQL); err != nil {
		return errors.New("PostgreSQL migration verification failed")
	}
	return nil
}

// Apply connects through the installation-owned administrative DSN, takes a
// context-specific advisory lock, executes embedded migration content under
// the declared role boundary, provisions exact runtime logins, and verifies
// both schema and credentials. Equal replay performs no password rotation.
func Apply(ctx context.Context, adminDSN string, source Source, logins []Login) error {
	if ctx == nil || validateSource(source) != nil || validateLogins(logins) != nil {
		return errors.New("PostgreSQL migration input is invalid")
	}
	connection, adminConfig, err := openAdministrator(ctx, adminDSN, source.Context)
	if err != nil {
		return err
	}
	defer connection.Close(context.Background())

	if err := Bootstrap(ctx, connection, source); err != nil {
		return err
	}
	if err := retryMigrationApply(func() error {
		return applyUnderRole(ctx, connection, source)
	}); err != nil {
		return err
	}
	for _, login := range logins {
		if err := ensureLogin(ctx, connection, adminConfig, login); err != nil {
			return err
		}
	}
	return Verify(ctx, connection, source)
}

// VerifyInstalled is read-only with respect to schema and role state. It
// rechecks PostgreSQL, embedded schema invariants, login attributes and group
// ownership, and authenticates every exact runtime DSN.
func VerifyInstalled(ctx context.Context, adminDSN string, source Source, logins []Login) error {
	if ctx == nil || validateSource(source) != nil || validateLogins(logins) != nil {
		return errors.New("PostgreSQL migration verification input is invalid")
	}
	connection, adminConfig, err := openAdministrator(ctx, adminDSN, source.Context)
	if err != nil {
		return err
	}
	defer connection.Close(context.Background())
	for _, login := range logins {
		if err := verifyLogin(ctx, connection, adminConfig, login); err != nil {
			return err
		}
	}
	return Verify(ctx, connection, source)
}

func openAdministrator(
	ctx context.Context,
	dsn string,
	migrationContext string,
) (*pgx.Conn, *pgx.ConnConfig, error) {
	if len(dsn) == 0 || len(dsn) > maximumDSNBytes || strings.ContainsAny(dsn, "\x00\r\n") {
		return nil, nil, errors.New("PostgreSQL migration database configuration is invalid")
	}
	config, err := pgx.ParseConfig(dsn)
	if err != nil || config.User == "" || config.Password == "" || config.Host == "" ||
		config.Port == 0 || config.Database == "" {
		return nil, nil, errors.New("PostgreSQL migration database configuration is invalid")
	}
	config.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	connection, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		return nil, nil, errors.New("PostgreSQL migration database is unavailable")
	}
	fail := func(message string) (*pgx.Conn, *pgx.ConnConfig, error) {
		connection.Close(context.Background())
		return nil, nil, errors.New(message)
	}
	var serverVersion int
	if err := connection.QueryRow(
		ctx,
		"SELECT pg_catalog.current_setting('server_version_num')::integer",
	).Scan(&serverVersion); err != nil || serverVersion < 180000 || serverVersion >= 190000 {
		return fail("PostgreSQL migration requires server major 18")
	}
	var locked bool
	if err := connection.QueryRow(
		ctx,
		"SELECT pg_catalog.pg_try_advisory_lock(pg_catalog.hashtextextended($1, 0))",
		"matrix:postgres-migration:"+migrationContext,
	).Scan(&locked); err != nil || !locked {
		return fail("PostgreSQL migration lock is unavailable")
	}
	return connection, config, nil
}

func applyUnderRole(ctx context.Context, connection *pgx.Conn, source Source) error {
	roleSet := source.ExecutionRole != ""
	if roleSet {
		role := pgx.Identifier{source.ExecutionRole}.Sanitize()
		if _, err := connection.Exec(ctx, "SET ROLE "+role); err != nil {
			return errors.New("PostgreSQL migration execution role is unavailable")
		}
	}
	reset := func() error {
		if _, err := connection.Exec(context.Background(), "ROLLBACK"); err != nil {
			return errors.New("PostgreSQL migration transaction cannot reset")
		}
		if roleSet {
			if _, err := connection.Exec(context.Background(), "RESET ROLE"); err != nil {
				return errors.New("PostgreSQL migration execution role cannot reset")
			}
		}
		return nil
	}
	if err := Up(ctx, connection, source); err != nil {
		if resetErr := reset(); resetErr != nil {
			return resetErr
		}
		return err
	}
	if roleSet {
		if err := reset(); err != nil {
			return err
		}
	}
	return nil
}

func retryMigrationApply(apply func() error) error {
	var err error
	for range maximumApplyAttempts {
		err = apply()
		if err == nil || !errors.Is(err, retryableApplyFailure) {
			return err
		}
	}
	return err
}

func retryableMigrationConflict(err error) bool {
	var databaseError *pgconn.PgError
	return errors.As(err, &databaseError) && databaseError.Code == "40P01"
}

func ensureLogin(
	ctx context.Context,
	admin *pgx.Conn,
	adminConfig *pgx.ConnConfig,
	login Login,
) error {
	runtimeConfig, err := parseRuntimeConfig(adminConfig, login)
	if err != nil {
		return err
	}
	exists, err := loginExists(ctx, admin, login.Name)
	if err != nil {
		return err
	}
	if !exists {
		transaction, err := admin.Begin(ctx)
		if err != nil {
			return errors.New("PostgreSQL runtime login transaction cannot start")
		}
		committed := false
		defer func() {
			if !committed {
				_ = transaction.Rollback(context.Background())
			}
		}()
		if _, err := transaction.Exec(
			ctx,
			"SELECT pg_catalog.set_config('matrix.migration_login_password', $1, true)",
			runtimeConfig.Password,
		); err != nil {
			return errors.New("PostgreSQL runtime login credential cannot stage")
		}
		name := pgx.Identifier{login.Name}.Sanitize()
		group := pgx.Identifier{login.Group}.Sanitize()
		statement := fmt.Sprintf(`DO $matrix_migration_login$
DECLARE
    login_password text := pg_catalog.current_setting('matrix.migration_login_password');
BEGIN
    EXECUTE 'CREATE ROLE %s LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE '
        || 'NOREPLICATION NOBYPASSRLS PASSWORD '
        || pg_catalog.quote_literal(login_password);
END
$matrix_migration_login$;
GRANT %s TO %s;`, name, group, name)
		if _, err := transaction.Exec(ctx, statement); err != nil {
			return errors.New("PostgreSQL runtime login cannot be provisioned")
		}
		if err := transaction.Commit(ctx); err != nil {
			return errors.New("PostgreSQL runtime login cannot be committed")
		}
		committed = true
	}
	return verifyLoginWithConfig(ctx, admin, runtimeConfig, login)
}

func verifyLogin(
	ctx context.Context,
	admin *pgx.Conn,
	adminConfig *pgx.ConnConfig,
	login Login,
) error {
	runtimeConfig, err := parseRuntimeConfig(adminConfig, login)
	if err != nil {
		return err
	}
	exists, err := loginExists(ctx, admin, login.Name)
	if err != nil || !exists {
		return errors.New("PostgreSQL runtime login is absent")
	}
	return verifyLoginWithConfig(ctx, admin, runtimeConfig, login)
}

func verifyLoginWithConfig(
	ctx context.Context,
	admin *pgx.Conn,
	runtimeConfig *pgx.ConnConfig,
	login Login,
) error {
	var canLogin, inherit, superuser, createDB, createRole, replication, bypassRLS bool
	var connectionLimit int
	var validUntilIsNull bool
	err := admin.QueryRow(
		ctx,
		`SELECT rolcanlogin, rolinherit, rolsuper, rolcreatedb, rolcreaterole,
		        rolreplication, rolbypassrls, rolconnlimit, rolvaliduntil IS NULL
		   FROM pg_catalog.pg_roles
		  WHERE rolname = $1`,
		login.Name,
	).Scan(
		&canLogin, &inherit, &superuser, &createDB, &createRole,
		&replication, &bypassRLS, &connectionLimit, &validUntilIsNull,
	)
	if err != nil || !canLogin || !inherit || superuser || createDB || createRole ||
		replication || bypassRLS || connectionLimit != -1 || !validUntilIsNull {
		return errors.New("PostgreSQL runtime login attributes conflict")
	}
	rows, err := admin.Query(
		ctx,
		`SELECT parent.rolname
		   FROM pg_catalog.pg_auth_members AS membership
		   JOIN pg_catalog.pg_roles AS parent ON parent.oid = membership.roleid
		   JOIN pg_catalog.pg_roles AS member ON member.oid = membership.member
		  WHERE member.rolname = $1
		  ORDER BY parent.rolname`,
		login.Name,
	)
	if err != nil {
		return errors.New("PostgreSQL runtime login memberships cannot be inspected")
	}
	memberships, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil || !slices.Equal(memberships, []string{login.Group}) {
		return errors.New("PostgreSQL runtime login memberships conflict")
	}
	runtimeConfig.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	runtimeConnection, err := pgx.ConnectConfig(ctx, runtimeConfig)
	if err != nil {
		return errors.New("PostgreSQL runtime login credential conflicts")
	}
	defer runtimeConnection.Close(context.Background())
	var currentUser, sessionUser string
	if err := runtimeConnection.QueryRow(
		ctx,
		"SELECT current_user::text, session_user::text",
	).Scan(&currentUser, &sessionUser); err != nil ||
		currentUser != login.Name || sessionUser != login.Name {
		return errors.New("PostgreSQL runtime login identity is invalid")
	}
	return nil
}

func parseRuntimeConfig(admin *pgx.ConnConfig, login Login) (*pgx.ConnConfig, error) {
	if len(login.DSN) == 0 || len(login.DSN) > maximumDSNBytes ||
		strings.ContainsAny(login.DSN, "\x00\r\n") {
		return nil, errors.New("PostgreSQL runtime login configuration is invalid")
	}
	config, err := pgx.ParseConfig(login.DSN)
	if err != nil || config.User != login.Name || config.Password == "" ||
		len(config.Password) > 256 || strings.ContainsAny(config.Password, "\x00\r\n") ||
		config.Host != admin.Host || config.Port != admin.Port ||
		config.Database != admin.Database {
		return nil, errors.New("PostgreSQL runtime login configuration is invalid")
	}
	return config, nil
}

func loginExists(ctx context.Context, connection *pgx.Conn, name string) (bool, error) {
	var exists bool
	if err := connection.QueryRow(
		ctx,
		"SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = $1)",
		name,
	).Scan(&exists); err != nil {
		return false, errors.New("PostgreSQL runtime login cannot be inspected")
	}
	return exists, nil
}

func validateSource(source Source) error {
	if !migrationContextPattern.MatchString(source.Context) ||
		(source.ExecutionRole != "" && !roleNamePattern.MatchString(source.ExecutionRole)) ||
		!validSQL(source.UpSQL) || !validSQL(source.VerifySQL) ||
		(source.BootstrapSQL != "" && !validSQL(source.BootstrapSQL)) {
		return errors.New("PostgreSQL migration source is invalid")
	}
	return nil
}

func validateLogins(logins []Login) error {
	if len(logins) == 0 || len(logins) > 8 {
		return errors.New("PostgreSQL runtime login inventory is invalid")
	}
	previous := ""
	for _, login := range logins {
		if !roleNamePattern.MatchString(login.Name) || !roleNamePattern.MatchString(login.Group) ||
			login.Name <= previous || login.Name == login.Group {
			return errors.New("PostgreSQL runtime login inventory is invalid")
		}
		previous = login.Name
	}
	return nil
}

func validSQL(statement string) bool {
	return len(statement) > 0 && len(statement) <= maximumMigrationSQL &&
		!strings.ContainsRune(statement, 0)
}
