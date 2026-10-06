// Package postgresqlha owns the task-local PostgreSQL failover acceptance
// fixture. It proves database semantics for higher-level gates without adding
// PostgreSQL HA to the signed installation topology or product runtime.
package postgresqlha

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net"
	"net/url"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

const (
	databaseName       = "matrix"
	databaseUser       = "matrix"
	replicationUser    = "matrix_replication"
	postgresData       = "/var/lib/postgresql/data"
	taskLabel          = "matrix.task"
	sliceLabel         = "matrix.slice"
	sliceLabelValue    = "postgres-ha-acceptance"
	maximumOutputBytes = 64 * 1024
)

var (
	imageIDPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	taskIDPattern  = regexp.MustCompile(`^matrix-pg-ha-[a-z0-9](?:[a-z0-9-]{0,25}[a-z0-9])?$`)
	lsnPattern     = regexp.MustCompile(`^[0-9A-F]+/[0-9A-F]+$`)
	resourceID     = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// Config identifies immutable input and the unique ownership scope for one
// task-local fixture.
type Config struct {
	// ImageID is an already-present immutable local image identity. The fixture
	// never pulls or resolves a moving registry tag.
	ImageID string
	// TaskID is also the ownership label for every mutable Docker resource.
	TaskID string
}

// Checkpoint is the exact primary flush and synchronous standby replay
// position admitted for one controlled failover attempt.
type Checkpoint struct {
	ConfirmedLSN     string
	StandbyReplayLSN string
	ConfirmedAt      time.Time

	fixtureID  string
	generation uint64
}

// FailoverObservation records ordered fencing, promotion and stable-endpoint
// evidence. ConfirmedRPOBytes is loss relative to the admitted checkpoint.
type FailoverObservation struct {
	ConfirmedLSN       string
	StandbyReplayLSN   string
	ConfirmedRPOBytes  int64
	FailureDetectedAt  time.Time
	PrimaryFencedAt    time.Time
	StandbyPromotedAt  time.Time
	EndpointSwitchedAt time.Time
	ReadyAt            time.Time
	RTO                time.Duration
}

// Fixture owns two bounded PostgreSQL containers and an in-process stable TCP
// endpoint. It is an acceptance dependency, not an installation runtime.
type Fixture struct {
	mu sync.Mutex

	config              Config
	docker              dockerCLI
	network             string
	databasePassword    string
	replicationPassword string
	endpoint            *stableEndpoint
	primary             *postgresNode
	standby             *postgresNode
	fenced              *postgresNode
	checkpoint          *Checkpoint
	generation          uint64
	state               fixtureState
	closed              bool
}

type fixtureState uint8

const (
	fixtureStarting fixtureState = iota
	fixtureReady
	fixtureFailedOver
	fixtureFailedClosed
)

type postgresNode struct {
	name            string
	volume          string
	address         string
	applicationName string
	slotName        string
}

type dockerCLI struct{}

type boundedBuffer struct {
	content   bytes.Buffer
	remaining int
	overflow  bool
}

// Start creates an empty primary, clones a physical standby and waits until
// commits are synchronously applied. It never pulls an image.
func Start(ctx context.Context, config Config) (_ *Fixture, returnErr error) {
	if ctx == nil || !imageIDPattern.MatchString(config.ImageID) ||
		!taskIDPattern.MatchString(config.TaskID) {
		return nil, errors.New("PostgreSQL HA fixture configuration is invalid")
	}
	fixture := &Fixture{
		config: config, docker: dockerCLI{}, network: config.TaskID + "-net",
		generation: 1, state: fixtureStarting,
	}
	fixture.primary = &postgresNode{
		name: config.TaskID + "-primary", volume: config.TaskID + "-primary-data",
		applicationName: "matrix_primary", slotName: "matrix_primary_slot",
	}
	fixture.standby = &postgresNode{
		name: config.TaskID + "-standby", volume: config.TaskID + "-standby-data",
		applicationName: "matrix_standby", slotName: "matrix_standby_slot",
	}
	fixture.databasePassword, returnErr = randomHex(24)
	if returnErr != nil {
		return nil, returnErr
	}
	fixture.replicationPassword, returnErr = randomHex(24)
	if returnErr != nil {
		return nil, returnErr
	}
	defer func() {
		if returnErr == nil {
			return
		}
		cleanup, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		returnErr = errors.Join(returnErr, fixture.Close(cleanup))
	}()
	if err := fixture.assertExclusive(ctx); err != nil {
		return nil, err
	}
	if err := fixture.verifyImage(ctx); err != nil {
		return nil, err
	}
	if err := fixture.createNetwork(ctx); err != nil {
		return nil, err
	}
	if err := fixture.createVolume(ctx, fixture.primary.volume); err != nil {
		return nil, err
	}
	if err := fixture.startNode(ctx, fixture.primary); err != nil {
		return nil, err
	}
	if err := fixture.waitForRole(ctx, fixture.primary, false); err != nil {
		return nil, err
	}
	if err := fixture.configureReplicationAuthority(ctx); err != nil {
		return nil, err
	}
	if err := fixture.createVolume(ctx, fixture.standby.volume); err != nil {
		return nil, err
	}
	if err := fixture.cloneStandby(ctx, fixture.primary, fixture.standby); err != nil {
		return nil, err
	}
	if err := fixture.startNode(ctx, fixture.standby); err != nil {
		return nil, err
	}
	if err := fixture.waitForRole(ctx, fixture.standby, true); err != nil {
		return nil, err
	}
	if err := fixture.enableSynchronousStandby(ctx, fixture.primary, fixture.standby); err != nil {
		return nil, err
	}
	fixture.endpoint, returnErr = newStableEndpoint(fixture.primary.address)
	if returnErr != nil {
		return nil, returnErr
	}
	if err := fixture.pingEndpoint(ctx); err != nil {
		return nil, err
	}
	fixture.state = fixtureReady
	return fixture, nil
}

// EndpointDSN returns the private task-local connection string. Callers must
// treat it as a secret and establish a new connection after failover.
func (fixture *Fixture) EndpointDSN() string {
	if fixture == nil || fixture.endpoint == nil {
		return ""
	}
	return postgresDSN(fixture.endpoint.address(), databaseUser, fixture.databasePassword)
}

// ConfirmedCheckpoint waits until the standby has synchronously replayed the
// primary's current flushed LSN.
func (fixture *Fixture) ConfirmedCheckpoint(ctx context.Context) (Checkpoint, error) {
	if fixture == nil {
		return Checkpoint{}, errors.New("PostgreSQL HA fixture is unavailable")
	}
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	if fixture.closed || fixture.state != fixtureReady || fixture.primary == nil || fixture.standby == nil {
		return Checkpoint{}, errors.New("PostgreSQL HA fixture is not ready")
	}
	if err := fixture.assertNodeRoles(ctx, fixture.primary, fixture.standby); err != nil {
		return Checkpoint{}, err
	}
	primary, err := fixture.connect(ctx, fixture.primary)
	if err != nil {
		return Checkpoint{}, err
	}
	defer primary.Close(ctx)
	var confirmedLSN string
	if err := primary.QueryRow(ctx, `SELECT pg_current_wal_flush_lsn()::text`).Scan(&confirmedLSN); err != nil ||
		!lsnPattern.MatchString(confirmedLSN) {
		return Checkpoint{}, errors.New("primary confirmed LSN is unavailable")
	}
	replayLSN, err := fixture.waitForReplay(ctx, fixture.primary, fixture.standby, confirmedLSN)
	if err != nil {
		return Checkpoint{}, err
	}
	checkpoint := Checkpoint{
		ConfirmedLSN: confirmedLSN, StandbyReplayLSN: replayLSN,
		ConfirmedAt: time.Now().UTC(), fixtureID: fixture.config.TaskID,
		generation: fixture.generation,
	}
	fixture.checkpoint = &checkpoint
	return checkpoint, nil
}

// ControlledFailover closes the endpoint, proves roles and replay, fences the
// old primary, promotes the standby, and only then publishes the new route.
func (fixture *Fixture) ControlledFailover(
	ctx context.Context,
	checkpoint Checkpoint,
) (FailoverObservation, error) {
	if fixture == nil {
		return FailoverObservation{}, errors.New("PostgreSQL HA fixture is unavailable")
	}
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	if fixture.closed || fixture.state != fixtureReady || fixture.endpoint == nil ||
		fixture.primary == nil || fixture.standby == nil {
		return FailoverObservation{}, errors.New("PostgreSQL HA fixture is not ready")
	}
	observation := FailoverObservation{
		ConfirmedLSN: checkpoint.ConfirmedLSN, StandbyReplayLSN: checkpoint.StandbyReplayLSN,
		FailureDetectedAt: time.Now().UTC(),
	}
	// Any attempted failover first closes the stable endpoint. If current role,
	// replay or fencing evidence is missing, callers cannot keep writing through
	// an ambiguous route.
	fixture.endpoint.disable()
	if fixture.checkpoint == nil || checkpoint != *fixture.checkpoint ||
		checkpoint.fixtureID != fixture.config.TaskID || checkpoint.generation != fixture.generation ||
		!lsnPattern.MatchString(checkpoint.ConfirmedLSN) ||
		!lsnPattern.MatchString(checkpoint.StandbyReplayLSN) || checkpoint.ConfirmedAt.IsZero() {
		fixture.state = fixtureFailedClosed
		return FailoverObservation{}, errors.New("failover checkpoint is invalid")
	}
	if err := fixture.assertNodeRoles(ctx, fixture.primary, fixture.standby); err != nil {
		fixture.state = fixtureFailedClosed
		return FailoverObservation{}, errors.New("single-primary state cannot be proven")
	}
	replayLSN, err := fixture.waitForReplay(ctx, fixture.primary, fixture.standby, checkpoint.ConfirmedLSN)
	if err != nil {
		fixture.state = fixtureFailedClosed
		return FailoverObservation{}, err
	}
	observation.StandbyReplayLSN = replayLSN
	oldPrimary := fixture.primary
	newPrimary := fixture.standby
	if err := fixture.fenceNode(ctx, oldPrimary); err != nil {
		fixture.state = fixtureFailedClosed
		return FailoverObservation{}, err
	}
	observation.PrimaryFencedAt = time.Now().UTC()
	if err := fixture.promote(ctx, newPrimary); err != nil {
		fixture.state = fixtureFailedClosed
		return FailoverObservation{}, err
	}
	observation.StandbyPromotedAt = time.Now().UTC()
	rpoBytes, err := fixture.proveFencedAndPromoted(ctx, oldPrimary, newPrimary, checkpoint.ConfirmedLSN)
	if err != nil {
		fixture.state = fixtureFailedClosed
		return FailoverObservation{}, err
	}
	if err := fixture.endpoint.switchTo(newPrimary.address); err != nil {
		fixture.state = fixtureFailedClosed
		return FailoverObservation{}, err
	}
	observation.EndpointSwitchedAt = time.Now().UTC()
	if err := fixture.pingEndpoint(ctx); err != nil {
		fixture.endpoint.disable()
		fixture.state = fixtureFailedClosed
		return FailoverObservation{}, err
	}
	observation.ReadyAt = time.Now().UTC()
	observation.RTO = observation.ReadyAt.Sub(observation.FailureDetectedAt)
	observation.ConfirmedRPOBytes = rpoBytes
	fixture.primary = newPrimary
	fixture.standby = nil
	fixture.fenced = oldPrimary
	fixture.checkpoint = nil
	fixture.generation++
	fixture.state = fixtureFailedOver
	return observation, nil
}

// RejoinFencedPrimary discards the old primary data directory, reclones it
// from the promoted node, and proves that it can only serve as a standby.
func (fixture *Fixture) RejoinFencedPrimary(ctx context.Context) error {
	if fixture == nil {
		return errors.New("PostgreSQL HA fixture is unavailable")
	}
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	if fixture.closed || fixture.state != fixtureFailedOver || fixture.primary == nil ||
		fixture.fenced == nil || fixture.standby != nil {
		return errors.New("fenced primary cannot be rejoined")
	}
	rejoined := fixture.fenced
	rejoined.applicationName = "matrix_rejoined"
	rejoined.slotName = "matrix_rejoined_slot"
	if err := fixture.removeOwnedVolume(ctx, rejoined.volume); err != nil {
		return err
	}
	if err := fixture.createVolume(ctx, rejoined.volume); err != nil {
		return err
	}
	if err := fixture.cloneStandby(ctx, fixture.primary, rejoined); err != nil {
		return err
	}
	if err := fixture.startNode(ctx, rejoined); err != nil {
		return err
	}
	if err := fixture.waitForRole(ctx, rejoined, true); err != nil {
		return err
	}
	if err := fixture.enableSynchronousStandby(ctx, fixture.primary, rejoined); err != nil {
		return err
	}
	if err := fixture.assertNodeRoles(ctx, fixture.primary, rejoined); err != nil {
		return err
	}
	if err := fixture.assertReadOnly(ctx, rejoined); err != nil {
		return err
	}
	fixture.standby = rejoined
	fixture.fenced = nil
	return nil
}

// AssertSinglePrimary proves exactly the expected writable/read-only role
// pair; unavailable or ambiguous observations fail closed.
func (fixture *Fixture) AssertSinglePrimary(ctx context.Context) error {
	if fixture == nil {
		return errors.New("PostgreSQL HA fixture is unavailable")
	}
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	if fixture.closed || fixture.primary == nil || fixture.standby == nil {
		return errors.New("single-primary state cannot be proven")
	}
	return fixture.assertNodeRoles(ctx, fixture.primary, fixture.standby)
}

// Close removes only Docker resources carrying this fixture's exact task and
// slice labels. The caller-owned image is intentionally retained.
func (fixture *Fixture) Close(ctx context.Context) error {
	if fixture == nil {
		return nil
	}
	fixture.mu.Lock()
	if fixture.closed {
		fixture.mu.Unlock()
		return nil
	}
	fixture.closed = true
	endpoint := fixture.endpoint
	fixture.endpoint = nil
	fixture.databasePassword = ""
	fixture.replicationPassword = ""
	fixture.mu.Unlock()
	var problems []error
	problems = append(problems, endpoint.close())
	problems = append(problems, fixture.removeOwnedResources(ctx))
	return errors.Join(problems...)
}

func (fixture *Fixture) assertExclusive(ctx context.Context) error {
	checks := [][]string{
		{"container", "ls", "--all", "--quiet", "--filter", "label=" + taskLabel + "=" + fixture.config.TaskID},
		{"volume", "ls", "--quiet", "--filter", "label=" + taskLabel + "=" + fixture.config.TaskID},
		{"network", "ls", "--quiet", "--filter", "label=" + taskLabel + "=" + fixture.config.TaskID},
	}
	for _, arguments := range checks {
		output, err := fixture.docker.output(ctx, arguments...)
		if err != nil || strings.TrimSpace(output) != "" {
			return errors.New("PostgreSQL HA task ownership is not exclusive")
		}
	}
	return nil
}

func (fixture *Fixture) verifyImage(ctx context.Context) error {
	output, err := fixture.docker.output(
		ctx, "image", "inspect", "--format", "{{.Id}}|{{.Os}}|{{.Architecture}}", fixture.config.ImageID,
	)
	if err != nil {
		return errors.New("fixed PostgreSQL fixture image is unavailable")
	}
	parts := strings.Split(strings.TrimSpace(output), "|")
	if len(parts) != 3 || parts[0] != fixture.config.ImageID || parts[1] != "linux" || parts[2] != "amd64" {
		return errors.New("fixed PostgreSQL fixture image identity is invalid")
	}
	return nil
}

func (fixture *Fixture) createNetwork(ctx context.Context) error {
	output, err := fixture.docker.output(
		ctx, "network", "create",
		"--label", taskLabel+"="+fixture.config.TaskID,
		"--label", sliceLabel+"="+sliceLabelValue,
		fixture.network,
	)
	if err != nil || !resourceID.MatchString(strings.TrimSpace(output)) {
		return errors.New("create PostgreSQL HA fixture network failed")
	}
	return nil
}

func (fixture *Fixture) createVolume(ctx context.Context, name string) error {
	output, err := fixture.docker.output(
		ctx, "volume", "create",
		"--label", taskLabel+"="+fixture.config.TaskID,
		"--label", sliceLabel+"="+sliceLabelValue,
		name,
	)
	if err != nil || strings.TrimSpace(output) != name {
		return errors.New("create PostgreSQL HA fixture volume failed")
	}
	return nil
}

func (fixture *Fixture) startNode(ctx context.Context, node *postgresNode) error {
	reservedAddress, err := reserveLoopbackAddress()
	if err != nil {
		return err
	}
	arguments := []string{
		"run", "--detach", "--pull", "never", "--name", node.name,
		"--label", taskLabel + "=" + fixture.config.TaskID,
		"--label", sliceLabel + "=" + sliceLabelValue,
		"--network", fixture.network, "--network-alias", node.name,
		"--publish", reservedAddress + ":5432/tcp",
		"--cpus", "0.50", "--memory", "512m", "--memory-swap", "512m",
		"--pids-limit", "128", "--shm-size", "64m",
		"--security-opt", "no-new-privileges:true",
		"--cap-drop", "ALL", "--cap-add", "CHOWN", "--cap-add", "DAC_OVERRIDE",
		"--cap-add", "FOWNER", "--cap-add", "SETGID", "--cap-add", "SETUID",
		"--mount", "type=volume,source=" + node.volume + ",target=" + postgresData,
		"--env", "PGDATA=" + postgresData,
		"--env", "POSTGRES_DB=" + databaseName,
		"--env", "POSTGRES_USER=" + databaseUser,
		"--env", "POSTGRES_PASSWORD=" + fixture.databasePassword,
		"--env", "POSTGRES_INITDB_ARGS=--data-checksums",
		fixture.config.ImageID,
		"-c", "wal_level=replica", "-c", "max_wal_senders=4",
		"-c", "max_replication_slots=4", "-c", "hot_standby=on",
		"-c", "listen_addresses=*", "-c", "password_encryption=scram-sha-256",
	}
	output, err := fixture.docker.output(ctx, arguments...)
	if err != nil || !resourceID.MatchString(strings.TrimSpace(output)) {
		return errors.New("start PostgreSQL HA fixture node failed")
	}
	address, err := fixture.waitForPublishedAddress(ctx, node.name)
	if err != nil || address != reservedAddress {
		if err == nil {
			err = errors.New("PostgreSQL fixture port binding changed")
		}
		return err
	}
	node.address = address
	return nil
}

func (fixture *Fixture) waitForPublishedAddress(ctx context.Context, container string) (string, error) {
	deadline, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	for {
		address, err := fixture.publishedAddress(deadline, container)
		if err == nil {
			return address, nil
		}
		if !wait(deadline, 100*time.Millisecond) {
			return "", errors.New("PostgreSQL fixture port is unavailable")
		}
	}
}

func reserveLoopbackAddress() (string, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", errors.New("reserve PostgreSQL fixture port failed")
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		return "", errors.New("release PostgreSQL fixture port failed")
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil || host != "127.0.0.1" {
		return "", errors.New("reserved PostgreSQL fixture port escaped loopback")
	}
	numericPort, err := strconv.ParseUint(port, 10, 16)
	if err != nil || numericPort == 0 {
		return "", errors.New("reserved PostgreSQL fixture port is invalid")
	}
	return net.JoinHostPort(host, port), nil
}

func (fixture *Fixture) configureReplicationAuthority(ctx context.Context) error {
	connection, err := fixture.connect(ctx, fixture.primary)
	if err != nil {
		return err
	}
	defer connection.Close(ctx)
	statement := "CREATE ROLE " + replicationUser + " WITH REPLICATION LOGIN PASSWORD '" +
		fixture.replicationPassword + "'"
	if _, err := connection.Exec(ctx, statement); err != nil {
		return errors.New("create PostgreSQL replication authority failed")
	}
	hba := "host replication " + replicationUser + " all scram-sha-256"
	if _, err := fixture.docker.output(
		ctx, "exec", "--user", "postgres", fixture.primary.name,
		"sh", "-ceu", `printf '%s\n' "$1" >> "$PGDATA/pg_hba.conf"`, "sh", hba,
	); err != nil {
		return errors.New("configure PostgreSQL replication admission failed")
	}
	var reloaded bool
	if err := connection.QueryRow(ctx, `SELECT pg_reload_conf()`).Scan(&reloaded); err != nil || !reloaded {
		return errors.New("reload PostgreSQL replication admission failed")
	}
	return nil
}

func (fixture *Fixture) cloneStandby(ctx context.Context, primary, standby *postgresNode) error {
	const cloneScript = `set -eu
install -d -m 0700 -o postgres -g postgres "$PGDATA"
gosu postgres env PGPASSWORD="$REPLICATION_PASSWORD" pg_basebackup \
  --host="$PRIMARY_HOST" --port=5432 --username="$REPLICATION_USER" \
  --pgdata="$PGDATA" --format=plain --wal-method=stream --checkpoint=fast \
  --write-recovery-conf --create-slot --slot="$SLOT_NAME" --no-password
printf '%s:%s:*:%s:%s\n' "$PRIMARY_HOST" 5432 "$REPLICATION_USER" "$REPLICATION_PASSWORD" > "$PGDATA/standby.pgpass"
chown postgres:postgres "$PGDATA/standby.pgpass"
chmod 0600 "$PGDATA/standby.pgpass"
printf "primary_conninfo = 'host=%s port=5432 user=%s passfile=''/var/lib/postgresql/data/standby.pgpass'' application_name=%s sslmode=disable'\n" \
  "$PRIMARY_HOST" "$REPLICATION_USER" "$APPLICATION_NAME" >> "$PGDATA/postgresql.auto.conf"
printf "primary_slot_name = '%s'\n" "$SLOT_NAME" >> "$PGDATA/postgresql.auto.conf"
chown postgres:postgres "$PGDATA/postgresql.auto.conf" "$PGDATA/standby.signal"`
	helper := fixture.config.TaskID + "-clone"
	output, err := fixture.docker.output(
		ctx, "run", "--rm", "--pull", "never", "--name", helper,
		"--label", taskLabel+"="+fixture.config.TaskID,
		"--label", sliceLabel+"="+sliceLabelValue,
		"--network", fixture.network,
		"--cpus", "0.50", "--memory", "512m", "--memory-swap", "512m",
		"--pids-limit", "128", "--security-opt", "no-new-privileges:true",
		"--mount", "type=volume,source="+standby.volume+",target="+postgresData,
		"--env", "PGDATA="+postgresData,
		"--env", "PRIMARY_HOST="+primary.name,
		"--env", "REPLICATION_USER="+replicationUser,
		"--env", "REPLICATION_PASSWORD="+fixture.replicationPassword,
		"--env", "APPLICATION_NAME="+standby.applicationName,
		"--env", "SLOT_NAME="+standby.slotName,
		"--entrypoint", "sh", fixture.config.ImageID, "-ceu", cloneScript,
	)
	if err != nil || strings.TrimSpace(output) != "" {
		return errors.New("clone PostgreSQL physical standby failed")
	}
	return nil
}

func (fixture *Fixture) enableSynchronousStandby(
	ctx context.Context,
	primary, standby *postgresNode,
) error {
	if !regexp.MustCompile(`^[a-z][a-z0-9_]{2,31}$`).MatchString(standby.applicationName) {
		return errors.New("synchronous standby identity is invalid")
	}
	connection, err := fixture.connect(ctx, primary)
	if err != nil {
		return err
	}
	defer connection.Close(ctx)
	statements := []string{
		"ALTER SYSTEM SET synchronous_standby_names = 'FIRST 1 (" + standby.applicationName + ")'",
		"ALTER SYSTEM SET synchronous_commit = 'remote_apply'",
	}
	for _, statement := range statements {
		if _, err := connection.Exec(ctx, statement); err != nil {
			return errors.New("configure synchronous PostgreSQL standby failed")
		}
	}
	var reloaded bool
	if err := connection.QueryRow(ctx, `SELECT pg_reload_conf()`).Scan(&reloaded); err != nil || !reloaded {
		return errors.New("reload synchronous PostgreSQL configuration failed")
	}
	deadline, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	for {
		var state, synchronous string
		err := connection.QueryRow(
			deadline,
			`SELECT state, sync_state FROM pg_stat_replication WHERE application_name=$1`,
			standby.applicationName,
		).Scan(&state, &synchronous)
		if err == nil && state == "streaming" && synchronous == "sync" {
			return nil
		}
		if !wait(deadline, 100*time.Millisecond) {
			return errors.New("synchronous PostgreSQL standby did not become ready")
		}
	}
}

func (fixture *Fixture) waitForReplay(
	ctx context.Context,
	primary, standby *postgresNode,
	confirmedLSN string,
) (string, error) {
	if !lsnPattern.MatchString(confirmedLSN) {
		return "", errors.New("confirmed PostgreSQL LSN is invalid")
	}
	deadline, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	for {
		primaryConnection, primaryErr := fixture.connect(deadline, primary)
		standbyConnection, standbyErr := fixture.connect(deadline, standby)
		var state, synchronous, replayLSN string
		var replayed bool
		if primaryErr == nil {
			primaryErr = primaryConnection.QueryRow(
				deadline,
				`SELECT state, sync_state, COALESCE(replay_lsn::text, '')
                   FROM pg_stat_replication WHERE application_name=$1`,
				standby.applicationName,
			).Scan(&state, &synchronous, &replayLSN)
			primaryConnection.Close(deadline)
		}
		if standbyErr == nil {
			standbyErr = standbyConnection.QueryRow(
				deadline,
				`SELECT pg_last_wal_replay_lsn()::text,
                        pg_wal_lsn_diff(pg_last_wal_replay_lsn(), $1::pg_lsn) >= 0`,
				confirmedLSN,
			).Scan(&replayLSN, &replayed)
			standbyConnection.Close(deadline)
		}
		if primaryErr == nil && standbyErr == nil && state == "streaming" && synchronous == "sync" &&
			replayed && lsnPattern.MatchString(replayLSN) {
			return replayLSN, nil
		}
		if !wait(deadline, 100*time.Millisecond) {
			return "", errors.New("standby did not confirm the committed PostgreSQL LSN")
		}
	}
}

func (fixture *Fixture) promote(ctx context.Context, node *postgresNode) error {
	connection, err := fixture.connect(ctx, node)
	if err != nil {
		return err
	}
	var promoted bool
	err = connection.QueryRow(ctx, `SELECT pg_promote(true, 30)`).Scan(&promoted)
	connection.Close(ctx)
	if err != nil || !promoted {
		return errors.New("promote PostgreSQL standby failed")
	}
	return fixture.waitForRole(ctx, node, false)
}

func (fixture *Fixture) proveFencedAndPromoted(
	ctx context.Context,
	oldPrimary, newPrimary *postgresNode,
	confirmedLSN string,
) (int64, error) {
	if present, err := fixture.ownedContainerPresent(ctx, oldPrimary.name); err != nil || present {
		return 0, errors.New("old PostgreSQL primary is not fenced")
	}
	recovery, err := fixture.nodeRecoveryState(ctx, newPrimary)
	if err != nil || recovery {
		return 0, errors.New("new PostgreSQL primary role is unproven")
	}
	connection, err := fixture.connect(ctx, newPrimary)
	if err != nil {
		return 0, err
	}
	defer connection.Close(ctx)
	var rpoBytes int64
	if err := connection.QueryRow(
		ctx,
		`SELECT GREATEST(pg_wal_lsn_diff($1::pg_lsn, pg_current_wal_lsn()), 0)::bigint`,
		confirmedLSN,
	).Scan(&rpoBytes); err != nil || rpoBytes != 0 {
		return 0, errors.New("promoted PostgreSQL primary lacks the confirmed LSN")
	}
	return rpoBytes, nil
}

func (fixture *Fixture) assertNodeRoles(ctx context.Context, primary, standby *postgresNode) error {
	primaryRecovery, primaryErr := fixture.nodeRecoveryState(ctx, primary)
	standbyRecovery, standbyErr := fixture.nodeRecoveryState(ctx, standby)
	if primaryErr != nil || standbyErr != nil || primaryRecovery || !standbyRecovery {
		return errors.New("single-primary PostgreSQL state cannot be proven")
	}
	return nil
}

func (fixture *Fixture) assertReadOnly(ctx context.Context, standby *postgresNode) error {
	connection, err := fixture.connect(ctx, standby)
	if err != nil {
		return err
	}
	defer connection.Close(ctx)
	_, err = connection.Exec(ctx, `CREATE TEMPORARY TABLE matrix_failover_write_probe (id integer)`)
	var postgresError *pgconn.PgError
	if !errors.As(err, &postgresError) || postgresError.Code != "25006" {
		return errors.New("rejoined PostgreSQL primary remained writable")
	}
	return nil
}

func (fixture *Fixture) fenceNode(ctx context.Context, node *postgresNode) error {
	present, err := fixture.ownedContainerPresent(ctx, node.name)
	if err != nil || !present {
		return errors.New("old PostgreSQL primary ownership is unavailable")
	}
	if _, err := fixture.docker.output(ctx, "stop", "--time", "10", node.name); err != nil {
		return errors.New("stop old PostgreSQL primary failed")
	}
	if _, err := fixture.docker.output(ctx, "rm", node.name); err != nil {
		return errors.New("remove old PostgreSQL primary fence failed")
	}
	present, err = fixture.ownedContainerPresent(ctx, node.name)
	if err != nil || present {
		return errors.New("old PostgreSQL primary fence is unproven")
	}
	return nil
}

func (fixture *Fixture) publishedAddress(ctx context.Context, container string) (string, error) {
	output, err := fixture.docker.output(ctx, "port", container, "5432/tcp")
	if err != nil {
		return "", errors.New("PostgreSQL fixture port is unavailable")
	}
	lines := strings.Fields(strings.TrimSpace(output))
	if len(lines) != 1 {
		return "", errors.New("PostgreSQL fixture port binding is invalid")
	}
	host, port, err := net.SplitHostPort(lines[0])
	if err != nil || host != "127.0.0.1" {
		return "", errors.New("PostgreSQL fixture port binding escaped loopback")
	}
	numericPort, err := strconv.ParseUint(port, 10, 16)
	if err != nil || numericPort == 0 {
		return "", errors.New("PostgreSQL fixture port binding is invalid")
	}
	return net.JoinHostPort(host, port), nil
}

func (fixture *Fixture) waitForRole(ctx context.Context, node *postgresNode, recovery bool) error {
	deadline, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	for {
		actual, err := fixture.nodeRecoveryState(deadline, node)
		if err == nil && actual == recovery {
			return nil
		}
		if !wait(deadline, 100*time.Millisecond) {
			return errors.New("PostgreSQL fixture node did not reach its required role")
		}
	}
}

func (fixture *Fixture) nodeRecoveryState(ctx context.Context, node *postgresNode) (bool, error) {
	connection, err := fixture.connect(ctx, node)
	if err != nil {
		return false, err
	}
	defer connection.Close(ctx)
	var recovery bool
	if err := connection.QueryRow(ctx, `SELECT pg_is_in_recovery()`).Scan(&recovery); err != nil {
		return false, errors.New("query PostgreSQL fixture role failed")
	}
	return recovery, nil
}

func (fixture *Fixture) pingEndpoint(ctx context.Context) error {
	connection, err := pgx.Connect(ctx, fixture.EndpointDSN())
	if err != nil {
		return errors.New("stable PostgreSQL endpoint is unavailable")
	}
	defer connection.Close(ctx)
	var primary bool
	if err := connection.QueryRow(ctx, `SELECT NOT pg_is_in_recovery()`).Scan(&primary); err != nil || !primary {
		return errors.New("stable PostgreSQL endpoint does not resolve to the primary")
	}
	return nil
}

func (fixture *Fixture) connect(ctx context.Context, node *postgresNode) (*pgx.Conn, error) {
	if node == nil || node.address == "" {
		return nil, errors.New("PostgreSQL fixture node address is unavailable")
	}
	connection, err := pgx.Connect(ctx, postgresDSN(node.address, databaseUser, fixture.databasePassword))
	if err != nil {
		return nil, errors.New("connect PostgreSQL fixture node failed")
	}
	return connection, nil
}

func (fixture *Fixture) ownedContainerPresent(ctx context.Context, name string) (bool, error) {
	output, err := fixture.docker.output(
		ctx, "container", "ls", "--all", "--quiet", "--filter", "name=^/"+name+"$",
		"--filter", "label="+taskLabel+"="+fixture.config.TaskID,
	)
	if err != nil {
		return false, err
	}
	trimmed := strings.TrimSpace(output)
	if trimmed == "" {
		return false, nil
	}
	if len(strings.Fields(trimmed)) != 1 {
		return false, errors.New("owned PostgreSQL container identity is ambiguous")
	}
	label, err := fixture.docker.output(
		ctx, "inspect", "--format", `{{ index .Config.Labels "matrix.task" }}|{{ index .Config.Labels "matrix.slice" }}`,
		name,
	)
	if err != nil || strings.TrimSpace(label) != fixture.config.TaskID+"|"+sliceLabelValue {
		return false, errors.New("PostgreSQL container ownership is invalid")
	}
	return true, nil
}

func (fixture *Fixture) removeOwnedVolume(ctx context.Context, name string) error {
	label, err := fixture.docker.output(
		ctx, "volume", "inspect", "--format", `{{ index .Labels "matrix.task" }}|{{ index .Labels "matrix.slice" }}`,
		name,
	)
	if err != nil || strings.TrimSpace(label) != fixture.config.TaskID+"|"+sliceLabelValue {
		return errors.New("PostgreSQL volume ownership is invalid")
	}
	if _, err := fixture.docker.output(ctx, "volume", "rm", name); err != nil {
		return errors.New("remove PostgreSQL HA fixture volume failed")
	}
	return nil
}

func (fixture *Fixture) removeOwnedResources(ctx context.Context) error {
	if fixture == nil || !taskIDPattern.MatchString(fixture.config.TaskID) {
		return errors.New("PostgreSQL HA cleanup scope is invalid")
	}
	var problems []error
	containers, err := fixture.docker.lines(
		ctx, "container", "ls", "--all", "--quiet", "--no-trunc", "--filter",
		"label="+taskLabel+"="+fixture.config.TaskID,
	)
	if err != nil {
		problems = append(problems, errors.New("list owned PostgreSQL containers failed"))
	} else {
		for _, container := range containers {
			if !resourceID.MatchString(container) {
				problems = append(problems, errors.New("owned PostgreSQL container identity is invalid"))
				continue
			}
			label, inspectErr := fixture.docker.output(
				ctx, "inspect", "--format", `{{ index .Config.Labels "matrix.task" }}|{{ index .Config.Labels "matrix.slice" }}`,
				container,
			)
			if inspectErr != nil || strings.TrimSpace(label) != fixture.config.TaskID+"|"+sliceLabelValue {
				problems = append(problems, errors.New("refusing to remove unowned PostgreSQL container"))
				continue
			}
			_, removeErr := fixture.docker.output(ctx, "rm", "--force", container)
			problems = append(problems, removeErr)
		}
	}
	volumes, err := fixture.docker.lines(
		ctx, "volume", "ls", "--quiet", "--filter", "label="+taskLabel+"="+fixture.config.TaskID,
	)
	if err != nil {
		problems = append(problems, errors.New("list owned PostgreSQL volumes failed"))
	} else {
		for _, volume := range volumes {
			label, inspectErr := fixture.docker.output(
				ctx, "volume", "inspect", "--format", `{{ index .Labels "matrix.task" }}|{{ index .Labels "matrix.slice" }}`,
				volume,
			)
			if inspectErr != nil || strings.TrimSpace(label) != fixture.config.TaskID+"|"+sliceLabelValue {
				problems = append(problems, errors.New("refusing to remove unowned PostgreSQL volume"))
				continue
			}
			_, removeErr := fixture.docker.output(ctx, "volume", "rm", volume)
			problems = append(problems, removeErr)
		}
	}
	networks, err := fixture.docker.lines(
		ctx, "network", "ls", "--quiet", "--no-trunc", "--filter", "label="+taskLabel+"="+fixture.config.TaskID,
	)
	if err != nil {
		problems = append(problems, errors.New("list owned PostgreSQL networks failed"))
	} else {
		for _, network := range networks {
			if !resourceID.MatchString(network) {
				problems = append(problems, errors.New("owned PostgreSQL network identity is invalid"))
				continue
			}
			label, inspectErr := fixture.docker.output(
				ctx, "network", "inspect", "--format", `{{ index .Labels "matrix.task" }}|{{ index .Labels "matrix.slice" }}`,
				network,
			)
			if inspectErr != nil || strings.TrimSpace(label) != fixture.config.TaskID+"|"+sliceLabelValue {
				problems = append(problems, errors.New("refusing to remove unowned PostgreSQL network"))
				continue
			}
			_, removeErr := fixture.docker.output(ctx, "network", "rm", network)
			problems = append(problems, removeErr)
		}
	}
	return errors.Join(problems...)
}

func (cli dockerCLI) output(ctx context.Context, arguments ...string) (string, error) {
	if ctx == nil || len(arguments) == 0 {
		return "", errors.New("Docker fixture command is invalid")
	}
	stdout := newBoundedBuffer(maximumOutputBytes)
	stderr := newBoundedBuffer(maximumOutputBytes)
	command := exec.CommandContext(ctx, "docker", arguments...)
	command.Stdin = nil
	command.Stdout = stdout
	command.Stderr = stderr
	err := command.Run()
	if err != nil || stdout.overflow || stderr.overflow {
		return "", errors.New("Docker PostgreSQL HA fixture command failed")
	}
	return stdout.content.String(), nil
}

func (cli dockerCLI) lines(ctx context.Context, arguments ...string) ([]string, error) {
	output, err := cli.output(ctx, arguments...)
	if err != nil {
		return nil, err
	}
	trimmed := strings.TrimSpace(output)
	if trimmed == "" {
		return nil, nil
	}
	lines := strings.Split(trimmed, "\n")
	for index := range lines {
		lines[index] = strings.TrimSpace(lines[index])
		if lines[index] == "" || strings.ContainsAny(lines[index], "\r\t ") {
			return nil, errors.New("Docker fixture returned an invalid identity list")
		}
	}
	return lines, nil
}

func newBoundedBuffer(limit int) *boundedBuffer {
	return &boundedBuffer{remaining: limit}
}

func (buffer *boundedBuffer) Write(content []byte) (int, error) {
	original := len(content)
	if original > buffer.remaining {
		content = content[:buffer.remaining]
		buffer.overflow = true
	}
	written, err := buffer.content.Write(content)
	buffer.remaining -= written
	if err != nil {
		return written, err
	}
	return original, nil
}

func postgresDSN(address, username, password string) string {
	value := &url.URL{
		Scheme: "postgres", User: url.UserPassword(username, password),
		Host: address, Path: "/" + databaseName,
	}
	query := value.Query()
	query.Set("sslmode", "disable")
	query.Set("connect_timeout", "2")
	value.RawQuery = query.Encode()
	return value.String()
}

func randomHex(size int) (string, error) {
	content := make([]byte, size)
	if _, err := rand.Read(content); err != nil {
		return "", errors.New("generate PostgreSQL HA fixture secret failed")
	}
	return hex.EncodeToString(content), nil
}

func wait(ctx context.Context, duration time.Duration) bool {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
