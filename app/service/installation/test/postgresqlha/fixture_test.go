package postgresqlha

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestStartRejectsUnboundedConfigurationBeforeDocker(t *testing.T) {
	validImage := "sha256:" + strings.Repeat("a", 64)
	for name, config := range map[string]Config{
		"moving image": {ImageID: "postgres:18", TaskID: "matrix-pg-ha-test"},
		"foreign task": {ImageID: validImage, TaskID: "another-project"},
		"long task": {
			ImageID: validImage,
			TaskID:  "matrix-pg-ha-" + strings.Repeat("a", 40),
		},
	} {
		t.Run(name, func(t *testing.T) {
			if fixture, err := Start(context.Background(), config); err == nil || fixture != nil {
				t.Fatal("unbounded fixture configuration reached Docker")
			}
		})
	}
}

func TestPhysicalReplicationControlledFailover(t *testing.T) {
	fixture := startAcceptanceFixture(t, "lifecycle")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	connection, err := pgx.Connect(ctx, fixture.EndpointDSN())
	if err != nil {
		t.Fatal("connect stable endpoint", err)
	}
	if _, err := connection.Exec(ctx, `
CREATE TABLE matrix_ha_markers (
  marker text PRIMARY KEY,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
INSERT INTO matrix_ha_markers(marker) VALUES ('confirmed-before-failover')`); err != nil {
		connection.Close(ctx)
		t.Fatal("commit marker through stable endpoint", err)
	}
	connection.Close(ctx)

	checkpoint, err := fixture.ConfirmedCheckpoint(ctx)
	if err != nil {
		t.Fatal("observe confirmed checkpoint", err)
	}
	if !lsnPattern.MatchString(checkpoint.ConfirmedLSN) ||
		!lsnPattern.MatchString(checkpoint.StandbyReplayLSN) || checkpoint.ConfirmedAt.IsZero() {
		t.Fatal("checkpoint omitted confirmed/replayed LSN evidence")
	}
	observation, err := fixture.ControlledFailover(ctx, checkpoint)
	if err != nil {
		t.Fatal("controlled failover", err)
	}
	if observation.ConfirmedLSN != checkpoint.ConfirmedLSN ||
		observation.ConfirmedRPOBytes != 0 || observation.RTO <= 0 || observation.RTO > 45*time.Second ||
		observation.FailureDetectedAt.IsZero() || observation.PrimaryFencedAt.IsZero() ||
		observation.StandbyPromotedAt.IsZero() || observation.EndpointSwitchedAt.IsZero() ||
		observation.ReadyAt.IsZero() ||
		observation.PrimaryFencedAt.Before(observation.FailureDetectedAt) ||
		observation.StandbyPromotedAt.Before(observation.PrimaryFencedAt) ||
		observation.EndpointSwitchedAt.Before(observation.StandbyPromotedAt) ||
		observation.ReadyAt.Before(observation.EndpointSwitchedAt) {
		t.Fatalf("failover evidence violated fence/promote/switch order: %#v", observation)
	}

	connection, err = pgx.Connect(ctx, fixture.EndpointDSN())
	if err != nil {
		t.Fatal("reconnect stable endpoint after failover", err)
	}
	var markers int
	if err := connection.QueryRow(
		ctx, `SELECT count(*) FROM matrix_ha_markers WHERE marker='confirmed-before-failover'`,
	).Scan(&markers); err != nil || markers != 1 {
		connection.Close(ctx)
		t.Fatal("confirmed transaction was not retained after failover", err)
	}
	connection.Close(ctx)

	if err := fixture.RejoinFencedPrimary(ctx); err != nil {
		t.Fatal("rejoin fenced primary as standby", err)
	}
	if err := fixture.AssertSinglePrimary(ctx); err != nil {
		t.Fatal("single-primary state after rejoin", err)
	}
	standby, err := fixture.connect(ctx, fixture.standby)
	if err != nil {
		t.Fatal("connect rejoined standby", err)
	}
	_, writeErr := standby.Exec(ctx, `INSERT INTO matrix_ha_markers(marker) VALUES ('must-not-write')`)
	standby.Close(ctx)
	var postgresError *pgconn.PgError
	if !errors.As(writeErr, &postgresError) || postgresError.Code != "25006" {
		t.Fatalf("rejoined old primary accepted a write: %v", writeErr)
	}
}

func TestFailoverClosesEndpointWhenSinglePrimaryCannotBeProven(t *testing.T) {
	fixture := startAcceptanceFixture(t, "failclosed")
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	checkpoint, err := fixture.ConfirmedCheckpoint(ctx)
	if err != nil {
		t.Fatal("observe confirmed checkpoint", err)
	}
	if _, err := fixture.docker.output(ctx, "stop", "--time", "5", fixture.standby.name); err != nil {
		t.Fatal("make standby role unobservable", err)
	}
	if _, err := fixture.ControlledFailover(ctx, checkpoint); err == nil {
		t.Fatal("failover admitted an unprovable single-primary state")
	}
	if fixture.state != fixtureFailedClosed {
		t.Fatal("ambiguous failover did not enter failure-closed state")
	}
	endpoint, endpointErr := pgx.Connect(ctx, fixture.EndpointDSN())
	if endpointErr == nil {
		var one int
		endpointErr = endpoint.QueryRow(ctx, `SELECT 1`).Scan(&one)
		endpoint.Close(ctx)
	}
	if endpointErr == nil {
		t.Fatal("stable endpoint remained writable after ambiguous failover")
	}
	primaryRecovery, err := fixture.nodeRecoveryState(ctx, fixture.primary)
	if err != nil || primaryRecovery {
		t.Fatal("failed-closed attempt changed the original primary role", err)
	}
	present, err := fixture.ownedContainerPresent(ctx, fixture.primary.name)
	if err != nil || !present {
		t.Fatal("failed-closed attempt fenced the healthy primary without proof", err)
	}
}

func startAcceptanceFixture(t *testing.T, suffix string) *Fixture {
	t.Helper()
	if os.Getenv("MATRIX_POSTGRES_HA_ACCEPTANCE") != "1" {
		t.Skip("set MATRIX_POSTGRES_HA_ACCEPTANCE=1 with an immutable local PostgreSQL image")
	}
	imageID := os.Getenv("MATRIX_POSTGRES_HA_IMAGE_ID")
	base := os.Getenv("MATRIX_POSTGRES_HA_TASK")
	if base == "" {
		content := make([]byte, 6)
		if _, err := rand.Read(content); err != nil {
			t.Fatal("generate task identity", err)
		}
		base = "matrix-pg-ha-" + hex.EncodeToString(content)
	}
	taskID := base + "-" + suffix
	fixture, err := Start(context.Background(), Config{ImageID: imageID, TaskID: taskID})
	if err != nil {
		t.Fatal("start PostgreSQL HA fixture", err)
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		if err := fixture.Close(cleanup); err != nil {
			t.Error("clean PostgreSQL HA fixture", err)
		}
	})
	return fixture
}
