package localpostgres

import (
	"context"
	"errors"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	managedserviceadapterv1 "github.com/xiak/matrix/api/adapter/managedservice/v1"
	composeadapter "github.com/xiak/matrix/app/adapter/apphosting/compose"
)

const localPostgresE2E = "MATRIX_LOCAL_POSTGRES_E2E"

func TestLocalPostgresRealRuntime(t *testing.T) {
	if os.Getenv(localPostgresE2E) != "1" {
		t.Skipf("set %s=1 with the fixed PostgreSQL image already loaded", localPostgresE2E)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	runtime := composeadapter.NewLocalRuntime()
	root := t.TempDir()
	provisioner, err := New(Config{
		Root:    root,
		ImageID: "sha256:3a82e1f56c8f0f5616a11103ac3d47e632c3938698946a7ad26da0df1334744a",
		Runtime: runtime,
	})
	if err != nil {
		t.Fatalf("new real provisioner: %v", err)
	}
	request := testProvisionRequest()
	result, err := provisioner.Ensure(ctx, request)
	if err != nil {
		t.Fatalf("ensure real PostgreSQL: %v", err)
	}
	project := projectName(request.TenantID, request.InstallationID)
	directory := filepath.Join(root, project)
	runtimeProject := composeadapter.RuntimeProject{
		Name: project, Directory: directory,
		EffectDocument:      filepath.Join(directory, "compose.json"),
		ObservationDocument: filepath.Join(directory, "observe.json"),
		TimeoutSeconds:      30,
	}
	defer func() {
		cleanup, cleanupCancel := context.WithTimeout(context.Background(), time.Minute)
		defer cleanupCancel()
		if _, err := os.Stat(runtimeProject.ObservationDocument); err == nil {
			if err := runtime.Stop(cleanup, runtimeProject); err != nil {
				t.Errorf("stop real PostgreSQL: %v", err)
			}
		}
	}()
	password, err := os.ReadFile(filepath.Join(directory, "postgres-password"))
	if err != nil {
		t.Fatal("read generated PostgreSQL credential")
	}
	dsn := &url.URL{
		Scheme: "postgresql", Host: result.Endpoint, Path: "/service",
		User:     url.UserPassword("matrix_service", string(password)),
		RawQuery: "sslmode=disable",
	}
	connection, err := pgx.Connect(ctx, dsn.String())
	if err != nil {
		t.Fatal("connect generated PostgreSQL endpoint")
	}
	if _, err := connection.Exec(ctx, `CREATE TABLE durable_probe (value text PRIMARY KEY)`); err != nil {
		t.Fatal("create durability probe")
	}
	if _, err := connection.Exec(ctx, `INSERT INTO durable_probe (value) VALUES ('preserved')`); err != nil {
		t.Fatal("write durability probe")
	}
	connection.Close(context.Background())
	replayed, err := provisioner.Ensure(ctx, request)
	if err != nil || replayed != result {
		t.Fatalf("reconcile real PostgreSQL=%#v err=%v", replayed, err)
	}
	connection, err = pgx.Connect(ctx, dsn.String())
	if err != nil {
		t.Fatal("reconnect generated PostgreSQL endpoint")
	}
	defer connection.Close(context.Background())
	var value string
	var version int
	if err := connection.QueryRow(ctx, `SELECT value FROM durable_probe`).Scan(&value); err != nil || value != "preserved" {
		t.Fatalf("durability probe=%q err=%v", value, err)
	}
	if err := connection.QueryRow(ctx, `SELECT current_setting('server_version_num')::integer`).Scan(&version); err != nil || version < 180000 || version >= 190000 {
		t.Fatalf("server version=%d err=%v", version, err)
	}
	if err := connection.Close(ctx); err != nil {
		t.Fatal("close generated PostgreSQL connection")
	}
	deprovision := managedserviceadapterv1.DeprovisionRequest{
		TenantID: request.TenantID, InstallationID: request.InstallationID,
		OperationID: "operation-real-delete", OfferingID: request.OfferingID,
		EngineVersion: request.EngineVersion, RegionID: request.RegionID,
	}
	if err := provisioner.Delete(ctx, deprovision); err != nil {
		t.Fatalf("delete real PostgreSQL: %v", err)
	}
	if _, err := os.Lstat(directory); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("real PostgreSQL data or credentials remain: %v", err)
	}
	if connection, err := net.DialTimeout("tcp", result.Endpoint, time.Second); err == nil {
		_ = connection.Close()
		t.Fatal("terminated PostgreSQL endpoint still accepts connections")
	}
	if err := provisioner.Delete(ctx, deprovision); err != nil {
		t.Fatalf("equal real PostgreSQL delete replay: %v", err)
	}
}
