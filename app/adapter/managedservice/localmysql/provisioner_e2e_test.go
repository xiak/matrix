package localmysql

import (
	"context"
	"database/sql"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	mysqldriver "github.com/go-sql-driver/mysql"

	composeadapter "github.com/xiak/matrix/app/adapter/apphosting/compose"
	localcontaineradapter "github.com/xiak/matrix/app/adapter/managedservice/localcontainer"
)

const localMySQLE2EImage = "MATRIX_LOCAL_MYSQL_E2E_IMAGE_ID"

func TestLocalMySQLRealRuntime(t *testing.T) {
	imageID := os.Getenv(localMySQLE2EImage)
	if imageID == "" {
		t.Skipf("set %s to an already loaded, immutable MySQL 8.4 image ID", localMySQLE2EImage)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	runtime := composeadapter.NewLocalRuntime()
	root := t.TempDir()
	provisioner, err := New(Config{Root: root, ImageID: imageID, Runtime: runtime})
	if err != nil {
		t.Fatalf("new real MySQL provisioner: %v", err)
	}
	request := testProvisionRequest()
	project := localcontaineradapter.ProjectName(request.TenantID, request.InstallationID)
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
				t.Errorf("stop real MySQL: %v", err)
			}
		}
	}()
	result, err := provisioner.Ensure(ctx, request)
	if err != nil {
		command := exec.CommandContext(context.Background(), "docker", "compose",
			"--project-name", project, "--project-directory", directory,
			"--file", runtimeProject.EffectDocument, "config")
		configuration, configurationErr := command.CombinedOutput()
		if configurationErr != nil {
			t.Fatalf("ensure real MySQL: %v; Compose configuration rejected: %s", err, configuration)
		}
		containers, observationErr := runtime.Observe(context.Background(), runtimeProject)
		if observationErr != nil {
			t.Fatalf("ensure real MySQL: %v; observation unavailable", err)
		}
		t.Fatalf("ensure real MySQL: %v; containers=%#v", err, containers)
	}
	password, err := os.ReadFile(filepath.Join(directory, "mysql-password"))
	if err != nil {
		t.Fatal("read generated MySQL credential")
	}
	config := mysqldriver.NewConfig()
	config.User = "matrix_service"
	config.Passwd = string(password)
	config.Net = "tcp"
	config.Addr = result.Endpoint
	config.DBName = "service"
	config.Timeout = 5 * time.Second
	config.ReadTimeout = 5 * time.Second
	config.WriteTimeout = 5 * time.Second
	database, err := sql.Open("mysql", config.FormatDSN())
	if err != nil {
		t.Fatal("open generated MySQL endpoint")
	}
	defer database.Close()
	if err := database.PingContext(ctx); err != nil {
		t.Fatal("connect generated MySQL endpoint")
	}
	if _, err := database.ExecContext(ctx, `CREATE TABLE durable_probe (value varchar(64) PRIMARY KEY)`); err != nil {
		t.Fatal("create MySQL durability probe")
	}
	if _, err := database.ExecContext(ctx, `INSERT INTO durable_probe (value) VALUES ('preserved')`); err != nil {
		t.Fatal("write MySQL durability probe")
	}
	replayed, err := provisioner.Ensure(ctx, request)
	if err != nil || replayed != result {
		t.Fatalf("reconcile real MySQL=%#v err=%v", replayed, err)
	}
	var value, version string
	if err := database.QueryRowContext(ctx, `SELECT value FROM durable_probe`).Scan(&value); err != nil || value != "preserved" {
		t.Fatalf("MySQL durability probe=%q err=%v", value, err)
	}
	if err := database.QueryRowContext(ctx, `SELECT VERSION()`).Scan(&version); err != nil ||
		len(version) < len("8.4.") || version[:len("8.4.")] != "8.4." {
		t.Fatalf("MySQL version=%q err=%v", version, err)
	}
}
