package localrabbitmq

import (
	"context"
	"errors"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	amqp "github.com/rabbitmq/amqp091-go"

	managedserviceadapterv1 "github.com/xiak/matrix/api/adapter/managedservice/v1"
	composeadapter "github.com/xiak/matrix/app/adapter/apphosting/compose"
	localcontaineradapter "github.com/xiak/matrix/app/adapter/managedservice/localcontainer"
)

const localRabbitMQE2EImage = "MATRIX_LOCAL_RABBITMQ_E2E_IMAGE_ID"

func TestLocalRabbitMQRealRuntime(t *testing.T) {
	imageID := os.Getenv(localRabbitMQE2EImage)
	if imageID == "" {
		t.Skipf("set %s to an already loaded, immutable RabbitMQ 4.1.8 image ID", localRabbitMQE2EImage)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	runtime := composeadapter.NewLocalRuntime()
	root := t.TempDir()
	provisioner, err := New(Config{Root: root, ImageID: imageID, Runtime: runtime})
	if err != nil {
		t.Fatalf("new real RabbitMQ provisioner: %v", err)
	}
	request := testProvisionRequest()
	projectName := localcontaineradapter.ProjectName(request.TenantID, request.InstallationID)
	directory := filepath.Join(root, projectName)
	project := composeadapter.RuntimeProject{
		Name: projectName, Directory: directory,
		EffectDocument:      filepath.Join(directory, "compose.json"),
		ObservationDocument: filepath.Join(directory, "observe.json"),
		TimeoutSeconds:      120,
	}
	defer func() {
		cleanup, cleanupCancel := context.WithTimeout(context.Background(), time.Minute)
		defer cleanupCancel()
		if _, err := os.Stat(project.ObservationDocument); err == nil {
			_ = runtime.Stop(cleanup, project)
		}
	}()
	result, err := provisioner.Ensure(ctx, request)
	if err != nil {
		configuration, _ := exec.CommandContext(context.Background(), "docker", "compose",
			"--project-name", projectName, "--project-directory", directory,
			"--file", project.EffectDocument, "config").CombinedOutput()
		logs, _ := exec.CommandContext(context.Background(), "docker", "compose",
			"--project-name", projectName, "--project-directory", directory,
			"--file", project.ObservationDocument, "logs", "--no-color", "--tail", "80").CombinedOutput()
		t.Fatalf("ensure real RabbitMQ: %v; Compose configuration: %s; logs: %s", err, configuration, logs)
	}
	password, err := os.ReadFile(filepath.Join(directory, "rabbitmq-password"))
	if err != nil {
		t.Fatal("read generated RabbitMQ credential")
	}
	connection := rabbitMQConnection(t, result.Endpoint, password)
	channel, err := connection.Channel()
	if err != nil {
		t.Fatal("open RabbitMQ channel")
	}
	queue, err := channel.QueueDeclare("matrix-durable-probe", true, false, false, false, nil)
	if err != nil {
		t.Fatal("declare RabbitMQ durability probe")
	}
	if err := channel.PublishWithContext(ctx, "", queue.Name, false, false, amqp.Publishing{
		ContentType: "text/plain", DeliveryMode: amqp.Persistent, Body: []byte("preserved"),
	}); err != nil {
		t.Fatal("publish RabbitMQ durability probe")
	}
	_ = channel.Close()
	_ = connection.Close()
	if err := runtime.Stop(ctx, project); err != nil {
		t.Fatalf("stop RabbitMQ before persistence replay: %v", err)
	}
	replayed, err := provisioner.Ensure(ctx, request)
	if err != nil || replayed != result {
		t.Fatalf("reconcile real RabbitMQ=%#v err=%v", replayed, err)
	}
	connection = rabbitMQConnection(t, result.Endpoint, password)
	channel, err = connection.Channel()
	if err != nil {
		t.Fatal("reopen RabbitMQ channel")
	}
	delivery, found, err := channel.Get(queue.Name, true)
	if err != nil || !found || string(delivery.Body) != "preserved" {
		t.Fatalf("RabbitMQ persistence probe found=%v body=%q err=%v", found, delivery.Body, err)
	}
	_ = channel.Close()
	_ = connection.Close()
	deprovision := managedserviceadapterv1.DeprovisionRequest{
		TenantID: request.TenantID, InstallationID: request.InstallationID,
		OperationID: "operation-real-delete", OfferingID: request.OfferingID,
		EngineVersion: request.EngineVersion, RegionID: request.RegionID,
	}
	if err := provisioner.Delete(ctx, deprovision); err != nil {
		t.Fatalf("delete real RabbitMQ: %v", err)
	}
	if _, err := os.Lstat(directory); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("real RabbitMQ data or credentials remain: %v", err)
	}
	endpoint, _ := url.Parse(result.Endpoint)
	if connection, err := net.DialTimeout("tcp", endpoint.Host, time.Second); err == nil {
		_ = connection.Close()
		t.Fatal("terminated RabbitMQ endpoint still accepts connections")
	}
	if err := provisioner.Delete(ctx, deprovision); err != nil {
		t.Fatalf("equal real RabbitMQ delete replay: %v", err)
	}
}

func rabbitMQConnection(t *testing.T, endpoint string, password []byte) *amqp.Connection {
	t.Helper()
	parsed, err := url.Parse(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	parsed.User = url.UserPassword("matrix_service", string(password))
	connection, err := amqp.DialConfig(parsed.String(), amqp.Config{
		Dial: func(network, address string) (net.Conn, error) {
			return net.DialTimeout(network, address, 5*time.Second)
		},
	})
	if err != nil {
		t.Fatalf("connect generated RabbitMQ endpoint: %v", err)
	}
	return connection
}
