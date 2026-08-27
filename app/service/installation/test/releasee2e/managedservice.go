package releasee2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"time"

	auditv1 "github.com/xiak/matrix/api/audit/v1"
	managedservicev1 "github.com/xiak/matrix/api/managedservice/v1"
	"github.com/xiak/matrix/app/service/installation/internal/layout"
)

const (
	managedServicePath        = "/api/managed-services/v1"
	managedInstallationID     = "release-postgres"
	managedLateInstallationID = "release-postgres-later"
)

func (value *gate) createManagedPostgres(ctx context.Context, bearer []byte, platformID string) error {
	var offerings managedservicev1.ServiceOfferingList
	if _, err := value.edge.get(ctx, managedServicePath+"/offerings", bearer, &offerings); err != nil ||
		len(offerings.Items) != 1 || managedservicev1.ValidateServiceOffering(offerings.Items[0]) != nil ||
		offerings.Items[0].ID != managedservicev1.PostgreSQLOfferingID {
		return fail("managed-service-catalog")
	}
	var offering managedservicev1.ServiceOffering
	if _, err := value.edge.get(ctx, managedServicePath+"/offerings/"+offerings.Items[0].ID, bearer, &offering); err != nil ||
		!reflect.DeepEqual(offering, offerings.Items[0]) {
		return fail("managed-service-offering-read")
	}
	var regions managedservicev1.RegionList
	if _, err := value.edge.get(ctx, managedServicePath+"/regions", bearer, &regions); err != nil ||
		len(regions.Items) != 1 || managedservicev1.ValidateRegion(regions.Items[0]) != nil ||
		regions.Items[0].Profile != managedservicev1.RegionLocalMachine || regions.Items[0].State != managedservicev1.RegionReady {
		return fail("managed-service-local-region")
	}
	var region managedservicev1.Region
	if _, err := value.edge.get(ctx, managedServicePath+"/regions/"+regions.Items[0].ID, bearer, &region); err != nil ||
		managedservicev1.ValidateRegion(region) != nil || region.ID != regions.Items[0].ID ||
		region.Profile != regions.Items[0].Profile || region.State != managedservicev1.RegionReady {
		return fail("managed-service-region-read")
	}
	var initialQuotas managedservicev1.QuotaEntitlementList
	var initialInstallations managedservicev1.ServiceInstallationList
	if _, err := value.edge.get(ctx, managedServicePath+"/quota-entitlements", bearer, &initialQuotas); err != nil || len(initialQuotas.Items) != 0 {
		return fail("managed-service-empty-quota")
	}
	if _, err := value.edge.get(ctx, managedServicePath+"/service-installations", bearer, &initialInstallations); err != nil || len(initialInstallations.Items) != 0 {
		return fail("managed-service-empty-region")
	}
	activation := managedservicev1.ActivateQuotaRequest{
		OfferingID: offering.ID, QuotaShapeID: "pg-small", InstanceCount: 1,
	}
	var quota managedservicev1.QuotaEntitlement
	if err := value.managedWrite(ctx, "/quota-entitlements", bearer, activation, "release-activate-pg", http.StatusCreated, &quota); err != nil {
		return err
	}
	if managedservicev1.ValidateQuotaEntitlement(quota) != nil || quota.OfferingID != activation.OfferingID ||
		quota.QuotaShapeID != activation.QuotaShapeID || quota.PurchasedCount != 1 || quota.ReservedCount != 0 || quota.ConsumedCount != 0 {
		return fail("managed-service-quota-activation")
	}
	var replayedQuota managedservicev1.QuotaEntitlement
	if err := value.managedWrite(ctx, "/quota-entitlements", bearer, activation, "release-activate-pg", http.StatusOK, &replayedQuota); err != nil ||
		!reflect.DeepEqual(quota, replayedQuota) {
		return fail("managed-service-quota-replay")
	}
	changedActivation := activation
	changedActivation.InstanceCount = 2
	if err := value.expectManagedProblem(ctx, http.MethodPost, "/quota-entitlements", bearer, changedActivation,
		"release-activate-pg", http.StatusConflict, managedservicev1.ErrorIdempotencyConflict); err != nil {
		return err
	}
	unsupported := activation
	unsupported.OfferingID = "mysql"
	if err := value.expectManagedProblem(ctx, http.MethodPost, "/quota-entitlements", bearer, unsupported,
		"release-unsupported-offering", http.StatusBadRequest, managedservicev1.ErrorInvalidArgument); err != nil {
		return err
	}

	workers, err := dockerLines(ctx, "container", "ls", "--quiet",
		"--filter", "label=com.xiak.matrix.installation="+platformID,
		"--filter", "label=com.xiak.matrix.role=paas-worker")
	if err != nil || len(workers) != 1 {
		return fail("managed-service-worker-identity")
	}
	if _, err := docker(ctx, "container", "stop", workers[0]); err != nil {
		return fail("managed-service-worker-stop")
	}
	workerStopped := true
	defer func() {
		if workerStopped {
			cleanup, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			_, _ = docker(cleanup, "container", "start", workers[0])
		}
	}()
	request := managedservicev1.CreateInstallationRequest{
		ID: managedInstallationID, Name: "Release PostgreSQL", OfferingID: offering.ID,
		QuotaEntitlementID: quota.ID, RegionID: region.ID,
	}
	var accepted managedservicev1.ServiceInstallation
	if err := value.managedWrite(ctx, "/service-installations", bearer, request, "release-install-pg", http.StatusAccepted, &accepted); err != nil {
		return err
	}
	if managedservicev1.ValidateServiceInstallation(accepted) != nil || accepted.ID != request.ID ||
		accepted.Phase != managedservicev1.InstallationPending || accepted.QuotaEntitlementID != quota.ID || accepted.RegionID != region.ID {
		return fail("managed-service-durable-acceptance")
	}
	var replayed managedservicev1.ServiceInstallation
	if err := value.managedWrite(ctx, "/service-installations", bearer, request, "release-install-pg", http.StatusOK, &replayed); err != nil ||
		!reflect.DeepEqual(accepted, replayed) {
		return fail("managed-service-installation-replay")
	}
	changed := request
	changed.Name = "Changed PostgreSQL"
	if err := value.expectManagedProblem(ctx, http.MethodPost, "/service-installations", bearer, changed,
		"release-install-pg", http.StatusConflict, managedservicev1.ErrorIdempotencyConflict); err != nil {
		return err
	}
	exhausted := request
	exhausted.ID = "release-postgres-excess"
	if err := value.expectManagedProblem(ctx, http.MethodPost, "/service-installations", bearer, exhausted,
		"release-exhausted-pg", http.StatusConflict, managedservicev1.ErrorQuotaExhausted); err != nil {
		return err
	}
	if _, err := docker(ctx, "container", "start", workers[0]); err != nil {
		return fail("managed-service-worker-restart")
	}
	workerStopped = false
	poll, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	for {
		var installation managedservicev1.ServiceInstallation
		_, err := value.edge.get(poll, managedServicePath+"/service-installations/"+request.ID, bearer, &installation)
		if err != nil || managedservicev1.ValidateServiceInstallation(installation) != nil ||
			installation.ID != request.ID || installation.Operation.ID != accepted.Operation.ID ||
			installation.Phase == managedservicev1.InstallationFailed {
			return fail("managed-service-provisioning")
		}
		if installation.Phase == managedservicev1.InstallationReady {
			value.managed = installation
			break
		}
		if !waitPoll(poll, 200*time.Millisecond) {
			return fail("managed-service-provisioning-timeout")
		}
	}
	if err := value.writeManagedProbe(ctx, managedInstallationID, 1); err != nil {
		return err
	}
	if err := value.assertManagedPostgres(ctx, bearer, 1); err != nil {
		return err
	}
	if _, err := value.edge.waitAuditActions(ctx, bearer, map[auditv1.Action]string{
		auditv1.ActionManagedServiceQuotaEntitlementActivated: quota.ID,
		auditv1.ActionManagedServiceInstallationCreated:       request.ID,
		auditv1.ActionManagedServiceInstallationReady:         request.ID,
	}); err != nil {
		return fail("managed-service-audit-delivery")
	}
	return nil
}

func (value *gate) assertManagedRecoveryBoundary(ctx context.Context, bearer []byte, backupID string) error {
	var quota managedservicev1.QuotaEntitlement
	activation := managedservicev1.ActivateQuotaRequest{
		OfferingID: managedservicev1.PostgreSQLOfferingID, QuotaShapeID: "pg-small", InstanceCount: 1,
	}
	if err := value.managedWrite(ctx, "/quota-entitlements", bearer, activation, "release-later-quota", http.StatusCreated, &quota); err != nil {
		return err
	}
	request := managedservicev1.CreateInstallationRequest{
		ID: managedLateInstallationID, Name: "Post-backup PostgreSQL", OfferingID: activation.OfferingID,
		QuotaEntitlementID: quota.ID, RegionID: value.managed.RegionID,
	}
	var accepted managedservicev1.ServiceInstallation
	if err := value.managedWrite(ctx, "/service-installations", bearer, request, "release-later-installation", http.StatusAccepted, &accepted); err != nil {
		return err
	}
	poll, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	for {
		var installation managedservicev1.ServiceInstallation
		_, err := value.edge.get(poll, managedServicePath+"/service-installations/"+request.ID, bearer, &installation)
		if err != nil || managedservicev1.ValidateServiceInstallation(installation) != nil ||
			installation.ID != request.ID || installation.Operation.ID != accepted.Operation.ID ||
			installation.Phase == managedservicev1.InstallationFailed {
			return fail("post-backup-managed-service-provisioning")
		}
		if installation.Phase == managedservicev1.InstallationReady {
			value.managedLate = installation
			break
		}
		if !waitPoll(poll, 200*time.Millisecond) {
			return fail("post-backup-managed-service-provisioning-timeout")
		}
	}
	if err := value.writeManagedProbe(ctx, managedLateInstallationID, 1); err != nil {
		return err
	}
	if _, err := value.edge.waitAuditActions(ctx, bearer, map[auditv1.Action]string{
		auditv1.ActionManagedServiceQuotaEntitlementActivated: quota.ID,
		auditv1.ActionManagedServiceInstallationCreated:       request.ID,
		auditv1.ActionManagedServiceInstallationReady:         request.ID,
	}); err != nil {
		return fail("post-backup-managed-service-audit")
	}
	output, err := runProcess(ctx, mxPath(value.releases.a), "--format", "json", "platform", "recover",
		"--root", value.config.root, "--backup", backupID)
	defer clear(output.stdout)
	defer clear(output.stderr)
	if err != nil || containsAny(output.stdout, value.pathLeakage()) || containsAny(output.stderr, value.pathLeakage()) {
		return fail("managed-service-recovery-command")
	}
	if err := value.assertManagedProbe(ctx, managedLateInstallationID, 1); err != nil {
		return err
	}
	var retained managedservicev1.ServiceInstallation
	if _, err := value.edge.get(ctx, managedServicePath+"/service-installations/"+request.ID, bearer, &retained); err != nil ||
		!reflect.DeepEqual(retained, value.managedLate) {
		return fail("recovery-orphaned-new-managed-service")
	}
	var failure mxFailure
	if output.exit != 3 || len(output.stdout) != 0 || decodeOne(output.stderr, &failure) != nil ||
		failure.Kind != "PlatformCommandFailure" || failure.Action != "RECOVER" ||
		failure.Status != "FAILED" || failure.Error.Class != "PRECONDITION_FAILED" {
		return fail("recovery-admitted-changed-managed-inventory")
	}
	if _, err := assertPlatform(ctx, value.config.root, value.releases.a.Manifest, ""); err != nil {
		return err
	}
	return value.assertManagedPostgres(ctx, bearer, 1)
}

func (value *gate) managedWrite(ctx context.Context, path string, bearer []byte, body any, key string, status int, destination any) error {
	response, err := value.edge.json(ctx, http.MethodPost, managedServicePath+path, bearer, body,
		map[string]string{"Idempotency-Key": key}, status)
	if err != nil {
		return fail("managed-service-mutation")
	}
	defer clear(response.body)
	if decodeOne(response.body, destination) != nil {
		return fail("managed-service-mutation-contract")
	}
	return nil
}

func (value *gate) expectManagedProblem(ctx context.Context, method, path string, bearer []byte, body any, key string,
	status int, code managedservicev1.ErrorCode,
) error {
	headers := map[string]string{}
	if key != "" {
		headers["Idempotency-Key"] = key
	}
	response, err := value.edge.json(ctx, method, managedServicePath+path, bearer, body, headers, status)
	if err != nil {
		return fail("managed-service-rejection-" + string(code))
	}
	defer clear(response.body)
	var problem managedservicev1.Problem
	if decodeOne(response.body, &problem) != nil || managedservicev1.ValidateProblem(problem) != nil ||
		problem.Status != status || problem.Code != code {
		return fail("managed-service-normalized-problem")
	}
	return nil
}

func (value *gate) assertManagedPostgres(ctx context.Context, bearer []byte, rows int) error {
	var installations managedservicev1.ServiceInstallationList
	var installation managedservicev1.ServiceInstallation
	var operation managedservicev1.InstallationOperation
	var quotas managedservicev1.QuotaEntitlementList
	var quota managedservicev1.QuotaEntitlement
	for _, read := range []struct {
		path string
		to   any
	}{
		{"/service-installations", &installations},
		{"/service-installations/" + managedInstallationID, &installation},
		{"/service-installations/" + managedInstallationID + "/operation", &operation},
		{"/quota-entitlements", &quotas},
		{"/quota-entitlements/" + value.managed.QuotaEntitlementID, &quota},
	} {
		if _, err := value.edge.get(ctx, managedServicePath+read.path, bearer, read.to); err != nil {
			return fail("managed-service-preserved-resource-read")
		}
	}
	expected := map[string]managedservicev1.ServiceInstallation{value.managed.ID: value.managed}
	if value.managedLate.ID != "" {
		expected[value.managedLate.ID] = value.managedLate
	}
	if len(installations.Items) != len(expected) || len(quotas.Items) != len(expected) ||
		!reflect.DeepEqual(installation, value.managed) || !reflect.DeepEqual(operation, installation.Operation) ||
		managedservicev1.ValidateQuotaEntitlement(quota) != nil || quota.PurchasedCount != 1 ||
		quota.ReservedCount != 0 || quota.ConsumedCount != 1 {
		return fail("managed-service-preserved-identity-and-quota")
	}
	quotaIDs := make(map[string]bool, len(expected))
	for _, installation := range installations.Items {
		if !reflect.DeepEqual(installation, expected[installation.ID]) {
			return fail("managed-service-preserved-installation-list")
		}
		delete(expected, installation.ID)
		quotaIDs[installation.QuotaEntitlementID] = true
	}
	for _, quota := range quotas.Items {
		if !quotaIDs[quota.ID] || managedservicev1.ValidateQuotaEntitlement(quota) != nil ||
			quota.PurchasedCount != 1 || quota.ReservedCount != 0 || quota.ConsumedCount != 1 {
			return fail("managed-service-preserved-quota-list")
		}
		delete(quotaIDs, quota.ID)
	}
	if err := value.assertManagedProbe(ctx, managedInstallationID, rows); err != nil {
		return err
	}
	if value.managedLate.ID != "" {
		return value.assertManagedProbe(ctx, managedLateInstallationID, 1)
	}
	return nil
}

type managedDatabase struct {
	imageID  string
	endpoint string
	password []byte
}

func (value *gate) managedDatabase(ctx context.Context, installationID string) (*managedDatabase, error) {
	ids, err := dockerLines(ctx, "container", "ls", "--all", "--quiet",
		"--filter", "label=com.xiak.matrix.role=managed-postgresql",
		"--filter", "label=com.xiak.matrix.managedservice.installation="+installationID)
	if err != nil || len(ids) != 1 {
		return nil, fail("managed-postgres-single-runtime")
	}
	inspections, err := inspectContainers(ctx, ids)
	if err != nil {
		return nil, fail("managed-postgres-runtime-inspection")
	}
	container := inspections[0]
	wantImage := ""
	for _, image := range value.releases.a.Manifest.Images {
		if image.Component == "postgres" {
			wantImage = image.ImageID
		}
	}
	if wantImage == "" || container.Config.Image != wantImage ||
		container.Config.Labels["com.xiak.matrix.managed"] != "true" ||
		container.Config.Labels["com.xiak.matrix.managedservice.installation"] != installationID ||
		container.Config.Labels["com.xiak.matrix.managedservice.offering"] != managedservicev1.PostgreSQLOfferingID ||
		container.Config.Labels["com.xiak.matrix.managedservice.storage-gib"] != "10" ||
		container.HostConfig.Memory != 1024*1024*1024 || container.HostConfig.NanoCPUs != 500000000 ||
		!container.State.Running || container.State.Health == nil || container.State.Health.Status != "healthy" {
		return nil, fail("managed-postgres-runtime-contract")
	}
	bindings := container.NetworkSettings.Ports["5432/tcp"]
	var binding struct {
		HostIP   string `json:"HostIp"`
		HostPort string `json:"HostPort"`
	}
	if len(bindings) != 1 || json.Unmarshal(bindings[0], &binding) != nil || binding.HostIP != "127.0.0.1" {
		return nil, fail("managed-postgres-local-endpoint")
	}
	port, err := strconv.ParseUint(binding.HostPort, 10, 16)
	if err != nil || port == 0 {
		return nil, fail("managed-postgres-local-port")
	}
	endpoint := net.JoinHostPort(binding.HostIP, binding.HostPort)
	expected := value.managed
	if installationID == managedLateInstallationID {
		expected = value.managedLate
	}
	if expected.Endpoint != nil && *expected.Endpoint != endpoint {
		return nil, fail("managed-postgres-endpoint-identity")
	}
	ownedRoot := filepath.Join(value.config.root, filepath.FromSlash(layout.ExecutorRoot), "managed-postgres")
	passwordPath := ""
	for _, mount := range container.Mounts {
		if mount.Destination != "/run/secrets/postgres-password" {
			continue
		}
		relative, err := filepath.Rel(ownedRoot, mount.Source)
		if err != nil || mount.RW || filepath.Clean(mount.Source) != mount.Source ||
			relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || filepath.IsAbs(relative) {
			return nil, fail("managed-postgres-credential-custody")
		}
		passwordPath = mount.Source
	}
	info, err := os.Lstat(passwordPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() < 32 || info.Size() > 256 {
		return nil, fail("managed-postgres-credential-permissions")
	}
	password, err := os.ReadFile(passwordPath)
	if err != nil {
		return nil, fail("managed-postgres-credential-read")
	}
	value.sensitive = append(value.sensitive, password)
	value.edge.addForbidden(password)
	connection := &managedDatabase{imageID: wantImage, endpoint: endpoint, password: password}
	identity, err := connection.query(ctx, "SELECT current_database(), current_user, current_setting('server_version_num')")
	fields := strings.Split(identity, "|")
	if err != nil || len(fields) != 3 || fields[0] != "service" || fields[1] != "matrix_service" {
		return nil, fail("managed-postgres-database-identity")
	}
	number, err := strconv.Atoi(fields[2])
	if err != nil || number < 180000 || number >= 190000 {
		return nil, fail("managed-postgres-engine-version")
	}
	return connection, nil
}

func (database *managedDatabase) query(ctx context.Context, query string) (string, error) {
	bounded, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	input := append(append([]byte(nil), database.password...), '\n')
	defer clear(input)
	output, err := runProcessInput(bounded, bytes.NewReader(input), "docker",
		"run", "--rm", "--interactive", "--network", "host", "--user", "postgres",
		"--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
		"--label", "com.xiak.matrix.acceptance=managed-postgres-probe", "--entrypoint", "psql", database.imageID,
		"--password", "--no-psqlrc", "--tuples-only", "--no-align", "--set", "ON_ERROR_STOP=1",
		"--dbname", "postgresql://matrix_service@"+database.endpoint+"/service?sslmode=disable", "--command", query,
	)
	defer clear(output.stdout)
	defer clear(output.stderr)
	prompt := strings.TrimSpace(string(output.stderr))
	if err != nil || output.exit != 0 || containsAny(output.stdout, [][]byte{database.password}) ||
		containsAny(output.stderr, [][]byte{database.password}) ||
		(prompt != "Password:" && prompt != "Password for user matrix_service:") {
		return "", fail("managed-postgres-authenticated-query")
	}
	return strings.TrimSpace(string(output.stdout)), nil
}

func (value *gate) writeManagedProbe(ctx context.Context, installationID string, row int) error {
	connection, err := value.managedDatabase(ctx, installationID)
	if err != nil {
		return err
	}
	if row == 1 {
		if _, err := connection.query(ctx, "CREATE TABLE release_acceptance_probe (id integer PRIMARY KEY, value text NOT NULL)"); err != nil {
			return fail("managed-postgres-durable-probe-create")
		}
	}
	probe := fmt.Sprintf("release-durable-value-%d", row)
	value.sensitive = append(value.sensitive, []byte(probe))
	if row != 1 && row != 2 {
		return fail("managed-postgres-durable-probe-input")
	}
	query := fmt.Sprintf("INSERT INTO release_acceptance_probe(id, value) VALUES (%d, 'release-durable-value-%d')", row, row)
	if _, err := connection.query(ctx, query); err != nil {
		return fail("managed-postgres-durable-probe-write")
	}
	return nil
}

func (value *gate) assertManagedProbe(ctx context.Context, installationID string, want int) error {
	connection, err := value.managedDatabase(ctx, installationID)
	if err != nil {
		return err
	}
	result, err := connection.query(ctx, `SELECT count(*),
		coalesce(sum(CASE WHEN id IN (1, 2) AND value = 'release-durable-value-' || id::text THEN 1 ELSE 0 END), 0),
		coalesce(max(id), 0) FROM release_acceptance_probe`)
	if err != nil || result != fmt.Sprintf("%d|%d|%d", want, want, want) {
		return fail("managed-postgres-durable-probe-preservation")
	}
	return nil
}
