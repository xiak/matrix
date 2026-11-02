package authorityprocess

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"os/exec"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	mysql "github.com/go-sql-driver/mysql"
	managedservicev1 "github.com/xiak/matrix/api/managedservice/v1"
)

func beginManagedMySQLTenantIsolation(t *testing.T, ctx context.Context, runtime managedProductRuntime, endpoint, owner, foreign, foreignTenantID string,
	productA managedProductFixture, instanceA managedservicev1.ServiceInstallation, projectA string) func() {
	t.Helper()
	base := endpoint + "/managed-services/v1"
	productB := managedMySQLFixture(t, "foreign", runtime.images.mysql)
	productB.tenantID = foreignTenantID
	t.Cleanup(func() { cleanupManagedProduct(t, productB) })
	response := performJSON(t, http.MethodGet, base+"/services/"+productB.serviceID, foreign, nil)
	var definition managedservicev1.ServiceDefinition
	if response.Status != http.StatusOK || json.Unmarshal(response.Body, &definition) != nil {
		t.Fatal("foreign tenant service definition")
	}
	response = performJSONWithIdempotency(t, http.MethodPost, base+"/service-activations", foreign, "mysql-isolation-activate",
		managedservicev1.ActivateServiceRequest{Service: managedservicev1.ServiceDefinitionReference{ID: definition.ID, Revision: definition.Revision, ContentDigest: definition.ContentDigest}})
	if response.Status != http.StatusCreated {
		t.Fatal("foreign tenant activation")
	}
	response = performJSONWithIdempotency(t, http.MethodPost, base+"/quota-entitlements", foreign, "mysql-isolation-quota",
		managedservicev1.ActivateQuotaRequest{OfferingID: productB.offeringID, QuotaShapeID: productB.quotaShapeID, InstanceCount: 1})
	var quota managedservicev1.QuotaEntitlement
	if response.Status != http.StatusCreated || json.Unmarshal(response.Body, &quota) != nil {
		t.Fatal("foreign tenant quota")
	}
	response = performJSONWithIdempotency(t, http.MethodPost, base+"/service-installations", foreign, "mysql-isolation-create",
		managedservicev1.CreateInstallationRequest{ID: productB.installationID, Name: "Isolated tenant MySQL", OfferingID: productB.offeringID, QuotaEntitlementID: quota.ID, RegionID: "local-primary"})
	if response.Status != http.StatusAccepted {
		t.Fatal("foreign tenant installation")
	}
	instanceB := waitManagedProductReady(t, ctx, endpoint, foreign, productB)
	projectB := assertManagedProductRuntime(t, ctx, instanceB, runtime, productB)
	passwordA, errA := readManagedProductCredential(ctx, runtime, productA, projectA)
	passwordB, errB := readManagedProductCredential(ctx, runtime, productB, projectB)
	if errA != nil || errB != nil || string(passwordA) == string(passwordB) || projectA == projectB || *instanceA.Endpoint == *instanceB.Endpoint || *instanceA.CredentialReference == *instanceB.CredentialReference {
		t.Fatal("tenant runtime or credentials not distinct")
	}
	t.Cleanup(func() { clear(passwordA); clear(passwordB) })
	for _, direction := range []struct {
		instance   managedservicev1.ServiceInstallation
		own, other []byte
	}{{instanceA, passwordA, passwordB}, {instanceB, passwordB, passwordA}} {
		assertMySQLTenantMarker(t, ctx, direction.instance, direction.own, direction.instance.ID, true)
		db := mysqlTenantDatabase(t, *direction.instance.Endpoint, direction.other)
		var rejected *mysql.MySQLError
		err := db.PingContext(ctx)
		_ = db.Close()
		if !errors.As(err, &rejected) || rejected.Number != 1045 {
			t.Fatal("cross-tenant SQL credential was not rejected by MySQL")
		}
	}
	for _, direction := range []struct {
		own, other managedservicev1.ServiceInstallation
		bearer     string
	}{{instanceA, instanceB, owner}, {instanceB, instanceA, foreign}} {
		response := performJSON(t, http.MethodGet, base+"/service-installations", direction.bearer, nil)
		var list managedservicev1.ServiceInstallationList
		if response.Status != http.StatusOK || json.Unmarshal(response.Body, &list) != nil {
			t.Fatal("tenant instance list unavailable")
		}
		found := false
		for _, item := range list.Items {
			if item.ID == direction.other.ID {
				t.Fatal("foreign tenant visible in list")
			}
			found = found || item.ID == direction.own.ID
		}
		if !found {
			t.Fatal("own instance missing from tenant list")
		}
		for _, suffix := range []string{"", "/operation"} {
			if response := performJSON(t, http.MethodGet, base+"/service-installations/"+direction.other.ID+suffix, direction.bearer, nil); response.Status != http.StatusNotFound {
				t.Fatal("foreign instance/operation visible")
			}
		}
		if response := performJSONWithIdempotency(t, http.MethodPost, base+"/service-installations/"+direction.other.ID+"/termination", direction.bearer, "isolation-denied-delete-"+direction.other.ID, nil); response.Status != http.StatusNotFound {
			t.Fatal("foreign termination was not rejected")
		}
	}
	assertMySQLNetworkIsolation(t, ctx, projectA, projectB, *instanceA.Endpoint, *instanceB.Endpoint)
	// Restart both owned processes without rewriting their networks or secrets.
	for _, project := range []string{projectA, projectB} {
		if err := exec.CommandContext(ctx, "docker", "restart", project+"-mysql-1", project+"-mysql-endpoint-1").Run(); err != nil {
			t.Fatal("restart owned MySQL")
		}
	}
	for _, direction := range []struct {
		instance managedservicev1.ServiceInstallation
		password []byte
	}{{instanceA, passwordA}, {instanceB, passwordB}} {
		db := mysqlTenantDatabase(t, *direction.instance.Endpoint, direction.password)
		deadline := time.Now().Add(time.Minute)
		for db.PingContext(ctx) != nil {
			if time.Now().After(deadline) || ctx.Err() != nil {
				t.Fatal("MySQL did not recover after restart")
			}
			time.Sleep(200 * time.Millisecond)
		}
		_ = db.Close()
		assertMySQLTenantMarker(t, ctx, direction.instance, direction.password, direction.instance.ID, false)
	}
	assertMySQLNetworkIsolation(t, ctx, projectA, projectB, *instanceA.Endpoint, *instanceB.Endpoint)
	before := inspectMySQLBoundary(t, ctx, projectB)
	return func() {
		// The caller has deleted A through the real API and proved A's runtime,
		// data, credentials, quota and networks absent.
		after := inspectMySQLBoundary(t, ctx, projectB)
		if !reflect.DeepEqual(before, after) {
			t.Fatal("deleting A changed B runtime, network or mounts")
		}
		remainingPassword, err := readManagedProductCredential(ctx, runtime, productB, projectB)
		if err != nil || string(remainingPassword) != string(passwordB) {
			t.Fatal("deleting A changed B credentials")
		}
		clear(remainingPassword)
		assertMySQLTenantMarker(t, ctx, instanceB, passwordB, instanceB.ID, false)
		assertMySQLTenantMarker(t, ctx, instanceB, passwordB, "write-after-peer-deletion", true)
		response := performJSON(t, http.MethodGet, base+"/quota-entitlements/"+quota.ID, foreign, nil)
		var preserved managedservicev1.QuotaEntitlement
		if response.Status != http.StatusOK || json.Unmarshal(response.Body, &preserved) != nil || preserved.ConsumedCount != 1 || preserved.ReservedCount != 0 {
			t.Fatal("deleting A changed B quota")
		}
		key := "mysql-isolation-delete-b"
		path := base + "/service-installations/" + instanceB.ID + "/termination"
		if response := performJSONWithIdempotency(t, http.MethodPost, path, foreign, key, nil); response.Status != http.StatusAccepted {
			t.Fatal("delete tenant B")
		}
		waitManagedProductTerminated(t, ctx, endpoint, foreign, productB)
		assertManagedProductDeleted(t, ctx, runtime, productB, projectB, *instanceB.Endpoint)
		if response := performJSONWithIdempotency(t, http.MethodPost, path, foreign, key, nil); response.Status != http.StatusOK {
			t.Fatal("replay B deletion")
		}
		t.Log("two real MySQL tenants: private and host-published paths denied in both directions before/after restart; credentials, data, API scope and deletion independently verified")
	}
}

func mysqlTenantDatabase(t *testing.T, address string, password []byte) *sql.DB {
	t.Helper()
	config := mysql.NewConfig()
	config.User, config.Passwd, config.Net, config.Addr, config.DBName = "matrix_service", string(password), "tcp", address, "service"
	config.Timeout, config.ReadTimeout, config.WriteTimeout = 3*time.Second, 3*time.Second, 3*time.Second
	config.Logger = log.New(io.Discard, "", 0)
	db, err := sql.Open("mysql", config.FormatDSN())
	if err != nil {
		t.Fatal("open tenant SQL probe")
	}
	return db
}

func assertMySQLTenantMarker(t *testing.T, ctx context.Context, instance managedservicev1.ServiceInstallation, password []byte, marker string, write bool) {
	t.Helper()
	db := mysqlTenantDatabase(t, *instance.Endpoint, password)
	defer db.Close()
	if write {
		if _, err := db.ExecContext(ctx, "CREATE TABLE IF NOT EXISTS tenant_isolation (id integer PRIMARY KEY, marker varchar(128) NOT NULL)"); err != nil {
			t.Fatal("create tenant data probe")
		}
		if _, err := db.ExecContext(ctx, "INSERT INTO tenant_isolation (id,marker) VALUES (1,?) ON DUPLICATE KEY UPDATE marker=VALUES(marker)", marker); err != nil {
			t.Fatal("write tenant data probe")
		}
	}
	var actual string
	if err := db.QueryRowContext(ctx, "SELECT marker FROM tenant_isolation WHERE id=1").Scan(&actual); err != nil || actual != marker {
		t.Fatal("tenant data was lost or mixed")
	}
}

type mysqlBoundary struct {
	ID     string
	Config struct {
		Env    []string
		Labels map[string]string
		User   string
	}
	Mounts     []struct{ Type, Source, Destination string }
	HostConfig struct {
		ReadonlyRootfs bool
		CapDrop        []string
		Sysctls        map[string]string
		PortBindings   map[string][]struct{ HostIP, HostPort string }
	}
	NetworkSettings struct {
		Networks map[string]struct{ IPAddress, Gateway, NetworkID string }
	}
}

func inspectMySQLBoundary(t *testing.T, ctx context.Context, project string) mysqlBoundary {
	return inspectMySQLContainer(t, ctx, project+"-mysql-1")
}

func inspectMySQLContainer(t *testing.T, ctx context.Context, name string) mysqlBoundary {
	t.Helper()
	output, err := exec.CommandContext(ctx, "docker", "inspect", name).Output()
	var containers []mysqlBoundary
	if err != nil || json.Unmarshal(output, &containers) != nil || len(containers) != 1 {
		t.Fatal("inspect owned MySQL boundary")
	}
	sort.Slice(containers[0].Mounts, func(i, j int) bool { return containers[0].Mounts[i].Destination < containers[0].Mounts[j].Destination })
	return containers[0]
}

func assertMySQLNetworkIsolation(t *testing.T, ctx context.Context, projectA, projectB, endpointA, endpointB string) {
	t.Helper()
	a, b := inspectMySQLBoundary(t, ctx, projectA), inspectMySQLBoundary(t, ctx, projectB)
	for _, direction := range []struct {
		project, peerProject, peerEndpoint string
		own, peer                          mysqlBoundary
	}{{projectA, projectB, endpointB, a, b}, {projectB, projectA, endpointA, b, a}} {
		private := direction.own.NetworkSettings.Networks[direction.project+"_private"]
		ingress := inspectMySQLContainer(t, ctx, direction.project+"-mysql-endpoint-1")
		if ingress.Config.User != "65532:65532" || !ingress.HostConfig.ReadonlyRootfs ||
			len(ingress.NetworkSettings.Networks) != 2 || ingress.HostConfig.Sysctls["net.ipv4.ip_forward"] != "0" ||
			len(ingress.HostConfig.PortBindings) != 1 || len(ingress.HostConfig.CapDrop) != 1 || ingress.HostConfig.CapDrop[0] != "ALL" {
			t.Fatal("MySQL ingress privilege or network boundary drifted")
		}
		for _, mount := range ingress.Mounts {
			if mount.Type != "tmpfs" || mount.Destination != "/var/lib/docker" {
				t.Fatal("MySQL ingress received a host/data/credential mount")
			}
		}
		for _, bindings := range ingress.HostConfig.PortBindings {
			if len(bindings) != 1 || bindings[0].HostIP != "127.0.0.1" {
				t.Fatal("MySQL ingress is not loopback bound")
			}
		}
		peerPrivate := direction.peer.NetworkSettings.Networks[direction.peerProject+"_private"]
		if len(direction.own.NetworkSettings.Networks) != 1 || private.IPAddress == "" || private.Gateway != "" || private.NetworkID == peerPrivate.NetworkID || peerPrivate.IPAddress == "" {
			t.Fatal("database is not in its own network without a host gateway")
		}
		output, err := exec.CommandContext(ctx, "docker", "network", "inspect", private.NetworkID).Output()
		var networks []struct {
			Internal bool
			Options  map[string]string
		}
		if err != nil || json.Unmarshal(output, &networks) != nil || len(networks) != 1 || !networks[0].Internal || networks[0].Options["com.docker.network.bridge.gateway_mode_ipv4"] != "isolated" {
			t.Fatal("private bridge does not enforce isolated mode")
		}
		for _, ownMount := range direction.own.Mounts {
			for _, peerMount := range direction.peer.Mounts {
				if ownMount.Source == peerMount.Source {
					t.Fatal("tenant data/credential mount is shared")
				}
			}
		}
		for _, mount := range direction.peer.Mounts {
			if err := exec.CommandContext(ctx, "docker", "exec", "--user", "mysql", direction.project+"-mysql-1", "sh", "-c", `test ! -e "$1" && test ! -S /var/run/docker.sock && test -d /var/lib/mysql && test -f /run/secrets/mysql-password`, "sh", mount.Source).Run(); err != nil {
				t.Fatal("foreign files or Docker socket accessible")
			}
		}
		probe := func(host, port string, allow bool) {
			command := exec.CommandContext(ctx, "docker", "exec", "--user", "mysql", direction.project+"-mysql-1", "timeout", "2", "bash", "-c", `exec 3<>/dev/tcp/"$1"/"$2"`, "--", host, port)
			err := command.Run()
			if allow {
				if err != nil {
					t.Fatal("network positive control failed")
				}
				return
			}
			var exit *exec.ExitError
			if !errors.As(err, &exit) || (exit.ExitCode() != 1 && exit.ExitCode() != 124) {
				t.Fatal("cross-tenant network path connected or probe failed unexpectedly")
			}
		}
		_, peerPort, err := net.SplitHostPort(direction.peerEndpoint)
		if err != nil {
			t.Fatal("invalid tenant endpoint")
		}
		probe("127.0.0.1", "3306", true)
		probe(peerPrivate.IPAddress, "3306", false)
		probe(direction.peerProject+"-mysql-1", "3306", false)
		probe("host.docker.internal", peerPort, false)
		// Explicitly test the host path on Linux too, where the Desktop DNS
		// name may not exist. This is B's actual external bridge gateway.
		output, err = exec.CommandContext(ctx, "docker", "network", "inspect", "--format", "{{(index .IPAM.Config 0).Gateway}}", direction.peerProject+"_default").Output()
		if err != nil || net.ParseIP(strings.TrimSpace(string(output))) == nil {
			t.Fatal("inspect peer host bridge address")
		}
		probe(strings.TrimSpace(string(output)), peerPort, false)
		probe("127.0.0.1", "3306", true)
	}
}
