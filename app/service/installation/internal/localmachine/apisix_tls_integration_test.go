package localmachine

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	paasv1 "github.com/xiak/matrix/api/paas/v1"
	"github.com/xiak/matrix/app/service/installation/internal/layout"
	"github.com/xiak/matrix/app/service/installation/topology"
)

const apisixTLSIntegrationImageEnvironment = "MATRIX_APISIX_TLS_TEST_IMAGE"

// TestAPISIXServesInstallationAuthenticatedEnrollmentTLS is an explicit real
// provider gate. Normal unit runs stay hermetic; a release gate supplies the
// already-pinned APISIX image identity from the offline bundle.
func TestAPISIXServesInstallationAuthenticatedEnrollmentTLS(t *testing.T) {
	image := os.Getenv(apisixTLSIntegrationImageEnvironment)
	if image == "" {
		t.Skipf("set %s to the pinned APISIX image identity", apisixTLSIntegrationImageEnvironment)
	}
	if err := paasv1.ValidateDigest("APISIX TLS integration image", image); err != nil {
		t.Fatalf("APISIX TLS integration image must be an immutable image identity: %v", err)
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Fatal("APISIX TLS integration requires the Docker CLI")
	}

	plan := newInstallPlan(t)
	if err := stageInstallation(plan, rand.Reader); err != nil {
		t.Fatalf("stage APISIX TLS integration installation: %v", err)
	}
	compiled, err := topology.Compile(plan.Bundle.Manifest, topology.Options{
		InstallationID: plan.InstallationID, Root: "/srv/matrix",
		Listener: plan.Listener, Port: plan.Port,
	})
	if err != nil {
		t.Fatalf("compile APISIX TLS integration topology: %v", err)
	}
	if err := publishInstallationConfiguration(plan.Root, plan.Bundle.Manifest, compiled); err != nil {
		t.Fatalf("publish APISIX TLS integration configuration: %v", err)
	}
	testID := fmt.Sprintf("%d-%x", os.Getpid(), uint64(time.Now().UnixNano()))
	networkName := "matrix-enrollment-test-" + testID
	createNetwork := exec.Command(
		"docker", "network", "create", "--label", "com.xiak.matrix.test=node-enrollment-tls", networkName,
	)
	if output, err := createNetwork.CombinedOutput(); err != nil {
		t.Fatalf("create APISIX TLS integration network: %v: %s", err, strings.TrimSpace(string(output)))
	}
	t.Cleanup(func() {
		remove := exec.Command("docker", "network", "rm", networkName)
		if output, err := remove.CombinedOutput(); err != nil && !bytes.Contains(output, []byte("not found")) {
			t.Errorf("remove APISIX TLS integration network: %v: %s", err, strings.TrimSpace(string(output)))
		}
	})

	upstreamConfig := filepath.Join(t.TempDir(), "nginx.conf")
	if err := os.WriteFile(upstreamConfig, []byte(`worker_processes 1;
pid /tmp/matrix-paas-api.pid;
error_log /dev/stderr notice;
events { worker_connections 64; }
http {
  access_log /dev/stdout;
  server {
    listen 8080;
    location / {
      add_header X-Matrix-Test-Observed-Peer $http_x_matrix_observed_peer always;
      add_header X-Matrix-Test-Transport-Scheme $http_x_matrix_transport_scheme always;
      add_header X-Matrix-Test-Authorization $http_authorization always;
      add_header X-Matrix-Test-Cookie $http_cookie always;
      add_header X-Matrix-Test-Idempotency-Key $http_idempotency_key always;
      add_header X-Matrix-Test-If-Match $http_if_match always;
      add_header X-Matrix-Test-Subject-Credential $http_matrix_subject_credential always;
      add_header X-Matrix-Test-Public-Origin $http_x_matrix_public_origin always;
      add_header X-Matrix-Test-TLS-Peer $http_x_matrix_tls_peer always;
      return 204;
    }
  }
}
	`), 0o600); err != nil {
		t.Fatalf("write APISIX TLS integration upstream configuration: %v", err)
	}
	upstreamName := "matrix-paas-api-test-" + testID
	t.Cleanup(func() { removeDockerTestContainer(t, upstreamName) })
	startUpstream := exec.Command(
		"docker", "run", "--detach", "--name", upstreamName,
		"--user", "0:0",
		"--network", networkName, "--network-alias", "paas-api",
		"--mount", "type=bind,source="+upstreamConfig+",target=/tmp/matrix-paas-api.conf,readonly",
		"--entrypoint", "/usr/local/openresty/bin/openresty", image,
		"-c", "/tmp/matrix-paas-api.conf", "-g", "daemon off;",
	)
	if output, err := startUpstream.CombinedOutput(); err != nil {
		t.Fatalf("start APISIX TLS integration upstream: %v: %s", err, strings.TrimSpace(string(output)))
	}
	requireDockerTestContainerRunning(t, upstreamName)

	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve APISIX TLS integration port: %v", err)
	}
	hostPort := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatalf("release APISIX TLS integration port: %v", err)
	}
	containerName := "matrix-apisix-enrollment-test-" + testID
	t.Cleanup(func() { removeDockerTestContainer(t, containerName) })
	arguments := []string{
		"run", "--detach", "--name", containerName,
		"--network", networkName,
		"--env", "APISIX_STAND_ALONE=true",
		"--publish", "127.0.0.1:" + strconv.Itoa(hostPort) + ":" +
			strconv.Itoa(int(topology.NodeEnrollmentIngressTargetPort)) + "/tcp",
	}
	for _, mount := range []struct {
		source, target string
		readOnly       bool
	}{
		{layout.APISIXConfig, "/usr/local/apisix/conf/config.yaml", true},
		{layout.APISIXRoutes, "/usr/local/apisix/conf/apisix.yaml", true},
		{layout.APISIXUID, "/usr/local/apisix/conf/apisix.uid", true},
		{layout.APISIXNginx, "/usr/local/apisix/conf/nginx.conf", false},
		{layout.EnrollmentIngressCertificate, topology.NodeEnrollmentIngressCertificateTarget, true},
		{layout.EnrollmentIngressPrivateKey, topology.NodeEnrollmentIngressPrivateKeyTarget, true},
	} {
		source := filepath.Join(plan.Root, filepath.FromSlash(mount.source))
		declaration := "type=bind,source=" + source + ",target=" + mount.target
		if mount.readOnly {
			declaration += ",readonly"
		}
		arguments = append(arguments, "--mount", declaration)
	}
	arguments = append(arguments, image)
	start := exec.Command("docker", arguments...)
	if output, err := start.CombinedOutput(); err != nil {
		t.Fatalf("start APISIX TLS integration container: %v: %s", err, strings.TrimSpace(string(output)))
	}

	issuerDER := readTestFile(t, plan.Root, layout.EnrollmentIssuerCertificate)
	defer clear(issuerDER)
	issuer, err := x509.ParseCertificate(issuerDER)
	if err != nil {
		t.Fatalf("parse APISIX TLS integration issuer: %v", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(issuer)
	serverName, err := paasv1.NodeEnrollmentIngressServerName(plan.InstallationID)
	if err != nil {
		t.Fatalf("derive APISIX TLS integration server name: %v", err)
	}
	baseURL := "https://127.0.0.1:" + strconv.Itoa(hostPort)
	security := &tls.Config{
		MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		RootCAs: roots, ServerName: serverName,
	}
	response := waitForAPISIXTLS(t, containerName, baseURL+"/ready", security.Clone())
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1024))
	if err != nil || response.StatusCode != http.StatusOK || !bytes.Equal(body, []byte("{\"status\":\"ready\"}\n")) ||
		response.TLS == nil || response.TLS.Version != tls.VersionTLS13 ||
		len(response.TLS.PeerCertificates) == 0 ||
		response.TLS.PeerCertificates[0].VerifyHostname(serverName) != nil {
		t.Fatalf("APISIX TLS readiness status=%d body=%q err=%v", response.StatusCode, body, err)
	}
	for _, action := range []string{"exchange", "recovery-challenge", "recover"} {
		bootstrap := waitForAPISIXEnrollmentBootstrap(t, containerName, baseURL, action, security.Clone())
		peer := net.ParseIP(bootstrap.Header.Get("X-Matrix-Test-Observed-Peer"))
		if bootstrap.StatusCode != http.StatusNoContent || peer == nil || !peer.IsPrivate() ||
			bootstrap.Header.Get("X-Matrix-Test-Transport-Scheme") != "https" {
			bootstrap.Body.Close()
			t.Fatalf(
				"APISIX enrollment %s TLS route status=%d peer=%q scheme=%q",
				action, bootstrap.StatusCode,
				bootstrap.Header.Get("X-Matrix-Test-Observed-Peer"),
				bootstrap.Header.Get("X-Matrix-Test-Transport-Scheme"),
			)
		}
		for _, header := range []string{
			"X-Matrix-Test-Authorization", "X-Matrix-Test-Cookie",
			"X-Matrix-Test-Idempotency-Key", "X-Matrix-Test-If-Match",
			"X-Matrix-Test-Subject-Credential", "X-Matrix-Test-Public-Origin",
			"X-Matrix-Test-TLS-Peer",
		} {
			if bootstrap.Header.Get(header) != "" {
				bootstrap.Body.Close()
				t.Fatalf("APISIX enrollment %s TLS route forwarded ambient authority %s", action, header)
			}
		}
		bootstrap.Body.Close()
	}
	client := newAPISIXTLSClient(security.Clone(), 5*time.Second)
	denied, err := client.Get(baseURL + "/api/iam/v1/ready")
	if err != nil {
		t.Fatalf("request APISIX enrollment TLS closed route: %v", err)
	}
	denied.Body.Close()
	if denied.StatusCode != http.StatusNotFound {
		t.Fatalf("APISIX enrollment TLS front admitted an unrelated route: %d", denied.StatusCode)
	}
	oversized, err := http.NewRequest(
		http.MethodPost,
		baseURL+"/api/paas/v1/node-enrollments/node-enrollment-11111111111111111111111111111111/exchange",
		strings.NewReader(strings.Repeat("x", 64*1024+1)),
	)
	if err != nil {
		t.Fatal(err)
	}
	oversizedResponse, err := client.Do(oversized)
	if err != nil {
		t.Fatalf("request oversized APISIX enrollment exchange: %v", err)
	}
	oversizedResponse.Body.Close()
	if oversizedResponse.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("APISIX enrollment TLS front accepted oversized exchange: %d", oversizedResponse.StatusCode)
	}

	wrongName, err := paasv1.NodeEnrollmentIngressServerName("mxi-22222222222222222222222222222222")
	if err != nil {
		t.Fatal(err)
	}
	assertAPISIXTLSRejected(t, baseURL+"/ready", &tls.Config{
		MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		RootCAs: roots, ServerName: wrongName,
	})
	assertAPISIXTLSRejected(t, baseURL+"/ready", &tls.Config{
		MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12,
		RootCAs: roots, ServerName: serverName,
	})
}

func removeDockerTestContainer(t *testing.T, name string) {
	t.Helper()
	remove := exec.Command("docker", "rm", "--force", name)
	if output, err := remove.CombinedOutput(); err != nil && !bytes.Contains(output, []byte("No such container")) {
		t.Errorf("remove Docker test container: %v: %s", err, strings.TrimSpace(string(output)))
	}
}

func requireDockerTestContainerRunning(t *testing.T, name string) {
	t.Helper()
	inspect := exec.Command("docker", "inspect", "--format", "{{.State.Running}}", name)
	output, err := inspect.CombinedOutput()
	if err == nil && strings.TrimSpace(string(output)) == "true" {
		return
	}
	logs := exec.Command("docker", "logs", "--tail", "100", name)
	logOutput, logsErr := logs.CombinedOutput()
	t.Fatalf(
		"Docker test container is not running: inspect error=%v state=%q logs error=%v logs=%s",
		err, strings.TrimSpace(string(output)), logsErr, strings.TrimSpace(string(logOutput)),
	)
}

func waitForAPISIXTLS(t *testing.T, containerName, endpoint string, security *tls.Config) *http.Response {
	t.Helper()
	client := newAPISIXTLSClient(security, 3*time.Second)
	deadline := time.Now().Add(30 * time.Second)
	for {
		response, err := client.Get(endpoint)
		if err == nil {
			return response
		}
		if time.Now().After(deadline) {
			logs := exec.Command("docker", "logs", "--tail", "100", containerName)
			output, logsErr := logs.CombinedOutput()
			t.Fatalf("APISIX TLS endpoint did not become ready: %v; logs error=%v logs=%s", err, logsErr, strings.TrimSpace(string(output)))
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func waitForAPISIXEnrollmentBootstrap(
	t *testing.T,
	containerName, baseURL, action string,
	security *tls.Config,
) *http.Response {
	t.Helper()
	client := newAPISIXTLSClient(security, 3*time.Second)
	deadline := time.Now().Add(10 * time.Second)
	for {
		request, err := http.NewRequest(
			http.MethodPost,
			baseURL+"/api/paas/v1/node-enrollments/node-enrollment-11111111111111111111111111111111/"+action,
			strings.NewReader(`{"credential":"test-only"}`),
		)
		if err != nil {
			t.Fatal(err)
		}
		for name, value := range map[string]string{
			"Authorization":             "Bearer ambient-authority",
			"Cookie":                    "ambient=cookie",
			"Idempotency-Key":           "ambient-idempotency",
			"If-Match":                  `"ambient-etag"`,
			"Matrix-Subject-Credential": "ambient-subject",
			"X-Matrix-Public-Origin":    "http://ambient.invalid",
			"X-Matrix-Observed-Peer":    "203.0.113.1",
			"X-Matrix-Transport-Scheme": "http",
			"X-Matrix-TLS-Peer":         "203.0.113.2",
		} {
			request.Header.Set(name, value)
		}
		response, requestErr := client.Do(request)
		if requestErr == nil && response.StatusCode == http.StatusNoContent {
			return response
		}
		if response != nil {
			response.Body.Close()
		}
		if time.Now().After(deadline) {
			logs := exec.Command("docker", "logs", "--tail", "100", containerName)
			output, logsErr := logs.CombinedOutput()
			t.Fatalf(
				"APISIX enrollment %s TLS route did not become ready: request error=%v; logs error=%v logs=%s",
				action, requestErr, logsErr, strings.TrimSpace(string(output)),
			)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func assertAPISIXTLSRejected(t *testing.T, endpoint string, security *tls.Config) {
	t.Helper()
	client := newAPISIXTLSClient(security, 5*time.Second)
	response, err := client.Get(endpoint)
	if response != nil {
		response.Body.Close()
	}
	if err == nil {
		t.Fatal("APISIX accepted a rejected enrollment TLS identity or protocol")
	}
}

func newAPISIXTLSClient(security *tls.Config, timeout time.Duration) *http.Client {
	return &http.Client{Transport: &http.Transport{
		Proxy: nil, TLSClientConfig: security, DisableKeepAlives: true,
		TLSHandshakeTimeout: 3 * time.Second, ResponseHeaderTimeout: 3 * time.Second,
	}, Timeout: timeout}
}
