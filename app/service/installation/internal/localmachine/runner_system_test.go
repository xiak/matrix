package localmachine

import (
	"bytes"
	"strings"
	"testing"
)

func TestRunnerServiceProfileIsExactAndCredentialIsPrivate(t *testing.T) {
	plan := validRunnerSystemTestPlan(1)
	content, err := renderRunnerService(plan, plan.Slots[0], runnerSystemAccount{
		Index: 1, Name: "matrix-devops-1", UID: 2001, GID: 3001,
	})
	if err != nil {
		t.Fatal(err)
	}
	want := `# Managed by Matrix DevOps runner installer; do not edit.
[Unit]
Description=Matrix DevOps runner slot 1
Wants=network-online.target
Requires=docker.service matrix-devops-runner-firewall.service
After=network-online.target docker.service matrix-devops-runner-firewall.service

[Service]
Type=simple
User=matrix-devops-1
Group=matrix-devops-1
SupplementaryGroups=docker
ExecStart=/var/lib/matrix-devops/runner-one/installed/runner/linux-amd64/bin/matrix-devops-runner
LoadCredential=client.key:/var/lib/matrix-devops/runner-one/secrets/slots/1/client.key
LoadCredential=client.crt:/var/lib/matrix-devops/runner-one/installed/pki/slots/1/client.crt
LoadCredential=server-ca.pem:/var/lib/matrix-devops/runner-one/installed/pki/server-ca.pem
Environment=MATRIX_DEVOPS_RUNNER_JOURNAL_ROOT=/var/lib/matrix-devops/runner-one/data/slots/1/journal
Environment=MATRIX_DEVOPS_RUNNER_WORKSPACE_ROOT=/var/lib/matrix-devops/runner-one/data/slots/1/workspace
Environment=MATRIX_DEVOPS_RUNNER_STORAGE_ROOT=/var/lib/matrix-devops/runner-one/data/slots/1
Environment=MATRIX_DEVOPS_RUNNER_DOCKER_SOCKET=/var/run/docker.sock
Environment=MATRIX_DEVOPS_RUNNER_LISTEN_ADDRESS=127.0.0.1:18081
Environment=MATRIX_DEVOPS_RUNNER_GATEWAY_ORIGIN=https://192.0.2.10:8444
Environment=MATRIX_DEVOPS_RUNNER_GATEWAY_SERVER_NAME=devops-executor-gateway
Environment=MATRIX_DEVOPS_RUNNER_CLIENT_CERT_FILE=%d/client.crt
Environment=MATRIX_DEVOPS_RUNNER_CLIENT_KEY_FILE=%d/client.key
Environment=MATRIX_DEVOPS_RUNNER_SERVER_CA_FILE=%d/server-ca.pem
Environment=MATRIX_DEVOPS_RUNNER_CLIENT_IDENTITY=spiffe://matrix.xiak.com/installations/11111111111111111111111111111111/devops/runners/nodes/runner-one/slots/1
Environment=MATRIX_DEVOPS_RUNNER_NAMESPACE=spiffe://matrix.xiak.com/installations/11111111111111111111111111111111/devops/runners
Environment=ALL_PROXY=
Environment=HTTP_PROXY=
Environment=HTTPS_PROXY=
Environment=NO_PROXY=
Environment=all_proxy=
Environment=http_proxy=
Environment=https_proxy=
Environment=no_proxy=
Environment=LANG=C
Environment=LC_ALL=C
Environment=PATH=/usr/bin:/bin
Environment=TZ=UTC
NoNewPrivileges=yes
PrivateTmp=yes
PrivateDevices=yes
PrivateMounts=yes
ProtectSystem=strict
ProtectHome=yes
ProtectClock=yes
ProtectHostname=yes
ProtectControlGroups=yes
ProtectKernelLogs=yes
ProtectKernelModules=yes
ProtectKernelTunables=yes
ProtectProc=invisible
ProcSubset=pid
LockPersonality=yes
MemoryDenyWriteExecute=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
RestrictNamespaces=yes
RemoveIPC=yes
KeyringMode=private
SystemCallArchitectures=native
CapabilityBoundingSet=
AmbientCapabilities=
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
ReadWritePaths=/var/lib/matrix-devops/runner-one/data/slots/1
UMask=0077
Restart=no
TimeoutStopSec=30s

[Install]
WantedBy=multi-user.target
`
	if !bytes.Equal(content, []byte(want)) {
		t.Fatalf("runner service changed:\n%s", content)
	}
	if bytes.Contains(content, []byte("/run/credentials/")) {
		t.Fatal("runner service hard-coded a systemd credential directory")
	}
}

func TestRunnerFirewallProfileIsUIDBoundAndFailClosed(t *testing.T) {
	plan := validRunnerSystemTestPlan(2)
	content, err := renderRunnerFirewall(plan, []runnerSystemAccount{
		{Index: 1, Name: "matrix-devops-1", UID: 2001, GID: 3001},
		{Index: 2, Name: "matrix-devops-2", UID: 2002, GID: 3002},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := `# Managed by Matrix DevOps runner installer; do not edit.
destroy table inet matrix_devops_runner
table inet matrix_devops_runner {
  chain output {
    type filter hook output priority filter; policy accept;
    meta skuid 2001 ip daddr 192.0.2.10 tcp dport 8444 accept
    meta skuid 2001 oifname "lo" ip daddr 127.0.0.1 tcp sport 18081 ct state established accept
    meta skuid 2001 reject with icmpx type admin-prohibited
    meta skuid 2002 ip daddr 192.0.2.10 tcp dport 8444 accept
    meta skuid 2002 oifname "lo" ip daddr 127.0.0.1 tcp sport 18082 ct state established accept
    meta skuid 2002 reject with icmpx type admin-prohibited
  }
}
`
	if !bytes.Equal(content, []byte(want)) {
		t.Fatalf("runner firewall changed:\n%s", content)
	}
	duplicate := []runnerSystemAccount{
		{Index: 1, Name: "matrix-devops-1", UID: 2001, GID: 3001},
		{Index: 2, Name: "matrix-devops-2", UID: 2001, GID: 3002},
	}
	if _, err := renderRunnerFirewall(plan, duplicate); err == nil {
		t.Fatal("shared runner account identity was accepted")
	}
}

func TestRunnerDockerAndFirewallUnitProfilesAreExact(t *testing.T) {
	wantDefault := "{\"runtimes\":{\"runsc\":{\"path\":\"/var/lib/matrix-devops/runner-one/installed/gvisor/runsc\"}}}\n"
	wantClassic := "{\"features\":{\"containerd-snapshotter\":false},\"runtimes\":{\"runsc\":{\"path\":\"/var/lib/matrix-devops/runner-one/installed/gvisor/runsc\"}}}\n"
	for _, test := range []struct {
		classic bool
		want    string
	}{{want: wantDefault}, {classic: true, want: wantClassic}} {
		content, err := renderRunnerDockerConfig(
			"/var/lib/matrix-devops/runner-one/installed/gvisor/runsc", test.classic,
		)
		if err != nil || !bytes.Equal(content, []byte(test.want)) {
			t.Fatalf("classic=%t content=%s err=%v", test.classic, content, err)
		}
	}
	if !isRunnerClassicDockerBase([]byte("{\"features\":{\"containerd-snapshotter\":false}}\n")) ||
		isRunnerClassicDockerBase([]byte("{\"features\": {\"containerd-snapshotter\":false}}\n")) {
		t.Fatal("classic Docker base recognition is not byte-exact")
	}
	unit, err := renderRunnerFirewallService(
		"/usr/sbin/nft", "/etc/matrix-devops/runner-egress.nft",
	)
	if err != nil {
		t.Fatal(err)
	}
	wantUnit := `# Managed by Matrix DevOps runner installer; do not edit.
[Unit]
Description=Matrix DevOps runner egress firewall
Before=matrix-devops-runner-slot-1.service matrix-devops-runner-slot-2.service matrix-devops-runner-slot-3.service matrix-devops-runner-slot-4.service

[Service]
Type=oneshot
ExecStart=/usr/sbin/nft --file /etc/matrix-devops/runner-egress.nft
ExecReload=/usr/sbin/nft --file /etc/matrix-devops/runner-egress.nft
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
`
	if !bytes.Equal(unit, []byte(wantUnit)) {
		t.Fatalf("runner firewall unit changed:\n%s", unit)
	}
}

func TestRunnerSystemPlanRejectsPathIdentityAndGatewayDrift(t *testing.T) {
	valid := validRunnerSystemTestPlan(2)
	mutations := []func(*runnerSystemPlan){
		func(plan *runnerSystemPlan) { plan.NodeID = "runner-one\nEnvironment=ESCAPE" },
		func(plan *runnerSystemPlan) { plan.GatewayAddress = "192.0.2.11" },
		func(plan *runnerSystemPlan) { plan.RunnerNamespace = "spiffe://foreign" },
		func(plan *runnerSystemPlan) { plan.RunnerBinary = "/usr/bin/matrix-devops-runner" },
		func(plan *runnerSystemPlan) { plan.Slots[1].StorageRoot = plan.Slots[0].StorageRoot },
		func(plan *runnerSystemPlan) { plan.Slots[0].ClientKey = "/etc/shadow" },
	}
	for index, mutate := range mutations {
		plan := valid
		plan.Slots = append([]runnerSystemSlot(nil), valid.Slots...)
		mutate(&plan)
		if err := validateRunnerSystemPlan(plan); err == nil {
			t.Fatalf("unsafe runner system mutation %d was accepted", index)
		}
	}
	if _, err := renderRunnerService(valid, valid.Slots[0], runnerSystemAccount{
		Index: 1, Name: "matrix-devops-1\nRootDirectory=/", UID: 2001, GID: 3001,
	}); err == nil {
		t.Fatal("unsafe account name reached systemd rendering")
	}
	if _, err := renderRunnerDockerConfig("/opt/runsc\nroot", false); err == nil {
		t.Fatal("unsafe Docker runtime path was accepted")
	}
}

func validRunnerSystemTestPlan(slots int) runnerSystemPlan {
	const (
		root           = "/var/lib/matrix-devops/runner-one"
		installationID = "mxi-11111111111111111111111111111111"
		namespace      = "spiffe://matrix.xiak.com/installations/11111111111111111111111111111111/devops/runners"
	)
	plan := runnerSystemPlan{
		Root: root, ReleaseID: "matrix-v0.1.0-aaaaaaaaaaaa", InstallationID: installationID,
		NodeID: "runner-one", GatewayOrigin: "https://192.0.2.10:8444",
		GatewayAddress: "192.0.2.10", GatewayServerName: "devops-executor-gateway",
		RunnerNamespace:  namespace,
		RunnerBinary:     root + "/installed/runner/linux-amd64/bin/matrix-devops-runner",
		RunscBinary:      root + "/installed/gvisor/runsc",
		ToolchainArchive: root + "/installed/runner/linux-amd64/images/go-1.26-offline-v1.tar",
		ServerCA:         root + "/installed/pki/server-ca.pem",
		Slots:            make([]runnerSystemSlot, slots),
	}
	for index := range plan.Slots {
		slot := index + 1
		base := root + "/data/slots/" + string(rune('0'+slot))
		plan.Slots[index] = runnerSystemSlot{
			Index: uint8(slot), Identity: namespace + "/nodes/runner-one/slots/" + string(rune('0'+slot)),
			Listen:      "127.0.0.1:1808" + string(rune('0'+slot)),
			ClientKey:   root + "/secrets/slots/" + string(rune('0'+slot)) + "/client.key",
			ClientCert:  root + "/installed/pki/slots/" + string(rune('0'+slot)) + "/client.crt",
			StorageRoot: base, JournalRoot: base + "/journal", WorkspaceRoot: base + "/workspace",
		}
	}
	if validateRunnerSystemPlan(plan) != nil || strings.Contains(plan.RunnerBinary, "\\") {
		panic("static runner system test plan is invalid")
	}
	return plan
}
