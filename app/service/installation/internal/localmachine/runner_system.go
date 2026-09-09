package localmachine

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"path"
	"regexp"
	"strconv"
	"strings"

	"github.com/xiak/matrix/app/service/installation/internal/lifecycle"
	"github.com/xiak/matrix/app/service/installation/internal/runnerenrollment"
	"github.com/xiak/matrix/app/service/installation/release"
	"github.com/xiak/matrix/app/service/installation/topology"
)

const (
	runnerDockerSocket  = "/var/run/docker.sock"
	runnerReadyPortBase = 18080
	runnerFirewallTable = "matrix_devops_runner"
	runnerFirewallUnit  = "matrix-devops-runner-firewall.service"
	runnerManagedHeader = "# Managed by Matrix DevOps runner installer; do not edit.\n"
)

var (
	runnerUnixPathPattern  = regexp.MustCompile(`^/[A-Za-z0-9._/-]+$`)
	runnerReleaseIDPattern = regexp.MustCompile(`^matrix-v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z][0-9A-Za-z.-]{0,63})?-[0-9a-f]{12}$`)
)

type runnerNodeSystem interface {
	Preflight(context.Context, runnerSystemPlan) error
	Converge(context.Context, runnerSystemPlan) error
}

type runnerSystemPlan struct {
	Root              string
	ReleaseID         string
	InstallationID    string
	NodeID            string
	GatewayOrigin     string
	GatewayAddress    string
	GatewayServerName string
	RunnerNamespace   string
	RunnerBinary      string
	RunscBinary       string
	ToolchainArchive  string
	ServerCA          string
	Slots             []runnerSystemSlot
}

type runnerSystemSlot struct {
	Index         uint8
	Identity      string
	Listen        string
	ClientKey     string
	ClientCert    string
	StorageRoot   string
	JournalRoot   string
	WorkspaceRoot string
}

type runnerSystemAccount struct {
	Index uint8
	Name  string
	UID   uint32
	GID   uint32
}

func newRunnerSystemPlan(
	root string,
	request runnerenrollment.Request,
) (runnerSystemPlan, error) {
	origin, err := url.Parse(request.GatewayOrigin)
	if err != nil {
		return runnerSystemPlan{}, err
	}
	address := net.ParseIP(origin.Hostname())
	if address == nil || address.String() != origin.Hostname() {
		return runnerSystemPlan{}, runnernodeInputError()
	}
	installed := path.Join(root, runnerInstalledDirectory)
	plan := runnerSystemPlan{
		Root: root, ReleaseID: request.ReleaseID, InstallationID: request.InstallationID,
		NodeID: request.NodeID, GatewayOrigin: request.GatewayOrigin,
		GatewayAddress: address.String(), GatewayServerName: topology.DevOpsExecutorGatewayServerName,
		RunnerNamespace:  request.RunnerNamespace,
		RunnerBinary:     path.Join(installed, release.RunnerBinaryPath),
		RunscBinary:      path.Join(installed, "gvisor", "runsc"),
		ToolchainArchive: path.Join(installed, release.RunnerToolchainArchivePath),
		ServerCA:         path.Join(installed, "pki", "server-ca.pem"),
		Slots:            make([]runnerSystemSlot, len(request.Slots)),
	}
	for index, slot := range request.Slots {
		slotName := strconv.Itoa(int(slot.Index))
		storage := path.Join(root, "data", "slots", slotName)
		plan.Slots[index] = runnerSystemSlot{
			Index: slot.Index, Identity: slot.Identity,
			Listen:      net.JoinHostPort("127.0.0.1", strconv.Itoa(runnerReadyPortBase+int(slot.Index))),
			ClientKey:   path.Join(root, "secrets", "slots", slotName, "client.key"),
			ClientCert:  path.Join(installed, "pki", "slots", slotName, "client.crt"),
			StorageRoot: storage, JournalRoot: path.Join(storage, "journal"),
			WorkspaceRoot: path.Join(storage, "workspace"),
		}
	}
	return plan, nil
}

func validateRunnerSystemPlan(plan runnerSystemPlan) error {
	if !validRunnerUnixPath(plan.Root) || !runnerReleaseIDPattern.MatchString(plan.ReleaseID) ||
		lifecycle.ValidateInstallationID(plan.InstallationID) != nil ||
		runnerenrollment.ValidateNodeID(plan.NodeID) != nil ||
		runnerenrollment.ValidateGatewayOrigin(plan.GatewayOrigin) != nil ||
		plan.GatewayServerName != topology.DevOpsExecutorGatewayServerName ||
		plan.RunnerNamespace != topology.DevOpsRunnerNamespace(plan.InstallationID) ||
		len(plan.Slots) == 0 || len(plan.Slots) > int(release.RunnerMaximumSlots) {
		return errors.New("runner system plan identity is invalid")
	}
	address := net.ParseIP(plan.GatewayAddress)
	origin, _ := url.Parse(plan.GatewayOrigin)
	if address == nil || address.String() != plan.GatewayAddress ||
		origin == nil || origin.Hostname() != plan.GatewayAddress {
		return errors.New("runner system gateway is invalid")
	}
	installed := path.Join(plan.Root, runnerInstalledDirectory)
	wantMaterials := []string{
		path.Join(installed, release.RunnerBinaryPath),
		path.Join(installed, "gvisor", "runsc"),
		path.Join(installed, release.RunnerToolchainArchivePath),
		path.Join(installed, "pki", "server-ca.pem"),
	}
	gotMaterials := []string{
		plan.RunnerBinary, plan.RunscBinary, plan.ToolchainArchive, plan.ServerCA,
	}
	for index, candidate := range gotMaterials {
		if candidate != wantMaterials[index] || !validRunnerUnixPath(candidate) ||
			!strictPathDescendant(plan.Root, candidate) {
			return errors.New("runner system material path is invalid")
		}
	}
	for index, slot := range plan.Slots {
		expected := uint8(index + 1)
		slotName := strconv.Itoa(int(expected))
		storage := path.Join(plan.Root, "data", "slots", slotName)
		if slot.Index != expected || slot.Identity != runnerenrollment.SlotIdentity(
			plan.InstallationID, plan.NodeID, expected,
		) || slot.Listen != net.JoinHostPort(
			"127.0.0.1", strconv.Itoa(runnerReadyPortBase+int(expected)),
		) || slot.ClientKey != path.Join(plan.Root, "secrets", "slots", slotName, "client.key") ||
			slot.ClientCert != path.Join(installed, "pki", "slots", slotName, "client.crt") ||
			slot.StorageRoot != storage || slot.JournalRoot != path.Join(storage, "journal") ||
			slot.WorkspaceRoot != path.Join(storage, "workspace") {
			return errors.New("runner system slot identity is invalid")
		}
		for _, path := range []string{
			slot.ClientKey, slot.ClientCert, slot.StorageRoot, slot.JournalRoot, slot.WorkspaceRoot,
		} {
			if !validRunnerUnixPath(path) || !strictPathDescendant(plan.Root, path) {
				return errors.New("runner system slot path is invalid")
			}
		}
		if !strictPathDescendant(slot.StorageRoot, slot.JournalRoot) ||
			!strictPathDescendant(slot.StorageRoot, slot.WorkspaceRoot) ||
			slot.JournalRoot == slot.WorkspaceRoot {
			return errors.New("runner system slot storage is invalid")
		}
	}
	return nil
}

func validRunnerUnixPath(value string) bool {
	return value != "/" && len(value) <= 4096 && runnerUnixPathPattern.MatchString(value) &&
		path.IsAbs(value) && path.Clean(value) == value && !strings.Contains(value, "//")
}

func strictPathDescendant(root, candidate string) bool {
	return validRunnerUnixPath(root) && validRunnerUnixPath(candidate) &&
		strings.HasPrefix(candidate, root+"/")
}

func runnernodeInputError() error {
	return errors.New("runner node system plan is invalid")
}

func runnerSlotUnit(index uint8) string {
	return "matrix-devops-runner-slot-" + strconv.Itoa(int(index)) + ".service"
}

func runnerAccountName(index uint8) string {
	return "matrix-devops-" + strconv.Itoa(int(index))
}

func renderRunnerService(
	plan runnerSystemPlan,
	slot runnerSystemSlot,
	account runnerSystemAccount,
) ([]byte, error) {
	if validateRunnerSystemPlan(plan) != nil || slot.Index != account.Index ||
		account.Name != runnerAccountName(slot.Index) || account.UID == 0 || account.GID == 0 {
		return nil, errors.New("runner service profile is invalid")
	}
	values := [][2]string{
		{"MATRIX_DEVOPS_RUNNER_JOURNAL_ROOT", slot.JournalRoot},
		{"MATRIX_DEVOPS_RUNNER_WORKSPACE_ROOT", slot.WorkspaceRoot},
		{"MATRIX_DEVOPS_RUNNER_STORAGE_ROOT", slot.StorageRoot},
		{"MATRIX_DEVOPS_RUNNER_DOCKER_SOCKET", runnerDockerSocket},
		{"MATRIX_DEVOPS_RUNNER_LISTEN_ADDRESS", slot.Listen},
		{"MATRIX_DEVOPS_RUNNER_GATEWAY_ORIGIN", plan.GatewayOrigin},
		{"MATRIX_DEVOPS_RUNNER_GATEWAY_SERVER_NAME", plan.GatewayServerName},
		{"MATRIX_DEVOPS_RUNNER_CLIENT_IDENTITY", slot.Identity},
		{"MATRIX_DEVOPS_RUNNER_NAMESPACE", plan.RunnerNamespace},
		{"ALL_PROXY", ""}, {"HTTP_PROXY", ""}, {"HTTPS_PROXY", ""}, {"NO_PROXY", ""},
		{"all_proxy", ""}, {"http_proxy", ""}, {"https_proxy", ""}, {"no_proxy", ""},
		{"LANG", "C"}, {"LC_ALL", "C"}, {"PATH", "/usr/bin:/bin"}, {"TZ", "UTC"},
	}
	var output strings.Builder
	output.WriteString(runnerManagedHeader)
	fmt.Fprintf(&output, "[Unit]\nDescription=Matrix DevOps runner slot %d\n", slot.Index)
	output.WriteString("Wants=network-online.target\n")
	output.WriteString("Requires=docker.service " + runnerFirewallUnit + "\n")
	output.WriteString("After=network-online.target docker.service " + runnerFirewallUnit + "\n\n")
	output.WriteString("[Service]\nType=simple\n")
	output.WriteString("User=" + account.Name + "\nGroup=" + account.Name + "\nSupplementaryGroups=docker\n")
	output.WriteString("ExecStart=" + plan.RunnerBinary + "\n")
	output.WriteString("LoadCredential=client.key:" + slot.ClientKey + "\n")
	output.WriteString("LoadCredential=client.crt:" + slot.ClientCert + "\n")
	output.WriteString("LoadCredential=server-ca.pem:" + plan.ServerCA + "\n")
	for _, value := range values {
		output.WriteString("Environment=" + value[0] + "=" + value[1] + "\n")
	}
	output.WriteString("NoNewPrivileges=yes\nPrivateTmp=yes\nPrivateDevices=yes\nPrivateMounts=yes\n")
	output.WriteString("ProtectSystem=strict\nProtectHome=yes\nProtectClock=yes\nProtectHostname=yes\n")
	output.WriteString("ProtectControlGroups=yes\nProtectKernelLogs=yes\nProtectKernelModules=yes\nProtectKernelTunables=yes\n")
	output.WriteString("ProtectProc=invisible\nProcSubset=pid\nLockPersonality=yes\nMemoryDenyWriteExecute=yes\n")
	output.WriteString("RestrictRealtime=yes\nRestrictSUIDSGID=yes\nRestrictNamespaces=yes\nRemoveIPC=yes\n")
	output.WriteString("KeyringMode=private\nSystemCallArchitectures=native\n")
	output.WriteString("CapabilityBoundingSet=\nAmbientCapabilities=\nRestrictAddressFamilies=AF_UNIX AF_INET AF_INET6\n")
	output.WriteString("ReadWritePaths=" + slot.StorageRoot + "\n")
	output.WriteString("UMask=0077\nRestart=no\nTimeoutStopSec=30s\n\n[Install]\nWantedBy=multi-user.target\n")
	return []byte(output.String()), nil
}

func renderRunnerFirewall(
	plan runnerSystemPlan,
	accounts []runnerSystemAccount,
) ([]byte, error) {
	if validateRunnerSystemPlan(plan) != nil || len(accounts) != len(plan.Slots) {
		return nil, errors.New("runner firewall profile is invalid")
	}
	family := "ip"
	if net.ParseIP(plan.GatewayAddress).To4() == nil {
		family = "ip6"
	}
	var output strings.Builder
	output.WriteString(runnerManagedHeader)
	output.WriteString("destroy table inet " + runnerFirewallTable + "\n")
	output.WriteString("table inet " + runnerFirewallTable + " {\n  chain output {\n")
	output.WriteString("    type filter hook output priority filter; policy accept;\n")
	seenUIDs := make(map[uint32]struct{}, len(accounts))
	seenGIDs := make(map[uint32]struct{}, len(accounts))
	for index, account := range accounts {
		slot := plan.Slots[index]
		if account.Index != slot.Index || account.Name != runnerAccountName(slot.Index) ||
			account.UID == 0 || account.GID == 0 {
			return nil, errors.New("runner firewall account is invalid")
		}
		if _, found := seenUIDs[account.UID]; found {
			return nil, errors.New("runner firewall account is duplicated")
		}
		if _, found := seenGIDs[account.GID]; found {
			return nil, errors.New("runner firewall group is duplicated")
		}
		seenUIDs[account.UID] = struct{}{}
		seenGIDs[account.GID] = struct{}{}
		fmt.Fprintf(
			&output, "    meta skuid %d %s daddr %s tcp dport 8444 accept\n",
			account.UID, family, plan.GatewayAddress,
		)
		fmt.Fprintf(
			&output, "    meta skuid %d oifname \"lo\" ip daddr 127.0.0.1 tcp sport %d ct state established accept\n",
			account.UID, runnerReadyPortBase+int(slot.Index),
		)
		fmt.Fprintf(&output, "    meta skuid %d reject with icmpx type admin-prohibited\n", account.UID)
	}
	output.WriteString("  }\n}\n")
	return []byte(output.String()), nil
}

func renderRunnerFirewallService(nftPath, rulesPath string) ([]byte, error) {
	if !validRunnerUnixPath(nftPath) || !validRunnerUnixPath(rulesPath) {
		return nil, errors.New("runner firewall service path is invalid")
	}
	return []byte(runnerManagedHeader + "[Unit]\nDescription=Matrix DevOps runner egress firewall\n" +
		"Before=matrix-devops-runner-slot-1.service matrix-devops-runner-slot-2.service " +
		"matrix-devops-runner-slot-3.service matrix-devops-runner-slot-4.service\n\n" +
		"[Service]\nType=oneshot\nExecStart=" + nftPath + " --file " + rulesPath + "\n" +
		"ExecReload=" + nftPath + " --file " + rulesPath + "\nRemainAfterExit=yes\n\n" +
		"[Install]\nWantedBy=multi-user.target\n"), nil
}

type runnerDockerDaemonConfig struct {
	Features *runnerDockerFeatures          `json:"features,omitempty"`
	Runtimes map[string]runnerDockerRuntime `json:"runtimes"`
}

type runnerDockerFeatures struct {
	ContainerdSnapshotter bool `json:"containerd-snapshotter"`
}

type runnerDockerRuntime struct {
	Path string `json:"path"`
}

func renderRunnerDockerConfig(runscPath string, classic bool) ([]byte, error) {
	if !validRunnerUnixPath(runscPath) {
		return nil, errors.New("runner Docker runtime path is invalid")
	}
	config := runnerDockerDaemonConfig{
		Runtimes: map[string]runnerDockerRuntime{"runsc": {Path: runscPath}},
	}
	if classic {
		config.Features = &runnerDockerFeatures{ContainerdSnapshotter: false}
	}
	content, err := json.Marshal(config)
	if err != nil {
		return nil, err
	}
	return append(content, '\n'), nil
}

func isRunnerClassicDockerBase(content []byte) bool {
	return bytes.Equal(content, []byte("{\"features\":{\"containerd-snapshotter\":false}}\n"))
}
