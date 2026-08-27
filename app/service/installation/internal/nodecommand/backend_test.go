package nodecommand

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	nodev1 "github.com/xiak/matrix/api/adapter/node/v1"
	"github.com/xiak/matrix/app/service/installation/internal/cli"
	"github.com/xiak/matrix/app/service/installation/internal/journal"
	"github.com/xiak/matrix/app/service/installation/internal/layout"
	"github.com/xiak/matrix/app/service/installation/internal/lifecycle"
	"github.com/xiak/matrix/app/service/installation/internal/releasetest"
	"github.com/xiak/matrix/app/service/installation/nodeconfig"
	"github.com/xiak/matrix/app/service/installation/release"
)

func TestNodeInstallResumesUnknownStartupAndPinsEnrollment(t *testing.T) {
	request, input := nodeRequest(t)
	effects := &nodeEffects{failPhase: lifecycle.PhaseStarting, failure: ErrOutcomeUnknown}
	backend, _ := NewBackend(effects)
	_, err := backend.Run(context.Background(), request)
	assertNodeFault(t, err, "EFFECT_OUTCOME_UNKNOWN")
	state := nodeState(t, request.Root)
	if state.Node == nil || state.Active == nil || state.Active.Phase != lifecycle.PhaseStarting || state.CurrentReleaseID != "" {
		t.Fatal("unknown startup was not retained as an uncommitted intent")
	}
	commandID := state.Active.Command.ID
	before := journalBytes(t, request.Root)
	input.Node.ExpectedFingerprint = "sha256:" + strings.Repeat("b", 64)
	writeInput(t, request.Configuration, input)
	_, err = backend.Run(context.Background(), request)
	assertNodeFault(t, err, "NODE_ENROLLMENT_CONFLICT")
	if !bytes.Equal(before, journalBytes(t, request.Root)) {
		t.Fatal("conflicting enrollment changed the sealed journal")
	}
	input.Node.ExpectedFingerprint = "sha256:" + strings.Repeat("a", 64)
	writeInput(t, request.Configuration, input)
	result, err := backend.Run(context.Background(), request)
	if err != nil || result.State != "READY" || !result.Changed || result.CorrelationID != commandID {
		t.Fatalf("resume node: %#v / %v", result, err)
	}
	state = nodeState(t, request.Root)
	if state.CurrentReleaseID != result.ReleaseID || state.Active != nil || state.Last.Outcome != lifecycle.OutcomeSucceeded {
		t.Fatal("node release was not committed")
	}
	for _, phase := range effects.phases {
		if phase == lifecycle.PhaseMigrating || phase == lifecycle.PhaseLoadingImages || phase == lifecycle.PhaseBackingUp {
			t.Fatal("node ran platform effects")
		}
	}
	before = journalBytes(t, request.Root)
	effects.ready = false
	result, err = backend.Run(context.Background(), request)
	if err != nil || result.Changed || result.State != "NOT_READY" || !bytes.Equal(before, journalBytes(t, request.Root)) {
		t.Fatal("install replay fabricated readiness or changed state")
	}
	result, err = backend.Run(context.Background(), cli.Request{Action: lifecycle.ActionStart, Root: request.Root})
	if err != nil || result.State != "READY" || nodeState(t, request.Root).PreviousRelease != "" {
		t.Fatalf("restart sealed node: %v", err)
	}
}

func TestNodeRejectsInvalidInputAndPlatformRootsBeforeEffects(t *testing.T) {
	for _, mode := range []string{"platform release", "invalid credential", "platform root"} {
		t.Run(mode, func(t *testing.T) {
			request, _ := nodeRequest(t)
			effects := &nodeEffects{}
			if mode == "platform release" {
				fixture, err := releasetest.Write(t.TempDir())
				if err != nil {
					t.Fatal(err)
				}
				request.Bundle, request.TrustKey = fixture.Root, fixture.TrustPath
			}
			if mode == "invalid credential" {
				effects.invalid = true
			}
			var before []byte
			if mode == "platform root" {
				_, trust, err := release.ReadTrustRootFile(request.TrustKey)
				if err != nil {
					t.Fatal(err)
				}
				session, err := journal.Acquire(context.Background(), request.Root)
				if err != nil {
					t.Fatal(err)
				}
				state, err := lifecycle.New("mxi-"+strings.Repeat("a", 32), lifecycle.ReleaseTrust{KeyID: trust.KeyID, Fingerprint: trust.PublicKeyFingerprint})
				if err != nil || session.Initialize(state) != nil || session.Close() != nil {
					t.Fatal("initialize platform fixture")
				}
				before = journalBytes(t, request.Root)
			}
			backend, _ := NewBackend(effects)
			if _, err := backend.Run(context.Background(), request); err == nil || len(effects.phases) != 0 || effects.rollbacks != 0 {
				t.Fatal("invalid node install reached effects")
			}
			if mode == "platform root" {
				if !bytes.Equal(before, journalBytes(t, request.Root)) {
					t.Fatal("node command changed a platform root")
				}
			} else if _, err := os.Lstat(request.Root); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("invalid enrollment created a root")
			}
		})
	}
}

func TestNodeStoredCredentialSubstitutionAndUnsupportedActionsFailClosed(t *testing.T) {
	request, _ := nodeRequest(t)
	effects := &nodeEffects{}
	backend, _ := NewBackend(effects)
	if _, err := backend.Run(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	before := journalBytes(t, request.Root)
	keyPath := filepath.Join(request.Root, filepath.FromSlash(layout.NodePrivateKey))
	if err := os.WriteFile(keyPath, []byte("substituted-key"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, action := range []lifecycle.Action{lifecycle.ActionStart, lifecycle.ActionStatus, lifecycle.ActionVerify,
		lifecycle.ActionUpgrade, lifecycle.ActionRecover, lifecycle.ActionBackup, lifecycle.ActionRollback} {
		calls := len(effects.phases)
		if _, err := backend.Run(context.Background(), cli.Request{Action: action, Root: request.Root}); err == nil {
			t.Fatalf("action %s accepted substituted material", action)
		}
		if calls != len(effects.phases) || !bytes.Equal(before, journalBytes(t, request.Root)) {
			t.Fatal("rejected node action changed state or provider")
		}
	}
}

func TestNodeFailedVerificationRollsBackOnlySupervisionAndCanRetry(t *testing.T) {
	request, _ := nodeRequest(t)
	effects := &nodeEffects{failPhase: lifecycle.PhaseVerifying, failure: ErrVerification}
	backend, _ := NewBackend(effects)
	if _, err := backend.Run(context.Background(), request); err == nil {
		t.Fatal("failed node verification was committed")
	}
	state := nodeState(t, request.Root)
	if state.CurrentReleaseID != "" || state.Active != nil || state.Last.Outcome != lifecycle.OutcomeRolledBack || effects.rollbacks != 1 {
		t.Fatal("node failure lost its rollback intent or committed the release")
	}
	keyPath := filepath.Join(request.Root, filepath.FromSlash(layout.NodePrivateKey))
	key, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal("node rollback removed enrollment credentials")
	}
	result, err := backend.Run(context.Background(), request)
	if err != nil || result.State != "READY" {
		t.Fatalf("node retry: %v", err)
	}
	retained, err := os.ReadFile(keyPath)
	if err != nil || !bytes.Equal(retained, key) {
		t.Fatal("node retry rotated credentials")
	}
}

type nodeEffects struct {
	invalid   bool
	ready     bool
	failPhase lifecycle.Phase
	failure   error
	phases    []lifecycle.Phase
	rollbacks int
}

func (effects *nodeEffects) ValidateEnrollment(Plan) error {
	if effects.invalid {
		return ErrVerification
	}
	return nil
}
func (effects *nodeEffects) ApplyPhase(_ context.Context, plan Plan, phase lifecycle.Phase) error {
	effects.phases = append(effects.phases, phase)
	if phase == effects.failPhase && effects.failure != nil {
		err := effects.failure
		effects.failure = nil
		return err
	}
	switch phase {
	case lifecycle.PhaseStaging:
		if err := os.MkdirAll(filepath.Join(plan.Root, "releases"), 0o700); err != nil {
			return err
		}
		_, err := release.StageDirectory(plan.Bundle, plan.TrustBytes, filepath.Join(plan.Root, "releases", plan.Bundle.Manifest.Release.ID))
		return err
	case lifecycle.PhaseConfiguring:
		encoded, _ := json.Marshal(plan.Configuration)
		for relative, source := range map[string][]byte{layout.ReleaseTrust: plan.TrustBytes, layout.NodeConfiguration: encoded,
			layout.NodeCertificate: plan.Credentials.Certificate, layout.NodePrivateKey: plan.Credentials.PrivateKey, layout.NodeTrust: plan.Credentials.Trust,
			layout.CollectorCertificate: plan.Credentials.CollectorCertificate, layout.CollectorPrivateKey: plan.Credentials.CollectorPrivateKey} {
			path := filepath.Join(plan.Root, filepath.FromSlash(relative))
			if os.MkdirAll(filepath.Dir(path), 0o700) != nil || os.WriteFile(path, source, 0o600) != nil {
				return ErrUnavailable
			}
		}
	case lifecycle.PhaseStarting:
		effects.ready = true
	}
	return nil
}
func (effects *nodeEffects) Rollback(context.Context, Plan) error {
	effects.rollbacks++
	effects.ready = false
	return nil
}
func (effects *nodeEffects) Observe(context.Context, Plan) (bool, error) { return effects.ready, nil }
func (effects *nodeEffects) ReadInstallation(root string) (nodeconfig.Configuration, Credentials, error) {
	source, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(layout.NodeConfiguration)))
	if err != nil {
		return nodeconfig.Configuration{}, Credentials{}, err
	}
	config, err := nodeconfig.DecodeConfiguration(source)
	if err != nil {
		return nodeconfig.Configuration{}, Credentials{}, err
	}
	var material Credentials
	for relative, target := range map[string]*[]byte{layout.NodeCertificate: &material.Certificate, layout.NodePrivateKey: &material.PrivateKey,
		layout.NodeTrust: &material.Trust, layout.CollectorCertificate: &material.CollectorCertificate, layout.CollectorPrivateKey: &material.CollectorPrivateKey} {
		*target, err = os.ReadFile(filepath.Join(root, filepath.FromSlash(relative)))
		if err != nil {
			material.Clear()
			return nodeconfig.Configuration{}, Credentials{}, err
		}
	}
	return config, material, nil
}

func nodeRequest(t *testing.T) (cli.Request, nodeconfig.Enrollment) {
	t.Helper()
	fixture, err := releasetest.WriteNode(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	base := t.TempDir()
	root := filepath.Join(base, "node")
	files := []string{"node.pem", "node-key.pem", "trust.pem", "collector.pem", "collector-key.pem"}
	for _, file := range files {
		if os.WriteFile(filepath.Join(base, file), []byte("test-only:"+file), 0o600) != nil {
			t.Fatal("write enrollment fixture")
		}
	}
	input := nodeconfig.Enrollment{APIVersion: nodeconfig.APIVersion, Kind: nodeconfig.EnrollmentKind,
		Node: nodeconfig.Configuration{APIVersion: nodeconfig.APIVersion, Kind: nodeconfig.ConfigurationKind,
			Identity:     nodev1.Identity{InstallationID: "mxi-" + strings.Repeat("a", 32), ExecutionTargetID: "target-a"},
			ControllerID: "controller-a", BindingRef: "binding-a", ExpectedFingerprint: "sha256:" + strings.Repeat("a", 64),
			ListenAddress: "127.0.0.1:16443", CollectorEndpoint: "https://127.0.0.1:19100", StoragePath: filepath.Join(root, "runtime", "executor"),
			CertificateFile: filepath.Join(base, files[0]), PrivateKeyFile: filepath.Join(base, files[1]), TrustFile: filepath.Join(base, files[2])},
		CollectorCertificateFile: filepath.Join(base, files[3]), CollectorPrivateKeyFile: filepath.Join(base, files[4])}
	path := filepath.Join(base, "enrollment.json")
	writeInput(t, path, input)
	return cli.Request{Action: lifecycle.ActionInstall, Subject: cli.SubjectNode, Root: root, Bundle: fixture.Root, TrustKey: fixture.TrustPath, Configuration: path}, input
}

func writeInput(t *testing.T, path string, value nodeconfig.Enrollment) {
	t.Helper()
	source, err := json.Marshal(value)
	if err != nil || os.WriteFile(path, source, 0o600) != nil {
		t.Fatal("write node input")
	}
}
func nodeState(t *testing.T, root string) lifecycle.Journal {
	t.Helper()
	session, err := journal.AcquireExisting(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	state, err := session.Read()
	if err != nil {
		t.Fatal(err)
	}
	return state
}
func journalBytes(t *testing.T, root string) []byte {
	t.Helper()
	source, err := os.ReadFile(filepath.Join(root, "state", "journal.json"))
	if err != nil {
		t.Fatal(err)
	}
	return source
}
func assertNodeFault(t *testing.T, err error, code string) {
	t.Helper()
	var value *cli.Fault
	if !errors.As(err, &value) || value.Code != code {
		t.Fatalf("node fault = %v, want %s", err, code)
	}
}
