package phase1e2e

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	iamv1 "github.com/xiak/matrix/api/iam/v1"
	managedservicev1 "github.com/xiak/matrix/api/managedservice/v1"
	paasv1 "github.com/xiak/matrix/api/paas/v1"
	"github.com/xiak/matrix/app/service/installation/release"
)

func fixtureTrustPEM(t *testing.T, notBefore, notAfter time.Time) string {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "phase1 mail fixture CA"},
		NotBefore: notBefore, NotAfter: notAfter, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestOfflinePhase1Lifecycle(t *testing.T) {
	if os.Getenv("MATRIX_PHASE1_E2E") != "1" {
		t.Skip("set MATRIX_PHASE1_E2E=1 inside a clean external-network-disabled Linux Docker host")
	}
	var available time.Duration
	if deadline, ok := t.Deadline(); ok {
		available = time.Until(deadline)
	}
	budget, err := lifecycleObservationBudget(os.Getenv("MATRIX_PHASE1_E2E_TIMEOUT"), available)
	if err != nil {
		t.Fatal(safeFailure(err))
	}
	config, err := optionsFromEnvironment()
	if err != nil {
		t.Fatal(safeFailure(err))
	}
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()
	if err := runGate(ctx, config); err != nil {
		t.Fatal(safeFailure(err))
	}
}

// This is a whole-run observation bound, not a product latency promise or a
// replacement for the five-minute recovery bound after a real injected fault.
// A slower acceptance host must opt in explicitly; no phase resets the budget.
// The ceiling covers the gate's five real platform transitions plus its mail,
// managed-product, retained-state, and support assertions while keeping one
// bounded run below two hours; every existing operation-local bound remains.
const maximumLifecycleObservationBudget = 90 * time.Minute

func lifecycleObservationBudget(raw string, available time.Duration) (time.Duration, error) {
	budget := 30 * time.Minute
	if raw != "" {
		var err error
		budget, err = time.ParseDuration(raw)
		if err != nil {
			return 0, fail("lifecycle-observation-budget")
		}
	}
	if budget < time.Minute || budget > maximumLifecycleObservationBudget || available <= budget+time.Minute {
		return 0, fail("lifecycle-observation-budget")
	}
	return budget, nil
}

func TestMXOutputKeepsClosedFailureClassification(t *testing.T) {
	valid := []byte(`{"apiVersion":"cli.matrix.xiak.com/v1","kind":"PlatformCommandResult","action":"ROLLBACK","status":"SUCCEEDED","result":{"state":"READY","releaseId":"release-a","changed":true}}`)
	failure := []byte(`{"apiVersion":"cli.matrix.xiak.com/v1","kind":"PlatformCommandFailure","action":"ROLLBACK","status":"FAILED","error":{"class":"PRECONDITION_FAILED","code":"ROLLBACK_SOURCE_NOT_READY","message":"not diagnostic output"}}`)
	for _, scenario := range []struct {
		name       string
		output     commandOutput
		processErr error
		contextErr error
		want       string
	}{
		{"valid result", commandOutput{stdout: valid}, nil, nil, ""},
		{"start failure", commandOutput{}, errors.New("private executable path"), nil, "mx-rollback-process"},
		{"cancelled ready response", commandOutput{stdout: valid}, nil, context.Canceled, "mx-rollback-cancelled"},
		{"deadline", commandOutput{}, nil, context.DeadlineExceeded, "mx-rollback-deadline"},
		{"output limit", commandOutput{}, errCommandOutputLimit, nil, "mx-rollback-output-limit"},
		{"closed CLI precondition", commandOutput{stderr: failure, exit: 3}, nil, nil, "mx-rollback-source-not-ready"},
		{"unknown exit", commandOutput{stderr: []byte("raw process detail"), exit: 70}, nil, nil, "mx-rollback-exit-unknown"},
		{"unexpected stderr", commandOutput{stdout: valid, stderr: []byte("raw process detail")}, nil, nil, "mx-rollback-unexpected-stderr"},
		{"secret stdout", commandOutput{stdout: []byte("sensitive-test-material")}, nil, nil, "mx-rollback-sensitive-output"},
		{"secret in failed stderr", commandOutput{stderr: bytes.ReplaceAll(failure, []byte("not diagnostic output"), []byte("sensitive-test-material")), exit: 3}, nil, nil, "mx-rollback-sensitive-output"},
		{"malformed JSON", commandOutput{stdout: []byte("{")}, nil, nil, "mx-rollback-json"},
		{"two JSON values", commandOutput{stdout: append(append([]byte(nil), valid...), []byte(" {}")...)}, nil, nil, "mx-rollback-json"},
		{"unknown result field", commandOutput{stdout: bytes.ReplaceAll(valid, []byte(`"changed":true`), []byte(`"changed":true,"unknown":true`))}, nil, nil, "mx-rollback-json"},
		{"API version", commandOutput{stdout: bytes.ReplaceAll(valid, []byte("cli.matrix.xiak.com/v1"), []byte("cli.matrix.xiak.com/unknown"))}, nil, nil, "mx-rollback-api-version"},
		{"kind", commandOutput{stdout: bytes.ReplaceAll(valid, []byte("PlatformCommandResult"), []byte("UnknownResult"))}, nil, nil, "mx-rollback-kind"},
		{"action", commandOutput{stdout: bytes.ReplaceAll(valid, []byte("ROLLBACK"), []byte("UPGRADE"))}, nil, nil, "mx-rollback-action"},
		{"status", commandOutput{stdout: bytes.ReplaceAll(valid, []byte("SUCCEEDED"), []byte("FAILED"))}, nil, nil, "mx-rollback-status"},
		{"state", commandOutput{stdout: bytes.ReplaceAll(valid, []byte("READY"), []byte("NOT_READY"))}, nil, nil, "mx-rollback-state"},
		{"wrong failure action", commandOutput{stderr: bytes.ReplaceAll(failure, []byte("ROLLBACK\""), []byte("UPGRADE\"")), exit: 3}, nil, nil, "mx-rollback-exit-unknown"},
		{"wrong exit for failure", commandOutput{stderr: failure, exit: 5}, nil, nil, "mx-rollback-exit-unknown"},
		{"unknown failure code", commandOutput{stderr: bytes.ReplaceAll(failure, []byte("ROLLBACK_SOURCE_NOT_READY"), []byte("PRIVATE_VALUE")), exit: 3}, nil, nil, "mx-rollback-exit-unknown"},
		{"unknown failure field", commandOutput{stderr: bytes.ReplaceAll(failure, []byte(`"class":`), []byte(`"private":"value","class":`)), exit: 3}, nil, nil, "mx-rollback-exit-unknown"},
		{"failure with stdout", commandOutput{stdout: valid, stderr: failure, exit: 3}, nil, nil, "mx-rollback-exit-unknown"},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			got, err := checkMXOutput("rollback", scenario.output, scenario.processErr, scenario.contextErr, [][]byte{[]byte("sensitive-test-material")})
			if scenario.want == "" {
				if err != nil || got.ReleaseID != "release-a" || !got.Changed {
					t.Fatal("valid signed command result was rejected")
				}
				return
			}
			if err == nil || err.Error() != "phase1 gate failed at "+scenario.want || got != (mxResult{}) {
				t.Fatalf("closed failure classification: got %v, want %s", safeFailure(err), scenario.want)
			}
		})
	}
}

func TestExplicitRollbackKeepsCommandAndReceiptFailuresSeparate(t *testing.T) {
	valid := mxResult{ReleaseID: "release-a", Changed: true}
	for _, scenario := range []struct {
		name   string
		result mxResult
		err    error
		want   string
	}{
		{"valid", valid, nil, ""},
		{"command", mxResult{}, fail("mx-rollback-source-not-ready"), "mx-rollback-source-not-ready"},
		{"unknown command error", mxResult{}, errors.New("private command output"), "internal-acceptance-error"},
		{"release", mxResult{ReleaseID: "release-b", Changed: true}, nil, "platform-rollback-release"},
		{"previous", mxResult{ReleaseID: "release-a", PreviousID: "release-b", Changed: true}, nil, "platform-rollback-previous"},
		{"changed", mxResult{ReleaseID: "release-a"}, nil, "platform-rollback-unchanged"},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			err := checkExplicitRollback(scenario.result, scenario.err, "release-a")
			if scenario.want == "" {
				if err != nil {
					t.Fatal("valid rollback receipt was rejected")
				}
				return
			}
			if err == nil || err.Error() != "phase1 gate failed at "+scenario.want {
				t.Fatalf("closed rollback failure: got %v, want %s", safeFailure(err), scenario.want)
			}
		})
	}
}

func TestLifecycleObservationBudget(t *testing.T) {
	for _, scenario := range []struct {
		name      string
		raw       string
		available time.Duration
		want      time.Duration
	}{
		{"default stays thirty minutes", "", 35 * time.Minute, 30 * time.Minute},
		{"explicit slower-host budget", "50m", 55 * time.Minute, 50 * time.Minute},
		{"explicit cold-host budget", "75m", 80 * time.Minute, 75 * time.Minute},
		{"maximum remains bounded", "90m", 95 * time.Minute, 90 * time.Minute},
		{"reject missing test deadline", "", 0, 0},
		{"reject expired test deadline", "", -time.Second, 0},
		{"reserve teardown time", "30m", 31 * time.Minute, 0},
		{"cannot exceed caller deadline", "50m", 35 * time.Minute, 0},
		{"reject invalid duration", "unlimited", 95 * time.Minute, 0},
		{"reject zero", "0", 95 * time.Minute, 0},
		{"reject negative", "-1m", 95 * time.Minute, 0},
		{"reject subminute", "59s", 95 * time.Minute, 0},
		{"reject above maximum", "91m", 100 * time.Minute, 0},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			got, err := lifecycleObservationBudget(scenario.raw, scenario.available)
			if scenario.want == 0 {
				if err == nil || got != 0 {
					t.Fatal("invalid observation budget reached an effectful gate")
				}
				return
			}
			if err != nil || got != scenario.want {
				t.Fatal("observation budget lost its explicit or default bound")
			}
		})
	}
}

// This is a focused fault diagnostic on an already prepared A installation,
// never a substitute for the fresh-host lifecycle or its restart gate.
func TestOfflinePhase1UpgradeFault(t *testing.T) {
	if os.Getenv("MATRIX_PHASE1_UPGRADE_FAULT") != "1" {
		t.Skip("set MATRIX_PHASE1_UPGRADE_FAULT=1 on a prepared isolated release-A installation")
	}
	config, err := optionsFromEnvironment()
	if err != nil || config.afterStart {
		t.Fatal(fail("focused-upgrade-input"))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	value, err := authenticatedGate(config)
	if err != nil {
		t.Fatal(safeFailure(err))
	}
	defer value.edge.close()
	if err := assertNoExternalRoute(); err != nil {
		t.Fatal(safeFailure(err))
	}
	state, err := assertPlatform(ctx, config.root, value.releases.a.Manifest, "")
	if err != nil {
		t.Fatal(safeFailure(err))
	}
	if err := value.readTenantRetention(state.InstallationID); err != nil {
		t.Fatal(safeFailure(err))
	}
	value.sensitive, err = installedSecretValues(config.root)
	if err != nil {
		t.Fatal(fail("focused-upgrade-secret-inventory"))
	}
	defer func() {
		for _, secret := range value.sensitive {
			clear(secret)
		}
	}()
	if err := value.failedUpgrade(ctx, nil, nil, nil); err != nil {
		t.Fatal(safeFailure(err))
	}
	if _, err := assertPlatform(ctx, config.root, value.releases.a.Manifest, ""); err != nil {
		t.Fatal(safeFailure(err))
	}
	if err := assertNoPlatformReleaseContainers(ctx, value.releases.b.Manifest.Release.ID); err != nil {
		t.Fatal(safeFailure(err))
	}
	if err := value.repeatedStatusAndVerify(ctx, value.releases.a, value.releases.a.Manifest.Release.ID, ""); err != nil {
		t.Fatal(safeFailure(err))
	}
	if err := assertNoExternalRoute(); err != nil {
		t.Fatal(safeFailure(err))
	}
	emit("focused-upgrade-injection-and-automatic-rollback")
}

// This executes one explicit rollback of an authenticated, prepared B
// installation. It does not replace the fresh-host lifecycle, its retained
// business-state assertions, backup recovery, or the separate restart gate.
func TestOfflinePhase1Rollback(t *testing.T) {
	if os.Getenv("MATRIX_PHASE1_ROLLBACK") != "1" {
		t.Skip("set MATRIX_PHASE1_ROLLBACK=1 on a prepared isolated release-B installation")
	}
	config, err := optionsFromEnvironment()
	if err != nil || config.afterStart {
		t.Fatal(fail("focused-rollback-input"))
	}
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Minute)
	defer cancel()
	value, err := authenticatedGate(config)
	if err != nil {
		t.Fatal(safeFailure(err))
	}
	defer value.edge.close()
	if err := assertNoExternalRoute(); err != nil {
		t.Fatal(safeFailure(err))
	}
	state, err := assertPlatform(ctx, config.root, value.releases.b.Manifest, value.releases.a.Manifest.Release.ID)
	if err != nil {
		t.Fatal(safeFailure(err))
	}
	if err := value.readTenantRetention(state.InstallationID); err != nil {
		t.Fatal(safeFailure(err))
	}
	value.sensitive, err = installedSecretValues(config.root)
	if err != nil {
		t.Fatal(fail("focused-rollback-secret-inventory"))
	}
	defer func() {
		for _, secret := range value.sensitive {
			clear(secret)
		}
	}()
	result, commandErr := runMX(ctx, value.releases.b, "rollback", []string{"--root", config.root}, value.pathLeakage())
	if err := checkExplicitRollback(result, commandErr, value.releases.a.Manifest.Release.ID); err != nil {
		t.Fatal(safeFailure(err))
	}
	if _, err := assertPlatform(ctx, config.root, value.releases.a.Manifest, ""); err != nil {
		t.Fatal(safeFailure(err))
	}
	if err := assertNoPlatformReleaseContainers(ctx, value.releases.b.Manifest.Release.ID); err != nil {
		t.Fatal(safeFailure(err))
	}
	if err := value.repeatedStatusAndVerify(ctx, value.releases.a, value.releases.a.Manifest.Release.ID, ""); err != nil {
		t.Fatal(safeFailure(err))
	}
	if err := assertNoExternalRoute(); err != nil {
		t.Fatal(safeFailure(err))
	}
	emit("focused-explicit-platform-rollback")
}

func TestInjectedUpgradeWaitBounds(t *testing.T) {
	t.Run("preparation does not consume the rollback window", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			outer, cancelOuter := context.WithTimeout(t.Context(), 30*time.Minute)
			defer cancelOuter()
			command, cancelCommand := context.WithCancel(outer)
			defer cancelCommand()
			time.Sleep(6 * time.Minute)
			if command.Err() != nil {
				t.Fatal("whole-gate budget expired during preparation")
			}
			waited := make(chan error, 1)
			want := errors.New("observed command failure")
			go func() {
				time.Sleep(2 * time.Minute)
				waited <- want
			}()
			started := time.Now()
			if got := waitInjectedUpgrade(command, cancelCommand, waited); got != want ||
				time.Since(started) != 2*time.Minute || command.Err() != nil {
				t.Fatal("completed fault recovery lost its command result or remaining budget")
			}
		})
	})
	for _, scenario := range []struct {
		name       string
		outerLimit time.Duration
		wantWait   time.Duration
		wantOuter  error
	}{
		{"rollback deadline cancels and joins command", 30 * time.Minute, 5 * time.Minute, nil},
		{"enclosing deadline is never extended", time.Minute, time.Minute, context.DeadlineExceeded},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				outer, cancelOuter := context.WithTimeout(t.Context(), scenario.outerLimit)
				defer cancelOuter()
				command, cancelCommand := context.WithCancel(outer)
				defer cancelCommand()
				waited := make(chan error)
				joined := false
				go func() {
					<-command.Done()
					joined = true
					waited <- command.Err()
				}()
				started := time.Now()
				got := waitInjectedUpgrade(command, cancelCommand, waited)
				if !errors.Is(got, context.DeadlineExceeded) || time.Since(started) != scenario.wantWait ||
					outer.Err() != scenario.wantOuter || command.Err() == nil || !joined {
					t.Fatal("fault recovery escaped its bound or left an unjoined command")
				}
			})
		})
	}
	t.Run("cancelled caller cannot accept a ready result", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			command, cancelCommand := context.WithCancel(t.Context())
			waited := make(chan error, 1)
			waited <- nil
			cancelCommand()
			if !errors.Is(waitInjectedUpgrade(command, cancelCommand, waited), context.Canceled) {
				t.Fatal("cancelled lifecycle accepted a coincident command result")
			}
		})
	})
}

func TestReleasePairAllowsReleaseSpecificWorkloadImages(t *testing.T) {
	a := release.VerifiedBundle{Manifest: release.Manifest{
		Release:  release.ReleaseIdentity{ID: "release-a", Version: "v0.1.0", SourceCommit: "commit"},
		Images:   []release.Image{{Purpose: release.ImageWorkload, SourceDigest: "sha256:a"}},
		Database: release.CurrentDatabaseProfile(),
	}}
	b := release.VerifiedBundle{Manifest: release.Manifest{
		Release: release.ReleaseIdentity{
			ID: "release-b", Version: "v0.2.0", SourceCommit: "commit",
			PreviousID: "release-a", PreviousVersion: "v0.1.0",
		},
		Images:   []release.Image{{Purpose: release.ImageWorkload, SourceDigest: "sha256:b"}},
		Database: release.CurrentDatabaseProfile(),
	}}
	if err := validateReleasePair(a, b); err != nil {
		t.Fatalf("release-specific workload images rejected: %v", err)
	}
	b.Manifest.Database.ContractRevision++
	if validateReleasePair(a, b) == nil {
		t.Fatal("different release contract revision admitted to offline lifecycle gate")
	}
}

func TestSignedReleaseComponentImageRequiresOnePlatformIdentity(t *testing.T) {
	manifest := release.Manifest{Images: []release.Image{
		{Component: "postgres", Purpose: release.ImagePlatform, ImageID: "sha256:" + strings.Repeat("a", 64)},
		{Component: "verification", Purpose: release.ImageWorkload, ImageID: "sha256:" + strings.Repeat("b", 64)},
	}}
	if imageID, ok := signedReleaseComponentImage(manifest, "postgres"); !ok || imageID != manifest.Images[0].ImageID {
		t.Fatal("one signed platform image was not selected")
	}
	if _, ok := signedReleaseComponentImage(manifest, "mysql"); ok {
		t.Fatal("missing signed product image was selected")
	}
	wrongPurpose := manifest
	wrongPurpose.Images = append([]release.Image(nil), manifest.Images...)
	wrongPurpose.Images[0].Purpose = release.ImageWorkload
	if _, ok := signedReleaseComponentImage(wrongPurpose, "postgres"); ok {
		t.Fatal("workload image was selected as a managed product")
	}
	duplicate := manifest
	duplicate.Images = append(append([]release.Image(nil), manifest.Images...), manifest.Images[0])
	if _, ok := signedReleaseComponentImage(duplicate, "postgres"); ok {
		t.Fatal("duplicate signed product image was selected")
	}
}

func TestCreateUserWireCarriesExplicitRootBoundary(t *testing.T) {
	encoded, err := json.Marshal(createUserWire{
		LoginName: "signed.fixture", DisplayName: "Signed fixture",
		InitialPassword: "Example-Only-Signed-Fixture-Password-51!", RequestID: "signed-fixture-create",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer clear(encoded)
	var request iamv1.CreateUserRequest
	if json.Unmarshal(encoded, &request) != nil || iamv1.ValidateCreateUserRequest(request) != nil ||
		request.PermissionBoundary != nil {
		t.Fatal("signed lifecycle user creation did not carry the explicit protected-Root boundary choice")
	}
}

func delegatedAuthorityFixture(t *testing.T) delegatedAuthorityRetention {
	t.Helper()
	now := time.Date(2026, time.October, 3, 1, 2, 3, 0, time.UTC)
	trust := iamv1.TrustPolicyDocument{LanguageVersion: iamv1.TrustPolicyLanguageVersion, Statements: []iamv1.TrustPolicyStatement{{
		SID: "root-source", Effect: iamv1.PolicyAllow,
		Principals: []iamv1.TrustPrincipal{{Type: iamv1.PrincipalUser, ID: "root-user"}},
	}}}
	_, trustDigest, err := iamv1.CanonicalizeTrustPolicyDocument(trust)
	if err != nil {
		t.Fatal(err)
	}
	group := iamv1.Group{APIVersion: iamv1.APIVersion, Kind: "Group", ID: "group-retained", AccountID: "account-retained",
		Name: "Retained group", ResourceVersion: 1, CreatedAt: now, UpdatedAt: now}
	role := iamv1.Role{APIVersion: iamv1.APIVersion, Kind: "Role", ID: "role-retained", AccountID: group.AccountID,
		Name: "Retained role", Tags: []iamv1.RoleTag{}, Management: iamv1.RoleCustomerManaged, Status: iamv1.RoleActive,
		MaxSessionDurationSeconds: iamv1.DefaultRoleSessionDurationSeconds, ResourceVersion: 2,
		CurrentTrustVersionID: "trust-retained", CreatedAt: now, UpdatedAt: now.Add(time.Microsecond)}
	attachment := func(id string, target iamv1.PolicyAttachmentTarget) iamv1.PolicyAttachment {
		return iamv1.PolicyAttachment{APIVersion: iamv1.APIVersion, Kind: "PolicyAttachment", ID: iamv1.PolicyAttachmentID(id),
			AccountID: group.AccountID, Target: target, PolicyID: iamv1.SystemPolicyPaaSDeveloper,
			Scope: iamv1.AuthorityScopeTenant, ResourceVersion: 1, CreatedAt: now, UpdatedAt: now}
	}
	groupTarget := iamv1.PolicyAttachmentTarget{Kind: iamv1.PolicyTargetGroup, ID: string(group.ID)}
	groupAttachment := attachment("attachment-group", groupTarget)
	return delegatedAuthorityRetention{
		Group: group,
		Membership: iamv1.GroupMembership{APIVersion: iamv1.APIVersion, Kind: "GroupMembership", ID: "membership-retained",
			AccountID: group.AccountID, GroupID: group.ID, UserID: "member-user", CreatedBy: "root-user",
			ResourceVersion: 1, CreatedAt: now, UpdatedAt: now},
		GroupAttachment: groupAttachment,
		GroupAttachmentChange: iamv1.PolicyAttachmentChange{
			APIVersion: iamv1.APIVersion, Kind: "PolicyAttachmentChange", Operation: iamv1.PolicyAttachmentChangeCreate,
			AccountID: group.AccountID, ActorPrincipalID: "root-user", RequestID: delegatedGroupAttachmentRequestID,
			CompletedAt: now, Target: &groupTarget, PolicyID: iamv1.SystemPolicyPaaSDeveloper,
			PolicyResourceVersion: 1, Attachment: &groupAttachment,
		},
		Role: role,
		TrustVersion: iamv1.RoleTrustVersion{APIVersion: iamv1.APIVersion, Kind: "RoleTrustVersion", ID: role.CurrentTrustVersionID,
			AccountID: group.AccountID, RoleID: role.ID, Document: trust, ContentDigest: trustDigest, CreatedAt: now},
		RoleAttachment: attachment("attachment-role", iamv1.PolicyAttachmentTarget{Kind: iamv1.PolicyTargetRole, ID: string(role.ID)}),
		RoleBoundary: iamv1.RolePermissionBoundary{APIVersion: iamv1.APIVersion, Kind: "RolePermissionBoundary", AccountID: group.AccountID,
			RoleID: role.ID, ResourceVersion: role.ResourceVersion, Policy: &iamv1.PolicyVersionReference{PolicyID: iamv1.SystemPolicyPaaSViewer,
				VersionID: "version-viewer", ContentDigest: "sha256:" + strings.Repeat("1", 64)}},
		PreRecoverySession: iamv1.RoleSession{APIVersion: iamv1.APIVersion, Kind: "RoleSession", ID: "session-retained",
			AccountID: group.AccountID, RoleID: role.ID, SourceUserID: "root-user", Status: iamv1.SessionActive,
			IssuedAt: now.Add(2 * time.Microsecond), ExpiresAt: now.Add(time.Hour)},
		PreRecoveryCredential: []byte("test-only-role-credential"),
	}
}

func TestDelegatedAuthorityRetentionBindsExactAccountGraph(t *testing.T) {
	if !validDelegatedAuthorityRetention(delegatedAuthorityFixture(t), "account-retained", "member-user", "root-user") {
		t.Fatal("valid delegated authority fixture was rejected")
	}
	for name, mutate := range map[string]func(*delegatedAuthorityRetention){
		"foreign group":          func(value *delegatedAuthorityRetention) { value.Group.AccountID = "account-other" },
		"foreign member":         func(value *delegatedAuthorityRetention) { value.Membership.UserID = "member-other" },
		"different group target": func(value *delegatedAuthorityRetention) { value.GroupAttachment.Target.ID = "group-other" },
		"different group receipt actor": func(value *delegatedAuthorityRetention) {
			value.GroupAttachmentChange.ActorPrincipalID = "root-other"
		},
		"missing group receipt": func(value *delegatedAuthorityRetention) {
			value.GroupAttachmentChange = iamv1.PolicyAttachmentChange{}
		},
		"different role target": func(value *delegatedAuthorityRetention) { value.RoleAttachment.Target.ID = "role-other" },
		"wider boundary": func(value *delegatedAuthorityRetention) {
			value.RoleBoundary.Policy.PolicyID = iamv1.SystemPolicyPaaSDeveloper
		},
		"different trust": func(value *delegatedAuthorityRetention) {
			value.TrustVersion.Document.Statements[0].Principals[0].ID = "root-other"
		},
		"different session source": func(value *delegatedAuthorityRetention) { value.PreRecoverySession.SourceUserID = "root-other" },
		"missing credential":       func(value *delegatedAuthorityRetention) { value.PreRecoveryCredential = nil },
	} {
		t.Run(name, func(t *testing.T) {
			fixture := delegatedAuthorityFixture(t)
			mutate(&fixture)
			if validDelegatedAuthorityRetention(fixture, "account-retained", "member-user", "root-user") {
				t.Fatal("changed delegated authority graph was accepted")
			}
		})
	}
}

func TestRoleSessionReceiptRetainsIssuanceAndClosesAuthorityAfterRecovery(t *testing.T) {
	issued := delegatedAuthorityFixture(t).PreRecoverySession
	observedAt := issued.IssuedAt.Add(30 * time.Minute)
	access := func(session iamv1.RoleSession, lifecycle iamv1.RoleSessionLifecycle, available bool, restriction iamv1.CapabilityRestriction) iamv1.RoleSessionAccess {
		return iamv1.RoleSessionAccess{
			APIVersion: iamv1.APIVersion,
			Kind:       "RoleSessionAccess",
			ObservedAt: observedAt,
			Item: iamv1.RoleSessionListing{
				Session: session,
				Source: iamv1.RoleSessionSourceDisplay{Type: iamv1.PrincipalUser, User: &iamv1.RoleSourceUserDisplay{
					ID: issued.SourceUserID, LoginName: "root", DisplayName: "Root user",
				}},
				Lifecycle: lifecycle,
				RevokeCapability: iamv1.ActionCapability{
					Action: iamv1.ActionIAMRoleSessionRevoke,
					Resource: iamv1.ResourceReference{
						Kind: iamv1.ResourceRoleSession,
						ID:   string(issued.ID),
					},
					Available: available, RestrictionReason: restriction,
				},
			},
		}
	}
	active := access(issued, iamv1.RoleSessionUnrevoked, true, "")
	if !retainedRoleSessionReceipt(active, issued, false) {
		t.Fatal("active role session receipt was not retained before recovery")
	}
	revokedAt := issued.IssuedAt.Add(10 * time.Minute)
	revoked := issued
	revoked.Status, revoked.RevokedAt = iamv1.SessionRevoked, &revokedAt
	terminal := access(revoked, iamv1.RoleSessionRevoked, false, iamv1.CapabilitySessionNotRevocable)
	if !retainedRoleSessionReceipt(terminal, issued, true) {
		t.Fatal("terminal role session receipt lost immutable issuance after recovery")
	}
	for name, mutate := range map[string]func(*iamv1.RoleSessionAccess){
		"active authority": func(value *iamv1.RoleSessionAccess) {
			*value = active
		},
		"different account": func(value *iamv1.RoleSessionAccess) {
			value.Item.Session.AccountID = "account-other"
		},
		"different role": func(value *iamv1.RoleSessionAccess) {
			value.Item.Session.RoleID = "role-other"
		},
		"different source": func(value *iamv1.RoleSessionAccess) {
			value.Item.Session.SourceUserID = "root-other"
			value.Item.Source.User.ID = "root-other"
		},
		"different issuance": func(value *iamv1.RoleSessionAccess) {
			value.Item.Session.IssuedAt = value.Item.Session.IssuedAt.Add(time.Microsecond)
		},
		"wrong terminal restriction": func(value *iamv1.RoleSessionAccess) {
			value.Item.RevokeCapability.RestrictionReason = iamv1.CapabilityAuthorityRequired
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed := terminal
			changed.Item.Source.User = &iamv1.RoleSourceUserDisplay{
				ID: terminal.Item.Source.User.ID, LoginName: terminal.Item.Source.User.LoginName, DisplayName: terminal.Item.Source.User.DisplayName,
			}
			mutate(&changed)
			if retainedRoleSessionReceipt(changed, issued, true) {
				t.Fatal("changed role session receipt was accepted after recovery")
			}
		})
	}
}

func TestNotificationContactRetentionRequiresExactVerifiedState(t *testing.T) {
	verifiedAt := time.Date(2026, time.October, 3, 1, 2, 3, 456000000, time.UTC)
	want := iamv1.NotificationContact{
		APIVersion: iamv1.APIVersion, Kind: "NotificationContact",
		AccountID: "account-retained", UserID: "principal-admin",
		State: "VERIFIED", ResourceVersion: 1, Email: "receiver@matrix.test", VerifiedAt: &verifiedAt,
	}
	if !sameNotificationContact(want, want) {
		t.Fatal("exact verified contact was not retained")
	}
	for name, mutate := range map[string]func(*iamv1.NotificationContact){
		"account":          func(value *iamv1.NotificationContact) { value.AccountID = "account-other" },
		"user":             func(value *iamv1.NotificationContact) { value.UserID = "principal-other" },
		"state":            func(value *iamv1.NotificationContact) { value.State = "NONE" },
		"resource-version": func(value *iamv1.NotificationContact) { value.ResourceVersion++ },
		"address":          func(value *iamv1.NotificationContact) { value.Email = "other@matrix.test" },
		"verification-time": func(value *iamv1.NotificationContact) {
			changed := value.VerifiedAt.Add(time.Microsecond)
			value.VerifiedAt = &changed
		},
		"missing-time": func(value *iamv1.NotificationContact) { value.VerifiedAt = nil },
	} {
		t.Run(name, func(t *testing.T) {
			observed := want
			mutate(&observed)
			if sameNotificationContact(observed, want) {
				t.Fatal("changed notification contact was accepted as retained")
			}
		})
	}
}

func TestAccessAnalyzerLifecycleCoverageStaysClosed(t *testing.T) {
	observedFrom := time.Date(2026, time.October, 3, 1, 2, 3, 0, time.UTC)
	observedThrough := observedFrom.Add(time.Minute)
	coverage := make([]iamv1.AccessObservationCoverage, 0, len(iamv1.AccessObservationCoverageSources()))
	for index, source := range iamv1.AccessObservationCoverageSources() {
		entry := iamv1.AccessObservationCoverage{Source: source}
		if index < 4 {
			entry.State = iamv1.AccessObservationInsufficientCoverage
			entry.Reason = iamv1.AccessObservationWindowIncomplete
			entry.ObservedFrom = &observedFrom
			entry.ObservedThrough = &observedThrough
		} else {
			entry.State = iamv1.AccessObservationNotIncluded
			entry.Reason = iamv1.AccessObservationSourceNotImplemented
		}
		coverage = append(coverage, entry)
	}
	if !accessAnalyzerCoverageIsClosed(coverage, iamv1.AccessObservationWindowIncomplete) ||
		!accessAnalyzerCoverageIsClosed(coverage, "") ||
		accessAnalyzerCoverageIsClosed(coverage, iamv1.AccessObservationRestoreGap) {
		t.Fatal("ordinary incomplete access coverage was not kept distinct")
	}
	for index := 0; index < 4; index++ {
		coverage[index].Reason = iamv1.AccessObservationRestoreGap
	}
	if !accessAnalyzerCoverageIsClosed(coverage, iamv1.AccessObservationRestoreGap) ||
		!accessAnalyzerCoverageIsClosed(coverage, "") ||
		accessAnalyzerCoverageIsClosed(coverage, iamv1.AccessObservationWindowIncomplete) {
		t.Fatal("restored access coverage was not kept distinct")
	}
	coverage[0].State = iamv1.AccessObservationComplete
	coverage[0].Reason = ""
	if accessAnalyzerCoverageIsClosed(coverage, "") {
		t.Fatal("complete access coverage admitted a no-effect lifecycle assertion")
	}
}

func TestSecurityMailFixtureTrustCoversLifecycleWindow(t *testing.T) {
	now := time.Date(2026, time.October, 3, 1, 2, 3, 0, time.UTC)
	through := now.Add(30 * time.Minute)
	valid := fixtureTrustPEM(t, now.Add(-time.Hour), through.Add(time.Hour))
	if !trustedCertificatesCoverWindow(valid, now, through) {
		t.Fatal("valid fixture trust did not cover lifecycle window")
	}
	for name, value := range map[string]string{
		"missing":         "",
		"malformed":       "not a certificate",
		"expired":         fixtureTrustPEM(t, now.Add(-2*time.Hour), now.Add(-time.Hour)),
		"not-yet-valid":   fixtureTrustPEM(t, now.Add(time.Minute), through.Add(time.Hour)),
		"expires-in-gate": fixtureTrustPEM(t, now.Add(-time.Hour), through.Add(-time.Minute)),
	} {
		t.Run(name, func(t *testing.T) {
			if trustedCertificatesCoverWindow(value, now, through) {
				t.Fatal("unsafe fixture trust covered lifecycle window")
			}
		})
	}
	if trustedCertificatesCoverWindow(valid, through, now) {
		t.Fatal("reversed lifecycle window was accepted")
	}
}

func TestSecurityMailFixtureRuntimeResourceBounds(t *testing.T) {
	valid := securityMailFixtureRuntime{NanoCPUs: 1_000_000_000, Memory: 536870912, MemorySwap: 536870912, Pids: 128}
	valid.Ulimits = append(valid.Ulimits, struct {
		Name       string
		Soft, Hard int64
	}{Name: "nofile", Soft: 4096, Hard: 4096})
	if !valid.boundedResources() {
		t.Fatal("explicit mail fixture resource limits were rejected")
	}
	for name, mutate := range map[string]func(*securityMailFixtureRuntime){
		"unbounded-cpu":        func(value *securityMailFixtureRuntime) { value.NanoCPUs = 0 },
		"unbounded-memory":     func(value *securityMailFixtureRuntime) { value.Memory = 0 },
		"unbounded-swap":       func(value *securityMailFixtureRuntime) { value.MemorySwap = -1 },
		"unbounded-pids":       func(value *securityMailFixtureRuntime) { value.Pids = 0 },
		"inherited-nofile":     func(value *securityMailFixtureRuntime) { value.Ulimits = nil },
		"different-limit":      func(value *securityMailFixtureRuntime) { value.Ulimits[0].Name = "nproc" },
		"wrong-soft-limit":     func(value *securityMailFixtureRuntime) { value.Ulimits[0].Soft = 1024 },
		"inherited-hard-limit": func(value *securityMailFixtureRuntime) { value.Ulimits[0].Hard = 1073741816 },
		"duplicate-limit":      func(value *securityMailFixtureRuntime) { value.Ulimits = append(value.Ulimits, value.Ulimits[0]) },
	} {
		t.Run(name, func(t *testing.T) {
			actual := valid
			actual.Ulimits = append(actual.Ulimits[:0:0], actual.Ulimits...)
			mutate(&actual)
			if actual.boundedResources() {
				t.Fatal("drifted mail fixture resource limits were accepted")
			}
		})
	}
}

func TestOptionsRequirePrivateSecurityMailOnlyForEffectfulLifecycle(t *testing.T) {
	root := t.TempDir()
	for name, value := range map[string]string{
		"MATRIX_PHASE1_E2E_PHASE": "run",
		"MATRIX_PHASE1_ROOT":      filepath.Join(root, "installation"),
		"MATRIX_PHASE1_RELEASE_A": filepath.Join(root, "release-a"),
		"MATRIX_PHASE1_RELEASE_B": filepath.Join(root, "release-b"),
		"MATRIX_PHASE1_TRUST_KEY": filepath.Join(root, "release-trust.json"),
	} {
		t.Setenv(name, value)
	}
	if _, err := optionsFromEnvironment(); err == nil {
		t.Fatal("effectful lifecycle admitted without private security-mail configuration")
	}
	securityMail := filepath.Join(root, "security-mail.json")
	t.Setenv("MATRIX_PHASE1_SECURITY_MAIL_CONFIGURATION", securityMail)
	fixture := filepath.Join(root, "postfix-fixture.tar")
	t.Setenv("MATRIX_PHASE1_SECURITY_MAIL_FIXTURE_ARCHIVE", fixture)
	t.Setenv("MATRIX_PHASE1_SECURITY_MAIL_FIXTURE_SHA256", "sha256:"+strings.Repeat("a", 64))
	t.Setenv("MATRIX_PHASE1_SECURITY_MAIL_FIXTURE_IMAGE_ID", "sha256:"+strings.Repeat("b", 64))
	t.Setenv("MATRIX_PHASE1_EDGE", "http://127.0.0.1:49123")
	config, err := optionsFromEnvironment()
	if err != nil || config.securityMail != securityMail || config.securityMailFixture != fixture ||
		config.edge != "http://127.0.0.1:49123" {
		t.Fatalf("effectful lifecycle options = %#v / %v", config, err)
	}
	t.Setenv("MATRIX_PHASE1_ACCESS_KEY_BROWSER", "1")
	if _, err := optionsFromEnvironment(); err == nil {
		t.Fatal("browser AccessKey lifecycle admitted without its private handoff directory")
	}
	t.Setenv("MATRIX_PHASE1_ACCESS_KEY_BROWSER_DIR", "relative-browser-handoff")
	if _, err := optionsFromEnvironment(); err == nil {
		t.Fatal("browser AccessKey lifecycle admitted a relative handoff directory")
	}
	browserDirectory := filepath.Join(root, "browser-handoff")
	t.Setenv("MATRIX_PHASE1_ACCESS_KEY_BROWSER_DIR", browserDirectory)
	config, err = optionsFromEnvironment()
	if err != nil || !config.accessKeyBrowser || config.accessKeyBrowserDir != browserDirectory {
		t.Fatalf("browser AccessKey lifecycle options = %#v / %v", config, err)
	}
	t.Setenv("MATRIX_PHASE1_SECURITY_MAIL_FIXTURE_SHA256", strings.Repeat("a", 64))
	if _, err := optionsFromEnvironment(); err == nil {
		t.Fatal("fixture archive admitted without an exact SHA-256 identity")
	}
	t.Setenv("MATRIX_PHASE1_SECURITY_MAIL_FIXTURE_SHA256", "sha256:"+strings.Repeat("a", 64))
	t.Setenv("MATRIX_PHASE1_EDGE", "http://example.test:49123")
	if _, err := optionsFromEnvironment(); err == nil {
		t.Fatal("non-loopback lifecycle endpoint admitted")
	}
	t.Setenv("MATRIX_PHASE1_EDGE", "http://127.0.0.1:49123")

	t.Setenv("MATRIX_PHASE1_E2E_PHASE", "after-restart")
	t.Setenv("MATRIX_PHASE1_RELEASE_B", "")
	t.Setenv("MATRIX_PHASE1_SECURITY_MAIL_CONFIGURATION", "")
	t.Setenv("MATRIX_PHASE1_SECURITY_MAIL_FIXTURE_ARCHIVE", "")
	t.Setenv("MATRIX_PHASE1_SECURITY_MAIL_FIXTURE_SHA256", "")
	t.Setenv("MATRIX_PHASE1_SECURITY_MAIL_FIXTURE_IMAGE_ID", "")
	if _, err := optionsFromEnvironment(); err == nil {
		t.Fatal("read-only after-restart lifecycle admitted an interactive browser selector")
	}
	t.Setenv("MATRIX_PHASE1_ACCESS_KEY_BROWSER", "")
	t.Setenv("MATRIX_PHASE1_ACCESS_KEY_BROWSER_DIR", "")
	if _, err := optionsFromEnvironment(); err != nil {
		t.Fatalf("read-only after-restart lifecycle requires removed private input: %v", err)
	}
}

func TestEdgeClientChecksSuccessAndProblemMediaTypes(t *testing.T) {
	for _, check := range []struct {
		name, mediaType string
		status          int
		valid           bool
	}{
		{"success", "application/json", http.StatusOK, true},
		{"authentication-denied", "application/problem+json", http.StatusUnauthorized, true},
		{"resource-hidden", "application/problem+json", http.StatusNotFound, true},
		{"invalid-success", "application/problem+json", http.StatusOK, false},
		{"invalid-problem", "application/json", http.StatusForbidden, false},
	} {
		t.Run(check.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
				response.Header().Set("Content-Type", check.mediaType)
				response.WriteHeader(check.status)
				_, _ = response.Write([]byte(`{}`))
			}))
			defer server.Close()
			client := newEdgeClient(server.URL)
			defer client.close()
			_, err := client.json(context.Background(), http.MethodGet, "/", nil, nil, nil, check.status)
			if (err == nil) != check.valid {
				t.Fatalf("response contract accepted=%t, want %t", err == nil, check.valid)
			}
		})
	}
}

func TestAccessKeyBrowserRelayObservesOnlyTheExactTransparentLifecycle(t *testing.T) {
	accountID := iamv1.AccountID("account-browser-relay")
	userID := iamv1.PrincipalID("user-browser-relay")
	keyID := iamv1.AccessKeyID("mak-browser-relay")
	sourceCIDR := "127.0.0.1/32"
	now := time.Date(2026, time.October, 25, 1, 2, 3, 0, time.UTC)
	key := iamv1.AccessKey{
		APIVersion: iamv1.APIVersion, Kind: "AccessKey", ID: keyID, AccountID: accountID, UserID: userID,
		Status: iamv1.AccessKeyEnabled, CredentialState: iamv1.AccessKeyCredentialCurrent,
		NetworkRestrictions: iamv1.AccessKeyNetworkRestrictions{AllowedSourceCIDRs: []string{sourceCIDR}},
		ResourceVersion:     1, CreatedAt: now, UpdatedAt: now,
	}
	secret, err := iamv1.NewSecret("mak1.AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8")
	if err != nil {
		t.Fatal(err)
	}
	created := iamv1.CreateAccessKeyResponse{Outcome: "APPLIED", Key: key, Secret: secret}
	createdDocument, err := iamv1.EncodeCreateAccessKeyResponse(created)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(createdDocument)
	disabledKey := key
	disabledKey.Status = iamv1.AccessKeyDisabled
	disabledKey.ResourceVersion = 2
	disabledKey.UpdatedAt = now.Add(time.Second)
	disabled := iamv1.SetAccessKeyStatusResponse{Outcome: "APPLIED", Key: disabledKey}
	disabledDocument, err := json.Marshal(disabled)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(disabledDocument)

	collection := "/api/iam/v1/users/" + string(userID) + "/access-keys"
	createRequest := iamv1.CreateAccessKeyRequest{UserResourceVersion: 4,
		NetworkRestrictions: iamv1.AccessKeyNetworkRestrictions{AllowedSourceCIDRs: []string{sourceCIDR}},
		RequestID:           "ui-access-key-create-0123456789abcdef0123456789abcdef"}
	disableRequest := iamv1.SetAccessKeyStatusRequest{AccessKeyResourceVersion: 1,
		Status: iamv1.AccessKeyDisabled, RequestID: "ui-access-key-status-fedcba9876543210fedcba9876543210"}
	var requests atomic.Int32
	var upstreamHost atomic.Value
	upstream := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		requests.Add(1)
		wantHost, _ := upstreamHost.Load().(string)
		if wantHost == "" || request.Host != wantHost ||
			request.Header.Get("X-Forwarded-For") != "" || request.Header.Get("Forwarded") != "" ||
			request.Header.Get("X-Matrix-Account-ID") != "" || request.Header.Get("X-Matrix-Principal-ID") != "" {
			t.Errorf("relay changed an authority-bearing request header: host=%q headers=%#v", request.Host, request.Header)
		}
		body, readErr := io.ReadAll(request.Body)
		if readErr != nil {
			t.Error(readErr)
			response.WriteHeader(http.StatusInternalServerError)
			return
		}
		defer clear(body)
		response.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case collection:
			want, _ := json.Marshal(createRequest)
			defer clear(want)
			if !bytes.Equal(body, want) {
				t.Errorf("create body changed across relay: %s", body)
			}
			response.Header().Set("Cache-Control", "no-store")
			response.WriteHeader(http.StatusCreated)
			_, _ = response.Write(createdDocument)
		case collection + "/" + string(keyID) + ":set-status":
			want, _ := json.Marshal(disableRequest)
			defer clear(want)
			if !bytes.Equal(body, want) {
				t.Errorf("disable body changed across relay: %s", body)
			}
			_, _ = response.Write(disabledDocument)
		default:
			response.WriteHeader(http.StatusNotFound)
		}
	}))
	defer upstream.Close()
	upstreamEndpoint, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	upstreamHost.Store(upstreamEndpoint.Host)
	observer := newAccessKeyBrowserObserver(accountID, userID, sourceCIDR)
	defer observer.clear()
	proxy, err := startAccessKeyBrowserProxy(upstream.URL, observer)
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.close()

	request := func(path string, body any, wantStatus int, wantDocument []byte) {
		t.Helper()
		encoded, encodeErr := json.Marshal(body)
		if encodeErr != nil {
			t.Fatal(encodeErr)
		}
		defer clear(encoded)
		httpRequest, requestErr := http.NewRequest(http.MethodPost, proxy.URL()+path, bytes.NewReader(encoded))
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		httpRequest.Header.Set("Authorization", "Bearer browser-relay-session")
		httpRequest.Header.Set("Content-Type", "application/json")
		httpResponse, requestErr := http.DefaultClient.Do(httpRequest)
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		content, readErr := io.ReadAll(httpResponse.Body)
		closeErr := httpResponse.Body.Close()
		defer clear(content)
		if readErr != nil || closeErr != nil || httpResponse.StatusCode != wantStatus || !bytes.Equal(content, wantDocument) {
			t.Fatalf("transparent relay response status=%d body_equal=%t read=%v close=%v",
				httpResponse.StatusCode, bytes.Equal(content, wantDocument), readErr, closeErr)
		}
	}
	request(collection, createRequest, http.StatusCreated, createdDocument)
	select {
	case <-observer.createReady:
	case <-time.After(time.Second):
		t.Fatal("create observation was not published")
	}
	observedCreateRequest, observedCreate, err := observer.takeCreate()
	if err != nil || !reflect.DeepEqual(observedCreateRequest, createRequest) ||
		!reflect.DeepEqual(observedCreate.Key, created.Key) || !observedCreate.Secret.Present() {
		t.Fatalf("create observation = %#v / %#v / %v", observedCreateRequest, observedCreate, err)
	}
	observedCreate.Secret = iamv1.Secret{}
	request(collection+"/"+string(keyID)+":set-status", disableRequest, http.StatusOK, disabledDocument)
	select {
	case <-observer.disableReady:
	case <-time.After(time.Second):
		t.Fatal("disable observation was not published")
	}
	observedDisableRequest, observedDisable, err := observer.takeDisable()
	if err != nil || !reflect.DeepEqual(observedDisableRequest, disableRequest) || !reflect.DeepEqual(observedDisable, disabled) || requests.Load() != 2 {
		t.Fatalf("disable observation = %#v / %#v / requests=%d / %v", observedDisableRequest, observedDisable, requests.Load(), err)
	}
}

func TestAccessKeyBrowserRequestIDMatchesCurrentUIIntentFormat(t *testing.T) {
	for _, sample := range []struct {
		value, prefix string
		valid         bool
	}{
		{"ui-access-key-create-0123456789abcdef0123456789abcdef", "ui-access-key-create-", true},
		{"ui-access-key-status-fedcba9876543210fedcba9876543210", "ui-access-key-status-", true},
		{"ui-access-key-create-0123456789ABCDEF0123456789ABCDEF", "ui-access-key-create-", false},
		{"ui-access-key-create-browser-relay", "ui-access-key-create-", false},
		{"ui-access-key-status-0123456789abcdef", "ui-access-key-status-", false},
	} {
		if got := validAccessKeyBrowserRequestID(sample.value, sample.prefix); got != sample.valid {
			t.Fatalf("validAccessKeyBrowserRequestID(%q, %q)=%t want=%t", sample.value, sample.prefix, got, sample.valid)
		}
	}
}

func TestAccessKeyBrowserRelayPreservesOversizedUnknownRequest(t *testing.T) {
	accountID := iamv1.AccountID("account-browser-oversized")
	userID := iamv1.PrincipalID("user-browser-oversized")
	payload := bytes.Repeat([]byte("x"), int(iamv1.MaxRequestBytes)+37)
	defer clear(payload)
	upstream := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		content, err := io.ReadAll(request.Body)
		if err != nil {
			t.Error(err)
		}
		defer clear(content)
		if !bytes.Equal(content, payload) {
			t.Errorf("oversized request changed across relay: got=%d want=%d", len(content), len(payload))
		}
		response.Header().Set("Content-Type", "application/problem+json")
		response.WriteHeader(http.StatusBadRequest)
		_, _ = response.Write([]byte(`{"type":"about:blank","title":"invalid","status":400}`))
	}))
	defer upstream.Close()
	observer := newAccessKeyBrowserObserver(accountID, userID, "127.0.0.1/32")
	defer observer.clear()
	proxy, err := startAccessKeyBrowserProxy(upstream.URL, observer)
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.close()
	collection := "/api/iam/v1/users/" + string(userID) + "/access-keys"
	request, err := http.NewRequest(http.MethodPost, proxy.URL()+collection, io.NopCloser(bytes.NewReader(payload)))
	if err != nil {
		t.Fatal(err)
	}
	request.ContentLength = -1
	request.Header.Set("Authorization", "Bearer browser-relay-session")
	request.Header.Set("Content-Type", "application/json")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	content, readErr := io.ReadAll(response.Body)
	closeErr := response.Body.Close()
	defer clear(content)
	if readErr != nil || closeErr != nil || response.StatusCode != http.StatusBadRequest {
		t.Fatalf("oversized relay response status=%d read=%v close=%v", response.StatusCode, readErr, closeErr)
	}
	if _, _, err := observer.takeCreate(); err == nil {
		t.Fatal("oversized request was admitted as a browser AccessKey observation")
	}
}

func TestAccessKeyBrowserHandoffRequiresPrivateEmptyMarkers(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	login, created, disabled, err := prepareAccessKeyBrowserHandoff(directory)
	if err != nil {
		t.Fatal(err)
	}
	password := []byte("Browser-Handoff-Password-93!")
	defer clear(password)
	if err := writeAccessKeyBrowserLogin(login, "offline.alpha.primary", password); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(login)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(content)
	expected := append([]byte("offline.alpha.primary\n"), password...)
	expected = append(expected, '\n')
	defer clear(expected)
	if !bytes.Equal(content, expected) {
		t.Fatal("protected browser login handoff changed")
	}
	information, err := os.Stat(login)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && information.Mode().Perm() != 0o600 {
		t.Fatalf("protected browser login mode=%v", information.Mode().Perm())
	}
	ready := make(chan struct{}, 1)
	ready <- struct{}{}
	if err := os.WriteFile(created, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := waitAccessKeyBrowserStage(ctx, ready, created); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(disabled, []byte("not-empty"), 0o600); err != nil {
		t.Fatal(err)
	}
	ready <- struct{}{}
	if err := waitAccessKeyBrowserStage(ctx, ready, disabled); err == nil {
		t.Fatal("non-empty browser marker was accepted")
	}
	removeAccessKeyBrowserHandoff(login, created, disabled)
}

func TestEdgeClientTouchesOnlyThePossessedCurrentSession(t *testing.T) {
	now := time.Date(2026, time.October, 24, 1, 2, 3, 456000000, time.UTC)
	want := iamv1.SessionActivity{
		APIVersion: iamv1.APIVersion, Kind: "SessionActivity",
		SessionID: "session-phase1", AccountID: "account-phase1", UserID: "principal-phase1",
		LastActivityAt: now, IdleExpiresAt: now.Add(30 * time.Minute), AbsoluteExpiresAt: now.Add(8 * time.Hour),
	}
	for _, check := range []struct {
		name              string
		status            int
		responseMediaType string
		noStore           bool
		body              iamv1.SessionActivity
		valid             bool
	}{
		{name: "explicit foreground touch", status: http.StatusOK, responseMediaType: "application/json", noStore: true, body: want, valid: true},
		{name: "revoked session rejected", status: http.StatusUnauthorized, responseMediaType: "application/problem+json"},
		{name: "wrong session rejected", status: http.StatusOK, responseMediaType: "application/json", noStore: true,
			body: func() iamv1.SessionActivity { result := want; result.SessionID = "session-other"; return result }()},
		{name: "wrong account rejected", status: http.StatusOK, responseMediaType: "application/json", noStore: true,
			body: func() iamv1.SessionActivity { result := want; result.AccountID = "account-other"; return result }()},
		{name: "wrong user rejected", status: http.StatusOK, responseMediaType: "application/json", noStore: true,
			body: func() iamv1.SessionActivity { result := want; result.UserID = "principal-other"; return result }()},
		{name: "cacheable activity rejected", status: http.StatusOK, responseMediaType: "application/json", body: want},
		{name: "invalid activity rejected", status: http.StatusOK, responseMediaType: "application/json", noStore: true, body: iamv1.SessionActivity{}},
	} {
		t.Run(check.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				if request.Method != http.MethodPost || request.URL.Path != "/api/iam/v1/auth/sessions/current:touch" ||
					request.Header.Get("Authorization") != "Bearer fixture-bearer" || request.ContentLength != 0 {
					response.Header().Set("Content-Type", "application/problem+json")
					response.WriteHeader(http.StatusBadRequest)
					_, _ = response.Write([]byte(`{}`))
					return
				}
				response.Header().Set("Content-Type", check.responseMediaType)
				if check.noStore {
					response.Header().Set("Cache-Control", "no-store")
				}
				response.WriteHeader(check.status)
				_ = json.NewEncoder(response).Encode(check.body)
			}))
			defer server.Close()
			client := newEdgeClient(server.URL)
			defer client.close()
			got, err := client.touchCurrentSession(
				context.Background(), []byte("fixture-bearer"), want.AccountID, want.UserID, want.SessionID,
			)
			if (err == nil) != check.valid {
				t.Fatalf("session touch accepted=%t, want %t", err == nil, check.valid)
			}
			if check.valid && got != want {
				t.Fatalf("session activity = %#v, want %#v", got, want)
			}
		})
	}
}

func TestEdgeClientReadsCurrentAccessAnalyzerDetail(t *testing.T) {
	now := time.Date(2026, time.October, 23, 1, 2, 3, 456000000, time.UTC)
	analyzer := iamv1.AccessAnalyzer{
		APIVersion: iamv1.APIVersion, Kind: "AccessAnalyzer",
		ID: "analyzer-phase1", AccountID: "account-phase1",
		Type: iamv1.AccessAnalyzerUnusedAccess, Status: iamv1.AccessAnalyzerActive,
		UnusedAccessAgeDays: iamv1.MinUnusedAccessAgeDays,
		Disposition: iamv1.AccessDispositionRule{
			Mode: iamv1.AccessDispositionDisableAccessKeys, FindingDelayDays: iamv1.MinAccessDispositionDelayDays,
		},
		ResourceVersion: 2, CreatedAt: now, UpdatedAt: now,
	}
	resource := iamv1.ResourceReference{Kind: iamv1.ResourceAccessAnalyzer, ID: string(analyzer.ID)}
	detail := iamv1.AccessAnalyzerDetail{
		APIVersion: iamv1.APIVersion, Kind: "AccessAnalyzerDetail", Analyzer: analyzer,
	}
	for _, action := range []iamv1.Action{
		iamv1.ActionIAMAccessAnalyzerUpdate,
		iamv1.ActionIAMAccessAnalyzerSetDisposition,
		iamv1.ActionIAMAccessFindingList,
	} {
		detail.Capabilities = append(detail.Capabilities, iamv1.ActionCapability{
			Action: action, Resource: resource, Available: false,
			RestrictionReason: iamv1.CapabilityAuthorityRequired,
		})
	}

	for _, test := range []struct {
		name string
		body any
		want bool
	}{
		{name: "current detail", body: detail, want: true},
		{name: "superseded flat analyzer", body: analyzer, want: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				if request.Method != http.MethodGet ||
					request.URL.Path != "/api/iam/v1/account/access-analyzers/"+string(analyzer.ID) ||
					request.Header.Get("Authorization") != "Bearer fixture-bearer" {
					response.Header().Set("Content-Type", "application/problem+json")
					response.WriteHeader(http.StatusBadRequest)
					_, _ = response.Write([]byte(`{}`))
					return
				}
				response.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(response).Encode(test.body)
			}))
			defer server.Close()
			client := newEdgeClient(server.URL)
			defer client.close()
			actual, err := client.readAccessAnalyzer(context.Background(), []byte("fixture-bearer"), analyzer.ID)
			if (err == nil) != test.want {
				t.Fatalf("read accepted=%t, want %t: %v", err == nil, test.want, err)
			}
			if test.want && actual != analyzer {
				t.Fatalf("read analyzer = %#v, want %#v", actual, analyzer)
			}
		})
	}
}

func TestEdgeClientReadsCurrentSecurityReportDetail(t *testing.T) {
	observed := time.Date(2026, time.October, 23, 1, 2, 3, 456000000, time.UTC)
	report := iamv1.AccountSecurityReport{
		Metadata: iamv1.AccountSecurityReportMetadata{
			APIVersion: iamv1.APIVersion, Kind: "AccountSecurityReportMetadata",
			ID: "report-phase1", AccountID: "account-phase1",
			FormatVersion: iamv1.SecurityReportFormatVersion,
			ObservedAt:    observed, ExpiresAt: observed.Add(iamv1.SecurityReportRetention),
			UserCount: 1, AccessKeyCount: 0, RowCount: 2,
		},
		AccountSecuritySettingsVersion: 1,
		Coverage:                       iamv1.SecurityReportCoverageContract(),
		Users: []iamv1.SecurityReportUser{{
			ID: "root-phase1", LoginName: "root.phase1", DisplayName: "Root Phase1",
			Status: iamv1.PrincipalActive, Root: true, ResourceVersion: 1,
			CreatedAt: observed.Add(-time.Hour),
			MFA:       iamv1.SecurityReportMFAState{EnrollmentState: "UNKNOWN"},
			LastPasswordLogin: iamv1.SecurityReportTimeObservation{
				State: iamv1.SecurityReportNotObservedInRetainedIAMState,
			},
		}},
		AccessKeys: []iamv1.SecurityReportAccessKey{},
	}
	_, documentDigest, err := iamv1.CanonicalizeAccountSecurityReportDocument(report)
	if err != nil {
		t.Fatal("canonicalize security report fixture", err)
	}
	report.Metadata.DocumentDigest = documentDigest
	csvDocument, csvDigest, err := iamv1.EncodeAccountSecurityReportCSV(report)
	if err != nil {
		t.Fatal("encode security report fixture", err)
	}
	report.Metadata.CSVContentDigest, report.Metadata.CSVBytes = csvDigest, uint32(len(csvDocument))
	resource := iamv1.ResourceReference{Kind: iamv1.ResourceSecurityReport, ID: string(report.Metadata.ID)}
	detail := iamv1.AccountSecurityReportDetail{
		APIVersion: iamv1.APIVersion, Kind: "AccountSecurityReportDetail", Report: report,
		Capabilities: []iamv1.ActionCapability{{
			Action: iamv1.ActionIAMSecurityReportDownload, Resource: resource,
			Available: false, RestrictionReason: iamv1.CapabilityAuthorityRequired,
		}},
	}
	if iamv1.ValidateAccountSecurityReportDetail(detail) != nil {
		t.Fatal("security report detail fixture is invalid")
	}

	for _, test := range []struct {
		name string
		body any
		want bool
	}{
		{name: "current detail", body: detail, want: true},
		{name: "superseded flat report", body: report, want: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				if request.Method != http.MethodGet ||
					request.URL.Path != "/api/iam/v1/account/security-reports/"+string(report.Metadata.ID) ||
					request.Header.Get("Authorization") != "Bearer fixture-bearer" {
					response.Header().Set("Content-Type", "application/problem+json")
					response.WriteHeader(http.StatusBadRequest)
					_, _ = response.Write([]byte(`{}`))
					return
				}
				response.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(response).Encode(test.body)
			}))
			defer server.Close()
			client := newEdgeClient(server.URL)
			defer client.close()
			actual, err := client.readSecurityReport(context.Background(), []byte("fixture-bearer"), report.Metadata.ID)
			if (err == nil) != test.want {
				t.Fatalf("read accepted=%t, want %t: %v", err == nil, test.want, err)
			}
			if test.want && !equalJSON(actual, report) {
				t.Fatal("read security report differs from detail content")
			}
		})
	}
}

func TestSignedManagedProductActivationReusesTheAccountActivation(t *testing.T) {
	service := managedservicev1.ServiceDefinitionReference{
		ID: managedservicev1.PostgreSQLServiceID, Revision: 1,
		ContentDigest: "sha256:" + strings.Repeat("a", 64),
	}
	activation := managedservicev1.ServiceActivation{
		Service: service, ResourceVersion: 1,
		ActivatedAt: time.Date(2026, time.October, 14, 1, 2, 3, 456000000, time.UTC),
	}
	for _, test := range []struct {
		name        string
		existing    bool
		wantCreates int32
	}{
		{name: "reuse existing account activation", existing: true},
		{name: "create absent account activation", wantCreates: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			var reads atomic.Int32
			var creates atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				switch {
				case request.Method == http.MethodGet && request.URL.Path == "/api/managed-services/v1/service-activations/postgresql":
					reads.Add(1)
					if !test.existing {
						response.Header().Set("Content-Type", "application/problem+json")
						response.WriteHeader(http.StatusNotFound)
						_, _ = response.Write([]byte(`{}`))
						return
					}
					response.Header().Set("Content-Type", "application/json")
					_ = json.NewEncoder(response).Encode(activation)
				case request.Method == http.MethodPost && request.URL.Path == "/api/managed-services/v1/service-activations":
					creates.Add(1)
					var body managedservicev1.ActivateServiceRequest
					if request.Header.Get("Idempotency-Key") != "phase1-signed-postgres-service-activation" ||
						json.NewDecoder(request.Body).Decode(&body) != nil || body.Service != service {
						response.Header().Set("Content-Type", "application/problem+json")
						response.WriteHeader(http.StatusBadRequest)
						_, _ = response.Write([]byte(`{}`))
						return
					}
					response.Header().Set("Content-Type", "application/json")
					response.WriteHeader(http.StatusCreated)
					_ = json.NewEncoder(response).Encode(activation)
				default:
					response.Header().Set("Content-Type", "application/problem+json")
					response.WriteHeader(http.StatusNotFound)
					_, _ = response.Write([]byte(`{}`))
				}
			}))
			defer server.Close()

			client := newEdgeClient(server.URL)
			defer client.close()
			value := gate{edge: client}
			if err := value.ensureSignedManagedProductActivation(
				context.Background(), []byte("fixture-bearer"), "/api/managed-services/v1",
				"phase1-signed-postgres", "postgres", service,
			); err != nil {
				t.Fatalf("ensure account service activation: %v", err)
			}
			if reads.Load() != 1 || creates.Load() != test.wantCreates {
				t.Fatalf("activation calls read=%d create=%d", reads.Load(), creates.Load())
			}
		})
	}
}

func TestSignedManagedProductServiceRoleAuthorityIsExplicitlyDelegated(t *testing.T) {
	now := time.Date(2026, time.October, 14, 1, 2, 3, 456000000, time.UTC)
	tenant := tenantRetention{
		Account: iamv1.Account{
			APIVersion: iamv1.APIVersion,
			Kind:       "Account",
			ID:         "account-product",
			RootIdentity: iamv1.RootIdentity{
				PrincipalID: "user-root",
			},
		},
		RetainedPrimaryCredential: []byte("fixture-bearer"),
	}
	target := iamv1.PolicyAttachmentTarget{Kind: iamv1.PolicyTargetUser, ID: "user-root"}
	attachment := iamv1.PolicyAttachment{
		APIVersion:      iamv1.APIVersion,
		Kind:            "PolicyAttachment",
		ID:              "attachment-service-role-administrator",
		AccountID:       tenant.Account.ID,
		Target:          target,
		PolicyID:        iamv1.SystemPolicyServiceRoleAdministrator,
		Scope:           iamv1.AuthorityScopeTenant,
		ResourceVersion: 1,
		CreatedAt:       now,
		UpdatedAt:       now,
	}
	change := iamv1.PolicyAttachmentChange{
		APIVersion:            iamv1.APIVersion,
		Kind:                  "PolicyAttachmentChange",
		Operation:             iamv1.PolicyAttachmentChangeCreate,
		AccountID:             tenant.Account.ID,
		ActorPrincipalID:      tenant.Account.RootIdentity.PrincipalID,
		RequestID:             serviceRoleAdministratorRequestID,
		CompletedAt:           now,
		Target:                &target,
		PolicyID:              attachment.PolicyID,
		PolicyResourceVersion: 1,
		Attachment:            &attachment,
	}
	var sequence atomic.Int32
	var invalid atomic.Bool
	reject := func(response http.ResponseWriter) {
		invalid.Store(true)
		response.Header().Set("Content-Type", "application/problem+json")
		response.WriteHeader(http.StatusBadRequest)
		_, _ = response.Write([]byte(`{}`))
	}
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer fixture-bearer" {
			reject(response)
			return
		}
		switch sequence.Add(1) {
		case 1:
			if request.Method != http.MethodGet || request.URL.Path != "/api/iam/v1/service-role-templates" {
				reject(response)
				return
			}
			response.Header().Set("Content-Type", "application/problem+json")
			response.WriteHeader(http.StatusForbidden)
			_, _ = response.Write([]byte(`{}`))
		case 2:
			var body iamv1.CreatePolicyAttachmentRequest
			if request.Method != http.MethodPost || request.URL.Path != "/api/iam/v1/policy-attachments" ||
				json.NewDecoder(request.Body).Decode(&body) != nil || body.Target != target ||
				body.PolicyID != iamv1.SystemPolicyServiceRoleAdministrator ||
				body.PolicyResourceVersion != 1 || body.RequestID != serviceRoleAdministratorRequestID {
				reject(response)
				return
			}
			response.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(response).Encode(attachment)
		case 3:
			if request.Method != http.MethodGet || request.URL.Path !=
				"/api/iam/v1/policy-attachment-changes/by-request/"+serviceRoleAdministratorRequestID {
				reject(response)
				return
			}
			response.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(response).Encode(change)
		default:
			reject(response)
		}
	}))
	defer server.Close()

	client := newEdgeClient(server.URL)
	defer client.close()
	value := gate{edge: client}
	if err := value.delegateSignedManagedProductServiceRoleAuthority(context.Background(), &tenant); err != nil {
		t.Fatalf("delegate service role authority: %v", err)
	}
	if invalid.Load() || sequence.Load() != 3 {
		t.Fatalf("service role authority requests=%d invalid=%t", sequence.Load(), invalid.Load())
	}
}

func TestRetainedPrimarySessionFixtureRequiresCredentialAndSessionIdentity(t *testing.T) {
	valid := []tenantRetention{
		{RetainedPrimaryCredential: []byte("first-bearer"), RetainedPrimarySessionID: "first-session"},
		{RetainedPrimaryCredential: []byte("second-bearer"), RetainedPrimarySessionID: "second-session"},
	}
	if !validRetainedPrimarySessions(valid) {
		t.Fatal("complete retained primary sessions were rejected")
	}
	for name, mutate := range map[string]func([]tenantRetention){
		"missing tenant":     func(value []tenantRetention) { value[1] = tenantRetention{} },
		"missing credential": func(value []tenantRetention) { value[0].RetainedPrimaryCredential = nil },
		"missing session":    func(value []tenantRetention) { value[0].RetainedPrimarySessionID = "" },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := append([]tenantRetention(nil), valid...)
			mutate(candidate)
			if validRetainedPrimarySessions(candidate) {
				t.Fatal("incomplete retained primary session was accepted")
			}
		})
	}
	if validRetainedPrimarySessions(valid[:1]) {
		t.Fatal("incomplete account set was accepted")
	}
}

func TestPhase1AccessKeySignerBindsExactNorthboundRequest(t *testing.T) {
	createdAt := time.Date(2026, time.October, 7, 1, 2, 3, 456000000, time.UTC)
	material := bytes.Repeat([]byte{0x2a}, 32)
	secret, err := iamv1.NewSecret("mak1." + base64.RawURLEncoding.EncodeToString(material))
	if err != nil {
		t.Fatal(err)
	}
	created := iamv1.CreateAccessKeyResponse{
		Outcome: "APPLIED",
		Key: iamv1.AccessKey{
			APIVersion: iamv1.APIVersion, Kind: "AccessKey", ID: "key-phase1",
			AccountID: "account-phase1", UserID: "user-phase1", Status: iamv1.AccessKeyEnabled,
			CredentialState:     iamv1.AccessKeyCredentialCurrent,
			NetworkRestrictions: iamv1.AccessKeyNetworkRestrictions{AllowedSourceCIDRs: []string{"172.18.0.1/32"}},
			ResourceVersion:     1, CreatedAt: createdAt, UpdatedAt: createdAt,
		},
		Secret: secret,
	}
	header, err := signAccessKeyRequest(created, "installation-phase1", "http://127.0.0.1:8080",
		"/api/paas/v1/applications?after=pc1.opaque")
	if err != nil {
		t.Fatal(err)
	}
	headerBytes := header.CopyBytes()
	defer clear(headerBytes)
	parameters, signature, err := iamv1.ParseAccessKeyAuthorization(string(headerBytes))
	if err != nil || parameters.AccessKeyID != created.Key.ID || parameters.InstallationID != "installation-phase1" ||
		parameters.Audience != iamv1.ProductPaaS || parameters.SignedAt <= 0 {
		t.Fatalf("signed header parameters = %#v / %v", parameters, err)
	}
	httpRequest := iamv1.AccessKeyHTTPRequest{
		Method: http.MethodGet, Scheme: "http", Authority: "127.0.0.1:8080",
		EscapedPath: "/api/paas/v1/applications", RawQuery: "after=pc1.opaque", BodyDigest: fixedDigest(""),
	}
	canonical, err := iamv1.AccessKeySigningBytes(parameters, httpRequest)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(canonical)
	mac := hmac.New(sha256.New, material)
	_, _ = mac.Write(canonical)
	wantSignature := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	gotSignature := signature.CopyBytes()
	defer clear(gotSignature)
	if string(gotSignature) != wantSignature {
		t.Fatal("phase1 signer did not bind the exact external request")
	}
	for name, input := range map[string]struct{ origin, target string }{
		"https topology": {"https://127.0.0.1:8080", "/api/paas/v1/applications"},
		"origin path":    {"http://127.0.0.1:8080/base", "/api/paas/v1/applications"},
		"empty query":    {"http://127.0.0.1:8080", "/api/paas/v1/applications?"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := signAccessKeyRequest(created, "installation-phase1", input.origin, input.target); err == nil {
				t.Fatal("invalid signed fixture input accepted")
			}
		})
	}
	for _, name := range []string{"Authorization", "Forwarded", "X-Forwarded-For", "X-Real-IP",
		"X-Matrix-External-Origin", "X-Matrix-External-Request-Target", "X-Matrix-External-Source-IP",
		"X-Matrix-Edge-Assertion", "X-Matrix-Subject-Credential"} {
		if forgedEdgeHeaders("signed")[name] == "" {
			t.Fatalf("forged edge attack omitted %s", name)
		}
	}
}

func TestRetainedAccessKeyBindsCurrentCredentialAndCustodian(t *testing.T) {
	now := time.Date(2026, time.October, 10, 1, 2, 3, 456000000, time.UTC)
	secret := []byte("mak1." + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x3a}, 32)))
	fixture := accessKeyRetention{
		Key: iamv1.AccessKey{
			APIVersion: iamv1.APIVersion, Kind: "AccessKey", ID: "key-retained",
			AccountID: "account-retained", UserID: "member-user", Status: iamv1.AccessKeyEnabled,
			CredentialState:     iamv1.AccessKeyCredentialCurrent,
			NetworkRestrictions: iamv1.AccessKeyNetworkRestrictions{AllowedSourceCIDRs: []string{"0.0.0.0/0"}},
			ResourceVersion:     3, CreatedAt: now, UpdatedAt: now.Add(time.Microsecond),
		},
		Secret: secret,
		CustodianGrant: iamv1.PolicyAttachment{
			APIVersion: iamv1.APIVersion, Kind: "PolicyAttachment", ID: "attachment-key-custodian",
			AccountID: "account-retained", Target: iamv1.PolicyAttachmentTarget{Kind: iamv1.PolicyTargetUser, ID: "root-user"},
			PolicyID: "policy-key-custodian", Scope: iamv1.AuthorityScopeTenant, ResourceVersion: 1,
			CreatedAt: now, UpdatedAt: now,
		},
	}
	if !validAccessKeyRetention(fixture, "account-retained", "member-user", "root-user") {
		t.Fatal("valid retained access key was rejected")
	}
	if !sameAccessKeyMetadata(fixture.Key, fixture.Key) {
		t.Fatal("identical retained access key metadata differed")
	}
	secretValue, err := iamv1.NewSecret(string(secret))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := signAccessKeyMaterial(fixture.Key, secretValue, "installation-phase1", "http://127.0.0.1:8080",
		"/api/paas/v1/applications"); err != nil {
		t.Fatalf("current retained key could not sign: %v", err)
	}
	for name, mutate := range map[string]func(*accessKeyRetention){
		"foreign account": func(value *accessKeyRetention) { value.Key.AccountID = "account-other" },
		"foreign user":    func(value *accessKeyRetention) { value.Key.UserID = "member-other" },
		"disabled key":    func(value *accessKeyRetention) { value.Key.Status = iamv1.AccessKeyDisabled },
		"missing lineage": func(value *accessKeyRetention) { value.Key.CredentialState = "" },
		"recovery fenced": func(value *accessKeyRetention) { value.Key.CredentialState = iamv1.AccessKeyCredentialRecoveryFenced },
		"different network": func(value *accessKeyRetention) {
			value.Key.NetworkRestrictions.AllowedSourceCIDRs = []string{"192.0.2.0/24"}
		},
		"missing secret":    func(value *accessKeyRetention) { value.Secret = nil },
		"foreign custodian": func(value *accessKeyRetention) { value.CustodianGrant.Target.ID = "root-other" },
		"revoked custodian": func(value *accessKeyRetention) {
			revoked := now.Add(time.Second)
			value.CustodianGrant.RevokedAt = &revoked
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed := fixture
			changed.Secret = append([]byte(nil), fixture.Secret...)
			mutate(&changed)
			if validAccessKeyRetention(changed, "account-retained", "member-user", "root-user") {
				t.Fatal("changed retained access key was accepted")
			}
		})
	}
	for name, mutate := range map[string]func(*iamv1.AccessKey){
		"different id":      func(value *iamv1.AccessKey) { value.ID = "key-other" },
		"different status":  func(value *iamv1.AccessKey) { value.Status = iamv1.AccessKeyDisabled },
		"different network": func(value *iamv1.AccessKey) { value.NetworkRestrictions.AllowedSourceCIDRs = []string{"192.0.2.0/24"} },
		"different version": func(value *iamv1.AccessKey) { value.ResourceVersion++ },
		"different update":  func(value *iamv1.AccessKey) { value.UpdatedAt = value.UpdatedAt.Add(time.Microsecond) },
	} {
		t.Run("metadata "+name, func(t *testing.T) {
			changed := fixture.Key
			changed.NetworkRestrictions.AllowedSourceCIDRs = append([]string(nil), fixture.Key.NetworkRestrictions.AllowedSourceCIDRs...)
			mutate(&changed)
			if sameAccessKeyMetadata(changed, fixture.Key) {
				t.Fatal("changed retained access key metadata was accepted")
			}
		})
	}
}

func TestRetainedAccessKeyDirectoryAllowsSameTenantGrowthOnly(t *testing.T) {
	now := time.Date(2026, time.October, 10, 2, 3, 4, 567000000, time.UTC)
	application := func(id paasv1.ResourceID, tenant paasv1.TenantID) paasv1.Application {
		return paasv1.Application{APIVersion: paasv1.APIVersion, Kind: "Application", Metadata: paasv1.ResourceMetadata{
			ID: id, Name: string(id), Scope: paasv1.ResourceScope{Kind: paasv1.AuthorityTenant, TenantID: tenant},
			ResourceVersion: 1, CreatedAt: now, UpdatedAt: now,
		}}
	}
	directory := paasv1.ApplicationList{APIVersion: paasv1.APIVersion, Kind: "ApplicationList", Items: []paasv1.Application{
		application("phase1-after-upgrade", "account-retained"), application(tenantApplicationID, "account-retained"),
	}}
	if !validRetainedApplicationDirectory(directory, "account-retained") {
		t.Fatal("valid same-tenant directory growth was rejected")
	}
	for name, mutate := range map[string]func(*paasv1.ApplicationList){
		"target missing":  func(value *paasv1.ApplicationList) { value.Items = value.Items[:1] },
		"foreign tenant":  func(value *paasv1.ApplicationList) { value.Items[1].Metadata.Scope.TenantID = "account-other" },
		"incomplete page": func(value *paasv1.ApplicationList) { value.NextAfter = "pc1.more" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := directory
			changed.Items = append([]paasv1.Application(nil), directory.Items...)
			mutate(&changed)
			if validRetainedApplicationDirectory(changed, "account-retained") {
				t.Fatal("invalid retained AccessKey directory was accepted")
			}
		})
	}
}

func optionsFromEnvironment() (options, error) {
	phase := os.Getenv("MATRIX_PHASE1_E2E_PHASE")
	if phase != "run" && phase != "after-restart" {
		return options{}, fail("command-input")
	}
	browserSelector := os.Getenv("MATRIX_PHASE1_ACCESS_KEY_BROWSER")
	browserDirectory := os.Getenv("MATRIX_PHASE1_ACCESS_KEY_BROWSER_DIR")
	if browserSelector != "" && browserSelector != "1" ||
		browserSelector == "" && browserDirectory != "" ||
		browserSelector == "1" && (phase != "run" || browserDirectory == "" ||
			!filepath.IsAbs(browserDirectory) || filepath.Clean(browserDirectory) != browserDirectory) {
		return options{}, fail("command-input")
	}
	edge := os.Getenv("MATRIX_PHASE1_EDGE")
	if edge == "" {
		edge = defaultEdgeEndpoint
	}
	endpoint, err := url.Parse(edge)
	if err != nil || endpoint.Scheme != "http" || endpoint.User != nil || endpoint.Path != "" ||
		endpoint.RawQuery != "" || endpoint.Fragment != "" {
		return options{}, fail("command-input")
	}
	host, port, err := net.SplitHostPort(endpoint.Host)
	portNumber, portErr := strconv.ParseUint(port, 10, 16)
	if err != nil || host != "127.0.0.1" || portErr != nil || portNumber == 0 {
		return options{}, fail("command-input")
	}
	config := options{
		root:                   os.Getenv("MATRIX_PHASE1_ROOT"),
		releaseA:               os.Getenv("MATRIX_PHASE1_RELEASE_A"),
		releaseB:               os.Getenv("MATRIX_PHASE1_RELEASE_B"),
		trustKey:               os.Getenv("MATRIX_PHASE1_TRUST_KEY"),
		securityMail:           os.Getenv("MATRIX_PHASE1_SECURITY_MAIL_CONFIGURATION"),
		securityMailFixture:    os.Getenv("MATRIX_PHASE1_SECURITY_MAIL_FIXTURE_ARCHIVE"),
		securityMailFixtureSHA: os.Getenv("MATRIX_PHASE1_SECURITY_MAIL_FIXTURE_SHA256"),
		securityMailFixtureID:  os.Getenv("MATRIX_PHASE1_SECURITY_MAIL_FIXTURE_IMAGE_ID"),
		edge:                   edge,
		accessKeyBrowser:       browserSelector == "1",
		accessKeyBrowserDir:    browserDirectory,
		afterStart:             phase == "after-restart",
	}
	for _, path := range []string{config.root, config.releaseA, config.trustKey} {
		if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return options{}, fail("command-input")
		}
	}
	if !config.afterStart {
		for _, path := range []string{config.releaseB, config.securityMail, config.securityMailFixture} {
			if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
				return options{}, fail("command-input")
			}
		}
		if !validSHA256(config.securityMailFixtureSHA) || !validSHA256(config.securityMailFixtureID) {
			return options{}, fail("command-input")
		}
	}
	return config, nil
}

func runGate(ctx context.Context, config options) error {
	value, err := authenticatedGate(config)
	if err != nil {
		return err
	}
	if config.afterStart {
		return value.afterRestart(ctx)
	}
	return value.beforeRestart(ctx)
}

func authenticatedGate(config options) (*gate, error) {
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		return nil, fail("unsupported-host")
	}
	trust, err := os.ReadFile(config.trustKey)
	if err != nil {
		return nil, fail("release-authentication")
	}
	defer clear(trust)
	a, err := release.VerifyDirectory(config.releaseA, trust)
	if err != nil {
		return nil, fail("release-a-authentication")
	}
	if config.afterStart {
		return newGate(config, releasePair{a: a}), nil
	}
	b, err := release.VerifyDirectory(config.releaseB, trust)
	if err != nil {
		return nil, fail("release-b-authentication")
	}
	if err := validateReleasePair(a, b); err != nil {
		return nil, err
	}
	return newGate(config, releasePair{a: a, b: b}), nil
}
