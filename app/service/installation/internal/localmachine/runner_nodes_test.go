package localmachine

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/xiak/matrix/app/service/installation/internal/layout"
	"github.com/xiak/matrix/app/service/installation/internal/runnerenrollment"
	"github.com/xiak/matrix/app/service/installation/internal/runnernodecommand"
)

func TestRunnerNodeCreateEnrollAndReplay(t *testing.T) {
	platform := newDevOpsInstallPlan(t)
	if err := stageInstallation(platform, rand.Reader); err != nil {
		t.Fatalf("stage DevOps installation: %v", err)
	}
	effects := NewEffects(nil)
	pins, err := readRunnerAuthorityPins(platform.Root, platform.InstallationID)
	if err != nil {
		t.Fatal(err)
	}
	if runnerenrollment.ValidateAuthorityPins(pins) != nil {
		t.Fatal("runner enrollment authority pins are invalid")
	}
	nodeRoot := filepath.Join(t.TempDir(), "runner-node")
	request, err := effects.CreateRunnerRequest(context.Background(), runnernodecommand.CreateRequestPlan{
		Root: nodeRoot, Bundle: platform.Bundle, InstallationID: platform.InstallationID,
		NodeID: "runner-one", Slots: 4, GatewayOrigin: "https://192.0.2.10:8444",
		AuthorityPins: pins,
	})
	if err != nil {
		t.Fatal(err)
	}
	if runnerenrollment.ValidateRequest(request) != nil || len(request.Slots) != 4 {
		t.Fatal("created runner request is invalid")
	}
	requestBytes, err := runnerenrollment.EncodeRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	storedRequest, err := os.ReadFile(filepath.Join(nodeRoot, runnernodecommand.EnrollmentRequestFilename))
	if err != nil || !bytes.Equal(storedRequest, requestBytes) {
		t.Fatal("runner request was not stored canonically")
	}
	clear(storedRequest)
	clear(requestBytes)

	privateScalars := make(map[string]struct{}, len(request.Slots))
	for _, slot := range request.Slots {
		keyPath := filepath.Join(
			nodeRoot, "secrets", "slots", strconv.Itoa(int(slot.Index)), "client.key",
		)
		key := readRunnerPrivateKey(t, keyPath)
		scalar := key.D.Text(16)
		if _, duplicate := privateScalars[scalar]; duplicate {
			t.Fatal("runner slots share a private key")
		}
		privateScalars[scalar] = struct{}{}
		dataRoot := filepath.Join(nodeRoot, "data", "slots", strconv.Itoa(int(slot.Index)))
		for _, child := range []string{"journal", "workspace"} {
			info, err := os.Lstat(filepath.Join(dataRoot, child))
			if err != nil || !info.IsDir() {
				t.Fatalf("slot %d %s root is absent", slot.Index, child)
			}
		}
	}
	effects.entropy = failingEntropy{}
	replayed, err := effects.CreateRunnerRequest(context.Background(), runnernodecommand.CreateRequestPlan{
		Root: nodeRoot, Bundle: platform.Bundle, InstallationID: platform.InstallationID,
		NodeID: "runner-one", Slots: 4, GatewayOrigin: "https://192.0.2.10:8444",
		AuthorityPins: pins,
	})
	if err != nil {
		t.Fatalf("replay runner request without entropy: %v", err)
	}
	if left, _ := runnerenrollment.RequestDigest(request); left == "" {
		t.Fatal("runner request digest is empty")
	} else if right, _ := runnerenrollment.RequestDigest(replayed); left != right {
		t.Fatal("runner request replay changed its identity")
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(nodeRoot, 0o711); err != nil {
			t.Fatal(err)
		}
		installedReplay, err := readExistingRunnerRequest(nodeRoot)
		if err != nil || !equalRunnerRequests(installedReplay, request) {
			t.Fatalf("installed search-only runner root could not replay: %v", err)
		}
	}

	effects.entropy = rand.Reader
	unpinned := request
	unpinned.AuthorityPins.RunnerCAFingerprint = "sha256:" + strings.Repeat("f", 64)
	_, err = effects.EnrollRunner(context.Background(), runnernodecommand.EnrollPlan{
		Root: platform.Root, InstallationID: platform.InstallationID,
		Bundle: platform.Bundle, Request: unpinned,
		Output: filepath.Join(t.TempDir(), "unpinned-enrollment.json"),
	})
	if !errors.Is(err, runnernodecommand.ErrEffectVerification) {
		t.Fatalf("unpinned runner enrollment error=%v", err)
	}
	output := filepath.Join(t.TempDir(), "runner-enrollment.json")
	signed, err := effects.EnrollRunner(context.Background(), runnernodecommand.EnrollPlan{
		Root: platform.Root, InstallationID: platform.InstallationID,
		Bundle: platform.Bundle, Request: request, Output: output,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := runnerenrollment.ValidateEnrollmentAgainstRequest(signed, request); err != nil {
		t.Fatal(err)
	}
	for index, slot := range signed.Document.Slots {
		keyPath := filepath.Join(
			nodeRoot, "secrets", "slots", strconv.Itoa(int(slot.Index)), "client.key",
		)
		key := readRunnerPrivateKey(t, keyPath)
		block, _ := pem.Decode(slot.Certificate)
		leaf, err := x509.ParseCertificate(block.Bytes)
		if err != nil || !runnerPublicKeysEqual(&key.PublicKey, leaf.PublicKey) ||
			len(leaf.URIs) != 1 || leaf.URIs[0].String() != request.Slots[index].Identity {
			t.Fatalf("slot %d certificate does not bind its node-local key", slot.Index)
		}
	}
	recordPath := filepath.Join(
		platform.Root, filepath.FromSlash(layout.DevOpsRunnerEnrollmentRoot), "runner-one.json",
	)
	record, err := os.ReadFile(recordPath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(record, []byte("PRIVATE KEY")) {
		clear(record)
		t.Fatal("platform enrollment record retained a runner private key")
	}
	clear(record)
	effects.entropy = failingEntropy{}
	secondOutput := filepath.Join(t.TempDir(), "runner-enrollment.json")
	replayedEnrollment, err := effects.EnrollRunner(
		context.Background(), runnernodecommand.EnrollPlan{
			Root: platform.Root, InstallationID: platform.InstallationID,
			Bundle: platform.Bundle, Request: request, Output: secondOutput,
		},
	)
	if err != nil {
		t.Fatalf("replay enrollment without entropy: %v", err)
	}
	firstBytes, _ := runnerenrollment.EncodeSignedEnrollment(signed)
	secondBytes, _ := runnerenrollment.EncodeSignedEnrollment(replayedEnrollment)
	if !bytes.Equal(firstBytes, secondBytes) {
		t.Fatal("runner enrollment replay changed the signed response")
	}
	clear(firstBytes)
	clear(secondBytes)

	changed := request
	changed.GatewayOrigin = "https://192.0.2.11:8444"
	changedOutput := filepath.Join(t.TempDir(), "changed-enrollment.json")
	_, err = effects.EnrollRunner(context.Background(), runnernodecommand.EnrollPlan{
		Root: platform.Root, InstallationID: platform.InstallationID,
		Bundle: platform.Bundle, Request: changed, Output: changedOutput,
	})
	if !errors.Is(err, runnernodecommand.ErrEffectConflict) {
		t.Fatalf("changed use of enrolled node identity error=%v", err)
	}
}

func readRunnerPrivateKey(t *testing.T, path string) *ecdsa.PrivateKey {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(content)
	block, rest := pem.Decode(content)
	if block == nil || block.Type != "PRIVATE KEY" || len(rest) != 0 {
		t.Fatal("runner private key is not canonical PEM")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	key, ok := parsed.(*ecdsa.PrivateKey)
	if err != nil || !ok || key.Curve != elliptic.P256() {
		t.Fatal("runner private key is invalid")
	}
	return key
}

func runnerPublicKeysEqual(left, right any) bool {
	leftBytes, leftErr := x509.MarshalPKIXPublicKey(left)
	rightBytes, rightErr := x509.MarshalPKIXPublicKey(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftBytes, rightBytes)
}
