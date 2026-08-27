package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xiak/matrix/app/service/paas/internal/apphosting/usecase/executionadmission"
)

func TestNodeConnectionsAreProtectedClosedInstallationInput(t *testing.T) {
	bindings, closeBindings, err := loadNodeBindings("", "installation-a")
	if err != nil || len(bindings) != 0 {
		t.Fatalf("empty optional node inventory = %v", err)
	}
	closeBindings()
	for _, document := range []string{
		`{"installationId":"other-installation","controllerId":"controller-a","certificateFile":"private-path","nodes":[]}`,
		`{"installationId":"installation-a","controllerId":"controller-a","nodes":[],"endpoint":"https://caller:443"}`,
		`{"installationId":"installation-a","installationId":"installation-b","nodes":[]}`,
		`{"installationId":"installation-a","nodes":[{"bindingRef":"binding-a","targetId":"node-a","endpoint":"https://node:443","identityFingerprint":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}],"certificateFile":"private-path"}`,
	} {
		path := filepath.Join(t.TempDir(), "nodes.json")
		if err := os.WriteFile(path, []byte(document), 0o600); err != nil {
			t.Fatal(err)
		}
		_, closeBindings, err := loadNodeBindings(path, "installation-a")
		closeBindings()
		if err == nil || strings.Contains(err.Error(), "private-path") || strings.Contains(err.Error(), "https://") {
			t.Fatalf("bad node input exposed details or was accepted: %v", err)
		}
	}
	oversized := nodeConnections{InstallationID: "installation-a", ControllerID: "controller-a", Nodes: make([]nodeConnection, executionadmission.MaximumTargets+1)}
	document, err := json.Marshal(oversized)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "nodes.json")
	if err := os.WriteFile(path, document, 0o600); err != nil {
		t.Fatal(err)
	}
	_, closeBindings, err = loadNodeBindings(path, "installation-a")
	closeBindings()
	if err == nil {
		t.Fatal("unbounded node inventory accepted")
	}
}
