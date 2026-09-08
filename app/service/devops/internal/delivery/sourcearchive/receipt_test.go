package sourcearchive

import (
	"strings"
	"testing"

	devopsv1 "github.com/xiak/matrix/api/devops/v1"
)

func TestValidateReceiptClosesPortableArchiveAuthority(t *testing.T) {
	valid := Receipt{
		TenantID:          "organization-acme",
		RunID:             devopsv1.ResourceID("pipeline-run-" + devopsHex("1", 48)),
		CommandID:         "pipeline-run-" + devopsHex("1", 48) + ":fetch:1",
		InputDigest:       "sha256:" + devopsHex("2", 64),
		HeadCommit:        devopsHex("a", 40),
		TrustedBaseCommit: devopsHex("b", 40),
		MediaType:         MediaType,
		ArchiveDigest:     "sha256:" + devopsHex("5", 64),
		ArchiveBytes:      1,
		ExpandedBytes:     0,
		PathCount:         0,
	}
	if err := ValidateReceipt(valid); err != nil {
		t.Fatalf("valid receipt: %v", err)
	}

	tests := map[string]func(*Receipt){
		"tenant": func(value *Receipt) {
			value.TenantID = devopsv1.TenantID("invalid tenant")
		},
		"run": func(value *Receipt) {
			value.RunID = "run-forged"
		},
		"command": func(value *Receipt) {
			value.CommandID = string(value.RunID) + ":fetch:01"
		},
		"commit": func(value *Receipt) {
			value.HeadCommit = strings.ToUpper(value.HeadCommit)
		},
		"media type": func(value *Receipt) {
			value.MediaType = "application/gzip"
		},
		"archive size": func(value *Receipt) {
			value.ArchiveBytes = MaximumArchiveBytes + 1
		},
		"expanded size": func(value *Receipt) {
			value.ExpandedBytes = MaximumExpandedBytes + 1
		},
		"path count": func(value *Receipt) {
			value.PathCount = MaximumPathCount + 1
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			changed := valid
			mutate(&changed)
			if err := ValidateReceipt(changed); err == nil {
				t.Fatal("invalid source archive receipt was accepted")
			}
		})
	}
}

func devopsHex(value string, length int) string {
	return strings.Repeat(value, length)
}
