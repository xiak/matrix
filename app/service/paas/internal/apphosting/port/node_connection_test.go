package port

import (
	"strings"
	"testing"

	paasv1 "github.com/xiak/matrix/api/paas/v1"
)

func TestEnrolledNodeConnectionAdmitsOnlyCanonicalPrivateHTTPSRoutes(t *testing.T) {
	valid := EnrolledNodeConnection{
		InstallationID:      "installation-a",
		ExecutionTargetID:   paasv1.ResourceID("execution-target-a"),
		ControllerID:        "controller-a",
		BindingRef:          "node-binding-" + strings.Repeat("a", 32),
		Endpoint:            "https://192.168.50.10:16443",
		IdentityFingerprint: "sha256:" + strings.Repeat("b", 64),
		Enabled:             true,
	}
	if err := ValidateEnrolledNodeConnection(valid); err != nil {
		t.Fatalf("validate canonical private route: %v", err)
	}
	disabled := valid
	disabled.Enabled = false
	if err := ValidateEnrolledNodeConnection(disabled); err != nil {
		t.Fatalf("validate disabled retained route: %v", err)
	}
	for name, endpoint := range map[string]string{
		"plaintext":         "http://192.168.50.10:16443",
		"public address":    "https://203.0.113.10:16443",
		"DNS name":          "https://node.internal:16443",
		"path":              "https://192.168.50.10:16443/ready",
		"low port":          "https://192.168.50.10:443",
		"noncanonical port": "https://192.168.50.10:016443",
		"IPv4-mapped IPv6":  "https://[::ffff:192.168.50.10]:16443",
	} {
		t.Run(name, func(t *testing.T) {
			candidate := valid
			candidate.Endpoint = endpoint
			if ValidateEnrolledNodeConnection(candidate) == nil {
				t.Fatal("noncanonical or nonprivate route was admitted")
			}
		})
	}
}
