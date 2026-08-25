package auditv1

import (
	"testing"
	"time"
)

func TestInstallationVerificationContract(t *testing.T) {
	request := VerifyInstallationRequest{
		InstallationID: "mxi-0123456789abcdef0123456789abcdef",
		OperationID:    "operation-verification",
		DeploymentID:   "deployment-verification",
	}
	if err := ValidateVerifyInstallationRequest(request); err != nil {
		t.Fatalf("validate installation Audit request: %v", err)
	}
	verification := InstallationVerification{
		APIVersion: APIVersion, Kind: "InstallationVerification",
		InstallationID: request.InstallationID,
		OperationID:    request.OperationID, DeploymentID: request.DeploymentID,
		State:   InstallationVerificationVerified,
		EventID: "event-verification", IAMDecisionID: "decision-verification",
		RecordSequence: 7, FromSequence: 1, ToSequence: 7,
		RecordHash: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		CheckedAt:  time.Unix(1_700_000_000, 0).UTC(),
	}
	if err := ValidateInstallationVerification(verification); err != nil {
		t.Fatalf("validate installation Audit result: %v", err)
	}
	verification.ToSequence++
	if err := ValidateInstallationVerification(verification); err == nil {
		t.Fatal("verified installation Audit range must end at the exact record")
	}
	verification.ToSequence = verification.RecordSequence
	verification.State = InstallationVerificationPending
	if err := ValidateInstallationVerification(verification); err == nil {
		t.Fatal("pending verification must not retain an Audit record claim")
	}
	verification.EventID = ""
	verification.IAMDecisionID = ""
	verification.RecordSequence = 0
	verification.FromSequence = 0
	verification.ToSequence = 0
	verification.RecordHash = ""
	if err := ValidateInstallationVerification(verification); err != nil {
		t.Fatalf("validate pending installation Audit result: %v", err)
	}
}
