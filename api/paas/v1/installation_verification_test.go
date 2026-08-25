package paasv1

import (
	"testing"
	"time"
)

func TestInstallationVerificationContract(t *testing.T) {
	request := VerifyInstallationRequest{
		InstallationID: "mxi-0123456789abcdef0123456789abcdef",
		ReleaseID:      "matrix-v0.1.0-001",
	}
	if err := ValidateVerifyInstallationRequest(request); err != nil {
		t.Fatalf("validate installation verification request: %v", err)
	}
	verification := InstallationVerification{
		APIVersion: APIVersion, Kind: "InstallationVerification",
		InstallationID: request.InstallationID, ReleaseID: request.ReleaseID,
		State: InstallationVerificationReady, DeploymentID: "verification-deployment",
		Generation: 1, OperationID: "operation-verification",
		OperationState: OperationSucceeded, DeploymentPhase: DeploymentReady,
		CheckedAt: time.Unix(1_700_000_000, 0).UTC(),
	}
	if err := ValidateInstallationVerification(verification); err != nil {
		t.Fatalf("validate ready installation verification: %v", err)
	}

	verification.State = InstallationVerificationPending
	if err := ValidateInstallationVerification(verification); err == nil {
		t.Fatal("pending verification must not accept a terminal Operation")
	}
	verification.State = InstallationVerificationFailed
	verification.DeploymentPhase = DeploymentDegraded
	if err := ValidateInstallationVerification(verification); err != nil {
		t.Fatalf("validate degraded installation verification: %v", err)
	}
	request.ReleaseID = ""
	if err := ValidateVerifyInstallationRequest(request); err == nil {
		t.Fatal("verification request must identify the release")
	}
}
