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

func TestInstallationVerificationDeploymentIdentityIsStableAndBounded(t *testing.T) {
	identity, err := InstallationVerificationDeploymentID(
		"mxi-0123456789abcdef0123456789abcdef",
	)
	if err != nil {
		t.Fatalf("derive installation verification Deployment identity: %v", err)
	}
	const expected = "installation-verification-deploy-e49f9e8e2231b7e1e92bf1fe"
	if identity != expected {
		t.Fatalf("installation verification Deployment identity = %q, want %q", identity, expected)
	}
	if _, err := InstallationVerificationDeploymentID(""); err == nil {
		t.Fatal("empty installation identity was accepted")
	}
}
