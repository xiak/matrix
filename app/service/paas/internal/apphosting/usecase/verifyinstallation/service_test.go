package verifyinstallation

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	paasv1 "github.com/xiak/matrix/api/paas/v1"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/port"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/usecase/applicationlifecycle"
)

const (
	testInstallationID = "mxi-0123456789abcdef0123456789abcdef"
	testReleaseID      = "matrix-v0.1.0-001"
	testArtifactDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)

var testVerificationTime = time.Date(2026, 8, 26, 3, 4, 5, 678_000, time.UTC)

func TestServiceCreatesOnlyFixedNoSecretProbeAndReturnsReady(t *testing.T) {
	iam := &verificationIAM{}
	applications := &verificationApplications{operationState: paasv1.OperationSucceeded}
	service := newVerificationService(t, iam, applications)

	verification, err := service.VerifyInstallation(context.Background(), verificationCommand())
	if err != nil {
		t.Fatalf("verify installation: %v", err)
	}
	if verification.State != paasv1.InstallationVerificationReady ||
		verification.ReleaseID != testReleaseID ||
		verification.OperationState != paasv1.OperationSucceeded ||
		verification.DeploymentPhase != paasv1.DeploymentReady {
		t.Fatalf("installation verification=%#v", verification)
	}
	if iam.calls != 1 || iam.installationID != testInstallationID ||
		iam.requestID != "request-installation-verify" {
		t.Fatalf("IAM verification call=%#v", iam)
	}
	if len(applications.applications) != 1 || len(applications.configurations) != 1 ||
		len(applications.configurationRevisions) != 1 ||
		len(applications.applicationRevisions) != 1 || len(applications.submissions) != 1 {
		t.Fatalf("fixed workflow calls=%#v", applications)
	}
	configuration := applications.configurationRevisions[0].Request.Spec
	if len(configuration.Values) != 2 ||
		configuration.Values["MATRIX_INSTALLATION_ID"] != testInstallationID ||
		configuration.Values["MATRIX_RELEASE_ID"] != testReleaseID ||
		configuration.ContentDigest != paasv1.ConfigurationValuesDigest(configuration.Values) {
		t.Fatalf("fixed verification configuration=%#v", configuration)
	}
	revision := applications.applicationRevisions[0].Request.Spec
	if len(revision.Components) != 1 || len(revision.Components[0].Inputs) != 1 ||
		revision.Components[0].Inputs[0].Kind != paasv1.InputConfiguration ||
		revision.Components[0].Inputs[0].Injection != paasv1.InjectionEnvironment ||
		revision.Components[0].Artifact.Digest != testArtifactDigest ||
		strings.Contains(strings.ToLower(string(mustJSON(t, revision))), "secret") {
		t.Fatalf("fixed verification application revision=%#v", revision)
	}
	submission := applications.submissions[0]
	if submission.ExpectedResourceVersion != 0 ||
		submission.Spec.PlacementPolicyID != verificationPlacementPolicyID ||
		len(submission.Spec.Components) != 1 ||
		len(submission.Spec.Components[0].Bindings) != 1 ||
		submission.Spec.Components[0].Bindings[0].SecretVersion != nil {
		t.Fatalf("fixed verification deployment=%#v", submission)
	}
}

func TestServiceUsesCurrentResourceVersionForReleaseUpdate(t *testing.T) {
	oldResources, err := compileFixedResources(Config{
		InstallationID: testInstallationID,
		ReleaseID:      "matrix-v0.0.9-001",
		ArtifactDigest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
	})
	if err != nil {
		t.Fatalf("compile old resources: %v", err)
	}
	current := deploymentResult(
		oldResources.deploymentID,
		oldResources.deploymentName,
		oldResources.deploymentSpec,
		port.Authorization{
			TenantID: "organization-default",
			Subject: paasv1.SubjectRef{
				Type: paasv1.SubjectServiceAccount, ID: "service-installation-verifier",
			},
			DecisionID: "decision-old", RequestID: "request-old",
		},
		7,
		4,
		paasv1.OperationSucceeded,
	).Deployment
	applications := &verificationApplications{
		current:        &current,
		operationState: paasv1.OperationAccepted,
	}
	service := newVerificationService(t, &verificationIAM{}, applications)
	verification, err := service.VerifyInstallation(context.Background(), verificationCommand())
	if err != nil {
		t.Fatalf("verify upgraded installation: %v", err)
	}
	if verification.State != paasv1.InstallationVerificationPending ||
		len(applications.submissions) != 1 {
		t.Fatalf("upgrade verification=%#v submissions=%d", verification, len(applications.submissions))
	}
	submission := applications.submissions[0]
	if submission.Name != "" || submission.ExpectedResourceVersion != 7 ||
		!strings.HasSuffix(submission.IdempotencyKey, "-deployment-rv-7") ||
		submission.Spec.ApplicationRevisionID == current.Spec.ApplicationRevisionID {
		t.Fatalf("upgrade verification submission=%#v", submission)
	}
}

func TestServiceRejectsAnotherRunningReleaseBeforeIAMOrApplicationMutation(t *testing.T) {
	iam := &verificationIAM{}
	applications := &verificationApplications{}
	service := newVerificationService(t, iam, applications)
	command := verificationCommand()
	command.Request.ReleaseID = "matrix-v9.9.9-001"
	_, err := service.VerifyInstallation(context.Background(), command)
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("mismatched release error=%v", err)
	}
	if iam.calls != 0 || applications.callCount() != 0 {
		t.Fatalf("mismatched release reached effects: IAM=%d workflow=%d", iam.calls, applications.callCount())
	}
}

type verificationIAM struct {
	calls          int
	installationID string
	requestID      string
}

func (value *verificationIAM) VerifyInstallation(
	_ context.Context,
	credential string,
	installationID string,
	requestID string,
) (port.Authorization, error) {
	value.calls++
	value.installationID = installationID
	value.requestID = requestID
	if credential != "Bearer verifier-credential" {
		return port.Authorization{}, port.ErrUnauthenticated
	}
	return port.Authorization{
		TenantID: "organization-default",
		Subject: paasv1.SubjectRef{
			Type: paasv1.SubjectServiceAccount, ID: "service-installation-verifier",
		},
		DecisionID: "decision-installation-verify",
		RequestID:  requestID,
	}, nil
}

type verificationApplications struct {
	applications           []applicationlifecycle.CreateApplicationCommand
	configurations         []applicationlifecycle.CreateConfigurationCommand
	configurationRevisions []applicationlifecycle.CreateConfigurationRevisionCommand
	applicationRevisions   []applicationlifecycle.CreateApplicationRevisionCommand
	submissions            []applicationlifecycle.SubmitCommand
	current                *paasv1.Deployment
	operationState         paasv1.OperationState
}

func (value *verificationApplications) CreateApplication(
	_ context.Context,
	command applicationlifecycle.CreateApplicationCommand,
) (paasv1.Application, paasv1.Operation, bool, error) {
	value.applications = append(value.applications, command)
	return paasv1.Application{}, paasv1.Operation{}, false, nil
}

func (value *verificationApplications) CreateConfiguration(
	_ context.Context,
	command applicationlifecycle.CreateConfigurationCommand,
) (paasv1.Configuration, paasv1.Operation, bool, error) {
	value.configurations = append(value.configurations, command)
	return paasv1.Configuration{}, paasv1.Operation{}, false, nil
}

func (value *verificationApplications) CreateConfigurationRevision(
	_ context.Context,
	command applicationlifecycle.CreateConfigurationRevisionCommand,
) (paasv1.ConfigurationRevision, paasv1.Operation, bool, error) {
	value.configurationRevisions = append(value.configurationRevisions, command)
	return paasv1.ConfigurationRevision{}, paasv1.Operation{}, false, nil
}

func (value *verificationApplications) CreateApplicationRevision(
	_ context.Context,
	command applicationlifecycle.CreateApplicationRevisionCommand,
) (paasv1.ApplicationRevision, paasv1.Operation, bool, error) {
	value.applicationRevisions = append(value.applicationRevisions, command)
	return paasv1.ApplicationRevision{}, paasv1.Operation{}, false, nil
}

func (value *verificationApplications) Submit(
	_ context.Context,
	command applicationlifecycle.SubmitCommand,
) (applicationlifecycle.Result, error) {
	value.submissions = append(value.submissions, command)
	resourceVersion, generation := uint64(1), uint64(1)
	name := command.Name
	if value.current != nil {
		resourceVersion = value.current.Metadata.ResourceVersion + 1
		generation = value.current.Generation + 1
		name = value.current.Metadata.Name
	}
	return deploymentResult(
		command.DeploymentID,
		name,
		command.Spec,
		command.Authorization,
		resourceVersion,
		generation,
		value.operationState,
	), nil
}

func (value *verificationApplications) GetDeployment(
	_ context.Context,
	_ port.Authorization,
	_ paasv1.ResourceID,
) (paasv1.Deployment, error) {
	if value.current == nil {
		return paasv1.Deployment{}, applicationlifecycle.ErrNotFound
	}
	return *value.current, nil
}

func (*verificationApplications) GetDeploymentGeneration(
	context.Context,
	port.Authorization,
	paasv1.ResourceID,
	uint64,
) (paasv1.DeploymentGeneration, error) {
	return paasv1.DeploymentGeneration{}, errors.New("unexpected GetDeploymentGeneration")
}

func (*verificationApplications) GetOperation(
	context.Context,
	port.Authorization,
	paasv1.OperationID,
) (paasv1.Operation, error) {
	return paasv1.Operation{}, errors.New("unexpected GetOperation")
}

func (value *verificationApplications) callCount() int {
	return len(value.applications) + len(value.configurations) +
		len(value.configurationRevisions) + len(value.applicationRevisions) +
		len(value.submissions)
}

func deploymentResult(
	deploymentID paasv1.ResourceID,
	name string,
	spec paasv1.DeploymentSpec,
	authorization port.Authorization,
	resourceVersion uint64,
	generationNumber uint64,
	operationState paasv1.OperationState,
) applicationlifecycle.Result {
	operationID := paasv1.OperationID("operation-verification")
	phase := paasv1.DeploymentPending
	status := paasv1.DeploymentStatus{
		Phase: phase, CurrentOperationID: operationID, ObservedAt: testVerificationTime,
	}
	var terminalAt *time.Time
	if operationState == paasv1.OperationSucceeded {
		phase = paasv1.DeploymentReady
		status = paasv1.DeploymentStatus{
			Phase: phase, ObservedGeneration: generationNumber,
			CurrentOperationID:            operationID,
			ObservedApplicationRevisionID: spec.ApplicationRevisionID,
			ReadyComponents:               uint32(len(spec.Components)),
			ObservedAt:                    testVerificationTime,
		}
		terminal := testVerificationTime
		terminalAt = &terminal
	}
	deployment := paasv1.Deployment{
		APIVersion: paasv1.APIVersion, Kind: "Deployment",
		Metadata: paasv1.ResourceMetadata{
			ID: deploymentID, Name: name,
			Scope:           paasv1.ResourceScope{Kind: paasv1.AuthorityTenant, TenantID: authorization.TenantID},
			ResourceVersion: resourceVersion,
			CreatedAt:       testVerificationTime, UpdatedAt: testVerificationTime,
		},
		Generation: generationNumber, Spec: spec, Status: status,
	}
	generation := paasv1.DeploymentGeneration{
		APIVersion: paasv1.APIVersion, Kind: "DeploymentGeneration",
		Scope: deployment.Metadata.Scope, DeploymentID: deploymentID,
		Generation: generationNumber, Spec: spec,
		ContentDigest:        paasv1.DeploymentSpecContentDigest(spec),
		CreatedByOperationID: operationID, CreatedAt: testVerificationTime,
	}
	operation := paasv1.Operation{
		APIVersion: paasv1.APIVersion, Kind: "Operation", ID: operationID,
		Scope: deployment.Metadata.Scope, Action: paasv1.OperationDeploy,
		Target:                 paasv1.ResourceRef{Kind: "Deployment", ID: deploymentID},
		RequestedBy:            authorization.Subject,
		IdempotencyFingerprint: testArtifactDigest,
		RequestDigest:          testArtifactDigest,
		State:                  operationState, Attempt: 1,
		CreatedAt: testVerificationTime, UpdatedAt: testVerificationTime,
		TerminalAt: terminalAt,
	}
	if resourceVersion > 1 {
		operation.Action = paasv1.OperationUpdate
	}
	return applicationlifecycle.Result{
		Deployment: deployment, Generation: generation, Operation: operation,
	}
}

func newVerificationService(
	t *testing.T,
	iam IAM,
	applications ApplicationWorkflow,
) *Service {
	t.Helper()
	service, err := NewService(iam, applications, Config{
		InstallationID: testInstallationID,
		ReleaseID:      testReleaseID,
		ArtifactDigest: testArtifactDigest,
		Clock:          func() time.Time { return testVerificationTime },
	})
	if err != nil {
		t.Fatalf("create verification service: %v", err)
	}
	return service
}

func verificationCommand() Command {
	return Command{
		Credential: "Bearer verifier-credential",
		RequestID:  "request-installation-verify",
		Request: paasv1.VerifyInstallationRequest{
			InstallationID: testInstallationID,
			ReleaseID:      testReleaseID,
		},
	}
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("encode test value: %v", err)
	}
	return encoded
}
