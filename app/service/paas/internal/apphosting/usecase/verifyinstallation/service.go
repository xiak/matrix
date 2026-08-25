// Package verifyinstallation owns the fixed, no-secret application probe
// used by the platform installation lifecycle. It composes existing
// apphosting use cases; it is not a second generic application API.
package verifyinstallation

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	paasv1 "github.com/xiak/matrix/api/paas/v1"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/port"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/usecase/applicationlifecycle"
)

var (
	ErrInvalidArgument = errors.New("installation verification request is invalid")
	ErrConflict        = errors.New("installation verification conflicts with the running release")
	ErrUnavailable     = errors.New("installation verification is unavailable")
)

const (
	verificationPlacementPolicyID = paasv1.ResourceID("placement-policy-local")
	verificationArtifactLocator   = "offline.matrix.invalid/matrix/verification"
	verificationComponentName     = "probe"
	verificationBindingName       = "runtime"
)

type IAM interface {
	VerifyInstallation(
		context.Context,
		string,
		string,
		string,
	) (port.Authorization, error)
}

type ApplicationWorkflow interface {
	CreateApplication(
		context.Context,
		applicationlifecycle.CreateApplicationCommand,
	) (paasv1.Application, paasv1.Operation, bool, error)
	CreateConfiguration(
		context.Context,
		applicationlifecycle.CreateConfigurationCommand,
	) (paasv1.Configuration, paasv1.Operation, bool, error)
	CreateConfigurationRevision(
		context.Context,
		applicationlifecycle.CreateConfigurationRevisionCommand,
	) (paasv1.ConfigurationRevision, paasv1.Operation, bool, error)
	CreateApplicationRevision(
		context.Context,
		applicationlifecycle.CreateApplicationRevisionCommand,
	) (paasv1.ApplicationRevision, paasv1.Operation, bool, error)
	Submit(context.Context, applicationlifecycle.SubmitCommand) (applicationlifecycle.Result, error)
	GetDeployment(context.Context, port.Authorization, paasv1.ResourceID) (paasv1.Deployment, error)
	GetDeploymentGeneration(
		context.Context,
		port.Authorization,
		paasv1.ResourceID,
		uint64,
	) (paasv1.DeploymentGeneration, error)
	GetOperation(context.Context, port.Authorization, paasv1.OperationID) (paasv1.Operation, error)
}

type Config struct {
	InstallationID string
	ReleaseID      string
	ArtifactDigest string
	Clock          func() time.Time
}

type Command struct {
	Credential string
	RequestID  string
	Request    paasv1.VerifyInstallationRequest
}

type Service struct {
	iam          IAM
	applications ApplicationWorkflow
	config       Config
}

type fixedResources struct {
	application           paasv1.CreateApplicationRequest
	configuration         paasv1.CreateConfigurationRequest
	configurationRevision paasv1.CreateConfigurationRevisionRequest
	applicationRevision   paasv1.CreateApplicationRevisionRequest
	deploymentID          paasv1.ResourceID
	deploymentName        string
	deploymentSpec        paasv1.DeploymentSpec
	installationToken     string
	releaseToken          string
}

func NewService(iam IAM, applications ApplicationWorkflow, config Config) (*Service, error) {
	if iam == nil || applications == nil {
		return nil, errors.New("installation verification IAM and application workflow are required")
	}
	if paasv1.ValidateID("installationId", config.InstallationID) != nil ||
		paasv1.ValidateID("releaseId", config.ReleaseID) != nil ||
		paasv1.ValidateDigest("artifactDigest", config.ArtifactDigest) != nil {
		return nil, errors.New("installation verification configuration is invalid")
	}
	if config.Clock == nil {
		config.Clock = time.Now
	}
	return &Service{iam: iam, applications: applications, config: config}, nil
}

func (service *Service) VerifyInstallation(
	ctx context.Context,
	command Command,
) (paasv1.InstallationVerification, error) {
	if service == nil || service.iam == nil || service.applications == nil || service.config.Clock == nil {
		return paasv1.InstallationVerification{}, ErrUnavailable
	}
	if ctx == nil || command.Credential == "" ||
		paasv1.ValidateID("requestId", command.RequestID) != nil ||
		paasv1.ValidateVerifyInstallationRequest(command.Request) != nil {
		return paasv1.InstallationVerification{}, ErrInvalidArgument
	}
	if command.Request.InstallationID != service.config.InstallationID ||
		command.Request.ReleaseID != service.config.ReleaseID {
		return paasv1.InstallationVerification{}, ErrConflict
	}
	authorization, err := service.iam.VerifyInstallation(
		ctx,
		command.Credential,
		command.Request.InstallationID,
		command.RequestID,
	)
	if err != nil {
		return paasv1.InstallationVerification{}, err
	}
	if port.ValidateAuthorization(authorization) != nil ||
		authorization.RequestID != command.RequestID ||
		authorization.Subject.Type != paasv1.SubjectServiceAccount {
		return paasv1.InstallationVerification{}, ErrUnavailable
	}

	resources, err := compileFixedResources(service.config)
	if err != nil {
		return paasv1.InstallationVerification{}, ErrUnavailable
	}
	if err := service.ensureResources(ctx, authorization, resources); err != nil {
		return paasv1.InstallationVerification{}, mapWorkflowError(err)
	}
	result, err := service.ensureDeployment(ctx, authorization, resources)
	if err != nil {
		return paasv1.InstallationVerification{}, mapWorkflowError(err)
	}
	verification, err := service.observe(ctx, authorization, resources, result)
	if err != nil {
		return paasv1.InstallationVerification{}, mapWorkflowError(err)
	}
	if paasv1.ValidateInstallationVerification(verification) != nil {
		return paasv1.InstallationVerification{}, ErrUnavailable
	}
	return verification, nil
}

func (service *Service) ensureResources(
	ctx context.Context,
	authorization port.Authorization,
	resources fixedResources,
) error {
	if _, _, _, err := service.applications.CreateApplication(
		ctx,
		applicationlifecycle.CreateApplicationCommand{
			Authorization:  authorization,
			Request:        resources.application,
			IdempotencyKey: "verify-" + resources.installationToken + "-application",
		},
	); err != nil {
		return err
	}
	if _, _, _, err := service.applications.CreateConfiguration(
		ctx,
		applicationlifecycle.CreateConfigurationCommand{
			Authorization:  authorization,
			Request:        resources.configuration,
			IdempotencyKey: "verify-" + resources.installationToken + "-configuration",
		},
	); err != nil {
		return err
	}
	if _, _, _, err := service.applications.CreateConfigurationRevision(
		ctx,
		applicationlifecycle.CreateConfigurationRevisionCommand{
			Authorization:  authorization,
			Request:        resources.configurationRevision,
			IdempotencyKey: "verify-" + resources.releaseToken + "-configuration-revision",
		},
	); err != nil {
		return err
	}
	if _, _, _, err := service.applications.CreateApplicationRevision(
		ctx,
		applicationlifecycle.CreateApplicationRevisionCommand{
			Authorization:  authorization,
			Request:        resources.applicationRevision,
			IdempotencyKey: "verify-" + resources.releaseToken + "-application-revision",
		},
	); err != nil {
		return err
	}
	return nil
}

func (service *Service) ensureDeployment(
	ctx context.Context,
	authorization port.Authorization,
	resources fixedResources,
) (*applicationlifecycle.Result, error) {
	current, err := service.applications.GetDeployment(ctx, authorization, resources.deploymentID)
	if errors.Is(err, applicationlifecycle.ErrNotFound) {
		result, submitErr := service.applications.Submit(ctx, applicationlifecycle.SubmitCommand{
			Authorization:  authorization,
			DeploymentID:   resources.deploymentID,
			Name:           resources.deploymentName,
			Spec:           resources.deploymentSpec,
			IdempotencyKey: "verify-" + resources.releaseToken + "-deployment-create",
		})
		return &result, submitErr
	}
	if err != nil {
		return nil, err
	}
	if paasv1.DeploymentSpecContentDigest(current.Spec) ==
		paasv1.DeploymentSpecContentDigest(resources.deploymentSpec) {
		return nil, nil
	}
	if activeDeploymentPhase(current.Status.Phase) {
		return nil, nil
	}
	result, err := service.applications.Submit(ctx, applicationlifecycle.SubmitCommand{
		Authorization:           authorization,
		DeploymentID:            resources.deploymentID,
		Name:                    current.Metadata.Name,
		Spec:                    resources.deploymentSpec,
		ExpectedResourceVersion: current.Metadata.ResourceVersion,
		IdempotencyKey: fmt.Sprintf(
			"verify-%s-deployment-rv-%d",
			resources.releaseToken,
			current.Metadata.ResourceVersion,
		),
	})
	return &result, err
}

func (service *Service) observe(
	ctx context.Context,
	authorization port.Authorization,
	resources fixedResources,
	mutation *applicationlifecycle.Result,
) (paasv1.InstallationVerification, error) {
	var deployment paasv1.Deployment
	var generation paasv1.DeploymentGeneration
	var operation paasv1.Operation
	var err error
	if mutation != nil {
		deployment = mutation.Deployment
		generation = mutation.Generation
		operation = mutation.Operation
	} else {
		deployment, err = service.applications.GetDeployment(ctx, authorization, resources.deploymentID)
		if err != nil {
			return paasv1.InstallationVerification{}, err
		}
		generation, err = service.applications.GetDeploymentGeneration(
			ctx, authorization, resources.deploymentID, deployment.Generation,
		)
		if err != nil {
			return paasv1.InstallationVerification{}, err
		}
		operation, err = service.applications.GetOperation(
			ctx, authorization, generation.CreatedByOperationID,
		)
		if err != nil {
			return paasv1.InstallationVerification{}, err
		}
	}
	if paasv1.ValidateDeployment(deployment) != nil ||
		paasv1.ValidateDeploymentGeneration(generation) != nil ||
		paasv1.ValidateOperation(operation) != nil ||
		deployment.Metadata.ID != resources.deploymentID ||
		generation.DeploymentID != deployment.Metadata.ID ||
		generation.Generation != deployment.Generation ||
		generation.CreatedByOperationID != operation.ID ||
		operation.Target.Kind != "Deployment" ||
		operation.Target.ID != deployment.Metadata.ID ||
		operation.RequestedBy != authorization.Subject {
		return paasv1.InstallationVerification{}, ErrUnavailable
	}

	state := paasv1.InstallationVerificationPending
	if terminalOperation(operation.State) {
		state = paasv1.InstallationVerificationFailed
		if operation.State == paasv1.OperationSucceeded {
			desired := paasv1.DeploymentSpecContentDigest(deployment.Spec) ==
				paasv1.DeploymentSpecContentDigest(resources.deploymentSpec)
			switch {
			case desired && deployment.Status.Phase == paasv1.DeploymentReady &&
				deployment.Status.ObservedGeneration == deployment.Generation &&
				deployment.Status.ObservedApplicationRevisionID == deployment.Spec.ApplicationRevisionID &&
				deployment.Status.ReadyComponents == uint32(len(deployment.Spec.Components)):
				state = paasv1.InstallationVerificationReady
			case deployment.Status.Phase != paasv1.DeploymentDegraded &&
				deployment.Status.Phase != paasv1.DeploymentFailed &&
				deployment.Status.Phase != paasv1.DeploymentStopped:
				return paasv1.InstallationVerification{}, ErrUnavailable
			}
		}
	}
	checkedAt := service.config.Clock().UTC().Truncate(time.Microsecond)
	if checkedAt.IsZero() {
		return paasv1.InstallationVerification{}, ErrUnavailable
	}
	return paasv1.InstallationVerification{
		APIVersion:      paasv1.APIVersion,
		Kind:            "InstallationVerification",
		InstallationID:  service.config.InstallationID,
		ReleaseID:       service.config.ReleaseID,
		State:           state,
		DeploymentID:    deployment.Metadata.ID,
		Generation:      deployment.Generation,
		OperationID:     operation.ID,
		OperationState:  operation.State,
		DeploymentPhase: deployment.Status.Phase,
		CheckedAt:       checkedAt,
	}, nil
}

func compileFixedResources(config Config) (fixedResources, error) {
	installationToken := identityToken("installation", config.InstallationID)
	releaseToken := identityToken(
		"release",
		config.InstallationID+"\x00"+config.ReleaseID+"\x00"+config.ArtifactDigest,
	)
	applicationID := paasv1.ResourceID("installation-verification-app-" + installationToken)
	configurationID := paasv1.ResourceID("installation-verification-config-" + installationToken)
	configurationRevisionID := paasv1.ResourceID("installation-verification-config-rev-" + releaseToken)
	applicationRevisionID := paasv1.ResourceID("installation-verification-app-rev-" + releaseToken)
	values := map[string]string{
		"MATRIX_INSTALLATION_ID": config.InstallationID,
		"MATRIX_RELEASE_ID":      config.ReleaseID,
	}
	configurationSpec := paasv1.ConfigurationRevisionSpec{
		ConfigurationID: configurationID,
		Values:          values,
		ContentDigest:   paasv1.ConfigurationValuesDigest(values),
	}
	applicationSpec := paasv1.ApplicationRevisionSpec{
		ApplicationID: applicationID,
		Revision:      "release-" + releaseToken,
		Components: []paasv1.ApplicationRevisionComponent{{
			Name: verificationComponentName,
			Artifact: paasv1.ArtifactRef{
				Kind:    paasv1.ArtifactOCIImage,
				Locator: verificationArtifactLocator,
				Digest:  config.ArtifactDigest,
			},
			Resources: paasv1.ResourceRequirements{
				CPUMillis:   50,
				MemoryBytes: 64 * 1024 * 1024,
			},
			Endpoints: []paasv1.ApplicationEndpoint{{
				Name: "ready", Port: 8080,
				Protocol: paasv1.EndpointHTTP, Visibility: paasv1.EndpointPrivate,
			}},
			Inputs: []paasv1.ComponentInput{{
				Name:      verificationBindingName,
				Kind:      paasv1.InputConfiguration,
				Injection: paasv1.InjectionEnvironment,
				Required:  true,
			}},
		}},
	}
	contentDigest, err := contentDigest("application-revision", applicationSpec)
	if err != nil {
		return fixedResources{}, err
	}
	applicationSpec.ContentDigest = contentDigest
	result := fixedResources{
		application: paasv1.CreateApplicationRequest{
			ID: applicationID, Name: "installation-verification",
		},
		configuration: paasv1.CreateConfigurationRequest{
			ID: configurationID, Name: "verification-runtime", ApplicationID: applicationID,
		},
		configurationRevision: paasv1.CreateConfigurationRevisionRequest{
			ID:   configurationRevisionID,
			Name: "verification-config-" + releaseToken[:12],
			Spec: configurationSpec,
		},
		applicationRevision: paasv1.CreateApplicationRevisionRequest{
			ID:   applicationRevisionID,
			Name: "verification-app-" + releaseToken[:12],
			Spec: applicationSpec,
		},
		deploymentID:      paasv1.ResourceID("installation-verification-deploy-" + installationToken),
		deploymentName:    "installation-verification",
		installationToken: installationToken,
		releaseToken:      releaseToken,
	}
	result.deploymentSpec = paasv1.DeploymentSpec{
		ApplicationRevisionID: applicationRevisionID,
		PlacementPolicyID:     verificationPlacementPolicyID,
		DesiredState:          paasv1.DeploymentDesiredRunning,
		Components: []paasv1.DeploymentComponent{{
			Name:     verificationComponentName,
			Replicas: 1,
			Bindings: []paasv1.ComponentBinding{{
				Name:                    verificationBindingName,
				ConfigurationRevisionID: configurationRevisionID,
			}},
		}},
	}
	return result, nil
}

func identityToken(domain, value string) string {
	digest := sha256.Sum256([]byte("matrix.installation.verification.v1\x00" + domain + "\x00" + value))
	return hex.EncodeToString(digest[:12])
}

func contentDigest(domain string, value any) (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	digest := sha256.New()
	_, _ = digest.Write([]byte("matrix.installation.verification.content.v1\x00" + domain + "\x00"))
	_, _ = digest.Write(encoded)
	clear(encoded)
	return "sha256:" + hex.EncodeToString(digest.Sum(nil)), nil
}

func activeDeploymentPhase(value paasv1.DeploymentPhase) bool {
	return value == paasv1.DeploymentPending ||
		value == paasv1.DeploymentPlacing ||
		value == paasv1.DeploymentApplying ||
		value == paasv1.DeploymentStopping
}

func terminalOperation(value paasv1.OperationState) bool {
	return value == paasv1.OperationSucceeded ||
		value == paasv1.OperationFailed ||
		value == paasv1.OperationCancelled ||
		value == paasv1.OperationManualIntervention
}

func mapWorkflowError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded),
		errors.Is(err, port.ErrUnauthenticated),
		errors.Is(err, port.ErrPermissionDenied),
		errors.Is(err, port.ErrAuthorizationUnavailable):
		return err
	case errors.Is(err, applicationlifecycle.ErrIdempotencyConflict),
		errors.Is(err, applicationlifecycle.ErrAlreadyExists),
		errors.Is(err, applicationlifecycle.ErrResourceVersionConflict):
		return ErrConflict
	default:
		return ErrUnavailable
	}
}
