// Package compose compiles provider-neutral application generations into the
// closed Docker Compose profile supported by Matrix PaaS v0.1.
package compose

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"

	paasv1 "github.com/xiak/matrix/api/paas/v1"
)

const maxComposeDocumentBytes = 4 * 1024 * 1024

var localImageDigestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// ArtifactResolver proves that a public artifact digest is already present
// and returns a Docker-local immutable image reference. It must not pull or
// build an image.
type ArtifactResolver interface {
	ResolveVerifiedImage(context.Context, paasv1.ArtifactRef) (VerifiedImage, error)
}

type VerifiedImage struct {
	ArtifactDigest string
	LocalReference string
}

type SecretFile struct {
	Name         string
	RelativePath string
	Reference    paasv1.SecretVersionReference
}

// PlannedService contains only the non-secret declaration needed to validate
// provider observations. Configuration values remain in the effecting Compose
// document and secret material is resolved only while the executor holds the
// project lock.
type PlannedService struct {
	Name      string
	Image     string
	Replicas  uint32
	Endpoints []paasv1.DeploymentEndpointObservation
}

type ExecutionPlan struct {
	ProjectName    string
	DeploymentID   paasv1.ResourceID
	Generation     uint64
	ContentDigest  string
	Document       []byte
	DocumentDigest string
	SecretFiles    []SecretFile
	Services       []PlannedService
}

type Compiler struct {
	artifacts ArtifactResolver
}

func NewCompiler(artifacts ArtifactResolver) (*Compiler, error) {
	if artifacts == nil {
		return nil, errors.New("artifact resolver is required")
	}
	return &Compiler{artifacts: artifacts}, nil
}

func (compiler *Compiler) Compile(
	ctx context.Context,
	request paasv1.DeploymentExecutionRequest,
) (ExecutionPlan, error) {
	if ctx == nil {
		return ExecutionPlan{}, errors.New("compile context is required")
	}
	if err := paasv1.ValidateDeploymentExecutionRequest(request); err != nil {
		return ExecutionPlan{}, fmt.Errorf("invalid deployment execution request: %w", err)
	}
	if !containsAction(request.Command.Action, paasv1.AdapterValidateDeployment, paasv1.AdapterApplyDeployment, paasv1.AdapterRollbackDeployment) {
		return ExecutionPlan{}, fmt.Errorf("action %q does not compile a Compose project", request.Command.Action)
	}
	if request.Generation.Spec.DesiredState != paasv1.DeploymentDesiredRunning {
		return ExecutionPlan{}, errors.New("Compose compilation requires RUNNING desired state")
	}
	if request.Placement.GrantedIsolationGuarantee != paasv1.IsolationWorkload {
		return ExecutionPlan{}, errors.New("Compose v0.1 supports only WORKLOAD isolation")
	}

	revisionComponents := make(map[string]paasv1.ApplicationRevisionComponent, len(request.ApplicationRevision.Spec.Components))
	for _, component := range request.ApplicationRevision.Spec.Components {
		revisionComponents[component.Name] = component
	}
	configurations := make(map[paasv1.ResourceID]paasv1.ConfigurationRevision, len(request.ConfigurationRevisions))
	for _, revision := range request.ConfigurationRevisions {
		configurations[revision.Metadata.ID] = revision
	}

	projectName := projectName(request.Command.Scope.TenantID, request.Generation.DeploymentID)
	document := composeDocument{
		Services: make(map[string]composeService, len(request.Generation.Spec.Components)),
		Secrets:  make(map[string]composeSecret),
	}
	secretFiles := make([]SecretFile, 0)
	preparedServices := make([]preparedService, 0, len(request.Generation.Spec.Components))
	components := append([]paasv1.DeploymentComponent(nil), request.Generation.Spec.Components...)
	slices.SortFunc(components, func(left, right paasv1.DeploymentComponent) int {
		return strings.Compare(left.Name, right.Name)
	})
	for _, component := range components {
		revisionComponent := revisionComponents[component.Name]
		if revisionComponent.Artifact.Kind != paasv1.ArtifactOCIImage {
			return ExecutionPlan{}, fmt.Errorf("component %q requires an unsupported artifact kind", component.Name)
		}
		if revisionComponent.Resources.CPUMillis <= 0 || revisionComponent.Resources.MemoryBytes <= 0 {
			return ExecutionPlan{}, fmt.Errorf("component %q requires positive CPU and memory limits", component.Name)
		}
		environment := make(map[string]string)
		grants := make([]composeSecretGrant, 0)
		bindings := append([]paasv1.ComponentBinding(nil), component.Bindings...)
		slices.SortFunc(bindings, func(left, right paasv1.ComponentBinding) int {
			return strings.Compare(left.Name, right.Name)
		})
		for _, binding := range bindings {
			if binding.ConfigurationRevisionID != "" {
				configuration := configurations[binding.ConfigurationRevisionID]
				keys := make([]string, 0, len(configuration.Spec.Values))
				for key := range configuration.Spec.Values {
					keys = append(keys, key)
				}
				slices.Sort(keys)
				for _, key := range keys {
					if _, duplicate := environment[key]; duplicate {
						return ExecutionPlan{}, fmt.Errorf("component %q has conflicting configuration key %q", component.Name, key)
					}
					environment[key] = configuration.Spec.Values[key]
				}
				continue
			}
			secretName := secretName(
				request.Command.Scope.TenantID,
				request.Generation.DeploymentID,
				request.Generation.Generation,
				component.Name,
				binding.Name,
				*binding.SecretVersion,
			)
			relativePath := "secrets/" + secretName
			document.Secrets[secretName] = composeSecret{File: relativePath}
			grants = append(grants, composeSecretGrant{
				Source: secretName,
				Target: binding.Name,
				Mode:   0o444,
			})
			secretFiles = append(secretFiles, SecretFile{
				Name:         secretName,
				RelativePath: relativePath,
				Reference:    *binding.SecretVersion,
			})
		}

		exposed := make([]string, 0, len(revisionComponent.Endpoints))
		endpoints := make([]paasv1.DeploymentEndpointObservation, 0, len(revisionComponent.Endpoints))
		for _, endpoint := range revisionComponent.Endpoints {
			exposed = append(exposed, strconv.FormatUint(uint64(endpoint.Port), 10))
			endpoints = append(endpoints, paasv1.DeploymentEndpointObservation{
				ComponentName: component.Name,
				EndpointName:  endpoint.Name,
				Protocol:      endpoint.Protocol,
				Address:       component.Name,
				Port:          endpoint.Port,
			})
		}
		slices.Sort(exposed)
		slices.SortFunc(endpoints, func(left, right paasv1.DeploymentEndpointObservation) int {
			return strings.Compare(left.EndpointName, right.EndpointName)
		})
		slices.SortFunc(grants, func(left, right composeSecretGrant) int {
			return strings.Compare(left.Target, right.Target)
		})
		preparedServices = append(preparedServices, preparedService{
			Name:      component.Name,
			Artifact:  revisionComponent.Artifact,
			Replicas:  component.Replicas,
			Endpoints: endpoints,
			Service: composeService{
				PullPolicy:  "never",
				Environment: environment,
				Expose:      exposed,
				Secrets:     grants,
				Labels: map[string]string{
					"com.xiak.matrix.application-revision-id": string(request.ApplicationRevision.Metadata.ID),
					"com.xiak.matrix.component":               component.Name,
					"com.xiak.matrix.content-digest":          request.Generation.ContentDigest,
					"com.xiak.matrix.deployment-id":           string(request.Generation.DeploymentID),
					"com.xiak.matrix.generation":              strconv.FormatUint(request.Generation.Generation, 10),
					"com.xiak.matrix.tenant-id":               string(request.Command.Scope.TenantID),
				},
				Deploy: composeDeploy{
					Replicas: component.Replicas,
					Resources: composeResources{Limits: composeResourceLimits{
						CPUs:   formatCPUs(revisionComponent.Resources.CPUMillis),
						Memory: strconv.FormatInt(revisionComponent.Resources.MemoryBytes, 10) + "b",
					}},
				},
			},
		})
	}
	plannedServices := make([]PlannedService, 0, len(preparedServices))
	for _, prepared := range preparedServices {
		image, err := compiler.artifacts.ResolveVerifiedImage(ctx, prepared.Artifact)
		if err != nil {
			return ExecutionPlan{}, fmt.Errorf("component %q artifact resolution failed", prepared.Name)
		}
		if image.ArtifactDigest != prepared.Artifact.Digest ||
			!localImageDigestPattern.MatchString(image.LocalReference) {
			return ExecutionPlan{}, fmt.Errorf("component %q artifact resolver returned an unverified image", prepared.Name)
		}
		prepared.Service.Image = image.LocalReference
		document.Services[prepared.Name] = prepared.Service
		plannedServices = append(plannedServices, PlannedService{
			Name: prepared.Name, Image: image.LocalReference,
			Replicas: prepared.Replicas, Endpoints: prepared.Endpoints,
		})
	}
	if len(document.Secrets) == 0 {
		document.Secrets = nil
	}
	slices.SortFunc(secretFiles, func(left, right SecretFile) int {
		return strings.Compare(left.Name, right.Name)
	})
	encoded, err := json.Marshal(document)
	if err != nil {
		return ExecutionPlan{}, errors.New("encode Compose document failed")
	}
	if len(encoded) > maxComposeDocumentBytes {
		return ExecutionPlan{}, errors.New("Compose document exceeds the v0.1 size limit")
	}
	documentHash := sha256.Sum256(encoded)
	return ExecutionPlan{
		ProjectName:    projectName,
		DeploymentID:   request.Generation.DeploymentID,
		Generation:     request.Generation.Generation,
		ContentDigest:  request.Generation.ContentDigest,
		Document:       encoded,
		DocumentDigest: "sha256:" + hex.EncodeToString(documentHash[:]),
		SecretFiles:    secretFiles,
		Services:       plannedServices,
	}, nil
}

type composeDocument struct {
	Services map[string]composeService `json:"services"`
	Secrets  map[string]composeSecret  `json:"secrets,omitempty"`
}

type preparedService struct {
	Name      string
	Artifact  paasv1.ArtifactRef
	Replicas  uint32
	Endpoints []paasv1.DeploymentEndpointObservation
	Service   composeService
}

type composeService struct {
	Image       string               `json:"image"`
	PullPolicy  string               `json:"pull_policy"`
	Environment map[string]string    `json:"environment,omitempty"`
	Expose      []string             `json:"expose,omitempty"`
	Secrets     []composeSecretGrant `json:"secrets,omitempty"`
	Labels      map[string]string    `json:"labels"`
	Deploy      composeDeploy        `json:"deploy"`
}

type composeDeploy struct {
	Replicas  uint32           `json:"replicas"`
	Resources composeResources `json:"resources"`
}

type composeResources struct {
	Limits composeResourceLimits `json:"limits"`
}

type composeResourceLimits struct {
	CPUs   string `json:"cpus"`
	Memory string `json:"memory"`
}

type composeSecret struct {
	File string `json:"file"`
}

type composeSecretGrant struct {
	Source string `json:"source"`
	Target string `json:"target"`
	Mode   uint32 `json:"mode"`
}

func projectName(tenantID paasv1.TenantID, deploymentID paasv1.ResourceID) string {
	digest := sha256.Sum256([]byte(string(tenantID) + "\x00" + string(deploymentID)))
	return "matrix-" + hex.EncodeToString(digest[:12])
}

func secretName(
	tenantID paasv1.TenantID,
	deploymentID paasv1.ResourceID,
	generation uint64,
	componentName string,
	inputName string,
	reference paasv1.SecretVersionReference,
) string {
	source := strings.Join([]string{
		string(tenantID),
		string(deploymentID),
		strconv.FormatUint(generation, 10),
		componentName,
		inputName,
		string(reference.SecretID),
		reference.Version,
	}, "\x00")
	digest := sha256.Sum256([]byte(source))
	return "secret-" + hex.EncodeToString(digest[:12])
}

func formatCPUs(millis int64) string {
	whole := millis / 1000
	fraction := millis % 1000
	if fraction == 0 {
		return strconv.FormatInt(whole, 10)
	}
	return strconv.FormatInt(whole, 10) + "." + strings.TrimRight(fmt.Sprintf("%03d", fraction), "0")
}

func containsAction(target paasv1.AdapterAction, values ...paasv1.AdapterAction) bool {
	return slices.Contains(values, target)
}
