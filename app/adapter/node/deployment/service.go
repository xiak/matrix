// Package deployment executes closed node-wire Deployment commands through
// the existing local Compose adapter. It never selects a target or resolves a
// caller-provided host path.
package deployment

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"strings"
	"time"

	apphostingv1 "github.com/xiak/matrix/api/adapter/apphosting/v1"
	nodev1 "github.com/xiak/matrix/api/adapter/node/v1"
	paasv1 "github.com/xiak/matrix/api/paas/v1"
	composeadapter "github.com/xiak/matrix/app/adapter/apphosting/compose"
)

type Config struct {
	BindingRef  string
	BindingRoot string
	Runtime     composeadapter.Runtime
	Readiness   func(context.Context) error
	Clock       composeadapter.Clock
}

type Service struct {
	bindingRef string
	root       string
	runtime    composeadapter.Runtime
	readiness  func(context.Context) error
	clock      composeadapter.Clock
	observer   *composeadapter.Executor
}

func New(config Config) (*Service, error) {
	if config.Runtime == nil {
		runtime := composeadapter.NewLocalRuntime()
		config.Runtime, config.Readiness = runtime, runtime.Ready
	}
	if config.Readiness == nil {
		return nil, errors.New("node Deployment readiness is required")
	}
	if config.Clock == nil {
		config.Clock = time.Now
	}
	observer, err := composeadapter.New(composeadapter.Config{
		BindingRef: config.BindingRef, BindingRoot: config.BindingRoot,
		Artifacts: unavailableArtifacts{}, Secrets: unavailableSecrets{},
		Runtime: config.Runtime, Clock: config.Clock,
	})
	if err != nil {
		return nil, err
	}
	return &Service{
		bindingRef: config.BindingRef, root: config.BindingRoot,
		runtime: config.Runtime, readiness: config.Readiness,
		clock: config.Clock, observer: observer,
	}, nil
}

func (service *Service) Ready(ctx context.Context) error {
	if service == nil || service.observer == nil || service.readiness == nil || ctx == nil {
		return errors.New("node Deployment service is unavailable")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := service.readiness(ctx); err != nil {
		return errors.New("node Deployment runtime is unavailable")
	}
	return nil
}

func (service *Service) ExecuteDeployment(
	ctx context.Context,
	request nodev1.DeploymentEffectRequest,
) (paasv1.AdapterResult, error) {
	if service == nil || service.observer == nil || ctx == nil ||
		nodev1.ValidateDeploymentEffectRequest(request) != nil ||
		request.Execution.Command.BindingRef != service.bindingRef {
		return paasv1.AdapterResult{}, invalidFault()
	}
	if request.Execution.Command.Action == paasv1.AdapterStopDeployment {
		return service.observer.StopDeployment(ctx, request.Execution)
	}
	executor, err := service.materialExecutor(request.Materials)
	if err != nil {
		return paasv1.AdapterResult{}, invalidFault()
	}
	switch request.Execution.Command.Action {
	case paasv1.AdapterValidateDeployment:
		return executor.ValidateDeployment(ctx, request.Execution)
	case paasv1.AdapterApplyDeployment:
		return executor.ApplyDeployment(ctx, request.Execution)
	case paasv1.AdapterRollbackDeployment:
		return executor.RollbackDeployment(ctx, request.Execution)
	default:
		return paasv1.AdapterResult{}, invalidFault()
	}
}

func (service *Service) ObserveDeployment(
	ctx context.Context,
	request paasv1.ObserveDeploymentRequest,
) (paasv1.DeploymentObservation, error) {
	if service == nil || service.observer == nil || request.Command.BindingRef != service.bindingRef {
		return paasv1.DeploymentObservation{}, invalidFault()
	}
	return service.observer.ObserveDeployment(ctx, request)
}

func (service *Service) ObserveDeploymentRuntime(
	ctx context.Context,
	request paasv1.ObserveDeploymentRuntimeRequest,
) (paasv1.DeploymentRuntimeObservation, error) {
	if service == nil || service.observer == nil || ctx == nil ||
		paasv1.ValidateObserveDeploymentRuntimeRequest(request) != nil {
		return paasv1.DeploymentRuntimeObservation{}, invalidFault()
	}
	return service.observer.ObserveDeploymentRuntime(ctx, request)
}

func (service *Service) materialExecutor(
	materials nodev1.DeploymentMaterials,
) (*composeadapter.Executor, error) {
	entries := make([]apphostingv1.ArtifactCatalogEntry, 0, len(materials.Artifacts))
	for _, material := range materials.Artifacts {
		entries = append(entries, apphostingv1.ArtifactCatalogEntry{
			ArtifactDigest: material.ArtifactDigest, ImageID: material.LocalImageID,
		})
	}
	slices.SortFunc(entries, func(left, right apphostingv1.ArtifactCatalogEntry) int {
		return strings.Compare(left.ArtifactDigest, right.ArtifactDigest)
	})
	artifacts, err := composeadapter.NewCatalogArtifactResolver(apphostingv1.ArtifactCatalog{
		APIVersion: apphostingv1.ArtifactCatalogAPIVersion,
		Kind:       apphostingv1.ArtifactCatalogKind,
		Entries:    entries,
	})
	if err != nil {
		return nil, err
	}
	secrets, err := newMaterialSecrets(materials.Secrets)
	if err != nil {
		return nil, err
	}
	return composeadapter.New(composeadapter.Config{
		BindingRef: service.bindingRef, BindingRoot: service.root,
		Artifacts: artifacts, Secrets: secrets, Runtime: service.runtime, Clock: service.clock,
	})
}

type materialSecrets struct {
	values map[string][]byte
}

func newMaterialSecrets(materials []nodev1.SecretMaterial) (*materialSecrets, error) {
	values := make(map[string][]byte, len(materials))
	for _, material := range materials {
		key := materialKey(material.Reference)
		if _, duplicate := values[key]; duplicate || len(material.Value) > nodev1.MaximumSecretMaterialBytes {
			return nil, errors.New("Deployment secret material is invalid")
		}
		values[key] = material.Value
	}
	return &materialSecrets{values: values}, nil
}

func (secrets *materialSecrets) ResolveSecret(
	ctx context.Context,
	reference paasv1.SecretVersionReference,
) ([]byte, error) {
	if secrets == nil || ctx == nil {
		return nil, errors.New("Deployment secret material is unavailable")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	value, found := secrets.values[materialKey(reference)]
	if !found {
		return nil, errors.New("Deployment secret material is unavailable")
	}
	return bytes.Clone(value), nil
}

func materialKey(reference paasv1.SecretVersionReference) string {
	return string(reference.SecretID) + "\x00" + reference.Version
}

type unavailableArtifacts struct{}

func (unavailableArtifacts) ResolveVerifiedImage(
	context.Context,
	paasv1.ArtifactRef,
) (composeadapter.VerifiedImage, error) {
	return composeadapter.VerifiedImage{}, errors.New("Deployment artifact material is unavailable")
}

type unavailableSecrets struct{}

func (unavailableSecrets) ResolveSecret(
	context.Context,
	paasv1.SecretVersionReference,
) ([]byte, error) {
	return nil, errors.New("Deployment secret material is unavailable")
}

func invalidFault() error {
	return paasv1.AdapterFault{Normalized: paasv1.NormalizedAdapterError{
		Class: paasv1.AdapterErrorValidation, Code: paasv1.ErrorAdapterRejected,
		Message: "Node Deployment input was rejected before any provider effect.",
	}}
}
