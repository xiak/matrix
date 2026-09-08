package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	paasv1 "github.com/xiak/matrix/api/paas/v1"
	composeadapter "github.com/xiak/matrix/app/adapter/apphosting/compose"
	"github.com/xiak/matrix/app/service/installation/internal/cli"
	"github.com/xiak/matrix/app/service/installation/internal/localmachine"
	"github.com/xiak/matrix/app/service/installation/internal/platformcommand"
	"github.com/xiak/matrix/app/service/installation/internal/runnernodecommand"
	"github.com/xiak/matrix/app/service/installation/internal/sourcecredentialcommand"
)

type composeRecoveryProjectInspector struct{}

func (composeRecoveryProjectInspector) InspectRecoveryProject(
	bindingRoot string,
	tenantID paasv1.TenantID,
	deploymentID paasv1.ResourceID,
) (localmachine.RecoveryProjectState, bool, error) {
	state, exists, err := composeadapter.InspectRunningProjectState(
		bindingRoot, tenantID, deploymentID,
	)
	if err != nil {
		return localmachine.RecoveryProjectState{}, false, err
	}
	services := make([]localmachine.RecoveryProjectService, 0, len(state.Services))
	for _, service := range state.Services {
		services = append(services, localmachine.RecoveryProjectService{
			Name: service.Name, Image: service.Image, Replicas: service.Replicas,
		})
	}
	return localmachine.RecoveryProjectState{
		ProjectName:           state.ProjectName,
		Directory:             state.Directory,
		EffectDocument:        state.EffectDocument,
		ObservationDocument:   state.ObservationDocument,
		TenantID:              state.TenantID,
		DeploymentID:          state.DeploymentID,
		Generation:            state.Generation,
		ApplicationRevisionID: state.ApplicationRevisionID,
		ContentDigest:         state.ContentDigest,
		Services:              services,
		SecretFileCount:       state.SecretFileCount,
	}, exists, nil
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)

	effects := localmachine.NewEffects(composeRecoveryProjectInspector{})
	platformBackend, err := platformcommand.NewBackend(effects)
	if err != nil {
		stop()
		_, _ = os.Stderr.WriteString("Matrix CLI initialization failed\n")
		os.Exit(cli.ExitInternal)
	}
	sourceCredentialBackend, err := sourcecredentialcommand.NewBackend(effects)
	if err != nil {
		stop()
		_, _ = os.Stderr.WriteString("Matrix CLI initialization failed\n")
		os.Exit(cli.ExitInternal)
	}
	runnerNodeBackend, err := runnernodecommand.NewBackend(effects)
	if err != nil {
		stop()
		_, _ = os.Stderr.WriteString("Matrix CLI initialization failed\n")
		os.Exit(cli.ExitInternal)
	}
	exitCode := cli.Run(ctx, os.Args[1:], cli.Streams{
		In: os.Stdin, Out: os.Stdout, ErrOut: os.Stderr,
	}, cli.Backends{
		Platform: platformBackend, SourceCredential: sourceCredentialBackend,
		RunnerNode: runnerNodeBackend,
	})
	stop()
	os.Exit(exitCode)
}
