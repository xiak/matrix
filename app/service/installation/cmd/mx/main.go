package main

import (
	"context"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	paasv1 "github.com/xiak/matrix/api/paas/v1"
	composeadapter "github.com/xiak/matrix/app/adapter/apphosting/compose"
	localpostgresadapter "github.com/xiak/matrix/app/adapter/managedservice/localpostgres"
	"github.com/xiak/matrix/app/service/installation/internal/cli"
	"github.com/xiak/matrix/app/service/installation/internal/localmachine"
	"github.com/xiak/matrix/app/service/installation/internal/platformcommand"
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

	backend, err := platformcommand.NewBackend(
		localmachine.NewEffects(composeRecoveryProjectInspector{}, func(bindingRoot string) (string, error) {
			return localpostgresadapter.InspectRecoveryInventory(filepath.Join(bindingRoot, localpostgresadapter.DirectoryName))
		}),
	)
	if err != nil {
		stop()
		_, _ = os.Stderr.WriteString("Matrix CLI initialization failed\n")
		os.Exit(cli.ExitInternal)
	}
	exitCode := cli.Run(ctx, os.Args[1:], cli.Streams{
		In: os.Stdin, Out: os.Stdout, ErrOut: os.Stderr,
	}, backend)
	stop()
	os.Exit(exitCode)
}
