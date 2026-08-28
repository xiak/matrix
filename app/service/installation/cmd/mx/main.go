package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	nodev1 "github.com/xiak/matrix/api/adapter/node/v1"
	paasv1 "github.com/xiak/matrix/api/paas/v1"
	composeadapter "github.com/xiak/matrix/app/adapter/apphosting/compose"
	nodehttps "github.com/xiak/matrix/app/adapter/node/https"
	"github.com/xiak/matrix/app/service/installation/internal/cli"
	"github.com/xiak/matrix/app/service/installation/internal/localmachine"
	"github.com/xiak/matrix/app/service/installation/internal/nodecommand"
	"github.com/xiak/matrix/app/service/installation/internal/platformcommand"
	"github.com/xiak/matrix/app/service/installation/nodeconfig"
)

type composeRecoveryProjectInspector struct{}

type nodeInstallationVerifier struct{}

func (nodeInstallationVerifier) ValidateController(configuration nodeconfig.ControllerConfiguration) error {
	credentials, err := nodehttps.NewCredentials(configuration.Certificate, configuration.PrivateKey, configuration.Trust)
	if err != nil {
		return err
	}
	for _, node := range configuration.Nodes {
		client, err := nodehttps.New(nodehttps.Config{Endpoint: node.Endpoint,
			Identity:     nodev1.Identity{InstallationID: configuration.InstallationID, ExecutionTargetID: node.TargetID},
			ControllerID: configuration.ControllerID, BindingRef: node.BindingRef, ExpectedFingerprint: node.IdentityFingerprint,
			Credentials: func() (nodehttps.Credentials, error) { return credentials, nil }})
		if err != nil {
			return err
		}
		client.Close()
	}
	return nil
}

func (nodeInstallationVerifier) Validate(config nodeconfig.Configuration, material nodecommand.Credentials) error {
	node, err := nodehttps.NewCredentials(material.Certificate, material.PrivateKey, material.Trust)
	if err != nil {
		return err
	}
	collector, err := nodehttps.NewCredentials(material.CollectorCertificate, material.CollectorPrivateKey, material.Trust)
	if err != nil {
		return err
	}
	address, err := nodeconfig.CollectorListenAddress(config)
	if err != nil {
		return err
	}
	return nodehttps.ValidateEnrollment(node, collector, config.Identity, config.ListenAddress, address)
}

func (nodeInstallationVerifier) Verify(ctx context.Context, config nodeconfig.Configuration, material nodecommand.Credentials) error {
	credentials, err := nodehttps.NewCredentials(material.Certificate, material.PrivateKey, material.Trust)
	if err != nil {
		return err
	}
	client, err := nodehttps.NewReadinessClient("https://"+config.ListenAddress, config.Identity, config.ExpectedFingerprint, credentials)
	if err != nil {
		return err
	}
	defer client.Close()
	_, err = client.Verify(ctx)
	return err
}

func (nodeInstallationVerifier) ValidateRotation(config nodeconfig.Configuration, previous, candidate nodecommand.Credentials, revokePrevious bool) error {
	previousNode, err := nodehttps.NewCredentials(previous.Certificate, previous.PrivateKey, previous.Trust)
	if err != nil {
		return err
	}
	previousCollector, err := nodehttps.NewCredentials(previous.CollectorCertificate, previous.CollectorPrivateKey, previous.Trust)
	if err != nil {
		return err
	}
	node, err := nodehttps.NewCredentials(candidate.Certificate, candidate.PrivateKey, candidate.Trust)
	if err != nil {
		return err
	}
	collector, err := nodehttps.NewCredentials(candidate.CollectorCertificate, candidate.CollectorPrivateKey, candidate.Trust)
	if err != nil {
		return err
	}
	address, err := nodeconfig.CollectorListenAddress(config)
	if err != nil {
		return err
	}
	return nodehttps.ValidateCredentialRotation(previousNode, previousCollector, node, collector,
		config.Identity, config.ListenAddress, address, revokePrevious)
}

type lifecycleCommands struct{ platform, node cli.Backend }

func (commands lifecycleCommands) Run(ctx context.Context, request cli.Request) (cli.Result, error) {
	if request.Subject == cli.SubjectNode {
		return commands.node.Run(ctx, request)
	}
	if request.Subject == cli.SubjectPlatform {
		return commands.platform.Run(ctx, request)
	}
	fault, _ := cli.NewFault(cli.FaultInvalidArgument, "COMMAND_SUBJECT_INVALID")
	return cli.Result{}, fault
}

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

	platform, err := platformcommand.NewBackend(
		localmachine.NewEffects(composeRecoveryProjectInspector{}, nodeInstallationVerifier{}.ValidateController),
	)
	if err != nil {
		stop()
		_, _ = os.Stderr.WriteString("Matrix CLI initialization failed\n")
		os.Exit(cli.ExitInternal)
	}
	node, err := nodecommand.NewBackend(localmachine.NewNodeEffects(nodeInstallationVerifier{}))
	if err != nil {
		stop()
		_, _ = os.Stderr.WriteString("Matrix CLI initialization failed\n")
		os.Exit(cli.ExitInternal)
	}
	exitCode := cli.Run(ctx, os.Args[1:], cli.Streams{
		In: os.Stdin, Out: os.Stdout, ErrOut: os.Stderr,
	}, lifecycleCommands{platform: platform, node: node})
	stop()
	os.Exit(exitCode)
}
