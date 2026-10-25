package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	devopsv1 "github.com/xiak/matrix/api/devops/v1"
	"github.com/xiak/matrix/app/service/devops/sourcecredential"
	"github.com/xiak/matrix/app/service/installation/internal/lifecycle"
	"github.com/xiak/matrix/app/service/internal/externalrequest"
)

const (
	ExitSuccess      = 0
	ExitInvalidInput = 2
	ExitPrecondition = 3
	ExitConflict     = 4
	ExitVerification = 5
	ExitUnavailable  = 6
	ExitInternal     = 70
	ExitInterrupted  = 130
)

type outputFormat string

const (
	formatHuman outputFormat = "human"
	formatJSON  outputFormat = "json"
)

type commandAction string

const (
	actionSourceCredentialApply          commandAction = "SOURCE_CREDENTIAL_APPLY"
	actionSourceCredentialRetirePrevious commandAction = "SOURCE_CREDENTIAL_RETIRE_PREVIOUS"
	actionSourceTrustApply               commandAction = "SOURCE_TRUST_APPLY"
	actionSourceTrustRemove              commandAction = "SOURCE_TRUST_REMOVE"
	actionRunnerNodeExportRelease        commandAction = "RUNNER_NODE_EXPORT_RELEASE"
	actionRunnerNodeRequest              commandAction = "RUNNER_NODE_REQUEST"
	actionRunnerNodeEnroll               commandAction = "RUNNER_NODE_ENROLL"
	actionRunnerNodeInstall              commandAction = "RUNNER_NODE_INSTALL"
)

type invocationError struct {
	subject Subject
	action  commandAction
	usage   bool
	err     error
}

func (value *invocationError) Error() string { return "platform command failed" }
func (value *invocationError) Unwrap() error { return value.err }

type commandOptions struct {
	root                        string
	bundle                      string
	trustKey                    string
	securityMailConfiguration   string
	northboundOrigin            string
	backupID                    string
	supportOutput               string
	join                        string
	configuration               string
	expectedConfigurationDigest string
	revokePreviousCredentials   bool
	recoveryInput               string
	resume                      bool
}

type sourceCredentialOptions struct {
	root      string
	tenantID  string
	purpose   string
	reference string
	fromFile  string
}

type sourceTrustOptions struct {
	root           string
	tenantID       string
	endpointOrigin string
	fromFile       string
}

type runnerNodeOptions struct {
	root           string
	release        string
	trustKey       string
	installationID string
	nodeID         string
	slots          uint8
	gatewayOrigin  string
	serverCAPin    string
	runnerCAPin    string
	requestFile    string
	enrollmentFile string
	output         string
}

func NewCommand(streams Streams, backends Backends) (*cobra.Command, error) {
	if err := validateStreams(streams); err != nil {
		return nil, err
	}
	if backends.Platform == nil || backends.Node == nil || backends.SourceCredential == nil ||
		backends.SourceTrust == nil || backends.RunnerNode == nil {
		return nil, errors.New("Matrix CLI backends are required")
	}
	format := string(formatHuman)
	root := &cobra.Command{
		Use:           "mx",
		Short:         "Operate the Matrix platform and its nodes",
		Args:          cobra.NoArgs,
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(command *cobra.Command, _ []string) error {
			return command.Help()
		},
	}
	root.SetIn(streams.In)
	root.SetOut(streams.Out)
	root.SetErr(streams.ErrOut)
	root.PersistentFlags().StringVar(&format, "format", string(formatHuman), "output format: human or json")
	root.PersistentPreRunE = func(command *cobra.Command, _ []string) error {
		if outputFormat(format) != formatHuman && outputFormat(format) != formatJSON {
			return &invocationError{
				subject: subjectForCommand(command), action: actionForCommand(command), usage: true,
				err: errors.New("output format must be human or json"),
			}
		}
		return nil
	}
	root.SetFlagErrorFunc(func(command *cobra.Command, err error) error {
		return &invocationError{
			subject: subjectForCommand(command), action: actionForCommand(command), usage: true, err: err,
		}
	})

	platform := &cobra.Command{
		Use:   "platform",
		Short: "Install and operate the private Matrix platform",
		Args:  cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			return command.Help()
		},
	}
	root.AddCommand(platform)
	for _, action := range []lifecycle.Action{
		lifecycle.ActionInstall, lifecycle.ActionVerify, lifecycle.ActionStatus,
		lifecycle.ActionBackup, lifecycle.ActionUpgrade, lifecycle.ActionRollback,
		lifecycle.ActionRecover, lifecycle.ActionRecoverCredentials,
		lifecycle.ActionConfigureNodes, lifecycle.ActionSupport,
	} {
		platform.AddCommand(newLifecycleCommand(
			streams.Out, backends.Platform, SubjectPlatform, action, &format,
		))
	}
	node := &cobra.Command{
		Use: "node", Short: "Enroll and supervise an existing Linux execution node", Args: cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error { return command.Help() },
	}
	root.AddCommand(node)
	for _, action := range []lifecycle.Action{
		lifecycle.ActionInstall, lifecycle.ActionStart, lifecycle.ActionVerify,
		lifecycle.ActionStatus, lifecycle.ActionRotateCredentials,
		lifecycle.ActionUpgrade, lifecycle.ActionRollback, lifecycle.ActionSupport,
	} {
		node.AddCommand(newLifecycleCommand(
			streams.Out, backends.Node, SubjectNode, action, &format,
		))
	}
	root.AddCommand(newDevOpsCommand(
		streams.Out, backends.SourceCredential, backends.SourceTrust,
		backends.RunnerNode, &format,
	))
	return root, nil
}

func newLifecycleCommand(
	out io.Writer,
	backend PlatformBackend,
	subject Subject,
	action lifecycle.Action,
	format *string,
) *cobra.Command {
	options := &commandOptions{}
	name := strings.ReplaceAll(strings.ToLower(string(action)), "_", "-")
	command := &cobra.Command{
		Use:   name,
		Short: commandDescription(subject, action),
		Args:  cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			if err := validateCommandFlags(subject, action, options); err != nil {
				return &invocationError{
					subject: subject, action: commandAction(action), usage: true, err: err,
				}
			}
			request := Request{
				Subject: subject, Action: action, Root: options.root,
				Bundle: options.bundle, TrustKey: options.trustKey,
				SecurityMailConfiguration: options.securityMailConfiguration,
				NorthboundOrigin:          options.northboundOrigin,
				BackupID:                  options.backupID, SupportOutput: options.supportOutput,
				Join: options.join, Configuration: options.configuration,
				ExpectedConfigurationDigest: options.expectedConfigurationDigest,
				RevokePreviousCredentials:   options.revokePreviousCredentials,
				RecoveryInput:               options.recoveryInput, Resume: options.resume,
			}
			result, err := backend.Run(command.Context(), request)
			if err != nil {
				return &invocationError{subject: subject, action: commandAction(action), err: err}
			}
			if err := validateResult(result); err != nil {
				return &invocationError{subject: subject, action: commandAction(action), err: err}
			}
			if err := writeSuccess(out, outputFormat(*format), subject, action, result); err != nil {
				return &invocationError{subject: subject, action: commandAction(action), err: err}
			}
			return nil
		},
	}
	bindCommandFlags(command.Flags(), subject, action, options)
	return command
}

func newDevOpsCommand(
	out io.Writer,
	sourceBackend SourceCredentialBackend,
	trustBackend SourceTrustBackend,
	runnerBackend RunnerNodeBackend,
	format *string,
) *cobra.Command {
	devops := &cobra.Command{
		Use:   "devops",
		Short: "Operate Matrix DevOps products",
		Args:  cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			return command.Help()
		},
	}
	source := &cobra.Command{
		Use:   "source-credential",
		Short: "Manage installation-owned source credentials",
		Args:  cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			return command.Help()
		},
	}
	source.AddCommand(
		newSourceCredentialOperationCommand(
			out, sourceBackend, SourceCredentialApply, format,
		),
		newSourceCredentialOperationCommand(
			out, sourceBackend, SourceCredentialRetirePrevious, format,
		),
	)
	trust := &cobra.Command{
		Use:   "source-trust",
		Short: "Manage endpoint-scoped source provider trust",
		Args:  cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			return command.Help()
		},
	}
	trust.AddCommand(
		newSourceTrustOperationCommand(out, trustBackend, SourceTrustApply, format),
		newSourceTrustOperationCommand(out, trustBackend, SourceTrustRemove, format),
	)
	devops.AddCommand(source, trust, newRunnerNodeCommand(out, runnerBackend, format))
	return devops
}

func newRunnerNodeCommand(
	out io.Writer,
	backend RunnerNodeBackend,
	format *string,
) *cobra.Command {
	runner := &cobra.Command{
		Use:   "runner-node",
		Short: "Provision dedicated Matrix DevOps runner nodes",
		Args:  cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			return command.Help()
		},
	}
	for _, operation := range []RunnerNodeOperation{
		RunnerNodeExportRelease, RunnerNodeCreateRequest, RunnerNodeEnroll, RunnerNodeInstall,
	} {
		runner.AddCommand(newRunnerNodeOperationCommand(out, backend, operation, format))
	}
	return runner
}

func newRunnerNodeOperationCommand(
	out io.Writer,
	backend RunnerNodeBackend,
	operation RunnerNodeOperation,
	format *string,
) *cobra.Command {
	options := &runnerNodeOptions{}
	name := map[RunnerNodeOperation]string{
		RunnerNodeExportRelease: "export-release",
		RunnerNodeCreateRequest: "request",
		RunnerNodeEnroll:        "enroll",
		RunnerNodeInstall:       "install",
	}[operation]
	short := map[RunnerNodeOperation]string{
		RunnerNodeExportRelease: "Export the authenticated dedicated-runner release subset",
		RunnerNodeCreateRequest: "Create node-local runner keys and a CSR request",
		RunnerNodeEnroll:        "Enroll a runner CSR request into this installation",
		RunnerNodeInstall:       "Install an enrolled dedicated runner node",
	}[operation]
	action := runnerNodeAction(operation)
	command := &cobra.Command{
		Use: name, Short: short, Args: cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			if err := validateRunnerNodeFlags(operation, options); err != nil {
				return &invocationError{action: action, usage: true, err: err}
			}
			result, err := backend.RunRunnerNode(command.Context(), RunnerNodeRequest{
				Operation: operation, Root: options.root, Release: options.release,
				TrustKey: options.trustKey, InstallationID: options.installationID,
				NodeID: options.nodeID, Slots: options.slots,
				GatewayOrigin: options.gatewayOrigin, ServerCAPin: options.serverCAPin,
				RunnerCAPin: options.runnerCAPin, RequestFile: options.requestFile,
				EnrollmentFile: options.enrollmentFile, Output: options.output,
			})
			if err != nil {
				return &invocationError{action: action, err: err}
			}
			request := RunnerNodeRequest{
				Operation: operation, Root: options.root, Release: options.release,
				TrustKey: options.trustKey, InstallationID: options.installationID,
				NodeID: options.nodeID, Slots: options.slots,
				GatewayOrigin: options.gatewayOrigin, ServerCAPin: options.serverCAPin,
				RunnerCAPin: options.runnerCAPin, RequestFile: options.requestFile,
				EnrollmentFile: options.enrollmentFile, Output: options.output,
			}
			if err := validateRunnerNodeResult(request, result); err != nil {
				return &invocationError{action: action, err: err}
			}
			if err := writeRunnerNodeSuccess(out, outputFormat(*format), action, result); err != nil {
				return &invocationError{action: action, err: err}
			}
			return nil
		},
	}
	flags := command.Flags()
	switch operation {
	case RunnerNodeExportRelease:
		flags.StringVar(&options.root, "root", "", "absolute Matrix installation root")
		flags.StringVar(&options.output, "output", "", "new dedicated-runner release directory")
	case RunnerNodeCreateRequest:
		flags.StringVar(&options.root, "root", "", "new private runner-node root")
		flags.StringVar(&options.release, "release", "", "authenticated dedicated-runner release directory")
		flags.StringVar(&options.trustKey, "trust-key", "", "out-of-band release trust root")
		flags.StringVar(&options.installationID, "installation", "", "target Matrix installation identity")
		flags.StringVar(&options.nodeID, "node", "", "runner node identity")
		flags.Uint8Var(&options.slots, "slots", 0, "independent execution slots (1-4)")
		flags.StringVar(&options.gatewayOrigin, "gateway-origin", "", "outbound HTTPS executor gateway origin")
		flags.StringVar(&options.serverCAPin, "server-ca-fingerprint", "", "server CA fingerprint from the trusted platform export")
		flags.StringVar(&options.runnerCAPin, "runner-ca-fingerprint", "", "runner CA fingerprint from the trusted platform export")
	case RunnerNodeEnroll:
		flags.StringVar(&options.root, "root", "", "absolute Matrix installation root")
		flags.StringVar(&options.requestFile, "request", "", "runner-node enrollment request file")
		flags.StringVar(&options.output, "output", "", "new signed enrollment response file")
	case RunnerNodeInstall:
		flags.StringVar(&options.root, "root", "", "private runner-node root created by request")
		flags.StringVar(&options.release, "release", "", "authenticated dedicated-runner release directory")
		flags.StringVar(&options.trustKey, "trust-key", "", "out-of-band release trust root")
		flags.StringVar(&options.enrollmentFile, "enrollment", "", "signed runner enrollment response file")
	}
	return command
}

func validateRunnerNodeFlags(operation RunnerNodeOperation, options *runnerNodeOptions) error {
	if options == nil || strings.TrimSpace(options.root) == "" {
		return errors.New("runner node root is required")
	}
	switch operation {
	case RunnerNodeExportRelease:
		if strings.TrimSpace(options.output) == "" {
			return errors.New("runner release output is required")
		}
	case RunnerNodeCreateRequest:
		if strings.TrimSpace(options.release) == "" || strings.TrimSpace(options.trustKey) == "" ||
			strings.TrimSpace(options.installationID) == "" || strings.TrimSpace(options.nodeID) == "" ||
			options.slots == 0 || options.slots > 4 || strings.TrimSpace(options.gatewayOrigin) == "" ||
			strings.TrimSpace(options.serverCAPin) == "" || strings.TrimSpace(options.runnerCAPin) == "" {
			return errors.New("runner enrollment request identity is required")
		}
	case RunnerNodeEnroll:
		if strings.TrimSpace(options.requestFile) == "" || strings.TrimSpace(options.output) == "" {
			return errors.New("runner enrollment request and output are required")
		}
	case RunnerNodeInstall:
		if strings.TrimSpace(options.release) == "" || strings.TrimSpace(options.trustKey) == "" ||
			strings.TrimSpace(options.enrollmentFile) == "" {
			return errors.New("runner release, trust, and enrollment are required")
		}
	default:
		return errors.New("runner node operation is invalid")
	}
	return nil
}

func runnerNodeAction(operation RunnerNodeOperation) commandAction {
	switch operation {
	case RunnerNodeExportRelease:
		return actionRunnerNodeExportRelease
	case RunnerNodeCreateRequest:
		return actionRunnerNodeRequest
	case RunnerNodeEnroll:
		return actionRunnerNodeEnroll
	case RunnerNodeInstall:
		return actionRunnerNodeInstall
	default:
		return ""
	}
}

func newSourceCredentialOperationCommand(
	out io.Writer,
	backend SourceCredentialBackend,
	operation SourceCredentialOperation,
	format *string,
) *cobra.Command {
	options := &sourceCredentialOptions{}
	name := "apply"
	short := "Apply source credential material"
	if operation == SourceCredentialRetirePrevious {
		name = "retire-previous"
		short = "Retire the previous webhook credential"
	}
	action := sourceCredentialAction(operation)
	command := &cobra.Command{
		Use:   name,
		Short: short,
		Args:  cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			if err := validateSourceCredentialFlags(operation, options); err != nil {
				return &invocationError{action: action, usage: true, err: err}
			}
			request := SourceCredentialRequest{
				Operation: operation,
				Root:      options.root,
				TenantID:  options.tenantID,
				Purpose:   sourcecredential.Purpose(options.purpose),
				Reference: options.reference,
				FromFile:  options.fromFile,
			}
			result, err := backend.RunSourceCredential(command.Context(), request)
			if err != nil {
				return &invocationError{action: action, err: err}
			}
			if err := validateSourceCredentialResult(request, result); err != nil {
				return &invocationError{action: action, err: err}
			}
			if err := writeSourceCredentialSuccess(
				out, outputFormat(*format), action, result,
			); err != nil {
				return &invocationError{action: action, err: err}
			}
			return nil
		},
	}
	flags := command.Flags()
	flags.StringVar(&options.root, "root", "", "absolute Matrix installation root")
	flags.StringVar(&options.tenantID, "tenant", "", "Matrix tenant identity")
	flags.StringVar(&options.purpose, "purpose", "", "credential purpose: WEBHOOK, FETCH, or REPORT")
	flags.StringVar(&options.reference, "reference", "", "opaque source credential reference")
	if operation == SourceCredentialApply {
		flags.StringVar(&options.fromFile, "from-file", "", "private source credential input file")
	}
	return command
}

func validateSourceCredentialFlags(
	operation SourceCredentialOperation,
	options *sourceCredentialOptions,
) error {
	if options == nil || strings.TrimSpace(options.root) == "" ||
		strings.TrimSpace(options.tenantID) == "" ||
		strings.TrimSpace(options.reference) == "" {
		return errors.New("source credential identity is required")
	}
	purpose := sourcecredential.Purpose(options.purpose)
	if sourcecredential.ValidatePurpose(purpose) != nil {
		return errors.New("source credential purpose is invalid")
	}
	switch operation {
	case SourceCredentialApply:
		if strings.TrimSpace(options.fromFile) == "" {
			return errors.New("source credential input file is required")
		}
	case SourceCredentialRetirePrevious:
		if purpose != sourcecredential.PurposeWebhook || options.fromFile != "" {
			return errors.New("only a webhook previous credential can be retired")
		}
	default:
		return errors.New("source credential operation is invalid")
	}
	return nil
}

func sourceCredentialAction(operation SourceCredentialOperation) commandAction {
	switch operation {
	case SourceCredentialApply:
		return actionSourceCredentialApply
	case SourceCredentialRetirePrevious:
		return actionSourceCredentialRetirePrevious
	default:
		return ""
	}
}

func newSourceTrustOperationCommand(
	out io.Writer,
	backend SourceTrustBackend,
	operation SourceTrustOperation,
	format *string,
) *cobra.Command {
	options := &sourceTrustOptions{}
	name := "apply"
	short := "Apply endpoint-scoped source provider trust"
	if operation == SourceTrustRemove {
		name = "remove"
		short = "Remove endpoint-scoped source provider trust"
	}
	action := sourceTrustAction(operation)
	command := &cobra.Command{
		Use: name, Short: short, Args: cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			if err := validateSourceTrustFlags(operation, options); err != nil {
				return &invocationError{action: action, usage: true, err: err}
			}
			request := SourceTrustRequest{
				Operation: operation, Root: options.root, TenantID: options.tenantID,
				EndpointOrigin: options.endpointOrigin, FromFile: options.fromFile,
			}
			result, err := backend.RunSourceTrust(command.Context(), request)
			if err != nil {
				return &invocationError{action: action, err: err}
			}
			if err := validateSourceTrustResult(request, result); err != nil {
				return &invocationError{action: action, err: err}
			}
			if err := writeSourceTrustSuccess(out, outputFormat(*format), action, result); err != nil {
				return &invocationError{action: action, err: err}
			}
			return nil
		},
	}
	flags := command.Flags()
	flags.StringVar(&options.root, "root", "", "absolute Matrix installation root")
	flags.StringVar(&options.tenantID, "tenant", "", "Matrix tenant identity")
	flags.StringVar(
		&options.endpointOrigin, "endpoint-origin", "", "exact canonical HTTPS provider origin",
	)
	if operation == SourceTrustApply {
		flags.StringVar(&options.fromFile, "from-file", "", "private source CA bundle input file")
	}
	return command
}

func validateSourceTrustFlags(operation SourceTrustOperation, options *sourceTrustOptions) error {
	if options == nil || strings.TrimSpace(options.root) == "" ||
		strings.TrimSpace(options.tenantID) == "" ||
		devopsv1.ValidateResourceScope(devopsv1.ResourceScope{
			TenantID: devopsv1.TenantID(options.tenantID),
		}) != nil || devopsv1.ValidateEndpointOrigin(options.endpointOrigin) != nil {
		return errors.New("source trust identity is invalid")
	}
	switch operation {
	case SourceTrustApply:
		if strings.TrimSpace(options.fromFile) == "" {
			return errors.New("source trust input file is required")
		}
	case SourceTrustRemove:
		if options.fromFile != "" {
			return errors.New("source trust removal cannot accept input material")
		}
	default:
		return errors.New("source trust operation is invalid")
	}
	return nil
}

func sourceTrustAction(operation SourceTrustOperation) commandAction {
	switch operation {
	case SourceTrustApply:
		return actionSourceTrustApply
	case SourceTrustRemove:
		return actionSourceTrustRemove
	default:
		return ""
	}
}

func bindCommandFlags(
	flags *pflag.FlagSet,
	subject Subject,
	action lifecycle.Action,
	options *commandOptions,
) {
	flags.StringVar(&options.root, "root", "", "absolute Matrix installation root")
	switch action {
	case lifecycle.ActionConfigureNodes:
		flags.StringVar(&options.configuration, "configuration", "", "protected node controller configuration file")
		flags.StringVar(&options.expectedConfigurationDigest, "expected-configuration-digest", "", "current configuration digest reported by platform status")
		flags.BoolVar(&options.resume, "resume", false, "resume only the sealed pending node configuration")
	case lifecycle.ActionRecoverCredentials:
		flags.StringVar(&options.recoveryInput, "recovery-input", "", "protected original-primary credential recovery request file")
		flags.BoolVar(&options.resume, "resume", false, "resume the exact sealed credential recovery without new input")
	case lifecycle.ActionRotateCredentials:
		flags.StringVar(&options.configuration, "configuration", "", "protected replacement node enrollment file")
		flags.StringVar(&options.expectedConfigurationDigest, "expected-configuration-digest", "", "current sealed node configuration digest")
		flags.BoolVar(&options.revokePreviousCredentials, "revoke-previous", true, "replace all previous management trust keys; false permits same-trust renewal")
	case lifecycle.ActionInstall:
		flags.StringVar(&options.bundle, "bundle", "", "verified offline release bundle directory")
		flags.StringVar(&options.trustKey, "trust-key", "", "out-of-band release trust root")
		if subject == SubjectNode {
			flags.StringVar(&options.join, "join", "", "protected one-time node join file")
		} else {
			flags.StringVar(&options.securityMailConfiguration, "security-mail-configuration", "", "protected SMTP security-mail configuration file")
			flags.StringVar(&options.northboundOrigin, "northbound-origin", "", "canonical public HTTP origin with explicit port")
		}
	case lifecycle.ActionUpgrade:
		flags.StringVar(&options.bundle, "bundle", "", "verified offline release bundle directory")
		if subject == SubjectNode {
			flags.BoolVar(&options.resume, "resume", false, "resume only the sealed node release change")
		} else {
			flags.StringVar(&options.securityMailConfiguration, "security-mail-configuration", "", "protected SMTP security-mail configuration file")
		}
	case lifecycle.ActionRecover:
		flags.StringVar(&options.backupID, "backup", "", "verified installation-owned backup identity")
	case lifecycle.ActionSupport:
		flags.StringVar(&options.supportOutput, "output", "", "support evidence destination")
	}
}

func validateCommandFlags(subject Subject, action lifecycle.Action, options *commandOptions) error {
	if options == nil || strings.TrimSpace(options.root) == "" {
		return errors.New("installation root is required")
	}
	switch action {
	case lifecycle.ActionConfigureNodes:
		if subject != SubjectPlatform ||
			(options.resume && (options.configuration != "" || options.expectedConfigurationDigest != "")) ||
			(!options.resume && (strings.TrimSpace(options.configuration) == "" ||
				!sha256Pattern.MatchString(options.expectedConfigurationDigest))) {
			return errors.New("node configuration and expected digest, or explicit resume, are required")
		}
	case lifecycle.ActionRecoverCredentials:
		if subject != SubjectPlatform || options.resume == (strings.TrimSpace(options.recoveryInput) != "") ||
			(options.resume && options.recoveryInput != "") {
			return errors.New("protected recovery input or explicit resume is required, but not both")
		}
	case lifecycle.ActionRotateCredentials:
		if subject != SubjectNode || strings.TrimSpace(options.configuration) == "" ||
			!sha256Pattern.MatchString(options.expectedConfigurationDigest) {
			return errors.New("replacement enrollment and current configuration digest are required")
		}
	case lifecycle.ActionInstall:
		if strings.TrimSpace(options.bundle) == "" || strings.TrimSpace(options.trustKey) == "" {
			return errors.New("offline bundle and trust key are required")
		}
		if subject == SubjectNode && strings.TrimSpace(options.join) == "" {
			return errors.New("protected one-time node join is required")
		}
		if subject == SubjectPlatform &&
			(strings.TrimSpace(options.securityMailConfiguration) == "" ||
				externalrequest.ValidateOrigin(options.northboundOrigin) != nil) {
			return errors.New("security-mail configuration and canonical northbound origin are required")
		}
	case lifecycle.ActionUpgrade:
		if subject == SubjectNode {
			if options.resume == (strings.TrimSpace(options.bundle) != "") ||
				(options.resume && options.bundle != "") {
				return errors.New("offline node bundle or explicit resume is required, but not both")
			}
		} else if strings.TrimSpace(options.bundle) == "" ||
			strings.TrimSpace(options.securityMailConfiguration) == "" {
			return errors.New("offline bundle and security-mail configuration are required")
		}
	case lifecycle.ActionRecover:
		if strings.TrimSpace(options.backupID) == "" {
			return errors.New("backup identity is required")
		}
	case lifecycle.ActionSupport:
		if strings.TrimSpace(options.supportOutput) == "" {
			return errors.New("support output is required")
		}
	}
	return nil
}

func commandDescription(subject Subject, action lifecycle.Action) string {
	if subject == SubjectNode {
		switch action {
		case lifecycle.ActionInstall:
			return "Install and enroll a node from a signed one-time join"
		case lifecycle.ActionStart:
			return "Start or reconcile the sealed node and collector services"
		case lifecycle.ActionUpgrade:
			return "Activate a compatible signed successor without changing node enrollment"
		case lifecycle.ActionRollback:
			return "Restore the retained signed predecessor with current node credentials"
		case lifecycle.ActionVerify:
			return "Verify the sealed node and fresh collector observations"
		case lifecycle.ActionStatus:
			return "Read node supervision and readiness status"
		case lifecycle.ActionRotateCredentials:
			return "Rotate node credentials without changing workload ownership"
		case lifecycle.ActionSupport:
			return "Write a sanitized node snapshot without changing its lifecycle or services"
		}
	}
	switch action {
	case lifecycle.ActionInstall:
		return "Install an authenticated offline Matrix release"
	case lifecycle.ActionVerify:
		return "Verify the installed Matrix platform"
	case lifecycle.ActionStatus:
		return "Read Matrix platform status"
	case lifecycle.ActionBackup:
		return "Create a verified Matrix platform backup"
	case lifecycle.ActionUpgrade:
		return "Upgrade to the immediate next Matrix release"
	case lifecycle.ActionRollback:
		return "Roll back to the previous Matrix release"
	case lifecycle.ActionRecover:
		return "Recover from a verified Matrix platform backup"
	case lifecycle.ActionRecoverCredentials:
		return "Recover the original platform administrator's credentials without restoring authority"
	case lifecycle.ActionConfigureNodes:
		return "Configure protected node connections without admitting or relocating hosts"
	case lifecycle.ActionSupport:
		return "Write sanitized Matrix support evidence"
	default:
		panic("unsupported static Matrix platform command")
	}
}

func actionForCommand(command *cobra.Command) commandAction {
	if command == nil {
		return ""
	}
	if command.Parent() != nil && command.Parent().Name() == "source-credential" {
		switch command.Name() {
		case "apply":
			return actionSourceCredentialApply
		case "retire-previous":
			return actionSourceCredentialRetirePrevious
		}
	}
	if command.Parent() != nil && command.Parent().Name() == "source-trust" {
		switch command.Name() {
		case "apply":
			return actionSourceTrustApply
		case "remove":
			return actionSourceTrustRemove
		}
	}
	if command.Parent() != nil && command.Parent().Name() == "runner-node" {
		switch command.Name() {
		case "export-release":
			return actionRunnerNodeExportRelease
		case "request":
			return actionRunnerNodeRequest
		case "enroll":
			return actionRunnerNodeEnroll
		case "install":
			return actionRunnerNodeInstall
		}
	}
	switch command.Name() {
	case "install":
		return commandAction(lifecycle.ActionInstall)
	case "start":
		return commandAction(lifecycle.ActionStart)
	case "rotate-credentials":
		return commandAction(lifecycle.ActionRotateCredentials)
	case "verify":
		return commandAction(lifecycle.ActionVerify)
	case "status":
		return commandAction(lifecycle.ActionStatus)
	case "backup":
		return commandAction(lifecycle.ActionBackup)
	case "upgrade":
		return commandAction(lifecycle.ActionUpgrade)
	case "rollback":
		return commandAction(lifecycle.ActionRollback)
	case "recover":
		return commandAction(lifecycle.ActionRecover)
	case "recover-credentials":
		return commandAction(lifecycle.ActionRecoverCredentials)
	case "configure-nodes":
		return commandAction(lifecycle.ActionConfigureNodes)
	case "support":
		return commandAction(lifecycle.ActionSupport)
	default:
		return ""
	}
}

func subjectForCommand(command *cobra.Command) Subject {
	for current := command; current != nil; current = current.Parent() {
		switch current.Name() {
		case "node":
			return SubjectNode
		case "platform":
			return SubjectPlatform
		}
	}
	return SubjectPlatform
}

// Run is the process boundary used by cmd/mx. Subcommands return errors; this
// boundary alone renders a normalized failure and selects the stable exit
// class.
func Run(ctx context.Context, arguments []string, streams Streams, backends Backends) int {
	if ctx == nil {
		ctx = context.Background()
	}
	command, err := NewCommand(streams, backends)
	if err != nil {
		if streams.ErrOut != nil {
			_, _ = io.WriteString(streams.ErrOut, "Matrix CLI initialization failed\n")
		}
		return ExitInternal
	}
	command.SetArgs(arguments)
	executed, err := command.ExecuteContextC(ctx)
	if err == nil {
		return ExitSuccess
	}
	format, getErr := command.PersistentFlags().GetString("format")
	if getErr != nil || (outputFormat(format) != formatHuman && outputFormat(format) != formatJSON) {
		format = string(formatHuman)
	}
	action, fault := normalizeFailure(err, ctx)
	subject := subjectForCommand(executed)
	var invocation *invocationError
	if errors.As(err, &invocation) && invocation.subject != "" {
		subject = invocation.subject
	}
	if writeErr := writeFailure(
		streams.ErrOut, outputFormat(format), subject, action, fault,
	); writeErr != nil {
		return ExitInternal
	}
	return exitCode(fault.Class)
}

func normalizeFailure(err error, ctx context.Context) (commandAction, *Fault) {
	action := commandAction("")
	var invocation *invocationError
	if !errors.As(err, &invocation) {
		return action, mustFault(FaultInvalidArgument, "INVALID_COMMAND_INPUT")
	}
	action = invocation.action
	if invocation.usage {
		return action, mustFault(FaultInvalidArgument, "INVALID_COMMAND_INPUT")
	}
	if ctx != nil && ctx.Err() != nil {
		return action, mustFault(FaultInterrupted, "COMMAND_INTERRUPTED")
	}
	var fault *Fault
	if errors.As(err, &fault) && validateFault(fault) == nil {
		return action, fault
	}
	return action, mustFault(FaultInternal, "INTERNAL_ERROR")
}

func mustFault(class FaultClass, code string) *Fault {
	fault, err := NewFault(class, code)
	if err != nil {
		panic("static Matrix CLI fault is invalid")
	}
	return fault
}

func exitCode(class FaultClass) int {
	switch class {
	case FaultInvalidArgument:
		return ExitInvalidInput
	case FaultPrecondition:
		return ExitPrecondition
	case FaultConflict:
		return ExitConflict
	case FaultVerification:
		return ExitVerification
	case FaultUnavailable:
		return ExitUnavailable
	case FaultInterrupted:
		return ExitInterrupted
	default:
		return ExitInternal
	}
}

type successEnvelope struct {
	APIVersion string        `json:"apiVersion"`
	Kind       string        `json:"kind"`
	Action     commandAction `json:"action"`
	Status     string        `json:"status"`
	Result     Result        `json:"result"`
}

type sourceCredentialSuccessEnvelope struct {
	APIVersion string                 `json:"apiVersion"`
	Kind       string                 `json:"kind"`
	Action     commandAction          `json:"action"`
	Status     string                 `json:"status"`
	Result     SourceCredentialResult `json:"result"`
}

type sourceTrustSuccessEnvelope struct {
	APIVersion string            `json:"apiVersion"`
	Kind       string            `json:"kind"`
	Action     commandAction     `json:"action"`
	Status     string            `json:"status"`
	Result     SourceTrustResult `json:"result"`
}

type runnerNodeSuccessEnvelope struct {
	APIVersion string           `json:"apiVersion"`
	Kind       string           `json:"kind"`
	Action     commandAction    `json:"action"`
	Status     string           `json:"status"`
	Result     RunnerNodeResult `json:"result"`
}

type failureEnvelope struct {
	APIVersion string        `json:"apiVersion"`
	Kind       string        `json:"kind"`
	Action     commandAction `json:"action,omitempty"`
	Status     string        `json:"status"`
	Error      failureBody   `json:"error"`
}

type failureBody struct {
	Class   FaultClass `json:"class"`
	Code    string     `json:"code"`
	Message string     `json:"message"`
}

func writeSuccess(
	out io.Writer,
	format outputFormat,
	subject Subject,
	action lifecycle.Action,
	result Result,
) error {
	kind := "PlatformCommandResult"
	if subject == SubjectNode {
		kind = "NodeCommandResult"
	}
	if format == formatJSON {
		return writeJSONLine(out, successEnvelope{
			APIVersion: OutputAPIVersion, Kind: kind, Action: commandAction(action),
			Status: "SUCCEEDED", Result: result,
		})
	}
	_, err := fmt.Fprintf(out, "%s SUCCEEDED state=%s", action, result.State)
	if err == nil && result.ReleaseID != "" {
		_, err = fmt.Fprintf(out, " release=%s", result.ReleaseID)
	}
	if err == nil && result.BackupID != "" {
		_, err = fmt.Fprintf(out, " backup=%s", result.BackupID)
	}
	if err == nil && result.ExecutionTargetID != "" {
		_, err = fmt.Fprintf(out, " target=%s", result.ExecutionTargetID)
	}
	if err == nil && result.ConfigurationDigest != "" {
		_, err = fmt.Fprintf(out, " configuration=%s", result.ConfigurationDigest)
	}
	if err == nil {
		_, err = io.WriteString(out, "\n")
	}
	return err
}

func writeSourceCredentialSuccess(
	out io.Writer,
	format outputFormat,
	action commandAction,
	result SourceCredentialResult,
) error {
	if format == formatJSON {
		return writeJSONLine(out, sourceCredentialSuccessEnvelope{
			APIVersion: OutputAPIVersion, Kind: "SourceCredentialCommandResult",
			Action: action, Status: "SUCCEEDED", Result: result,
		})
	}
	_, err := fmt.Fprintf(
		out, "%s SUCCEEDED state=%s purpose=%s tenant=%s reference=%s\n",
		action, result.State, result.Purpose, result.TenantID, result.Reference,
	)
	return err
}

func writeSourceTrustSuccess(
	out io.Writer,
	format outputFormat,
	action commandAction,
	result SourceTrustResult,
) error {
	if format == formatJSON {
		return writeJSONLine(out, sourceTrustSuccessEnvelope{
			APIVersion: OutputAPIVersion, Kind: "SourceTrustCommandResult",
			Action: action, Status: "SUCCEEDED", Result: result,
		})
	}
	_, err := fmt.Fprintf(
		out, "%s SUCCEEDED state=%s tenant=%s endpoint-origin=%s\n",
		action, result.State, result.TenantID, result.EndpointOrigin,
	)
	return err
}

func writeRunnerNodeSuccess(
	out io.Writer,
	format outputFormat,
	action commandAction,
	result RunnerNodeResult,
) error {
	if format == formatJSON {
		return writeJSONLine(out, runnerNodeSuccessEnvelope{
			APIVersion: OutputAPIVersion, Kind: "RunnerNodeCommandResult",
			Action: action, Status: "SUCCEEDED", Result: result,
		})
	}
	_, err := fmt.Fprintf(
		out, "%s SUCCEEDED state=%s release=%s", action, result.State, result.ReleaseID,
	)
	if err == nil && result.ServerCAPin != "" {
		_, err = fmt.Fprintf(
			out, " server-ca=%s runner-ca=%s", result.ServerCAPin, result.RunnerCAPin,
		)
	}
	if err == nil && result.NodeID != "" {
		_, err = fmt.Fprintf(out, " node=%s slots=%d request=%s", result.NodeID, result.Slots, result.RequestDigest)
	}
	if err == nil {
		_, err = io.WriteString(out, "\n")
	}
	return err
}

func writeFailure(
	out io.Writer,
	format outputFormat,
	subject Subject,
	action commandAction,
	fault *Fault,
) error {
	message := faultMessage(fault.Class)
	if subject == SubjectNode {
		message = strings.ReplaceAll(strings.ReplaceAll(message, "Platform", "Node"), "platform", "node")
	}
	if format == formatJSON {
		kind := "PlatformCommandFailure"
		if subject == SubjectNode {
			kind = "NodeCommandFailure"
		} else if action == actionSourceCredentialApply || action == actionSourceCredentialRetirePrevious {
			kind = "SourceCredentialCommandFailure"
		} else if action == actionSourceTrustApply || action == actionSourceTrustRemove {
			kind = "SourceTrustCommandFailure"
		} else if action == actionRunnerNodeExportRelease || action == actionRunnerNodeRequest ||
			action == actionRunnerNodeEnroll || action == actionRunnerNodeInstall {
			kind = "RunnerNodeCommandFailure"
		}
		return writeJSONLine(out, failureEnvelope{
			APIVersion: OutputAPIVersion, Kind: kind, Action: action,
			Status: "FAILED", Error: failureBody{Class: fault.Class, Code: fault.Code, Message: message},
		})
	}
	_, err := fmt.Fprintf(out, "%s: %s\n", fault.Code, message)
	return err
}

func faultMessage(class FaultClass) string {
	switch class {
	case FaultInvalidArgument:
		return "Command input is invalid"
	case FaultPrecondition:
		return "Matrix preconditions are not satisfied"
	case FaultConflict:
		return "Matrix state conflicts with this command"
	case FaultVerification:
		return "Matrix verification failed"
	case FaultUnavailable:
		return "A required Matrix dependency is unavailable"
	case FaultInterrupted:
		return "Command was interrupted"
	default:
		return "Matrix could not complete the command"
	}
}

func writeJSONLine(out io.Writer, value any) error {
	encoder := json.NewEncoder(out)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(value)
}
