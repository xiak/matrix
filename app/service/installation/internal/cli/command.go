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
	"github.com/xiak/matrix/app/service/devops/sourcecredential"
	"github.com/xiak/matrix/app/service/installation/internal/lifecycle"
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
	actionRunnerNodeExportRelease        commandAction = "RUNNER_NODE_EXPORT_RELEASE"
	actionRunnerNodeRequest              commandAction = "RUNNER_NODE_REQUEST"
	actionRunnerNodeEnroll               commandAction = "RUNNER_NODE_ENROLL"
	actionRunnerNodeInstall              commandAction = "RUNNER_NODE_INSTALL"
)

type invocationError struct {
	action commandAction
	usage  bool
	err    error
}

func (value *invocationError) Error() string { return "platform command failed" }
func (value *invocationError) Unwrap() error { return value.err }

type commandOptions struct {
	root          string
	bundle        string
	trustKey      string
	backupID      string
	supportOutput string
}

type sourceCredentialOptions struct {
	root      string
	tenantID  string
	purpose   string
	reference string
	fromFile  string
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
	if backends.Platform == nil || backends.SourceCredential == nil || backends.RunnerNode == nil {
		return nil, errors.New("Matrix CLI backends are required")
	}
	format := string(formatHuman)
	root := &cobra.Command{
		Use:           "mx",
		Short:         "Operate the Matrix platform",
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
				action: actionForCommand(command), usage: true,
				err: errors.New("output format must be human or json"),
			}
		}
		return nil
	}
	root.SetFlagErrorFunc(func(command *cobra.Command, err error) error {
		return &invocationError{action: actionForCommand(command), usage: true, err: err}
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
	platform.AddCommand(
		newPlatformCommand(streams.Out, backends.Platform, lifecycle.ActionInstall, &format),
		newPlatformCommand(streams.Out, backends.Platform, lifecycle.ActionVerify, &format),
		newPlatformCommand(streams.Out, backends.Platform, lifecycle.ActionStatus, &format),
		newPlatformCommand(streams.Out, backends.Platform, lifecycle.ActionBackup, &format),
		newPlatformCommand(streams.Out, backends.Platform, lifecycle.ActionUpgrade, &format),
		newPlatformCommand(streams.Out, backends.Platform, lifecycle.ActionRollback, &format),
		newPlatformCommand(streams.Out, backends.Platform, lifecycle.ActionRecover, &format),
		newPlatformCommand(streams.Out, backends.Platform, lifecycle.ActionSupport, &format),
	)
	root.AddCommand(newDevOpsCommand(
		streams.Out, backends.SourceCredential, backends.RunnerNode, &format,
	))
	return root, nil
}

func newPlatformCommand(
	out io.Writer,
	backend PlatformBackend,
	action lifecycle.Action,
	format *string,
) *cobra.Command {
	options := &commandOptions{}
	name := strings.ToLower(string(action))
	command := &cobra.Command{
		Use:   name,
		Short: commandDescription(action),
		Args:  cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			if err := validateCommandFlags(action, options); err != nil {
				return &invocationError{action: commandAction(action), usage: true, err: err}
			}
			request := Request{
				Action: action, Root: options.root, Bundle: options.bundle, TrustKey: options.trustKey,
				BackupID: options.backupID, SupportOutput: options.supportOutput,
			}
			result, err := backend.Run(command.Context(), request)
			if err != nil {
				return &invocationError{action: commandAction(action), err: err}
			}
			if err := validateResult(result); err != nil {
				return &invocationError{action: commandAction(action), err: err}
			}
			if err := writeSuccess(out, outputFormat(*format), action, result); err != nil {
				return &invocationError{action: commandAction(action), err: err}
			}
			return nil
		},
	}
	bindCommandFlags(command.Flags(), action, options)
	return command
}

func newDevOpsCommand(
	out io.Writer,
	sourceBackend SourceCredentialBackend,
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
	devops.AddCommand(source, newRunnerNodeCommand(out, runnerBackend, format))
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

func bindCommandFlags(flags *pflag.FlagSet, action lifecycle.Action, options *commandOptions) {
	flags.StringVar(&options.root, "root", "", "absolute Matrix installation root")
	switch action {
	case lifecycle.ActionInstall:
		flags.StringVar(&options.bundle, "bundle", "", "verified offline release bundle directory")
		flags.StringVar(&options.trustKey, "trust-key", "", "out-of-band release trust root")
	case lifecycle.ActionUpgrade:
		flags.StringVar(&options.bundle, "bundle", "", "verified offline release bundle directory")
	case lifecycle.ActionRecover:
		flags.StringVar(&options.backupID, "backup", "", "verified installation-owned backup identity")
	case lifecycle.ActionSupport:
		flags.StringVar(&options.supportOutput, "output", "", "support evidence destination")
	}
}

func validateCommandFlags(action lifecycle.Action, options *commandOptions) error {
	if options == nil || strings.TrimSpace(options.root) == "" {
		return errors.New("installation root is required")
	}
	switch action {
	case lifecycle.ActionInstall:
		if strings.TrimSpace(options.bundle) == "" || strings.TrimSpace(options.trustKey) == "" {
			return errors.New("offline bundle and trust key are required")
		}
	case lifecycle.ActionUpgrade:
		if strings.TrimSpace(options.bundle) == "" {
			return errors.New("offline bundle is required")
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

func commandDescription(action lifecycle.Action) string {
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
	case "support":
		return commandAction(lifecycle.ActionSupport)
	default:
		return ""
	}
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
	err = command.ExecuteContext(ctx)
	if err == nil {
		return ExitSuccess
	}
	format, getErr := command.PersistentFlags().GetString("format")
	if getErr != nil || (outputFormat(format) != formatHuman && outputFormat(format) != formatJSON) {
		format = string(formatHuman)
	}
	action, fault := normalizeFailure(err, ctx)
	if writeErr := writeFailure(streams.ErrOut, outputFormat(format), action, fault); writeErr != nil {
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

func writeSuccess(out io.Writer, format outputFormat, action lifecycle.Action, result Result) error {
	if format == formatJSON {
		return writeJSONLine(out, successEnvelope{
			APIVersion: OutputAPIVersion, Kind: "PlatformCommandResult", Action: commandAction(action),
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

func writeFailure(out io.Writer, format outputFormat, action commandAction, fault *Fault) error {
	message := faultMessage(fault.Class)
	if format == formatJSON {
		kind := "PlatformCommandFailure"
		if action == actionSourceCredentialApply || action == actionSourceCredentialRetirePrevious {
			kind = "SourceCredentialCommandFailure"
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
