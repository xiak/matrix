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

func NewCommand(streams Streams, backends Backends) (*cobra.Command, error) {
	if err := validateStreams(streams); err != nil {
		return nil, err
	}
	if backends.Platform == nil || backends.SourceCredential == nil {
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
	root.AddCommand(newDevOpsCommand(streams.Out, backends.SourceCredential, &format))
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
	backend SourceCredentialBackend,
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
			out, backend, SourceCredentialApply, format,
		),
		newSourceCredentialOperationCommand(
			out, backend, SourceCredentialRetirePrevious, format,
		),
	)
	devops.AddCommand(source)
	return devops
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

func writeFailure(out io.Writer, format outputFormat, action commandAction, fault *Fault) error {
	message := faultMessage(fault.Class)
	if format == formatJSON {
		kind := "PlatformCommandFailure"
		if action == actionSourceCredentialApply || action == actionSourceCredentialRetirePrevious {
			kind = "SourceCredentialCommandFailure"
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
