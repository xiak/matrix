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

type invocationError struct {
	subject Subject
	action  lifecycle.Action
	usage   bool
	err     error
}

func (value *invocationError) Error() string { return "Matrix command failed" }
func (value *invocationError) Unwrap() error { return value.err }

type commandOptions struct {
	root                        string
	bundle                      string
	trustKey                    string
	backupID                    string
	supportOutput               string
	configuration               string
	expectedConfigurationDigest string
	revokePreviousCredentials   bool
	recoveryInput               string
	resume                      bool
}

func NewCommand(streams Streams, backend Backend) (*cobra.Command, error) {
	if err := validateStreams(streams); err != nil {
		return nil, err
	}
	if backend == nil {
		return nil, errors.New("Matrix CLI backend is required")
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
	root.SetFlagErrorFunc(func(command *cobra.Command, err error) error {
		return &invocationError{subject: subjectForCommand(command), action: actionForCommand(command), usage: true, err: err}
	})

	root.PersistentPreRunE = func(command *cobra.Command, _ []string) error {
		if outputFormat(format) != formatHuman && outputFormat(format) != formatJSON {
			return &invocationError{
				subject: subjectForCommand(command), action: actionForCommand(command), usage: true,
				err: errors.New("output format must be human or json"),
			}
		}
		return nil
	}
	platform := &cobra.Command{
		Use: "platform", Short: "Install and operate the private Matrix platform", Args: cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			return command.Help()
		},
	}
	root.AddCommand(platform)
	for _, action := range []lifecycle.Action{lifecycle.ActionInstall, lifecycle.ActionVerify,
		lifecycle.ActionStatus, lifecycle.ActionBackup, lifecycle.ActionUpgrade,
		lifecycle.ActionRollback, lifecycle.ActionRecover, lifecycle.ActionRecoverCredentials, lifecycle.ActionConfigureNodes, lifecycle.ActionSupport} {
		platform.AddCommand(newLifecycleCommand(streams.Out, backend, SubjectPlatform, action, &format))
	}
	node := &cobra.Command{
		Use: "node", Short: "Enroll and supervise an existing Linux execution node", Args: cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error { return command.Help() },
	}
	root.AddCommand(node)
	for _, action := range []lifecycle.Action{lifecycle.ActionInstall, lifecycle.ActionStart,
		lifecycle.ActionVerify, lifecycle.ActionStatus, lifecycle.ActionRotateCredentials,
		lifecycle.ActionUpgrade, lifecycle.ActionRollback, lifecycle.ActionSupport} {
		node.AddCommand(newLifecycleCommand(streams.Out, backend, SubjectNode, action, &format))
	}
	return root, nil
}

func newLifecycleCommand(
	out io.Writer,
	backend Backend,
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
				return &invocationError{subject: subject, action: action, usage: true, err: err}
			}
			request := Request{
				Subject: subject, Action: action, Root: options.root, Bundle: options.bundle, TrustKey: options.trustKey,
				BackupID: options.backupID, SupportOutput: options.supportOutput,
				Configuration:               options.configuration,
				ExpectedConfigurationDigest: options.expectedConfigurationDigest,
				RevokePreviousCredentials:   options.revokePreviousCredentials,
				RecoveryInput:               options.recoveryInput,
				Resume:                      options.resume,
			}
			result, err := backend.Run(command.Context(), request)
			if err != nil {
				return &invocationError{subject: subject, action: action, err: err}
			}
			if err := validateResult(result); err != nil {
				return &invocationError{subject: subject, action: action, err: err}
			}
			if err := writeSuccess(out, outputFormat(*format), subject, action, result); err != nil {
				return &invocationError{subject: subject, action: action, err: err}
			}
			return nil
		},
	}
	bindCommandFlags(command.Flags(), subject, action, options)
	return command
}

func bindCommandFlags(flags *pflag.FlagSet, subject Subject, action lifecycle.Action, options *commandOptions) {
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
			flags.StringVar(&options.configuration, "configuration", "", "protected node enrollment file")
		}
	case lifecycle.ActionUpgrade:
		flags.StringVar(&options.bundle, "bundle", "", "verified offline release bundle directory")
		if subject == SubjectNode {
			flags.BoolVar(&options.resume, "resume", false, "resume only the sealed node release change")
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
		if subject != SubjectPlatform || (options.resume && (options.configuration != "" || options.expectedConfigurationDigest != "")) ||
			(!options.resume && (strings.TrimSpace(options.configuration) == "" || !safeDigestPattern.MatchString(options.expectedConfigurationDigest))) {
			return errors.New("node configuration and expected digest, or explicit resume, are required")
		}
	case lifecycle.ActionRecoverCredentials:
		if subject != SubjectPlatform || options.resume == (strings.TrimSpace(options.recoveryInput) != "") ||
			(options.resume && options.recoveryInput != "") {
			return errors.New("protected recovery input or explicit resume is required, but not both")
		}
	case lifecycle.ActionRotateCredentials:
		if subject != SubjectNode || strings.TrimSpace(options.configuration) == "" ||
			!safeDigestPattern.MatchString(options.expectedConfigurationDigest) {
			return errors.New("replacement enrollment and current configuration digest are required")
		}
	case lifecycle.ActionInstall:
		if strings.TrimSpace(options.bundle) == "" || strings.TrimSpace(options.trustKey) == "" {
			return errors.New("offline bundle and trust key are required")
		}
		if subject == SubjectNode && strings.TrimSpace(options.configuration) == "" {
			return errors.New("protected node enrollment is required")
		}
	case lifecycle.ActionUpgrade:
		if subject == SubjectNode {
			if options.resume == (strings.TrimSpace(options.bundle) != "") || (options.resume && options.bundle != "") {
				return errors.New("offline node bundle or explicit resume is required, but not both")
			}
		} else if strings.TrimSpace(options.bundle) == "" {
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

func commandDescription(subject Subject, action lifecycle.Action) string {
	if subject == SubjectNode {
		switch action {
		case lifecycle.ActionInstall:
			return "Install an authenticated offline node release"
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

func actionForCommand(command *cobra.Command) lifecycle.Action {
	if command == nil {
		return ""
	}
	switch command.Name() {
	case "install":
		return lifecycle.ActionInstall
	case "start":
		return lifecycle.ActionStart
	case "rotate-credentials":
		return lifecycle.ActionRotateCredentials
	case "verify":
		return lifecycle.ActionVerify
	case "status":
		return lifecycle.ActionStatus
	case "backup":
		return lifecycle.ActionBackup
	case "upgrade":
		return lifecycle.ActionUpgrade
	case "rollback":
		return lifecycle.ActionRollback
	case "recover":
		return lifecycle.ActionRecover
	case "recover-credentials":
		return lifecycle.ActionRecoverCredentials
	case "support":
		return lifecycle.ActionSupport
	default:
		return ""
	}
}

func subjectForCommand(command *cobra.Command) Subject {
	for current := command; current != nil; current = current.Parent() {
		if current.Name() == "node" {
			return SubjectNode
		}
		if current.Name() == "platform" {
			return SubjectPlatform
		}
	}
	return SubjectPlatform
}

// Run is the process boundary used by cmd/mx. Subcommands return errors; this
// boundary alone renders a normalized failure and selects the stable exit
// class.
func Run(ctx context.Context, arguments []string, streams Streams, backend Backend) int {
	if ctx == nil {
		ctx = context.Background()
	}
	command, err := NewCommand(streams, backend)
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
	if writeErr := writeFailure(streams.ErrOut, outputFormat(format), subject, action, fault); writeErr != nil {
		return ExitInternal
	}
	return exitCode(fault.Class)
}

func normalizeFailure(err error, ctx context.Context) (lifecycle.Action, *Fault) {
	action := lifecycle.Action("")
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
	APIVersion string           `json:"apiVersion"`
	Kind       string           `json:"kind"`
	Action     lifecycle.Action `json:"action"`
	Status     string           `json:"status"`
	Result     Result           `json:"result"`
}

type failureEnvelope struct {
	APIVersion string           `json:"apiVersion"`
	Kind       string           `json:"kind"`
	Action     lifecycle.Action `json:"action,omitempty"`
	Status     string           `json:"status"`
	Error      failureBody      `json:"error"`
}

type failureBody struct {
	Class   FaultClass `json:"class"`
	Code    string     `json:"code"`
	Message string     `json:"message"`
}

func writeSuccess(out io.Writer, format outputFormat, subject Subject, action lifecycle.Action, result Result) error {
	kind := "PlatformCommandResult"
	if subject == SubjectNode {
		kind = "NodeCommandResult"
	}
	if format == formatJSON {
		return writeJSONLine(out, successEnvelope{
			APIVersion: OutputAPIVersion, Kind: kind, Action: action,
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

func writeFailure(out io.Writer, format outputFormat, subject Subject, action lifecycle.Action, fault *Fault) error {
	message := faultMessage(fault.Class)
	kind := "PlatformCommandFailure"
	if subject == SubjectNode {
		kind = "NodeCommandFailure"
		message = strings.ReplaceAll(strings.ReplaceAll(message, "Platform", "Node"), "platform", "node")
	}
	if format == formatJSON {
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
		return "Platform preconditions are not satisfied"
	case FaultConflict:
		return "Platform state conflicts with this command"
	case FaultVerification:
		return "Platform verification failed"
	case FaultUnavailable:
		return "A required platform dependency is unavailable"
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
