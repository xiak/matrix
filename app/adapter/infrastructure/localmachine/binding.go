package localmachine

import (
	"context"
	"errors"
	"fmt"
	"net"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	paasv1 "matrix/api/paas/v1"
)

type BindingKind string

const (
	BindingLocal BindingKind = "LOCAL"
	BindingSSH   BindingKind = "SSH"
)

var (
	hostKeyFingerprintPattern = regexp.MustCompile(`^SHA256:[A-Za-z0-9+/]{43}$`)
	dnsLabelPattern           = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
)

var reservedLabels = map[string]struct{}{
	"matrix-arch": {},
	"matrix-os":   {},
}

type MachineBindingSpec struct {
	ID                         string
	Kind                       BindingKind
	Endpoint                   string
	CredentialRef              string
	HostKeySHA256              string
	ExpectedMachineFingerprint string
	Labels                     map[string]string
	AllowedIsolationClasses    []paasv1.IsolationClass
	StoragePath                string
}

// MachineBinding is deployment-owned access configuration. Its access fields
// never cross the versioned adapter observation boundary.
type MachineBinding struct {
	id                         string
	kind                       BindingKind
	endpoint                   string
	credentialRef              string
	hostKeySHA256              string
	expectedMachineFingerprint string
	labels                     map[string]string
	allowedIsolationClasses    []paasv1.IsolationClass
	storagePath                string
}

func NewMachineBinding(spec MachineBindingSpec) (MachineBinding, error) {
	isolationClasses := slices.Clone(spec.AllowedIsolationClasses)
	slices.Sort(isolationClasses)
	value := MachineBinding{
		id:                         spec.ID,
		kind:                       spec.Kind,
		endpoint:                   spec.Endpoint,
		credentialRef:              spec.CredentialRef,
		hostKeySHA256:              spec.HostKeySHA256,
		expectedMachineFingerprint: spec.ExpectedMachineFingerprint,
		labels:                     cloneLabels(spec.Labels),
		allowedIsolationClasses:    isolationClasses,
		storagePath:                spec.StoragePath,
	}
	if err := ValidateMachineBinding(value); err != nil {
		return MachineBinding{}, err
	}
	return value, nil
}

func ValidateMachineBinding(value MachineBinding) error {
	var problems []error
	problems = append(problems,
		paasv1.ValidateID("machine binding id", value.id),
		paasv1.ValidateLabels(value.labels),
		validateBindingLabels(value.labels),
		validateAllowedIsolationClasses(value.allowedIsolationClasses),
	)
	if value.expectedMachineFingerprint != "" {
		problems = append(
			problems,
			paasv1.ValidateDigest(
				"expected machine fingerprint",
				value.expectedMachineFingerprint,
			),
		)
	}

	switch value.kind {
	case BindingLocal:
		if value.endpoint != "" ||
			value.credentialRef != "" ||
			value.hostKeySHA256 != "" {
			problems = append(
				problems,
				errors.New("local binding cannot contain SSH access settings"),
			)
		}
		if value.storagePath != "" &&
			(!filepath.IsAbs(value.storagePath) ||
				filepath.Clean(value.storagePath) != value.storagePath) {
			problems = append(
				problems,
				errors.New("local storage path must be a canonical absolute path"),
			)
		}
	case BindingSSH:
		problems = append(problems,
			validateSSHEndpoint(value.endpoint),
			paasv1.ValidateID("credential reference", value.credentialRef),
		)
		if !hostKeyFingerprintPattern.MatchString(value.hostKeySHA256) {
			problems = append(
				problems,
				errors.New("SSH host key must be a pinned SHA-256 fingerprint"),
			)
		}
		if value.storagePath != "" &&
			(!path.IsAbs(value.storagePath) ||
				path.Clean(value.storagePath) != value.storagePath) {
			problems = append(
				problems,
				errors.New("remote storage path must be a canonical absolute POSIX path"),
			)
		}
	default:
		problems = append(problems, fmt.Errorf("unknown machine binding kind %q", value.kind))
	}
	return errors.Join(problems...)
}

func (value MachineBinding) ID() string {
	return value.id
}

func (value MachineBinding) Kind() BindingKind {
	return value.kind
}

func (value MachineBinding) Labels() map[string]string {
	return cloneLabels(value.labels)
}

func (value MachineBinding) AllowedIsolationClasses() []paasv1.IsolationClass {
	return slices.Clone(value.allowedIsolationClasses)
}

func (value MachineBinding) StoragePath() string {
	return value.storagePath
}

func (value MachineBinding) ExpectedMachineFingerprint() string {
	return value.expectedMachineFingerprint
}

func (value MachineBinding) clone() MachineBinding {
	value.labels = cloneLabels(value.labels)
	value.allowedIsolationClasses = slices.Clone(value.allowedIsolationClasses)
	return value
}

type BindingResolver interface {
	Resolve(context.Context, string) (MachineBinding, error)
}

var ErrBindingNotFound = errors.New("machine binding not found")

type StaticBindingResolver struct {
	bindings map[string]MachineBinding
}

func NewStaticBindingResolver(bindings ...MachineBinding) (*StaticBindingResolver, error) {
	values := make(map[string]MachineBinding, len(bindings))
	for index, binding := range bindings {
		if err := ValidateMachineBinding(binding); err != nil {
			return nil, fmt.Errorf("binding[%d]: %w", index, err)
		}
		if _, found := values[binding.id]; found {
			return nil, fmt.Errorf("binding[%d] duplicates id %q", index, binding.id)
		}
		values[binding.id] = binding.clone()
	}
	return &StaticBindingResolver{bindings: values}, nil
}

func (resolver *StaticBindingResolver) Resolve(
	ctx context.Context,
	id string,
) (MachineBinding, error) {
	if err := ctx.Err(); err != nil {
		return MachineBinding{}, err
	}
	if resolver == nil {
		return MachineBinding{}, ErrBindingNotFound
	}
	value, found := resolver.bindings[id]
	if !found {
		return MachineBinding{}, ErrBindingNotFound
	}
	return value.clone(), nil
}

func validateBindingLabels(labels map[string]string) error {
	var problems []error
	for key, value := range labels {
		if _, reserved := reservedLabels[key]; reserved {
			problems = append(problems, fmt.Errorf("label %q is adapter reserved", key))
		}
		if err := validateSafeExternalText("label "+key, value, 128, false); err != nil {
			problems = append(problems, err)
		}
	}
	return errors.Join(problems...)
}

func validateAllowedIsolationClasses(values []paasv1.IsolationClass) error {
	if len(values) == 0 {
		return errors.New("allowed isolation classes must not be empty")
	}
	var problems []error
	for index, value := range values {
		switch value {
		case paasv1.IsolationSharedCompose, paasv1.IsolationDedicatedCompose:
		default:
			problems = append(
				problems,
				fmt.Errorf("allowed isolation class %q is unsupported", value),
			)
		}
		if index > 0 && values[index-1] >= value {
			problems = append(
				problems,
				errors.New("allowed isolation classes must be a canonical unique set"),
			)
		}
	}
	return errors.Join(problems...)
}

func validateSSHEndpoint(value string) error {
	host, portText, err := net.SplitHostPort(value)
	if err != nil || host == "" {
		return errors.New("SSH endpoint must be an explicit host:port")
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return errors.New("SSH endpoint port must be between 1 and 65535")
	}
	if strings.Contains(host, "%") {
		return errors.New("SSH endpoint cannot contain an IPv6 zone")
	}
	if net.ParseIP(host) != nil {
		return nil
	}
	if len(host) > 253 || host != strings.ToLower(host) {
		return errors.New("SSH endpoint host must be a lowercase DNS name or IP address")
	}
	for _, label := range strings.Split(host, ".") {
		if !dnsLabelPattern.MatchString(label) {
			return errors.New("SSH endpoint host must be a lowercase DNS name or IP address")
		}
	}
	return nil
}

func validateSafeExternalText(name, value string, maxBytes int, required bool) error {
	return paasv1.ValidateSafeExternalText(name, value, maxBytes, required)
}

func cloneLabels(source map[string]string) map[string]string {
	if source == nil {
		return nil
	}
	result := make(map[string]string, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}
