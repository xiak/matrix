package localmachine

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"regexp"

	"golang.org/x/crypto/ssh"

	paasv1 "matrix/api/paas/v1"
)

var sshUsernamePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9._-]{0,63}$`)

type SSHCredentialSpec struct {
	Username      string
	PrivateKeyPEM []byte
	Passphrase    []byte
}

// SSHCredential retains a parsed signer rather than raw PEM or passphrase
// bytes. It is server-side access material and never a versioned API type.
type SSHCredential struct {
	username string
	signer   ssh.Signer
}

func NewSSHCredential(spec SSHCredentialSpec) (SSHCredential, error) {
	if !sshUsernamePattern.MatchString(spec.Username) {
		return SSHCredential{}, errors.New("SSH credential username is invalid")
	}
	if len(spec.PrivateKeyPEM) == 0 || len(spec.PrivateKeyPEM) > 64*1024 {
		return SSHCredential{}, errors.New("SSH private key must contain 1 to 65536 bytes")
	}
	if len(spec.Passphrase) > 4096 {
		return SSHCredential{}, errors.New("SSH private key passphrase exceeds 4096 bytes")
	}
	privateKeyPEM := bytes.Clone(spec.PrivateKeyPEM)
	passphrase := bytes.Clone(spec.Passphrase)
	defer clear(privateKeyPEM)
	defer clear(passphrase)
	var signer ssh.Signer
	var err error
	if len(passphrase) == 0 {
		signer, err = ssh.ParsePrivateKey(privateKeyPEM)
	} else {
		signer, err = ssh.ParsePrivateKeyWithPassphrase(
			privateKeyPEM,
			passphrase,
		)
	}
	if err != nil {
		return SSHCredential{}, errors.New("SSH private key could not be parsed")
	}
	value := SSHCredential{username: spec.Username, signer: signer}
	if err := ValidateSSHCredential(value); err != nil {
		return SSHCredential{}, err
	}
	return value, nil
}

func ValidateSSHCredential(value SSHCredential) error {
	var problems []error
	if !sshUsernamePattern.MatchString(value.username) {
		problems = append(problems, errors.New("SSH credential username is invalid"))
	}
	if value.signer == nil {
		problems = append(problems, errors.New("SSH credential signer is required"))
	}
	return errors.Join(problems...)
}

func (value SSHCredential) String() string {
	return "SSHCredential{username:<redacted> signer:<redacted>}"
}

func (value SSHCredential) GoString() string {
	return value.String()
}

type SSHCredentialResolver interface {
	ResolveSSHCredential(context.Context, string) (SSHCredential, error)
}

var ErrCredentialNotFound = errors.New("SSH credential not found")

type StaticSSHCredentialResolver struct {
	credentials map[string]SSHCredential
}

type NamedSSHCredential struct {
	Ref        string
	Credential SSHCredential
}

func NewStaticSSHCredentialResolver(
	values ...NamedSSHCredential,
) (*StaticSSHCredentialResolver, error) {
	credentials := make(map[string]SSHCredential, len(values))
	for index, value := range values {
		if err := validateCredentialRef(value.Ref); err != nil {
			return nil, fmt.Errorf("credential[%d]: %w", index, err)
		}
		if err := ValidateSSHCredential(value.Credential); err != nil {
			return nil, fmt.Errorf("credential[%d]: %w", index, err)
		}
		if _, found := credentials[value.Ref]; found {
			return nil, fmt.Errorf("credential[%d] duplicates ref %q", index, value.Ref)
		}
		credentials[value.Ref] = value.Credential
	}
	return &StaticSSHCredentialResolver{credentials: credentials}, nil
}

func (resolver *StaticSSHCredentialResolver) ResolveSSHCredential(
	ctx context.Context,
	ref string,
) (SSHCredential, error) {
	if err := ctx.Err(); err != nil {
		return SSHCredential{}, err
	}
	if resolver == nil {
		return SSHCredential{}, ErrCredentialNotFound
	}
	value, found := resolver.credentials[ref]
	if !found {
		return SSHCredential{}, ErrCredentialNotFound
	}
	return value, nil
}

func validateCredentialRef(value string) error {
	return paasv1.ValidateID("SSH credential reference", value)
}
