package paasv1

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

var (
	idPattern                   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	namePattern                 = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
	environmentKeyPattern       = regexp.MustCompile(`^[A-Z_][A-Z0-9_]{0,127}$`)
	digestPattern               = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	contractVersionPattern      = regexp.MustCompile(`^v[1-9][0-9]*$`)
	deploymentInstanceIDPattern = regexp.MustCompile(`^instance-[0-9a-f]{32}$`)
	terminalSessionIDPattern    = regexp.MustCompile(`^terminal-session-[0-9a-f]{32}$`)
	nodeEnrollmentIDPattern     = regexp.MustCompile(`^node-enrollment-[0-9a-f]{32}$`)
	nodeExchangeIDPattern       = regexp.MustCompile(`^node-exchange-[0-9a-f]{32}$`)
	nodeBindingIDPattern        = regexp.MustCompile(`^node-binding-[0-9a-f]{32}$`)
)

const (
	MaximumExecutionPoolListItems                  = 129
	MaximumNodeEnrollmentListItems                 = 128
	MaximumNodeEnrollmentLifetime                  = 30 * time.Minute
	MaximumNodeEnrollmentCertificateLifetime       = 30 * 24 * time.Hour
	MaximumNodeEnrollmentRecoveryChallengeLifetime = 5 * time.Minute
	MinimumNodeEnrollmentListenerPort              = 1024
	NodeEnrollmentJoinAPIVersion                   = "node.enrollment.matrix.xiak.com/v1"
	NodeEnrollmentJoinKind                         = "NodeEnrollmentJoin"
	NodeEnrollmentExchangeAPIVersion               = "node.enrollment.matrix.xiak.com/v1"
	NodeEnrollmentExchangeRequestKind              = "NodeEnrollmentExchangeRequest"
	NodeEnrollmentExchangeResponseKind             = "NodeEnrollmentExchangeResponse"
	NodeEnrollmentRecoveryAPIVersion               = "node.enrollment.matrix.xiak.com/v1"
	NodeEnrollmentRecoveryChallengeRequestKind     = "NodeEnrollmentRecoveryChallengeRequest"
	NodeEnrollmentRecoveryChallengeKind            = "NodeEnrollmentRecoveryChallenge"
	NodeEnrollmentRecoveryProofRequestKind         = "NodeEnrollmentRecoveryProofRequest"
	NodeEnrollmentCompletionRequestKind            = "NodeEnrollmentCompletionRequest"
)

var sensitiveKeyFragments = [...]string{
	"access_key",
	"accesskey",
	"api_key",
	"apikey",
	"authorization",
	"cookie",
	"credential",
	"password",
	"private_key",
	"privatekey",
	"refresh_token",
	"secret",
	"set-cookie",
	"token",
}

var rawSensitiveMaterialMarkers = [...]string{
	"authorization: bearer",
	"bearer ",
	"password=",
	"passwd=",
	"secret=",
	"client_secret=",
	"token=",
	"access_token=",
	"refresh_token=",
	"id_token=",
	"api_key=",
	"private_key=",
	"-----begin private key-----",
	"aws_secret_access_key",
	"credential_material=",
	"session_cookie=",
}

func ValidateID(name, value string) error {
	if !idPattern.MatchString(value) {
		return fmt.Errorf("%s must be an opaque 1-128 character identifier", name)
	}
	return nil
}

func ValidateDigest(name, value string) error {
	if !digestPattern.MatchString(value) {
		return fmt.Errorf("%s must be a lowercase sha256 digest", name)
	}
	return nil
}

func ValidateResourceScope(scope ResourceScope) error {
	switch scope.Kind {
	case AuthorityPlatform:
		if scope.TenantID != "" {
			return errors.New("platform scope cannot contain tenantId")
		}
	case AuthorityTenant:
		if err := ValidateID("tenantId", string(scope.TenantID)); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unknown scope kind %q", scope.Kind)
	}
	return nil
}

func ValidateResourceMetadata(value ResourceMetadata) error {
	var problems []error
	problems = append(problems,
		ValidateID("metadata.id", string(value.ID)),
		ValidateResourceScope(value.Scope),
		validateContractTime("metadata.createdAt", value.CreatedAt),
		validateContractTime("metadata.updatedAt", value.UpdatedAt),
	)
	if !namePattern.MatchString(value.Name) {
		problems = append(problems, errors.New("metadata.name must be a DNS label"))
	}
	if value.ResourceVersion == 0 {
		problems = append(problems, errors.New("metadata.resourceVersion must be positive"))
	}
	if value.UpdatedAt.Before(value.CreatedAt) {
		problems = append(problems, errors.New("metadata.updatedAt cannot precede createdAt"))
	}
	if err := validateLabels("metadata labels", value.Labels); err != nil {
		problems = append(problems, err)
	}
	return errors.Join(problems...)
}

func ValidateReadiness(value Readiness) error {
	var problems []error
	if value.APIVersion != APIVersion || value.Kind != "Readiness" {
		problems = append(problems, errors.New("readiness type metadata is invalid"))
	}
	if value.State != ReadinessReady && value.State != ReadinessNotReady {
		problems = append(problems, errors.New("readiness state is invalid"))
	}
	if value.SchemaVersion == 0 {
		problems = append(problems, errors.New("readiness schemaVersion must be positive"))
	}
	problems = append(problems, validateContractTime("readiness.checkedAt", value.CheckedAt))
	return errors.Join(problems...)
}

func ValidateVerifyInstallationRequest(value VerifyInstallationRequest) error {
	return errors.Join(
		ValidateID("installationId", value.InstallationID),
		ValidateID("releaseId", value.ReleaseID),
	)
}

func ValidateInstallationVerification(value InstallationVerification) error {
	var problems []error
	if value.APIVersion != APIVersion || value.Kind != "InstallationVerification" {
		problems = append(problems, errors.New("installation verification type metadata is invalid"))
	}
	problems = append(problems,
		ValidateID("installationId", value.InstallationID),
		ValidateID("releaseId", value.ReleaseID),
		ValidateID("deploymentId", string(value.DeploymentID)),
		ValidateID("operationId", string(value.OperationID)),
		validateContractTime("checkedAt", value.CheckedAt),
	)
	if value.Generation == 0 {
		problems = append(problems, errors.New("installation verification generation must be positive"))
	}
	if !contains(OperationStates(), value.OperationState) {
		problems = append(problems, errors.New("installation verification operation state is invalid"))
	}
	if !contains(DeploymentPhases(), value.DeploymentPhase) {
		problems = append(problems, errors.New("installation verification Deployment phase is invalid"))
	}
	terminal := value.OperationState == OperationSucceeded ||
		value.OperationState == OperationFailed ||
		value.OperationState == OperationCancelled ||
		value.OperationState == OperationManualIntervention
	switch value.State {
	case InstallationVerificationPending:
		if terminal {
			problems = append(problems, errors.New("pending installation verification cannot contain a terminal Operation"))
		}
	case InstallationVerificationReady:
		if value.OperationState != OperationSucceeded || value.DeploymentPhase != DeploymentReady {
			problems = append(problems, errors.New("ready installation verification requires a ready successful Deployment"))
		}
	case InstallationVerificationFailed:
		if !terminal || (value.OperationState == OperationSucceeded &&
			value.DeploymentPhase != DeploymentDegraded &&
			value.DeploymentPhase != DeploymentFailed &&
			value.DeploymentPhase != DeploymentStopped) {
			problems = append(problems, errors.New("failed installation verification requires a terminal failed result"))
		}
	default:
		problems = append(problems, errors.New("installation verification state is invalid"))
	}
	return errors.Join(problems...)
}

func ValidateExecutionPool(value ExecutionPool) error {
	var problems []error
	if value.APIVersion != APIVersion || value.Kind != "ExecutionPool" {
		problems = append(problems, errors.New("execution pool type metadata is invalid"))
	}
	problems = append(problems,
		ValidateResourceMetadata(value.Metadata),
		validateLabelSelector(
			"spec.executionTargetSelector",
			value.Spec.ExecutionTargetSelector,
		),
		validateUniqueKnown(
			"spec.allowedIsolationGuarantees",
			value.Spec.AllowedIsolationGuarantees,
			IsolationGuarantees(),
			true,
		),
		validateContractTime("status.observedAt", value.Status.ObservedAt),
	)
	if value.Metadata.Scope.Kind != AuthorityPlatform {
		problems = append(problems, errors.New("execution pool must be platform scoped"))
	}
	if !contains(
		[]ExecutionPoolPhase{ExecutionPoolReady, ExecutionPoolDegraded, ExecutionPoolUnavailable},
		value.Status.Phase,
	) {
		problems = append(problems, fmt.Errorf("unknown execution pool phase %q", value.Status.Phase))
	}
	if value.Status.ReadyExecutionTargetCount > value.Status.ExecutionTargetCount {
		problems = append(
			problems,
			errors.New("readyExecutionTargetCount cannot exceed executionTargetCount"),
		)
	}
	return errors.Join(problems...)
}

func ValidateCreateExecutionPoolRequest(value CreateExecutionPoolRequest) error {
	problems := []error{
		ValidateID("id", string(value.ID)),
		validateLabels("labels", value.Labels),
		validateLabelSelector("spec.executionTargetSelector", value.Spec.ExecutionTargetSelector),
		validateUniqueKnown("spec.allowedIsolationGuarantees", value.Spec.AllowedIsolationGuarantees, IsolationGuarantees(), true),
	}
	if !namePattern.MatchString(value.Name) {
		problems = append(problems, errors.New("name must be a DNS label"))
	}
	return errors.Join(problems...)
}

func ValidateExecutionPoolList(value ExecutionPoolList) error {
	var problems []error
	if value.APIVersion != APIVersion || value.Kind != "ExecutionPoolList" ||
		value.Items == nil || len(value.Items) > MaximumExecutionPoolListItems {
		problems = append(problems, errors.New("execution pool list metadata or size is invalid"))
	}
	seen := map[ResourceID]bool{}
	for _, pool := range value.Items {
		if ValidateExecutionPool(pool) != nil || seen[pool.Metadata.ID] {
			problems = append(problems, errors.New("execution pool list contains an invalid or duplicate pool"))
			continue
		}
		seen[pool.Metadata.ID] = true
	}
	return errors.Join(problems...)
}

func ValidateCreateNodeEnrollmentRequest(value CreateNodeEnrollmentRequest) error {
	problems := []error{
		ValidateID("executionPoolId", string(value.ExecutionPoolID)),
		validateLabels("labels", value.Labels),
		validateWrappingPublicKey(value.WrappingPublicKey),
	}
	if !namePattern.MatchString(value.Name) {
		problems = append(problems, errors.New("name must be a DNS label"))
	}
	if _, supplied := value.Labels["matrix-machine-fingerprint"]; supplied {
		problems = append(problems, errors.New("node identity label is installation-owned"))
	}
	return errors.Join(problems...)
}

func ValidateRegenerateNodeEnrollmentRequest(value RegenerateNodeEnrollmentRequest) error {
	return validateWrappingPublicKey(value.WrappingPublicKey)
}

func ValidateNodeEnrollmentDiagnostic(value NodeEnrollmentDiagnostic) error {
	if !contains(NodeEnrollmentDiagnosticCodes(), value.Code) {
		return errors.New("node enrollment diagnostic code is invalid")
	}
	retryable := value.Code == NodeEnrollmentDiagnosticListener ||
		value.Code == NodeEnrollmentDiagnosticNetworkInterrupted
	return errors.Join(
		validateContractTime("diagnostic.occurredAt", value.OccurredAt),
		func() error {
			if value.Retryable != retryable {
				return errors.New("node enrollment diagnostic retryability is invalid")
			}
			return nil
		}(),
	)
}

func ValidateNodeEnrollment(value NodeEnrollment) error {
	var problems []error
	if value.APIVersion != APIVersion || value.Kind != "NodeEnrollment" {
		problems = append(problems, errors.New("node enrollment type metadata is invalid"))
	}
	problems = append(problems,
		ValidateResourceMetadata(value.Metadata),
		ValidateID("executionTargetId", string(value.ExecutionTargetID)),
		ValidateID("executionPoolId", string(value.ExecutionPoolID)),
		ValidateID("operationId", string(value.OperationID)),
		validateContractTime("expiresAt", value.ExpiresAt),
	)
	if value.Metadata.Scope.Kind != AuthorityPlatform {
		problems = append(problems, errors.New("node enrollment must be platform scoped"))
	}
	if !nodeEnrollmentIDPattern.MatchString(string(value.Metadata.ID)) {
		problems = append(problems, errors.New("node enrollment identity is invalid"))
	}
	if !contains(NodeEnrollmentStates(), value.State) {
		problems = append(problems, errors.New("node enrollment state is invalid"))
	}
	if !value.ExpiresAt.After(value.Metadata.CreatedAt) ||
		value.ExpiresAt.Sub(value.Metadata.CreatedAt) > MaximumNodeEnrollmentLifetime {
		problems = append(problems, errors.New("node enrollment expiry is invalid"))
	}
	if value.CredentialConsumedAt != nil {
		problems = append(problems, validateContractTime("credentialConsumedAt", *value.CredentialConsumedAt))
		if value.CredentialConsumedAt.Before(value.Metadata.CreatedAt) ||
			value.CredentialConsumedAt.After(value.Metadata.UpdatedAt) ||
			!value.CredentialConsumedAt.Before(value.ExpiresAt) {
			problems = append(problems, errors.New("node enrollment credential time is invalid"))
		}
	}
	if value.ReadyAt != nil {
		problems = append(problems, validateContractTime("readyAt", *value.ReadyAt))
		if value.CredentialConsumedAt == nil || value.ReadyAt.Before(*value.CredentialConsumedAt) ||
			value.ReadyAt.After(value.Metadata.UpdatedAt) || value.ReadyAt.After(value.ExpiresAt) {
			problems = append(problems, errors.New("node enrollment ready time is invalid"))
		}
	}
	if value.ReplacedByID != "" && !nodeEnrollmentIDPattern.MatchString(string(value.ReplacedByID)) {
		problems = append(problems, errors.New("replacement enrollment identity is invalid"))
	}
	if value.Diagnostic != nil {
		problems = append(problems, ValidateNodeEnrollmentDiagnostic(*value.Diagnostic))
		if value.Diagnostic.OccurredAt.Before(value.Metadata.CreatedAt) ||
			value.Diagnostic.OccurredAt.After(value.Metadata.UpdatedAt) {
			problems = append(problems, errors.New("node enrollment diagnostic time is invalid"))
		}
	}
	switch value.State {
	case NodeEnrollmentWaitingInstall:
		if value.CredentialConsumedAt != nil || value.ReadyAt != nil || value.ReplacedByID != "" || value.Diagnostic != nil {
			problems = append(problems, errors.New("waiting node enrollment contains terminal or exchange state"))
		}
	case NodeEnrollmentVerifying:
		if value.CredentialConsumedAt == nil || value.ReadyAt != nil || value.ReplacedByID != "" || value.Diagnostic != nil {
			problems = append(problems, errors.New("verifying node enrollment state is incomplete"))
		}
	case NodeEnrollmentReady:
		if value.CredentialConsumedAt == nil || value.ReadyAt == nil || value.ReplacedByID != "" || value.Diagnostic != nil {
			problems = append(problems, errors.New("ready node enrollment state is incomplete"))
		}
	case NodeEnrollmentFailed:
		if value.CredentialConsumedAt == nil || value.ReadyAt != nil || value.ReplacedByID != "" || value.Diagnostic == nil ||
			(value.Diagnostic != nil && (value.Diagnostic.Code == NodeEnrollmentDiagnosticExpired || value.Diagnostic.Code == NodeEnrollmentDiagnosticRevoked)) {
			problems = append(problems, errors.New("failed node enrollment state is incomplete"))
		}
	case NodeEnrollmentExpired:
		if value.ReadyAt != nil || value.ReplacedByID != "" || value.Diagnostic == nil ||
			(value.Diagnostic != nil && value.Diagnostic.Code != NodeEnrollmentDiagnosticExpired) ||
			value.Metadata.UpdatedAt.Before(value.ExpiresAt) {
			problems = append(problems, errors.New("expired node enrollment state is incomplete"))
		}
	case NodeEnrollmentRevoked:
		if value.ReadyAt != nil || value.Diagnostic == nil ||
			(value.Diagnostic != nil && value.Diagnostic.Code != NodeEnrollmentDiagnosticRevoked) {
			problems = append(problems, errors.New("revoked node enrollment state is incomplete"))
		}
	}
	return errors.Join(problems...)
}

func ValidateNodeEnrollmentList(value NodeEnrollmentList) error {
	var problems []error
	if value.APIVersion != APIVersion || value.Kind != "NodeEnrollmentList" ||
		value.Items == nil || len(value.Items) > MaximumNodeEnrollmentListItems {
		problems = append(problems, errors.New("node enrollment list metadata or size is invalid"))
	}
	seen := map[ResourceID]bool{}
	for _, enrollment := range value.Items {
		if ValidateNodeEnrollment(enrollment) != nil || seen[enrollment.Metadata.ID] {
			problems = append(problems, errors.New("node enrollment list contains an invalid or duplicate enrollment"))
			continue
		}
		seen[enrollment.Metadata.ID] = true
	}
	return errors.Join(problems...)
}

func ValidateNodeEnrollmentJoin(value NodeEnrollmentJoin) error {
	commitment, certificate, err := nodeEnrollmentJoinCommitment(value)
	if err != nil {
		return err
	}
	signature, err := decodeRawURLBase64("node enrollment join signature", value.Signature, ed25519.SignatureSize)
	if err != nil {
		return err
	}
	publicKey, ok := certificate.PublicKey.(ed25519.PublicKey)
	if !ok || !ed25519.Verify(publicKey, commitment, signature) {
		return errors.New("node enrollment join signature is invalid")
	}
	return nil
}

func NodeEnrollmentIssuerURI(installationID string) (*url.URL, error) {
	if ValidateID("installationId", installationID) != nil {
		return nil, errors.New("node enrollment issuer installation is invalid")
	}
	return &url.URL{
		Scheme: "spiffe",
		Host:   "matrix.xiak.com",
		Path:   "/installation/" + installationID + "/node-enrollment-issuer",
	}, nil
}

// NodeEnrollmentIngressServerName is the installation-bound TLS name used by
// the bootstrap client. The signed join already commits InstallationID and the
// issuer certificate, so the connection address can remain independent from
// this deterministic verification name without relying on customer DNS.
func NodeEnrollmentIngressServerName(installationID string) (string, error) {
	if ValidateID("installationId", installationID) != nil {
		return "", errors.New("node enrollment ingress installation is invalid")
	}
	digest := sha256.Sum256([]byte("matrix-node-enrollment-ingress/v1\x00" + installationID))
	return "mx-" + hex.EncodeToString(digest[:24]) + ".enrollment.matrix.invalid", nil
}

// NodeEnrollmentJoinSigningBytes returns the exact public commitment signed by
// the installation enrollment issuer. It never contains the raw credential.
func NodeEnrollmentJoinSigningBytes(value NodeEnrollmentJoin) ([]byte, error) {
	commitment, _, err := nodeEnrollmentJoinCommitment(value)
	return commitment, err
}

func ValidateWrappedJoinCredential(value WrappedJoinCredential) error {
	if value.Algorithm != JoinCredentialRSAOAEP256 {
		return errors.New("join credential wrapping algorithm is invalid")
	}
	_, err := decodeRawURLBase64("wrapped join credential", value.Ciphertext, 384)
	return err
}

func ValidateCreateNodeEnrollmentResponse(value CreateNodeEnrollmentResponse) error {
	return errors.Join(
		ValidateNodeEnrollment(value.Enrollment),
		ValidateNodeEnrollmentJoin(value.Join),
		ValidateWrappedJoinCredential(value.WrappedCredential),
		func() error {
			if value.Enrollment.Metadata.ID != value.Join.EnrollmentID ||
				value.Enrollment.ExecutionTargetID != value.Join.ExecutionTargetID ||
				!value.Enrollment.ExpiresAt.Equal(value.Join.ExpiresAt) ||
				value.Enrollment.State != NodeEnrollmentWaitingInstall {
				return errors.New("node enrollment creation response is inconsistent")
			}
			return nil
		}(),
	)
}

func ValidateExchangeNodeEnrollmentRequest(value ExchangeNodeEnrollmentRequest) error {
	_, _, err := nodeEnrollmentExchangePublicKeys(value)
	return err
}

// NodeEnrollmentExchangePublicKeys returns canonical PKIX public-key bytes
// only after the complete exchange request has passed its closed contract.
// It never exposes or derives either target-host private key.
func NodeEnrollmentExchangePublicKeys(value ExchangeNodeEnrollmentRequest) ([]byte, []byte, error) {
	node, collector, err := nodeEnrollmentExchangePublicKeys(value)
	if err != nil {
		return nil, nil, err
	}
	return bytes.Clone(node.RawSubjectPublicKeyInfo), bytes.Clone(collector.RawSubjectPublicKeyInfo), nil
}

func nodeEnrollmentExchangePublicKeys(value ExchangeNodeEnrollmentRequest) (*x509.CertificateRequest, *x509.CertificateRequest, error) {
	var problems []error
	if value.APIVersion != NodeEnrollmentExchangeAPIVersion ||
		value.Kind != NodeEnrollmentExchangeRequestKind ||
		!nodeEnrollmentIDPattern.MatchString(string(value.EnrollmentID)) ||
		!nodeExchangeIDPattern.MatchString(value.ExchangeID) {
		problems = append(problems, errors.New("node enrollment exchange metadata is invalid"))
	}
	problems = append(problems,
		ValidateID("installationId", value.InstallationID),
		ValidateID("executionTargetId", string(value.ExecutionTargetID)),
		ValidateDigest("machineFingerprint", value.MachineFingerprint),
		ValidateDigest("runtimeContractDigest", value.RuntimeContractDigest),
	)
	if _, err := decodeRawURLBase64("node enrollment credential", value.Credential, 32); err != nil {
		problems = append(problems, errors.New("node enrollment credential is invalid"))
	}
	if value.Listener.ManagementPort < MinimumNodeEnrollmentListenerPort ||
		value.Listener.CollectorPort < MinimumNodeEnrollmentListenerPort ||
		value.Listener.ManagementPort == value.Listener.CollectorPort {
		problems = append(problems, errors.New("node enrollment listener claim is invalid"))
	}
	nodeRequest, nodeErr := parseNodeEnrollmentCertificateRequest("node", value.NodeCertificateRequest)
	collectorRequest, collectorErr := parseNodeEnrollmentCertificateRequest("collector", value.CollectorCertificateRequest)
	problems = append(problems, nodeErr, collectorErr)
	if nodeRequest != nil && collectorRequest != nil &&
		bytes.Equal(nodeRequest.RawSubjectPublicKeyInfo, collectorRequest.RawSubjectPublicKeyInfo) {
		problems = append(problems, errors.New("node enrollment public keys must be distinct"))
	}
	return nodeRequest, collectorRequest, errors.Join(problems...)
}

func parseNodeEnrollmentCertificateRequest(name, value string) (*x509.CertificateRequest, error) {
	encoded, err := decodeRawURLBase64(name+" certificate request", value, -1)
	if err != nil || len(encoded) < 64 || len(encoded) > 4096 {
		return nil, errors.New("node enrollment certificate request is invalid")
	}
	request, err := x509.ParseCertificateRequest(encoded)
	if err != nil || request == nil || request.CheckSignature() != nil ||
		request.PublicKeyAlgorithm != x509.Ed25519 || request.SignatureAlgorithm != x509.PureEd25519 ||
		request.Subject.String() != "" || !bytes.Equal(request.RawSubject, []byte{0x30, 0x00}) ||
		len(request.Attributes) != 0 || len(request.Extensions) != 0 || len(request.ExtraExtensions) != 0 ||
		len(request.DNSNames) != 0 || len(request.EmailAddresses) != 0 || len(request.IPAddresses) != 0 ||
		len(request.URIs) != 0 {
		return nil, errors.New("node enrollment certificate request is invalid")
	}
	publicKey, ok := request.PublicKey.(ed25519.PublicKey)
	if !ok || len(publicKey) != ed25519.PublicKeySize {
		return nil, errors.New("node enrollment certificate request is invalid")
	}
	return request, nil
}

func ValidateNodeEnrollmentExchangeResponse(value NodeEnrollmentExchangeResponse) error {
	var problems []error
	if value.APIVersion != NodeEnrollmentExchangeAPIVersion ||
		value.Kind != NodeEnrollmentExchangeResponseKind ||
		!nodeEnrollmentIDPattern.MatchString(string(value.EnrollmentID)) ||
		!nodeExchangeIDPattern.MatchString(value.ExchangeID) ||
		!nodeBindingIDPattern.MatchString(value.BindingRef) {
		problems = append(problems, errors.New("node enrollment exchange response metadata is invalid"))
	}
	problems = append(problems,
		ValidateID("installationId", value.InstallationID),
		ValidateID("executionTargetId", string(value.ExecutionTargetID)),
		ValidateID("controllerId", value.ControllerID),
		ValidateDigest("machineFingerprint", value.MachineFingerprint),
		ValidateDigest("runtimeContractDigest", value.RuntimeContractDigest),
		validateContractTime("certificateNotBefore", value.CertificateNotBefore),
		validateContractTime("certificateNotAfter", value.CertificateNotAfter),
	)
	if !value.CertificateNotAfter.After(value.CertificateNotBefore) ||
		value.CertificateNotAfter.Sub(value.CertificateNotBefore) > MaximumNodeEnrollmentCertificateLifetime {
		problems = append(problems, errors.New("node enrollment certificate lifetime is invalid"))
	}
	nodeAddress, nodePort, nodeAddressErr := parseNodeEnrollmentPrivateAddress(value.NodeListenAddress)
	collectorAddress, collectorPort, collectorAddressErr := parseNodeEnrollmentCollectorEndpoint(value.CollectorEndpoint)
	problems = append(problems, nodeAddressErr, collectorAddressErr)
	if nodeAddressErr == nil && collectorAddressErr == nil && nodePort == collectorPort {
		problems = append(problems, errors.New("node enrollment listener ports must be distinct"))
	}
	issuer, issuerErr := parseNodeEnrollmentIssuer(value.IssuerCertificate, value.InstallationID)
	nodeCertificate, nodeErr := parseNodeEnrollmentRoleCertificate(
		value.NodeCertificate,
		value.InstallationID,
		value.ExecutionTargetID,
		"nodes",
		nodeAddress,
		[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		issuer,
		value.CertificateNotBefore,
		value.CertificateNotAfter,
	)
	collectorCertificate, collectorErr := parseNodeEnrollmentRoleCertificate(
		value.CollectorCertificate,
		value.InstallationID,
		value.ExecutionTargetID,
		"collectors",
		collectorAddress,
		[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		issuer,
		value.CertificateNotBefore,
		value.CertificateNotAfter,
	)
	problems = append(problems, issuerErr, nodeErr, collectorErr)
	if nodeCertificate != nil && collectorCertificate != nil &&
		bytes.Equal(nodeCertificate.RawSubjectPublicKeyInfo, collectorCertificate.RawSubjectPublicKeyInfo) {
		problems = append(problems, errors.New("node enrollment certificates reuse one public key"))
	}
	return errors.Join(problems...)
}

// ValidateNodeEnrollmentExchangeResponseForRequest binds an issued result to
// the exact locally persisted exchange intent and both CSR public keys.
func ValidateNodeEnrollmentExchangeResponseForRequest(
	response NodeEnrollmentExchangeResponse,
	request ExchangeNodeEnrollmentRequest,
) error {
	if ValidateExchangeNodeEnrollmentRequest(request) != nil ||
		ValidateNodeEnrollmentExchangeResponse(response) != nil ||
		response.EnrollmentID != request.EnrollmentID ||
		response.InstallationID != request.InstallationID ||
		response.ExecutionTargetID != request.ExecutionTargetID ||
		response.ExchangeID != request.ExchangeID ||
		response.MachineFingerprint != request.MachineFingerprint ||
		response.RuntimeContractDigest != request.RuntimeContractDigest {
		return errors.New("node enrollment exchange response differs from its request")
	}
	_, managementPort, managementErr := parseNodeEnrollmentPrivateAddress(response.NodeListenAddress)
	_, collectorPort, collectorErr := parseNodeEnrollmentCollectorEndpoint(response.CollectorEndpoint)
	if managementErr != nil || collectorErr != nil ||
		managementPort != request.Listener.ManagementPort || collectorPort != request.Listener.CollectorPort {
		return errors.New("node enrollment exchange response changes its listener claim")
	}
	nodeRequest, collectorRequest, err := nodeEnrollmentExchangePublicKeys(request)
	if err != nil {
		return err
	}
	nodeCertificate, nodeErr := decodeNodeEnrollmentCertificate(response.NodeCertificate)
	collectorCertificate, collectorCertificateErr := decodeNodeEnrollmentCertificate(response.CollectorCertificate)
	if nodeErr != nil || collectorCertificateErr != nil ||
		!bytes.Equal(nodeCertificate.RawSubjectPublicKeyInfo, nodeRequest.RawSubjectPublicKeyInfo) ||
		!bytes.Equal(collectorCertificate.RawSubjectPublicKeyInfo, collectorRequest.RawSubjectPublicKeyInfo) {
		return errors.New("node enrollment exchange response changes its public keys")
	}
	return nil
}

func ValidateCompleteNodeEnrollmentRequest(value CompleteNodeEnrollmentRequest) error {
	var problems []error
	if value.APIVersion != NodeEnrollmentExchangeAPIVersion ||
		value.Kind != NodeEnrollmentCompletionRequestKind ||
		!nodeEnrollmentIDPattern.MatchString(string(value.EnrollmentID)) ||
		!nodeExchangeIDPattern.MatchString(value.ExchangeID) ||
		!nodeBindingIDPattern.MatchString(value.BindingRef) {
		problems = append(problems, errors.New("node enrollment completion metadata is invalid"))
	}
	problems = append(problems,
		ValidateID("installationId", value.InstallationID),
		ValidateID("executionTargetId", string(value.ExecutionTargetID)),
		ValidateID("controllerId", value.ControllerID),
		ValidateDigest("machineFingerprint", value.MachineFingerprint),
		ValidateDigest("runtimeContractDigest", value.RuntimeContractDigest),
		ValidateDigest("nodePublicKeyFingerprint", value.NodePublicKeyFingerprint),
		ValidateDigest("collectorPublicKeyFingerprint", value.CollectorPublicKeyFingerprint),
	)
	_, nodePort, nodeErr := parseNodeEnrollmentPrivateAddress(value.NodeListenAddress)
	_, collectorPort, collectorErr := parseNodeEnrollmentCollectorEndpoint(value.CollectorEndpoint)
	problems = append(problems, nodeErr, collectorErr)
	if nodeErr == nil && collectorErr == nil && nodePort == collectorPort {
		problems = append(problems, errors.New("node enrollment completion listener ports must be distinct"))
	}
	if value.NodePublicKeyFingerprint == value.CollectorPublicKeyFingerprint {
		problems = append(problems, errors.New("node enrollment completion public keys must be distinct"))
	}
	return errors.Join(problems...)
}

func ValidateCompleteNodeEnrollmentResponse(value CompleteNodeEnrollmentResponse) error {
	if ValidateNodeEnrollment(value.Enrollment) != nil ||
		ValidateExecutionTarget(value.ExecutionTarget) != nil ||
		ValidateOperation(value.Operation) != nil ||
		value.Enrollment.State != NodeEnrollmentReady ||
		value.Enrollment.ExecutionTargetID != value.ExecutionTarget.Metadata.ID ||
		value.Enrollment.ExecutionPoolID != value.ExecutionTarget.Spec.ExecutionPoolID ||
		value.Enrollment.OperationID != value.Operation.ID ||
		value.Operation.Action != OperationRegisterExecutionTarget ||
		value.Operation.Target != (ResourceRef{Kind: "ExecutionTarget", ID: value.ExecutionTarget.Metadata.ID}) ||
		value.Operation.State != OperationSucceeded {
		return errors.New("node enrollment completion response is invalid")
	}
	return nil
}

func ValidateCreateNodeEnrollmentRecoveryChallengeRequest(
	value CreateNodeEnrollmentRecoveryChallengeRequest,
) error {
	if value.APIVersion != NodeEnrollmentRecoveryAPIVersion ||
		value.Kind != NodeEnrollmentRecoveryChallengeRequestKind ||
		!validNodeEnrollmentRecoveryIdentity(
			value.EnrollmentID,
			value.InstallationID,
			value.ExecutionTargetID,
			value.ExchangeID,
			value.MachineFingerprint,
			value.RuntimeContractDigest,
			value.NodePublicKeyFingerprint,
			value.CollectorPublicKeyFingerprint,
		) {
		return errors.New("node enrollment recovery challenge request is invalid")
	}
	return nil
}

func ValidateNodeEnrollmentRecoveryChallenge(value NodeEnrollmentRecoveryChallenge) error {
	if _, err := nodeEnrollmentRecoveryChallengeAuthenticationBytes(value); err != nil {
		return err
	}
	authenticator, err := decodeRawURLBase64(
		"node enrollment recovery challenge authenticator",
		value.Authenticator,
		sha256.Size,
	)
	clear(authenticator)
	return err
}

// NodeEnrollmentRecoveryChallengeAuthenticationBytes returns the exact public
// challenge commitment authenticated by the installation issuer. The
// authenticator itself is deliberately excluded.
func NodeEnrollmentRecoveryChallengeAuthenticationBytes(
	value NodeEnrollmentRecoveryChallenge,
) ([]byte, error) {
	return nodeEnrollmentRecoveryChallengeAuthenticationBytes(value)
}

// NodeEnrollmentRecoveryProofSigningBytes returns the complete authenticated
// challenge that both target-host role keys must sign independently.
func NodeEnrollmentRecoveryProofSigningBytes(value NodeEnrollmentRecoveryChallenge) ([]byte, error) {
	if ValidateNodeEnrollmentRecoveryChallenge(value) != nil {
		return nil, errors.New("node enrollment recovery challenge is invalid")
	}
	encoded, err := json.Marshal(struct {
		Purpose   string                          `json:"purpose"`
		Challenge NodeEnrollmentRecoveryChallenge `json:"challenge"`
	}{"MATRIX_NODE_ENROLLMENT_RECOVERY_PROOF_V1", value})
	if err != nil {
		return nil, errors.New("node enrollment recovery proof cannot be encoded")
	}
	return encoded, nil
}

func ValidateRecoverNodeEnrollmentExchangeRequest(value RecoverNodeEnrollmentExchangeRequest) error {
	if value.APIVersion != NodeEnrollmentRecoveryAPIVersion ||
		value.Kind != NodeEnrollmentRecoveryProofRequestKind ||
		ValidateNodeEnrollmentRecoveryChallenge(value.Challenge) != nil {
		return errors.New("node enrollment recovery proof is invalid")
	}
	nodeSignature, nodeErr := decodeRawURLBase64(
		"node enrollment recovery node signature", value.NodeSignature, ed25519.SignatureSize,
	)
	collectorSignature, collectorErr := decodeRawURLBase64(
		"node enrollment recovery collector signature", value.CollectorSignature, ed25519.SignatureSize,
	)
	clear(nodeSignature)
	clear(collectorSignature)
	if nodeErr != nil || collectorErr != nil {
		return errors.New("node enrollment recovery proof is invalid")
	}
	return nil
}

func ValidateNodeEnrollmentRecoveryChallengeForRequest(
	challenge NodeEnrollmentRecoveryChallenge,
	request CreateNodeEnrollmentRecoveryChallengeRequest,
) error {
	if ValidateNodeEnrollmentRecoveryChallenge(challenge) != nil ||
		ValidateCreateNodeEnrollmentRecoveryChallengeRequest(request) != nil ||
		challenge.EnrollmentID != request.EnrollmentID ||
		challenge.InstallationID != request.InstallationID ||
		challenge.ExecutionTargetID != request.ExecutionTargetID ||
		challenge.ExchangeID != request.ExchangeID ||
		challenge.MachineFingerprint != request.MachineFingerprint ||
		challenge.RuntimeContractDigest != request.RuntimeContractDigest ||
		challenge.NodePublicKeyFingerprint != request.NodePublicKeyFingerprint ||
		challenge.CollectorPublicKeyFingerprint != request.CollectorPublicKeyFingerprint {
		return errors.New("node enrollment recovery challenge differs from its request")
	}
	return nil
}

func nodeEnrollmentRecoveryChallengeAuthenticationBytes(
	value NodeEnrollmentRecoveryChallenge,
) ([]byte, error) {
	if value.APIVersion != NodeEnrollmentRecoveryAPIVersion ||
		value.Kind != NodeEnrollmentRecoveryChallengeKind ||
		!validNodeEnrollmentRecoveryIdentity(
			value.EnrollmentID,
			value.InstallationID,
			value.ExecutionTargetID,
			value.ExchangeID,
			value.MachineFingerprint,
			value.RuntimeContractDigest,
			value.NodePublicKeyFingerprint,
			value.CollectorPublicKeyFingerprint,
		) ||
		validateContractTime("issuedAt", value.IssuedAt) != nil ||
		validateContractTime("expiresAt", value.ExpiresAt) != nil ||
		!value.ExpiresAt.After(value.IssuedAt) ||
		value.ExpiresAt.Sub(value.IssuedAt) > MaximumNodeEnrollmentRecoveryChallengeLifetime {
		return nil, errors.New("node enrollment recovery challenge is invalid")
	}
	challenge, err := decodeRawURLBase64("node enrollment recovery challenge", value.Challenge, 32)
	clear(challenge)
	if err != nil {
		return nil, errors.New("node enrollment recovery challenge is invalid")
	}
	encoded, err := json.Marshal(struct {
		Purpose                       string     `json:"purpose"`
		APIVersion                    string     `json:"apiVersion"`
		Kind                          string     `json:"kind"`
		EnrollmentID                  ResourceID `json:"enrollmentId"`
		InstallationID                string     `json:"installationId"`
		ExecutionTargetID             ResourceID `json:"executionTargetId"`
		ExchangeID                    string     `json:"exchangeId"`
		MachineFingerprint            string     `json:"machineFingerprint"`
		RuntimeContractDigest         string     `json:"runtimeContractDigest"`
		NodePublicKeyFingerprint      string     `json:"nodePublicKeyFingerprint"`
		CollectorPublicKeyFingerprint string     `json:"collectorPublicKeyFingerprint"`
		Challenge                     string     `json:"challenge"`
		IssuedAt                      time.Time  `json:"issuedAt"`
		ExpiresAt                     time.Time  `json:"expiresAt"`
	}{
		"MATRIX_NODE_ENROLLMENT_RECOVERY_CHALLENGE_V1",
		value.APIVersion,
		value.Kind,
		value.EnrollmentID,
		value.InstallationID,
		value.ExecutionTargetID,
		value.ExchangeID,
		value.MachineFingerprint,
		value.RuntimeContractDigest,
		value.NodePublicKeyFingerprint,
		value.CollectorPublicKeyFingerprint,
		value.Challenge,
		value.IssuedAt,
		value.ExpiresAt,
	})
	if err != nil {
		return nil, errors.New("node enrollment recovery challenge cannot be encoded")
	}
	return encoded, nil
}

func validNodeEnrollmentRecoveryIdentity(
	enrollmentID ResourceID,
	installationID string,
	executionTargetID ResourceID,
	exchangeID string,
	machineFingerprint string,
	runtimeContractDigest string,
	nodePublicKeyFingerprint string,
	collectorPublicKeyFingerprint string,
) bool {
	return nodeEnrollmentIDPattern.MatchString(string(enrollmentID)) &&
		ValidateID("installationId", installationID) == nil &&
		ValidateID("executionTargetId", string(executionTargetID)) == nil &&
		nodeExchangeIDPattern.MatchString(exchangeID) &&
		ValidateDigest("machineFingerprint", machineFingerprint) == nil &&
		ValidateDigest("runtimeContractDigest", runtimeContractDigest) == nil &&
		ValidateDigest("nodePublicKeyFingerprint", nodePublicKeyFingerprint) == nil &&
		ValidateDigest("collectorPublicKeyFingerprint", collectorPublicKeyFingerprint) == nil &&
		nodePublicKeyFingerprint != collectorPublicKeyFingerprint
}

func parseNodeEnrollmentPrivateAddress(value string) (netip.Addr, uint16, error) {
	host, portText, err := net.SplitHostPort(value)
	port, portErr := strconv.ParseUint(portText, 10, 16)
	address, addressErr := netip.ParseAddr(host)
	if err != nil || portErr != nil || addressErr != nil ||
		port < MinimumNodeEnrollmentListenerPort || address.Is4In6() || !address.IsPrivate() ||
		address.IsLoopback() || address.IsUnspecified() || address.IsMulticast() || address.IsLinkLocalUnicast() ||
		net.JoinHostPort(address.String(), strconv.FormatUint(port, 10)) != value {
		return netip.Addr{}, 0, errors.New("node enrollment management address is invalid")
	}
	return address, uint16(port), nil
}

func parseNodeEnrollmentCollectorEndpoint(value string) (netip.Addr, uint16, error) {
	endpoint, err := url.Parse(value)
	if err != nil || endpoint.Scheme != "https" || endpoint.User != nil || endpoint.Opaque != "" ||
		endpoint.Path != "" || endpoint.RawPath != "" || endpoint.RawQuery != "" || endpoint.ForceQuery ||
		endpoint.Fragment != "" {
		return netip.Addr{}, 0, errors.New("node enrollment collector endpoint is invalid")
	}
	host, portText, splitErr := net.SplitHostPort(endpoint.Host)
	port, portErr := strconv.ParseUint(portText, 10, 16)
	address, addressErr := netip.ParseAddr(host)
	if splitErr != nil || portErr != nil || addressErr != nil || port < MinimumNodeEnrollmentListenerPort ||
		address.Is4In6() || !address.IsLoopback() ||
		"https://"+net.JoinHostPort(address.String(), strconv.FormatUint(port, 10)) != value {
		return netip.Addr{}, 0, errors.New("node enrollment collector endpoint is invalid")
	}
	return address, uint16(port), nil
}

func parseNodeEnrollmentIssuer(value, installationID string) (*x509.Certificate, error) {
	encoded, err := decodeRawURLBase64("node enrollment exchange issuer certificate", value, -1)
	certificate, parseErr := x509.ParseCertificate(encoded)
	expectedURI, uriErr := NodeEnrollmentIssuerURI(installationID)
	if err != nil || parseErr != nil || certificate == nil || uriErr != nil ||
		!certificate.BasicConstraintsValid || !certificate.IsCA || !certificate.MaxPathLenZero || certificate.MaxPathLen != 0 ||
		certificate.PublicKeyAlgorithm != x509.Ed25519 || certificate.SignatureAlgorithm != x509.PureEd25519 ||
		certificate.KeyUsage != x509.KeyUsageCertSign|x509.KeyUsageDigitalSignature ||
		certificate.CheckSignatureFrom(certificate) != nil || len(certificate.URIs) != 1 ||
		certificate.URIs[0].String() != expectedURI.String() {
		return nil, errors.New("node enrollment exchange issuer certificate is invalid")
	}
	return certificate, nil
}

func parseNodeEnrollmentRoleCertificate(
	value string,
	installationID string,
	targetID ResourceID,
	role string,
	address netip.Addr,
	usages []x509.ExtKeyUsage,
	issuer *x509.Certificate,
	notBefore time.Time,
	notAfter time.Time,
) (*x509.Certificate, error) {
	certificate, err := decodeNodeEnrollmentCertificate(value)
	expectedURI := (&url.URL{
		Scheme: "spiffe", Host: "matrix.xiak.com",
		Path: "/installations/" + installationID + "/" + role + "/" + string(targetID),
	}).String()
	publicKey, publicKeyOK := certificatePublicKey(certificate)
	if err != nil || issuer == nil || !address.IsValid() || !publicKeyOK || len(publicKey) != ed25519.PublicKeySize ||
		certificate.SignatureAlgorithm != x509.PureEd25519 || certificate.IsCA || !certificate.BasicConstraintsValid ||
		certificate.SerialNumber == nil || certificate.SerialNumber.Sign() <= 0 ||
		certificate.Subject.String() != "" || !bytes.Equal(certificate.RawSubject, []byte{0x30, 0x00}) ||
		certificate.KeyUsage != x509.KeyUsageDigitalSignature || !slices.Equal(certificate.ExtKeyUsage, usages) ||
		len(certificate.UnknownExtKeyUsage) != 0 || len(certificate.DNSNames) != 0 || len(certificate.EmailAddresses) != 0 ||
		len(certificate.URIs) != 1 || certificate.URIs[0].String() != expectedURI ||
		len(certificate.IPAddresses) != 1 || !certificate.IPAddresses[0].Equal(net.IP(address.AsSlice())) ||
		!certificate.NotBefore.Equal(notBefore) || !certificate.NotAfter.Equal(notAfter) ||
		certificate.NotBefore.Before(issuer.NotBefore) || certificate.NotAfter.After(issuer.NotAfter) ||
		certificate.CheckSignatureFrom(issuer) != nil {
		return nil, errors.New("node enrollment role certificate is invalid")
	}
	return certificate, nil
}

func decodeNodeEnrollmentCertificate(value string) (*x509.Certificate, error) {
	encoded, err := decodeRawURLBase64("node enrollment role certificate", value, -1)
	if err != nil || len(encoded) > 4096 {
		return nil, errors.New("node enrollment role certificate is invalid")
	}
	certificate, err := x509.ParseCertificate(encoded)
	if err != nil || certificate == nil {
		return nil, errors.New("node enrollment role certificate is invalid")
	}
	return certificate, nil
}

func certificatePublicKey(certificate *x509.Certificate) (ed25519.PublicKey, bool) {
	if certificate == nil || certificate.PublicKeyAlgorithm != x509.Ed25519 {
		return nil, false
	}
	publicKey, ok := certificate.PublicKey.(ed25519.PublicKey)
	return publicKey, ok
}

func validateWrappingPublicKey(value string) error {
	encoded, err := decodeRawURLBase64("wrapping public key", value, -1)
	if err != nil || len(encoded) < 384 || len(encoded) > 1024 {
		return errors.New("wrapping public key is invalid")
	}
	parsed, err := x509.ParsePKIXPublicKey(encoded)
	key, ok := parsed.(*rsa.PublicKey)
	if err != nil || !ok || key.N == nil || key.N.BitLen() != 3072 || key.E != 65537 {
		return errors.New("wrapping public key must be RSA-3072 with exponent 65537")
	}
	return nil
}

func nodeEnrollmentJoinCommitment(value NodeEnrollmentJoin) ([]byte, *x509.Certificate, error) {
	var problems []error
	if value.APIVersion != NodeEnrollmentJoinAPIVersion || value.Kind != NodeEnrollmentJoinKind ||
		!nodeEnrollmentIDPattern.MatchString(string(value.EnrollmentID)) {
		problems = append(problems, errors.New("node enrollment join metadata is invalid"))
	}
	problems = append(problems,
		ValidateID("installationId", value.InstallationID),
		ValidateID("executionTargetId", string(value.ExecutionTargetID)),
		ValidateDigest("credentialDigest", value.CredentialDigest),
		validateContractTime("expiresAt", value.ExpiresAt),
	)
	endpoint, err := url.Parse(value.ControlPlaneURL)
	if err != nil || endpoint.Scheme != "https" || endpoint.Host == "" || endpoint.User != nil || endpoint.Opaque != "" ||
		endpoint.RawQuery != "" || endpoint.ForceQuery || endpoint.Fragment != "" ||
		endpoint.Path != "/api/paas/v1/node-enrollments/"+url.PathEscape(string(value.EnrollmentID))+"/exchange" {
		problems = append(problems, errors.New("node enrollment control-plane URL is invalid"))
	}
	certificateBytes, certificateErr := decodeRawURLBase64("node enrollment issuer certificate", value.IssuerCertificate, -1)
	certificate, parseErr := x509.ParseCertificate(certificateBytes)
	expectedIssuer, issuerErr := NodeEnrollmentIssuerURI(value.InstallationID)
	if certificateErr != nil || parseErr != nil || certificate == nil || !certificate.BasicConstraintsValid || !certificate.IsCA ||
		certificate.PublicKeyAlgorithm != x509.Ed25519 || certificate.KeyUsage&x509.KeyUsageCertSign == 0 ||
		certificate.CheckSignatureFrom(certificate) != nil ||
		value.ExpiresAt.Before(certificate.NotBefore) || value.ExpiresAt.After(certificate.NotAfter) ||
		issuerErr != nil || len(certificate.URIs) != 1 || certificate.URIs[0].String() != expectedIssuer.String() {
		problems = append(problems, errors.New("node enrollment issuer certificate is invalid"))
	}
	if value.SignatureAlgorithm != NodeJoinSignatureEd25519 {
		problems = append(problems, errors.New("node enrollment join signature algorithm is invalid"))
	}
	if err := errors.Join(problems...); err != nil {
		return nil, nil, err
	}
	commitment, err := json.Marshal(struct {
		APIVersion         string                     `json:"apiVersion"`
		Kind               string                     `json:"kind"`
		EnrollmentID       ResourceID                 `json:"enrollmentId"`
		InstallationID     string                     `json:"installationId"`
		ExecutionTargetID  ResourceID                 `json:"executionTargetId"`
		ControlPlaneURL    string                     `json:"controlPlaneUrl"`
		CredentialDigest   string                     `json:"credentialDigest"`
		ExpiresAt          time.Time                  `json:"expiresAt"`
		IssuerCertificate  string                     `json:"issuerCertificate"`
		SignatureAlgorithm NodeJoinSignatureAlgorithm `json:"signatureAlgorithm"`
	}{value.APIVersion, value.Kind, value.EnrollmentID, value.InstallationID, value.ExecutionTargetID,
		value.ControlPlaneURL, value.CredentialDigest, value.ExpiresAt, value.IssuerCertificate, value.SignatureAlgorithm})
	if err != nil {
		return nil, nil, errors.New("node enrollment join commitment cannot be encoded")
	}
	return commitment, certificate, nil
}

func decodeRawURLBase64(name, value string, exactBytes int) ([]byte, error) {
	if value == "" || len(value) > 16*1024 || strings.ContainsAny(value, "=\r\n\t ") {
		return nil, fmt.Errorf("%s is invalid", name)
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || (exactBytes >= 0 && len(decoded) != exactBytes) ||
		base64.RawURLEncoding.EncodeToString(decoded) != value {
		return nil, fmt.Errorf("%s is invalid", name)
	}
	return decoded, nil
}

func ValidateRegisterExecutionTargetRequest(value RegisterExecutionTargetRequest) error {
	problems := []error{
		ValidateID("id", string(value.ID)),
		ValidateID("executionPoolId", string(value.ExecutionPoolID)),
		ValidateID("bindingRef", value.BindingRef),
		validateLabels("labels", value.Labels),
	}
	if !namePattern.MatchString(value.Name) {
		problems = append(problems, errors.New("name must be a DNS label"))
	}
	if _, supplied := value.Labels["matrix-machine-fingerprint"]; supplied {
		problems = append(problems, errors.New("node identity label is installation-owned"))
	}
	return errors.Join(problems...)
}

func ValidateExecutionTarget(value ExecutionTarget) error {
	var problems []error
	if value.APIVersion != APIVersion || value.Kind != "ExecutionTarget" {
		problems = append(problems, errors.New("execution target type metadata is invalid"))
	}
	problems = append(problems,
		ValidateResourceMetadata(value.Metadata),
		ValidateID("spec.executionPoolId", string(value.Spec.ExecutionPoolID)),
		validateAdapterRef(
			"spec.infrastructureAdapter",
			value.Spec.InfrastructureAdapter,
			AdapterInfrastructure,
		),
		validateAdapterRef(
			"spec.deploymentExecutor",
			value.Spec.DeploymentExecutor,
			AdapterDeploymentExecutor,
		),
		validateCapacity("status.capacity", value.Status.Capacity),
		validateCapacity("status.allocatable", value.Status.Allocatable),
		validateUniqueKnown(
			"status.supportedIsolationGuarantees",
			value.Status.SupportedIsolationGuarantees,
			IsolationGuarantees(),
			value.Status.Health == ExecutionTargetHealthReady,
		),
		validateContractTime("status.observedAt", value.Status.ObservedAt),
	)
	if value.Metadata.Scope.Kind != AuthorityPlatform {
		problems = append(problems, errors.New("execution target must be platform scoped"))
	}
	if value.Spec.GatewayAdapter != nil {
		problems = append(
			problems,
			validateAdapterRef("spec.gatewayAdapter", *value.Spec.GatewayAdapter, AdapterGateway),
		)
	}
	if !contains([]ExecutionTargetDesiredState{ExecutionTargetActive, ExecutionTargetDraining, ExecutionTargetRemoved}, value.Spec.DesiredState) {
		problems = append(problems, fmt.Errorf("unknown target desired state %q", value.Spec.DesiredState))
	}
	if !contains(
		[]ExecutionTargetHealth{
			ExecutionTargetHealthUnknown,
			ExecutionTargetHealthReady,
			ExecutionTargetHealthDegraded,
			ExecutionTargetHealthUnavailable,
		},
		value.Status.Health,
	) {
		problems = append(problems, fmt.Errorf("unknown target health %q", value.Status.Health))
	}
	if exceedsCapacity(value.Status.Allocatable, value.Status.Capacity) {
		problems = append(problems, errors.New("allocatable resources cannot exceed capacity"))
	}
	if value.Status.Usage != nil {
		problems = append(problems, ValidateExecutionTargetUsage(*value.Status.Usage))
	}
	return errors.Join(problems...)
}

// MaximumExecutionTargetListItems bounds one built-in target plus the 128
// managed targets admitted by an installation.
const MaximumExecutionTargetListItems = 129

func ValidateExecutionTargetList(value ExecutionTargetList) error {
	if value.APIVersion != APIVersion || value.Kind != "ExecutionTargetList" ||
		value.Items == nil || len(value.Items) > MaximumExecutionTargetListItems {
		return errors.New("execution target list is invalid")
	}
	seen := make(map[ResourceID]bool, len(value.Items))
	for _, item := range value.Items {
		if ValidateExecutionTarget(item) != nil || seen[item.Metadata.ID] {
			return errors.New("execution target list is invalid")
		}
		seen[item.Metadata.ID] = true
	}
	return nil
}

func ValidatePlacementPolicy(value PlacementPolicy) error {
	var problems []error
	if value.APIVersion != APIVersion || value.Kind != "PlacementPolicy" {
		problems = append(problems, errors.New("placement policy type metadata is invalid"))
	}
	problems = append(problems,
		ValidateResourceMetadata(value.Metadata),
		validateLabelSelector(
			"spec.executionTargetSelector",
			value.Spec.ExecutionTargetSelector,
		),
	)
	if value.Metadata.Scope.Kind != AuthorityTenant {
		problems = append(problems, errors.New("placement policy must be tenant scoped"))
	}
	if !contains(IsolationGuarantees(), value.Spec.RequiredIsolationGuarantee) {
		problems = append(problems, errors.New("required isolation guarantee is invalid"))
	}
	if !contains(
		[]PlacementStrategy{PlacementFirstFit, PlacementSpread, PlacementBinPack},
		value.Spec.Strategy,
	) {
		problems = append(problems, fmt.Errorf("unknown placement strategy %q", value.Spec.Strategy))
	}
	if len(value.Spec.EligibleExecutionPoolIDs) == 0 {
		problems = append(problems, errors.New("eligibleExecutionPoolIds must not be empty"))
	}
	seen := make(map[ResourceID]struct{}, len(value.Spec.EligibleExecutionPoolIDs))
	for index, executionPoolID := range value.Spec.EligibleExecutionPoolIDs {
		problems = append(
			problems,
			ValidateID(
				fmt.Sprintf("spec.eligibleExecutionPoolIds[%d]", index),
				string(executionPoolID),
			),
		)
		if _, found := seen[executionPoolID]; found {
			problems = append(
				problems,
				fmt.Errorf("spec.eligibleExecutionPoolIds[%d] is duplicated", index),
			)
		}
		seen[executionPoolID] = struct{}{}
	}
	return errors.Join(problems...)
}

func ValidateTenant(value Tenant) error {
	var problems []error
	if value.APIVersion != APIVersion || value.Kind != "Tenant" {
		problems = append(problems, errors.New("tenant type metadata is invalid"))
	}
	problems = append(problems,
		ValidateID("tenant.id", string(value.ID)),
		ValidateSafeExternalText("tenant.displayName", value.DisplayName, 256, true),
		ValidateID("tenant.iamResourceVersion", value.IAMResourceVersion),
		validateContractTime("tenant.observedAt", value.ObservedAt),
	)
	if !contains([]TenantStatus{TenantActive, TenantSuspended, TenantDeactivated}, value.Status) {
		problems = append(problems, fmt.Errorf("unknown tenant status %q", value.Status))
	}
	return errors.Join(problems...)
}

func ValidatePlacementDecision(value PlacementDecision) error {
	var problems []error
	if value.APIVersion != APIVersion || value.Kind != "PlacementDecision" {
		problems = append(problems, errors.New("placement decision type metadata is invalid"))
	}
	problems = append(problems,
		ValidateResourceMetadata(value.Metadata),
		ValidateID("deploymentId", string(value.DeploymentID)),
		ValidateID("applicationRevisionId", string(value.ApplicationRevisionID)),
		ValidateID("placementPolicyId", string(value.PlacementPolicyID)),
		ValidateDigest("candidateSetDigest", value.CandidateSetDigest),
		validateContractTime("decidedAt", value.DecidedAt),
	)
	if value.Metadata.Scope.Kind != AuthorityTenant {
		problems = append(problems, errors.New("placement decision must be tenant scoped"))
	}
	if value.PolicyResourceVersion == 0 {
		problems = append(problems, errors.New("policyResourceVersion must be positive"))
	}
	if value.DeploymentResourceVersion == 0 {
		problems = append(problems, errors.New("deploymentResourceVersion must be positive"))
	}
	if value.DeploymentGeneration == 0 {
		problems = append(problems, errors.New("deploymentGeneration must be positive"))
	}
	if !contains(IsolationGuarantees(), value.RequestedIsolationGuarantee) {
		problems = append(problems, errors.New("requested isolation guarantee is invalid"))
	}
	switch value.Outcome {
	case PlacementScheduled:
		problems = append(problems, ValidateID("executionTargetId", string(value.ExecutionTargetID)))
		if value.ExecutionTargetResourceVersion == 0 {
			problems = append(
				problems,
				errors.New("executionTargetResourceVersion must be positive for a scheduled decision"),
			)
		}
		if value.GrantedIsolationGuarantee != value.RequestedIsolationGuarantee {
			problems = append(problems, errors.New("granted isolation must exactly equal requested isolation"))
		}
		if value.Reason != nil {
			problems = append(problems, errors.New("scheduled decision cannot contain a reason"))
		}
	case PlacementUnschedulable:
		if value.ExecutionTargetID != "" ||
			value.ExecutionTargetResourceVersion != 0 ||
			value.GrantedIsolationGuarantee != "" {
			problems = append(
				problems,
				errors.New("unschedulable decision cannot select or version a target or grant isolation"),
			)
		}
		if value.Reason == nil ||
			(value.Reason.Code != ErrorUnschedulable &&
				value.Reason.Code != ErrorCapabilityUnsupported) {
			problems = append(problems, errors.New("unschedulable decision requires a normalized scheduling reason"))
		} else {
			problems = append(problems, ValidateProblem(*value.Reason))
		}
	default:
		problems = append(problems, fmt.Errorf("unknown placement outcome %q", value.Outcome))
	}
	return errors.Join(problems...)
}

func ValidateApplication(value Application) error {
	var problems []error
	if value.APIVersion != APIVersion || value.Kind != "Application" {
		problems = append(problems, errors.New("application type metadata is invalid"))
	}
	problems = append(problems, ValidateResourceMetadata(value.Metadata))
	if value.Metadata.Scope.Kind != AuthorityTenant {
		problems = append(problems, errors.New("application must be tenant scoped"))
	}
	return errors.Join(problems...)
}

func ValidateConfiguration(value Configuration) error {
	var problems []error
	if value.APIVersion != APIVersion || value.Kind != "Configuration" {
		problems = append(problems, errors.New("configuration type metadata is invalid"))
	}
	problems = append(problems,
		ValidateResourceMetadata(value.Metadata),
		ValidateID("applicationId", string(value.ApplicationID)),
	)
	if value.Metadata.Scope.Kind != AuthorityTenant {
		problems = append(problems, errors.New("configuration must be tenant scoped"))
	}
	return errors.Join(problems...)
}

func ValidateConfigurationRevision(value ConfigurationRevision) error {
	var problems []error
	if value.APIVersion != APIVersion || value.Kind != "ConfigurationRevision" {
		problems = append(problems, errors.New("configuration revision type metadata is invalid"))
	}
	problems = append(problems,
		ValidateResourceMetadata(value.Metadata),
		validateImmutableMetadata("configuration revision", value.Metadata),
		ValidateID("spec.configurationId", string(value.Spec.ConfigurationID)),
		ValidateDigest("spec.contentDigest", value.Spec.ContentDigest),
	)
	if value.Metadata.Scope.Kind != AuthorityTenant {
		problems = append(problems, errors.New("configuration revision must be tenant scoped"))
	}
	problems = append(problems, ValidateConfigurationValues(value.Spec.Values))
	if digest := ConfigurationValuesDigest(value.Spec.Values); value.Spec.ContentDigest != digest {
		problems = append(problems, errors.New("spec.contentDigest does not match canonical values"))
	}
	return errors.Join(problems...)
}

// ValidateConfigurationValues applies the Phase 1 SDK-free ENV configuration
// boundary independently of resource metadata. It is shared by public clients
// that must calculate the exact immutable revision digest before submission.
func ValidateConfigurationValues(values map[string]string) error {
	var problems []error
	if len(values) > 256 {
		problems = append(problems, errors.New("configuration values cannot exceed 256 entries"))
	}
	for key, item := range values {
		if !environmentKeyPattern.MatchString(key) {
			problems = append(problems, fmt.Errorf("configuration key %q is not a portable environment key", key))
		}
		normalizedKey := strings.ToLower(key)
		for _, fragment := range sensitiveKeyFragments {
			if strings.Contains(normalizedKey, fragment) {
				problems = append(problems, fmt.Errorf("configuration key %q is sensitive and must use a secret", key))
				break
			}
		}
		problems = append(
			problems,
			ValidateSafeExternalText("configuration value "+key, item, 32768, false),
		)
	}
	return errors.Join(problems...)
}

func ValidateApplicationRevision(value ApplicationRevision) error {
	var problems []error
	if value.APIVersion != APIVersion || value.Kind != "ApplicationRevision" {
		problems = append(problems, errors.New("application revision type metadata is invalid"))
	}
	problems = append(problems,
		ValidateResourceMetadata(value.Metadata),
		validateImmutableMetadata("application revision", value.Metadata),
		ValidateID("spec.applicationId", string(value.Spec.ApplicationID)),
		ValidateID("spec.revision", value.Spec.Revision),
		ValidateDigest("spec.contentDigest", value.Spec.ContentDigest),
	)
	if value.Metadata.Scope.Kind != AuthorityTenant {
		problems = append(problems, errors.New("application revision must be tenant scoped"))
	}
	if len(value.Spec.Components) == 0 {
		problems = append(problems, errors.New("application revision must contain at least one component"))
	}
	componentNames := make(map[string]struct{}, len(value.Spec.Components))
	for index, component := range value.Spec.Components {
		path := fmt.Sprintf("components[%d]", index)
		if !namePattern.MatchString(component.Name) {
			problems = append(problems, fmt.Errorf("%s.name is invalid", path))
		}
		if _, duplicate := componentNames[component.Name]; duplicate {
			problems = append(problems, fmt.Errorf("%s.name is duplicated", path))
		}
		componentNames[component.Name] = struct{}{}
		if component.Resources.CPUMillis < 0 || component.Resources.MemoryBytes < 0 {
			problems = append(problems, fmt.Errorf("%s.resources cannot be negative", path))
		}
		if !contains(
			[]ArtifactKind{ArtifactOCIImage, ArtifactOCIArtifact, ArtifactReleaseBundle},
			component.Artifact.Kind,
		) {
			problems = append(problems, fmt.Errorf("%s.artifact.kind is invalid", path))
		}
		problems = append(problems,
			ValidateSafeExternalText(path+".artifact.locator", component.Artifact.Locator, 2048, true),
			ValidateDigest(path+".artifact.digest", component.Artifact.Digest),
		)
		endpointNames := make(map[string]struct{}, len(component.Endpoints))
		for endpointIndex, endpoint := range component.Endpoints {
			endpointPath := fmt.Sprintf("%s.endpoints[%d]", path, endpointIndex)
			if !namePattern.MatchString(endpoint.Name) {
				problems = append(problems, fmt.Errorf("%s.name is invalid", endpointPath))
			}
			if _, duplicate := endpointNames[endpoint.Name]; duplicate {
				problems = append(problems, fmt.Errorf("%s.name is duplicated", endpointPath))
			}
			endpointNames[endpoint.Name] = struct{}{}
			if endpoint.Port == 0 {
				problems = append(problems, fmt.Errorf("%s.port must be positive", endpointPath))
			}
			if !contains([]EndpointProtocol{EndpointHTTP, EndpointGRPC, EndpointTCP}, endpoint.Protocol) {
				problems = append(problems, fmt.Errorf("%s.protocol is invalid", endpointPath))
			}
			if !contains([]EndpointVisibility{EndpointPrivate, EndpointPublic}, endpoint.Visibility) {
				problems = append(problems, fmt.Errorf("%s.visibility is invalid", endpointPath))
			}
		}
		inputNames := make(map[string]struct{}, len(component.Inputs))
		for inputIndex, input := range component.Inputs {
			inputPath := fmt.Sprintf("%s.inputs[%d]", path, inputIndex)
			if !namePattern.MatchString(input.Name) {
				problems = append(problems, fmt.Errorf("%s.name is invalid", inputPath))
			}
			if _, duplicate := inputNames[input.Name]; duplicate {
				problems = append(problems, fmt.Errorf("%s.name is duplicated", inputPath))
			}
			inputNames[input.Name] = struct{}{}
			if !contains([]InputKind{InputConfiguration, InputSecret}, input.Kind) {
				problems = append(problems, fmt.Errorf("%s.kind is invalid", inputPath))
			}
			if !contains([]InjectionMode{InjectionEnvironment, InjectionFile}, input.Injection) {
				problems = append(problems, fmt.Errorf("%s.injection is invalid", inputPath))
			}
			switch input.Kind {
			case InputConfiguration:
				if input.Injection != InjectionEnvironment {
					problems = append(problems, fmt.Errorf("%s CONFIGURATION input must use ENV injection", inputPath))
				}
			case InputSecret:
				if input.Injection != InjectionFile {
					problems = append(problems, fmt.Errorf("%s SECRET input must use FILE injection", inputPath))
				}
			}
		}
	}
	return errors.Join(problems...)
}

func ValidateDeployment(value Deployment) error {
	var problems []error
	if value.APIVersion != APIVersion || value.Kind != "Deployment" {
		problems = append(problems, errors.New("deployment type metadata is invalid"))
	}
	problems = append(problems,
		ValidateResourceMetadata(value.Metadata),
		validateDeploymentSpec(value.Spec),
		validateContractTime("status.observedAt", value.Status.ObservedAt),
	)
	if value.Metadata.Scope.Kind != AuthorityTenant {
		problems = append(problems, errors.New("deployment must be tenant scoped"))
	}
	if value.Generation == 0 {
		problems = append(problems, errors.New("deployment generation must be positive"))
	}
	if value.Status.ObservedGeneration > value.Generation {
		problems = append(problems, errors.New("observedGeneration cannot exceed generation"))
	}
	if value.Status.ObservedGeneration == 0 {
		if value.Status.ObservedApplicationRevisionID != "" || value.Status.ReadyComponents != 0 {
			problems = append(problems, errors.New("unobserved deployment cannot contain observed revision or ready components"))
		}
	} else if value.Status.ObservedApplicationRevisionID == "" {
		problems = append(problems, errors.New("observed deployment requires observedApplicationRevisionId"))
	}
	if !contains(DeploymentPhases(), value.Status.Phase) {
		problems = append(problems, fmt.Errorf("unknown deployment phase %q", value.Status.Phase))
	}
	if value.Status.ReadyComponents > uint32(len(value.Spec.Components)) {
		problems = append(problems, errors.New("readyComponents cannot exceed component count"))
	}
	if value.Status.PlacementDecisionID != "" {
		problems = append(problems, ValidateID("status.placementDecisionId", string(value.Status.PlacementDecisionID)))
	}
	if value.Status.CurrentOperationID != "" {
		problems = append(problems, ValidateID("status.currentOperationId", string(value.Status.CurrentOperationID)))
	}
	if value.Status.ObservedApplicationRevisionID != "" {
		problems = append(problems, ValidateID("status.observedApplicationRevisionId", string(value.Status.ObservedApplicationRevisionID)))
	}
	if value.Status.Phase == DeploymentReady {
		if value.Status.ObservedGeneration != value.Generation ||
			value.Status.ObservedApplicationRevisionID != value.Spec.ApplicationRevisionID ||
			value.Status.ReadyComponents != uint32(len(value.Spec.Components)) {
			problems = append(problems, errors.New("ready deployment must fully observe its current generation"))
		}
	}
	if value.Status.Phase == DeploymentStopped {
		if value.Status.ObservedGeneration != value.Generation || value.Status.ReadyComponents != 0 {
			problems = append(problems, errors.New("stopped deployment must observe its current generation with no ready components"))
		}
	}
	return errors.Join(problems...)
}

func ValidateDeploymentGeneration(value DeploymentGeneration) error {
	var problems []error
	if value.APIVersion != APIVersion || value.Kind != "DeploymentGeneration" {
		problems = append(problems, errors.New("deployment generation type metadata is invalid"))
	}
	problems = append(problems,
		ValidateResourceScope(value.Scope),
		ValidateID("deploymentId", string(value.DeploymentID)),
		validateDeploymentSpec(value.Spec),
		ValidateDigest("contentDigest", value.ContentDigest),
		ValidateID("createdByOperationId", string(value.CreatedByOperationID)),
		validateContractTime("createdAt", value.CreatedAt),
	)
	if value.Scope.Kind != AuthorityTenant {
		problems = append(problems, errors.New("deployment generation must be tenant scoped"))
	}
	if value.Generation == 0 {
		problems = append(problems, errors.New("deployment generation must be positive"))
	}
	if value.ContentDigest != DeploymentSpecContentDigest(value.Spec) {
		problems = append(problems, errors.New("contentDigest does not match canonical deployment spec"))
	}
	return errors.Join(problems...)
}

// ValidateDeploymentAgainstRevision checks the cross-resource shape before a
// deployment can enter placement. Repository-level validation separately
// proves tenant and application ownership for every referenced resource.
func ValidateDeploymentAgainstRevision(deployment Deployment, revision ApplicationRevision) error {
	var problems []error
	if err := ValidateDeployment(deployment); err != nil {
		problems = append(problems, err)
	}
	if err := ValidateApplicationRevision(revision); err != nil {
		problems = append(problems, err)
	}
	problems = append(problems, validateDeploymentSpecAgainstRevision(deployment.Spec, revision))
	return errors.Join(problems...)
}

func ValidateDeploymentGenerationAgainstRevision(
	generation DeploymentGeneration,
	revision ApplicationRevision,
) error {
	var problems []error
	if err := ValidateDeploymentGeneration(generation); err != nil {
		problems = append(problems, err)
	}
	if err := ValidateApplicationRevision(revision); err != nil {
		problems = append(problems, err)
	}
	if generation.Scope != revision.Metadata.Scope {
		problems = append(problems, errors.New("deployment generation and application revision scopes differ"))
	}
	problems = append(problems, validateDeploymentSpecAgainstRevision(generation.Spec, revision))
	return errors.Join(problems...)
}

func ValidateDeploymentExecutionRequest(value DeploymentExecutionRequest) error {
	var problems []error
	problems = append(problems,
		ValidateAdapterCommand(value.Command),
		ValidateDeploymentGenerationAgainstRevision(value.Generation, value.ApplicationRevision),
		ValidatePlacementDecision(value.Placement),
	)
	if !contains([]AdapterAction{
		AdapterValidateDeployment,
		AdapterApplyDeployment,
		AdapterStopDeployment,
		AdapterRollbackDeployment,
	}, value.Command.Action) {
		problems = append(problems, fmt.Errorf("deployment execution request action %q is invalid", value.Command.Action))
	}
	if value.Placement.Outcome != PlacementScheduled {
		problems = append(problems, errors.New("deployment execution requires a scheduled placement"))
	}
	if value.Command.Scope != value.Generation.Scope ||
		value.Command.Scope != value.ApplicationRevision.Metadata.Scope ||
		value.Command.Scope != value.Placement.Metadata.Scope {
		problems = append(problems, errors.New("deployment execution resource scopes differ"))
	}
	if value.Command.DeploymentID != value.Generation.DeploymentID ||
		value.Command.DeploymentID != value.Placement.DeploymentID {
		problems = append(problems, errors.New("deployment execution identities differ"))
	}
	if value.Command.ApplicationRevisionID != value.ApplicationRevision.Metadata.ID ||
		value.Command.ApplicationRevisionID != value.Generation.Spec.ApplicationRevisionID ||
		value.Command.ApplicationRevisionID != value.Placement.ApplicationRevisionID {
		problems = append(problems, errors.New("deployment execution application revision identities differ"))
	}
	if value.Command.ApplicationID != value.ApplicationRevision.Spec.ApplicationID {
		problems = append(problems, errors.New("deployment execution application identities differ"))
	}
	if value.Command.OperationID != value.Generation.CreatedByOperationID {
		problems = append(problems, errors.New("deployment execution operation and generation identities differ"))
	}
	if value.Command.ExecutionTargetID != value.Placement.ExecutionTargetID {
		problems = append(problems, errors.New("deployment execution target identities differ"))
	}
	if value.Generation.Generation != value.Placement.DeploymentGeneration ||
		value.Generation.Spec.PlacementPolicyID != value.Placement.PlacementPolicyID {
		problems = append(problems, errors.New("deployment execution generation and placement differ"))
	}

	expectedConfigurations := make(map[ResourceID]struct{})
	for _, component := range value.Generation.Spec.Components {
		for _, binding := range component.Bindings {
			if binding.ConfigurationRevisionID != "" {
				expectedConfigurations[binding.ConfigurationRevisionID] = struct{}{}
			}
		}
	}
	seenConfigurations := make(map[ResourceID]struct{}, len(value.ConfigurationRevisions))
	for index, revision := range value.ConfigurationRevisions {
		if err := ValidateConfigurationRevision(revision); err != nil {
			problems = append(problems, fmt.Errorf("configurationRevisions[%d]: %w", index, err))
		}
		if revision.Metadata.Scope != value.Command.Scope {
			problems = append(problems, fmt.Errorf("configurationRevisions[%d] has another scope", index))
		}
		if _, duplicate := seenConfigurations[revision.Metadata.ID]; duplicate {
			problems = append(problems, fmt.Errorf("configurationRevisions[%d] is duplicated", index))
		}
		seenConfigurations[revision.Metadata.ID] = struct{}{}
		if _, required := expectedConfigurations[revision.Metadata.ID]; !required {
			problems = append(problems, fmt.Errorf("configurationRevisions[%d] is not bound", index))
		}
	}
	for revisionID := range expectedConfigurations {
		if _, found := seenConfigurations[revisionID]; !found {
			problems = append(problems, fmt.Errorf("bound configuration revision %q is missing", revisionID))
		}
	}
	if value.Command.RequestDigest != DeploymentExecutionRequestDigest(value) {
		problems = append(problems, errors.New("command requestDigest does not match canonical execution input"))
	}
	return errors.Join(problems...)
}

func ValidateObserveDeploymentRequest(value ObserveDeploymentRequest) error {
	var problems []error
	problems = append(problems,
		ValidateAdapterCommand(value.Command),
		ValidateDigest("expectedContentDigest", value.ExpectedContentDigest),
	)
	if value.Command.Action != AdapterObserveDeployment {
		problems = append(problems, fmt.Errorf("observe deployment request action = %q, want %q", value.Command.Action, AdapterObserveDeployment))
	}
	if value.Generation == 0 {
		problems = append(problems, errors.New("observe deployment generation must be positive"))
	}
	if value.Command.RequestDigest != ObserveDeploymentRequestDigest(value) {
		problems = append(problems, errors.New("command requestDigest does not match canonical observation input"))
	}
	return errors.Join(problems...)
}

func ValidateObserveDeploymentRuntimeRequest(value ObserveDeploymentRuntimeRequest) error {
	var problems []error
	problems = append(problems,
		ValidateID("requestId", string(value.RequestID)),
		ValidateResourceScope(value.Scope),
		ValidateID("deploymentId", string(value.DeploymentID)),
		ValidateID("applicationRevisionId", string(value.ApplicationRevisionID)),
		ValidateID("executionTargetId", string(value.ExecutionTargetID)),
		ValidateDigest("expectedContentDigest", value.ExpectedContentDigest),
		validateContractTime("deadline", value.Deadline),
	)
	if value.Scope.Kind != AuthorityTenant {
		problems = append(problems, errors.New("deployment runtime observation must be tenant scoped"))
	}
	if value.Generation == 0 {
		problems = append(problems, errors.New("deployment runtime observation generation must be positive"))
	}
	return errors.Join(problems...)
}

func ValidateDeploymentObservation(value DeploymentObservation) error {
	var problems []error
	problems = append(problems,
		ValidateID("deploymentId", string(value.DeploymentID)),
		ValidateID("applicationRevisionId", string(value.ApplicationRevisionID)),
		ValidateDigest("receiptDigest", value.ReceiptDigest),
		validateContractTime("observedAt", value.ObservedAt),
	)
	if value.Generation == 0 {
		problems = append(problems, errors.New("deployment observation generation must be positive"))
	}
	if !contains([]DeploymentPhase{
		DeploymentApplying,
		DeploymentReady,
		DeploymentDegraded,
		DeploymentFailed,
		DeploymentStopping,
		DeploymentStopped,
	}, value.Phase) {
		problems = append(problems, fmt.Errorf("deployment observation phase %q is invalid", value.Phase))
	}
	seenEndpoints := make(map[string]struct{}, len(value.Endpoints))
	for index, endpoint := range value.Endpoints {
		path := fmt.Sprintf("endpoints[%d]", index)
		if !namePattern.MatchString(endpoint.ComponentName) ||
			!namePattern.MatchString(endpoint.EndpointName) ||
			!namePattern.MatchString(endpoint.Address) {
			problems = append(problems, fmt.Errorf("%s contains an invalid network-local name", path))
		}
		if endpoint.Port == 0 {
			problems = append(problems, fmt.Errorf("%s.port must be positive", path))
		}
		if !contains([]EndpointProtocol{EndpointHTTP, EndpointGRPC, EndpointTCP}, endpoint.Protocol) {
			problems = append(problems, fmt.Errorf("%s.protocol is invalid", path))
		}
		identity := endpoint.ComponentName + "\x00" + endpoint.EndpointName
		if _, duplicate := seenEndpoints[identity]; duplicate {
			problems = append(problems, fmt.Errorf("%s is duplicated", path))
		}
		seenEndpoints[identity] = struct{}{}
	}
	for index, evidence := range value.Evidence {
		if err := ValidateEvidence(evidence); err != nil {
			problems = append(problems, fmt.Errorf("evidence[%d]: %w", index, err))
		}
	}
	return errors.Join(problems...)
}

func ValidateDeploymentList(value DeploymentList) error {
	if value.APIVersion != APIVersion || value.Kind != "DeploymentList" ||
		ValidateResourceScope(value.Scope) != nil || value.Scope.Kind != AuthorityTenant ||
		value.Items == nil || len(value.Items) > MaximumDeploymentListItems {
		return errors.New("deployment list is invalid")
	}
	var previous ResourceID
	for index, item := range value.Items {
		if ValidateDeployment(item) != nil || item.Metadata.Scope != value.Scope {
			return errors.New("deployment list is invalid")
		}
		if index > 0 && item.Metadata.ID <= previous {
			return errors.New("deployment list is invalid")
		}
		previous = item.Metadata.ID
	}
	if value.NextAfter != "" {
		if ValidateID("nextAfter", string(value.NextAfter)) != nil || len(value.Items) == 0 ||
			value.NextAfter != value.Items[len(value.Items)-1].Metadata.ID {
			return errors.New("deployment list is invalid")
		}
	}
	return nil
}

func ValidateDeploymentRuntimeObservation(value DeploymentRuntimeObservation) error {
	var problems []error
	problems = append(problems,
		ValidateID("deploymentId", string(value.DeploymentID)),
		ValidateID("applicationRevisionId", string(value.ApplicationRevisionID)),
		ValidateID("executionTargetId", string(value.ExecutionTargetID)),
		validateContractTime("observedAt", value.ObservedAt),
	)
	if value.Generation == 0 {
		problems = append(problems, errors.New("deployment runtime generation must be positive"))
	}
	if value.Instances == nil || len(value.Instances) > MaximumDeploymentRuntimeInstances {
		problems = append(problems, errors.New("deployment runtime instances are invalid"))
	}
	seen := make(map[ResourceID]struct{}, len(value.Instances))
	for index, instance := range value.Instances {
		path := fmt.Sprintf("instances[%d]", index)
		if !deploymentInstanceIDPattern.MatchString(string(instance.ID)) {
			problems = append(problems, fmt.Errorf("%s.id is not an opaque node-derived identity", path))
		}
		if !namePattern.MatchString(instance.ComponentName) {
			problems = append(problems, fmt.Errorf("%s.componentName is invalid", path))
		}
		if !contains(DeploymentInstanceStates(), instance.State) {
			problems = append(problems, fmt.Errorf("%s.state is invalid", path))
		}
		if !contains(DeploymentInstanceHealthStates(), instance.Health) {
			problems = append(problems, fmt.Errorf("%s.health is invalid", path))
		}
		terminal := instance.State == DeploymentInstanceExited ||
			instance.State == DeploymentInstanceDead
		if (instance.ExitCode != nil) != terminal {
			problems = append(
				problems,
				fmt.Errorf("%s.exitCode must exactly match a terminal state", path),
			)
		}
		if _, duplicate := seen[instance.ID]; duplicate {
			problems = append(problems, fmt.Errorf("%s.id is duplicated", path))
		}
		seen[instance.ID] = struct{}{}
	}
	return errors.Join(problems...)
}

func ValidateDeploymentResourceObservation(value DeploymentResourceObservation) error {
	var problems []error
	problems = append(problems,
		ValidateID("deploymentId", string(value.DeploymentID)),
		ValidateID("applicationRevisionId", string(value.ApplicationRevisionID)),
		ValidateID("executionTargetId", string(value.ExecutionTargetID)),
		validateContractTime("observedAt", value.ObservedAt),
	)
	if value.Generation == 0 {
		problems = append(problems, errors.New("deployment resource generation must be positive"))
	}
	if value.Instances == nil || len(value.Instances) > MaximumDeploymentRuntimeInstances {
		problems = append(problems, errors.New("deployment resource instances are invalid"))
	}
	previous := ResourceID("")
	for index, instance := range value.Instances {
		path := fmt.Sprintf("instances[%d]", index)
		if !deploymentInstanceIDPattern.MatchString(string(instance.ID)) || instance.ID <= previous {
			problems = append(problems, fmt.Errorf("%s.id is invalid or unordered", path))
		}
		previous = instance.ID
		problems = append(problems, validateDeploymentInstanceResources(path, instance))
	}
	return errors.Join(problems...)
}

func validateDeploymentInstanceResources(path string, value DeploymentResourceInstance) error {
	var problems []error
	if !validResourceMeasurement(value.CPU.State, value.CPU.Value != nil, true, false) {
		problems = append(problems, fmt.Errorf("%s.cpu is invalid", path))
	}
	if cpu := value.CPU.Value; cpu != nil {
		if cpu.WindowMillis < 1 || cpu.WindowMillis > 60000 ||
			!finiteNonnegative(cpu.UsedCores) || cpu.UsedCores > 4096 ||
			cpu.LimitCPUMillis < 1 || cpu.LimitCPUMillis > 4096000 {
			problems = append(problems, fmt.Errorf("%s.cpu value is invalid", path))
		}
	}
	if !validResourceMeasurement(value.Memory.State, value.Memory.Value != nil, false, false) {
		problems = append(problems, fmt.Errorf("%s.memory is invalid", path))
	}
	if memory := value.Memory.Value; memory != nil {
		if !safeMeasurementInteger(memory.UsedBytes, memory.LimitBytes) ||
			memory.LimitBytes == 0 || memory.UsedBytes > memory.LimitBytes {
			problems = append(problems, fmt.Errorf("%s.memory value is invalid", path))
		}
	}
	if !validResourceMeasurement(value.Network.State, value.Network.Value != nil, false, false) {
		problems = append(problems, fmt.Errorf("%s.network is invalid", path))
	}
	if network := value.Network.Value; network != nil && !safeMeasurementInteger(
		network.ReceivedBytes, network.TransmittedBytes,
		network.ReceiveErrors, network.TransmitErrors,
		network.ReceiveDrops, network.TransmitDrops,
	) {
		problems = append(problems, fmt.Errorf("%s.network value is invalid", path))
	}
	if !validResourceMeasurement(value.BlockIO.State, value.BlockIO.Value != nil, false, false) {
		problems = append(problems, fmt.Errorf("%s.blockIo is invalid", path))
	}
	if block := value.BlockIO.Value; block != nil && !safeMeasurementInteger(
		block.ReadBytes, block.WriteBytes, block.ReadOperations, block.WriteOperations,
	) {
		problems = append(problems, fmt.Errorf("%s.blockIo value is invalid", path))
	}
	if !validResourceMeasurement(value.Storage.State, value.Storage.Value != nil, false, true) {
		problems = append(problems, fmt.Errorf("%s.storage is invalid", path))
	}
	if storage := value.Storage.Value; storage != nil {
		if validateContractTime("storage.observedAt", storage.ObservedAt) != nil ||
			validateContractTime("storage.validUntil", storage.ValidUntil) != nil ||
			!storage.ValidUntil.After(storage.ObservedAt) ||
			storage.ValidUntil.Sub(storage.ObservedAt) > 5*time.Minute ||
			!safeMeasurementInteger(
				storage.WritableLayerBytes, storage.ImageTotalBytes,
				storage.ImageSharedBytes, storage.ImageUniqueBytes,
			) || storage.ImageSharedBytes > storage.ImageTotalBytes ||
			storage.ImageUniqueBytes != storage.ImageTotalBytes-storage.ImageSharedBytes ||
			!validResourceMeasurement(storage.VolumesState, storage.Volumes != nil, false, false) {
			problems = append(problems, fmt.Errorf("%s.storage value is invalid", path))
		}
		if volumes := storage.Volumes; volumes != nil {
			if !safeMeasurementInteger(volumes.Bytes, volumes.SharedBytes) ||
				volumes.SharedCount > volumes.Count || volumes.SharedBytes > volumes.Bytes {
				problems = append(problems, fmt.Errorf("%s.volume value is invalid", path))
			}
		}
	}
	return errors.Join(problems...)
}

func validResourceMeasurement(state MeasurementState, present, warming, stale bool) bool {
	switch state {
	case MeasurementAvailable:
		return present
	case MeasurementWarmingUp:
		return warming && !present
	case MeasurementStale:
		return stale && present
	case MeasurementUnavailable, MeasurementUnsupported:
		return !present
	default:
		return false
	}
}

func ValidateDeploymentResourceSnapshot(value DeploymentResourceSnapshot) error {
	switch value.State {
	case MeasurementAvailable, MeasurementStale:
		if value.Value == nil || ValidateDeploymentResourceObservation(value.Value.Observation) != nil ||
			validateContractTime("validUntil", value.Value.ValidUntil) != nil ||
			!value.Value.ValidUntil.After(value.Value.Observation.ObservedAt) ||
			value.Value.ValidUntil.Sub(value.Value.Observation.ObservedAt) > time.Minute {
			return errors.New("deployment resource snapshot is invalid")
		}
	case MeasurementUnavailable:
		if value.Value != nil {
			return errors.New("unavailable deployment resources must not contain a value")
		}
	default:
		return errors.New("deployment resource snapshot state is invalid")
	}
	return nil
}

func ValidateDeploymentRuntimeSnapshot(value DeploymentRuntimeSnapshot) error {
	var problems []error
	if value.APIVersion != APIVersion || value.Kind != "DeploymentRuntimeSnapshot" {
		problems = append(problems, errors.New("deployment runtime snapshot type metadata is invalid"))
	}
	problems = append(problems,
		ValidateResourceScope(value.Scope),
		ValidateDeploymentResourceSnapshot(value.Resources),
	)
	if value.Scope.Kind != AuthorityTenant {
		problems = append(problems, errors.New("deployment runtime snapshot must be tenant scoped"))
	}
	switch value.State {
	case MeasurementAvailable, MeasurementStale:
		if value.Value == nil {
			problems = append(problems, errors.New("deployment runtime value is required"))
			break
		}
		problems = append(problems,
			ValidateDeploymentRuntimeObservation(value.Value.Observation),
			validateContractTime("validUntil", value.Value.ValidUntil),
		)
		if !value.Value.ValidUntil.After(value.Value.Observation.ObservedAt) {
			problems = append(problems, errors.New("deployment runtime validity window is invalid"))
		}
	case MeasurementUnavailable:
		if value.Value != nil {
			problems = append(problems, errors.New("unavailable deployment runtime must not contain a value"))
		}
		if value.Resources.State != MeasurementUnavailable {
			problems = append(problems, errors.New("unavailable deployment runtime cannot contain current resources"))
		}
	default:
		problems = append(problems, errors.New("deployment runtime state is invalid"))
	}
	if value.Value != nil && value.Resources.Value != nil {
		runtime := value.Value.Observation
		resources := value.Resources.Value.Observation
		if runtime.DeploymentID != resources.DeploymentID || runtime.Generation != resources.Generation ||
			runtime.ApplicationRevisionID != resources.ApplicationRevisionID ||
			runtime.ExecutionTargetID != resources.ExecutionTargetID ||
			len(runtime.Instances) != len(resources.Instances) {
			problems = append(problems, errors.New("deployment runtime and resource identities do not match"))
		} else {
			seen := make(map[ResourceID]struct{}, len(runtime.Instances))
			for _, instance := range runtime.Instances {
				seen[instance.ID] = struct{}{}
			}
			for _, instance := range resources.Instances {
				if _, found := seen[instance.ID]; !found {
					problems = append(problems, errors.New("deployment runtime and resource instances do not match"))
					break
				}
			}
		}
	}
	return errors.Join(problems...)
}

func ValidateTerminalSize(value TerminalSize) error {
	if value.Columns < MinimumTerminalColumns || value.Columns > MaximumTerminalColumns ||
		value.Rows < MinimumTerminalRows || value.Rows > MaximumTerminalRows {
		return errors.New("terminal size is outside the supported range")
	}
	return nil
}

func ValidateTerminalSessionID(value ResourceID) error {
	if !terminalSessionIDPattern.MatchString(string(value)) {
		return errors.New("terminal session identity is invalid")
	}
	return nil
}

func ValidateDeploymentInstanceID(value ResourceID) error {
	if !deploymentInstanceIDPattern.MatchString(string(value)) {
		return errors.New("Deployment instance identity is invalid")
	}
	return nil
}

func ValidateCreateTerminalSessionRequest(value CreateTerminalSessionRequest) error {
	return errors.Join(
		ValidateDeploymentInstanceID(value.InstanceID),
		ValidateTerminalSize(value.Size),
	)
}

func ValidateTerminalSession(value TerminalSession) error {
	var problems []error
	if value.APIVersion != APIVersion || value.Kind != "TerminalSession" ||
		ValidateTerminalSessionID(value.ID) != nil {
		problems = append(problems, errors.New("terminal session type or identity is invalid"))
	}
	problems = append(problems,
		ValidateResourceScope(value.Scope),
		ValidateID("deploymentId", string(value.DeploymentID)),
		ValidateID("applicationRevisionId", string(value.ApplicationRevisionID)),
		ValidateTerminalSize(value.Size),
		validateContractTime("createdAt", value.CreatedAt),
		validateContractTime("connectBefore", value.ConnectBefore),
		validateContractTime("expiresAt", value.ExpiresAt),
	)
	if value.Scope.Kind != AuthorityTenant ||
		!deploymentInstanceIDPattern.MatchString(string(value.InstanceID)) || value.Generation == 0 {
		problems = append(problems, errors.New("terminal session Deployment binding is invalid"))
	}
	if !value.ConnectBefore.After(value.CreatedAt) || value.ConnectBefore.After(value.ExpiresAt) ||
		!value.ExpiresAt.After(value.CreatedAt) ||
		value.ConnectBefore.Sub(value.CreatedAt) > TerminalSessionConnectTimeout ||
		value.ExpiresAt.Sub(value.CreatedAt) > MaximumTerminalSessionDuration {
		problems = append(problems, errors.New("terminal session time boundary is invalid"))
	}
	if value.ConnectedAt != nil {
		problems = append(problems, validateContractTime("connectedAt", *value.ConnectedAt))
		if value.ConnectedAt.Before(value.CreatedAt) || value.ConnectedAt.After(value.ExpiresAt) {
			problems = append(problems, errors.New("terminal connection time is invalid"))
		}
	}
	if value.EndedAt != nil {
		problems = append(problems, validateContractTime("endedAt", *value.EndedAt))
		if value.EndedAt.Before(value.CreatedAt) ||
			(value.ConnectedAt != nil && value.EndedAt.Before(*value.ConnectedAt)) {
			problems = append(problems, errors.New("terminal end time is invalid"))
		}
	}
	switch value.State {
	case TerminalSessionPending, TerminalSessionConnecting:
		if value.Outcome != "" || value.ConnectedAt != nil || value.EndedAt != nil {
			problems = append(problems, errors.New("unstarted terminal session contains terminal fields"))
		}
	case TerminalSessionActive:
		if value.Outcome != "" || value.ConnectedAt == nil || value.EndedAt != nil {
			problems = append(problems, errors.New("active terminal session lifecycle is invalid"))
		}
	case TerminalSessionEnded:
		if !contains(TerminalSessionOutcomes(), value.Outcome) || value.EndedAt == nil {
			problems = append(problems, errors.New("ended terminal session requires a closed outcome and time"))
		}
	default:
		problems = append(problems, errors.New("terminal session state is invalid"))
	}
	return errors.Join(problems...)
}

func validateDeploymentSpec(value DeploymentSpec) error {
	var problems []error
	problems = append(problems,
		ValidateID("spec.applicationRevisionId", string(value.ApplicationRevisionID)),
		ValidateID("spec.placementPolicyId", string(value.PlacementPolicyID)),
	)
	if !contains([]DeploymentDesiredState{DeploymentDesiredRunning, DeploymentDesiredStopped}, value.DesiredState) {
		problems = append(problems, fmt.Errorf("unknown deployment desired state %q", value.DesiredState))
	}
	if len(value.Components) == 0 {
		problems = append(problems, errors.New("deployment must contain at least one component"))
	}
	componentNames := make(map[string]struct{}, len(value.Components))
	for componentIndex, component := range value.Components {
		path := fmt.Sprintf("components[%d]", componentIndex)
		if !namePattern.MatchString(component.Name) {
			problems = append(problems, fmt.Errorf("%s.name is invalid", path))
		}
		if _, duplicate := componentNames[component.Name]; duplicate {
			problems = append(problems, fmt.Errorf("%s.name is duplicated", path))
		}
		componentNames[component.Name] = struct{}{}
		if component.Replicas == 0 {
			problems = append(problems, fmt.Errorf("%s.replicas must be positive", path))
		}
		bindingNames := make(map[string]struct{}, len(component.Bindings))
		for bindingIndex, binding := range component.Bindings {
			bindingPath := fmt.Sprintf("%s.bindings[%d]", path, bindingIndex)
			if !namePattern.MatchString(binding.Name) {
				problems = append(problems, fmt.Errorf("%s.name is invalid", bindingPath))
			}
			if _, duplicate := bindingNames[binding.Name]; duplicate {
				problems = append(problems, fmt.Errorf("%s.name is duplicated", bindingPath))
			}
			bindingNames[binding.Name] = struct{}{}
			hasConfiguration := binding.ConfigurationRevisionID != ""
			hasSecret := binding.SecretVersion != nil
			if hasConfiguration == hasSecret {
				problems = append(problems, fmt.Errorf("%s must bind exactly one configuration revision or secret version", bindingPath))
			}
			if hasConfiguration {
				problems = append(problems, ValidateID(bindingPath+".configurationRevisionId", string(binding.ConfigurationRevisionID)))
			}
			if hasSecret {
				problems = append(problems,
					ValidateID(bindingPath+".secretVersion.secretId", string(binding.SecretVersion.SecretID)),
					ValidateID(bindingPath+".secretVersion.version", binding.SecretVersion.Version),
				)
			}
		}
	}
	return errors.Join(problems...)
}

func validateDeploymentSpecAgainstRevision(value DeploymentSpec, revision ApplicationRevision) error {
	var problems []error
	if value.ApplicationRevisionID != revision.Metadata.ID {
		problems = append(problems, errors.New("deployment references another application revision"))
	}
	revisionComponents := make(map[string]ApplicationRevisionComponent, len(revision.Spec.Components))
	for _, component := range revision.Spec.Components {
		revisionComponents[component.Name] = component
	}
	if len(value.Components) != len(revision.Spec.Components) {
		problems = append(problems, errors.New("deployment component set must exactly match application revision"))
	}
	for _, component := range value.Components {
		revisionComponent, found := revisionComponents[component.Name]
		if !found {
			problems = append(problems, fmt.Errorf("deployment component %q is not declared by the application revision", component.Name))
			continue
		}
		inputs := make(map[string]ComponentInput, len(revisionComponent.Inputs))
		for _, input := range revisionComponent.Inputs {
			inputs[input.Name] = input
		}
		bound := make(map[string]struct{}, len(component.Bindings))
		for _, binding := range component.Bindings {
			input, declared := inputs[binding.Name]
			if !declared {
				problems = append(problems, fmt.Errorf("component %q binding %q is not declared", component.Name, binding.Name))
				continue
			}
			bound[binding.Name] = struct{}{}
			if input.Kind == InputConfiguration && binding.ConfigurationRevisionID == "" {
				problems = append(problems, fmt.Errorf("component %q input %q requires a configuration revision", component.Name, input.Name))
			}
			if input.Kind == InputSecret && binding.SecretVersion == nil {
				problems = append(problems, fmt.Errorf("component %q input %q requires a secret version", component.Name, input.Name))
			}
		}
		for _, input := range revisionComponent.Inputs {
			if _, found := bound[input.Name]; input.Required && !found {
				problems = append(problems, fmt.Errorf("component %q required input %q is unbound", component.Name, input.Name))
			}
		}
	}
	return errors.Join(problems...)
}

func ValidateProblem(value Problem) error {
	var problems []error
	if value.Status < 400 || value.Status > 599 {
		problems = append(problems, errors.New("problem status must be an HTTP error status"))
	}
	if !contains(ErrorCodes(), value.Code) {
		problems = append(problems, fmt.Errorf("unknown problem code %q", value.Code))
	}
	problems = append(problems,
		ValidateSafeExternalText("problem.type", value.Type, 512, true),
		ValidateSafeExternalText("problem.title", value.Title, 256, true),
		ValidateSafeExternalText("problem.detail", value.Detail, 2048, true),
		ValidateID("problem.traceId", value.TraceID),
	)
	if len(value.Violations) > 64 {
		problems = append(problems, errors.New("problem violations cannot exceed 64 entries"))
	}
	for index, violation := range value.Violations {
		problems = append(problems,
			ValidateSafeExternalText(
				fmt.Sprintf("problem.violations[%d].field", index),
				violation.Field,
				256,
				true,
			),
			ValidateSafeExternalText(
				fmt.Sprintf("problem.violations[%d].description", index),
				violation.Description,
				512,
				true,
			),
		)
	}
	return errors.Join(problems...)
}

func ValidateOperation(value Operation) error {
	var problems []error
	if value.APIVersion != APIVersion || value.Kind != "Operation" {
		problems = append(problems, errors.New("operation type metadata is invalid"))
	}
	problems = append(problems,
		ValidateID("operation.id", string(value.ID)),
		ValidateResourceScope(value.Scope),
		ValidateID("operation.target.id", string(value.Target.ID)),
		ValidateID("operation.requestedBy.id", value.RequestedBy.ID),
		ValidateDigest("operation.idempotencyFingerprint", value.IdempotencyFingerprint),
		ValidateDigest("operation.requestDigest", value.RequestDigest),
		validateContractTime("operation.createdAt", value.CreatedAt),
		validateContractTime("operation.updatedAt", value.UpdatedAt),
	)
	if value.Attempt == 0 {
		problems = append(problems, errors.New("operation attempt must be positive"))
	}
	if !contains(OperationActions(), value.Action) {
		problems = append(problems, fmt.Errorf("unknown operation action %q", value.Action))
	}
	switch value.Action {
	case OperationCreateExecutionPool, OperationRegisterExecutionTarget,
		OperationDrainExecutionTarget, OperationActivateExecutionTarget,
		OperationRemoveExecutionTarget:
		problems = append(problems, ValidateID("operation.installationId", value.InstallationID))
		if value.Scope.Kind != AuthorityPlatform || value.RequestedBy.Type != SubjectUser {
			problems = append(problems, errors.New("platform operation requires installation scope and a user"))
		}
		expectedTarget := "ExecutionPool"
		if value.Action != OperationCreateExecutionPool {
			expectedTarget = "ExecutionTarget"
		}
		if value.Target.Kind != expectedTarget {
			problems = append(problems, errors.New("platform operation target kind differs from its action"))
		}
	case OperationCreatePlacement,
		OperationCreateApplication,
		OperationCreateConfiguration,
		OperationCreateConfigurationRevision,
		OperationCreateApplicationRevision,
		OperationDeploy,
		OperationUpdate,
		OperationStop,
		OperationRollback:
		if value.Scope.Kind != AuthorityTenant || value.InstallationID != "" {
			problems = append(problems, errors.New("tenant operation action requires tenant scope"))
		}
	}
	if !contains(OperationStates(), value.State) {
		problems = append(problems, fmt.Errorf("unknown operation state %q", value.State))
	}
	if strings.TrimSpace(value.Target.Kind) == "" {
		problems = append(problems, errors.New("operation target kind is required"))
	}
	if !contains(
		[]SubjectType{SubjectUser, SubjectServiceAccount, SubjectAgent, SubjectSystemUser},
		value.RequestedBy.Type,
	) {
		problems = append(problems, fmt.Errorf("unknown requester type %q", value.RequestedBy.Type))
	}
	if value.UpdatedAt.Before(value.CreatedAt) {
		problems = append(problems, errors.New("operation.updatedAt cannot precede createdAt"))
	}
	if value.Error != nil {
		problems = append(problems, ValidateProblem(*value.Error))
	}
	if value.TerminalAt != nil {
		problems = append(problems, validateContractTime("operation.terminalAt", *value.TerminalAt))
	}
	terminal := contains(
		[]OperationState{
			OperationSucceeded,
			OperationFailed,
			OperationCancelled,
			OperationManualIntervention,
		},
		value.State,
	)
	if terminal && value.TerminalAt == nil {
		problems = append(problems, errors.New("terminal operation requires terminalAt"))
	}
	if !terminal && value.TerminalAt != nil {
		problems = append(problems, errors.New("non-terminal operation cannot contain terminalAt"))
	}
	if value.TerminalAt != nil &&
		(value.TerminalAt.Before(value.CreatedAt) || value.TerminalAt.After(value.UpdatedAt)) {
		problems = append(
			problems,
			errors.New("operation.terminalAt must be between createdAt and updatedAt"),
		)
	}
	failed := value.State == OperationFailed || value.State == OperationManualIntervention
	if failed && value.Error == nil {
		problems = append(problems, errors.New("failed operation requires a normalized error"))
	}
	if !failed && value.Error != nil {
		problems = append(problems, errors.New("only failed operations can contain an error"))
	}
	return errors.Join(problems...)
}

func ValidateEvidence(value Evidence) error {
	var problems []error
	if value.APIVersion != APIVersion || value.Kind != "Evidence" {
		problems = append(problems, errors.New("evidence type metadata is invalid"))
	}
	problems = append(problems,
		ValidateID("evidence.id", string(value.ID)),
		ValidateResourceScope(value.Scope),
		ValidateID("evidence.operationId", string(value.OperationID)),
		ValidateID("evidence.source", value.Source),
		ValidateID("evidence.code", value.Code),
		ValidateSafeExternalText("evidence.message", value.Message, 1024, true),
		ValidateDigest("evidence.contentDigest", value.ContentDigest),
		validateContractTime("evidence.occurredAt", value.OccurredAt),
	)
	if value.Sequence == 0 {
		problems = append(problems, errors.New("evidence sequence must be positive"))
	}
	if value.PreviousDigest != "" {
		problems = append(problems, ValidateDigest("evidence.previousDigest", value.PreviousDigest))
	}
	if !contains(
		[]EvidenceType{
			EvidencePolicyDecision,
			EvidencePlacementDecision,
			EvidenceAdapterCommand,
			EvidenceAdapterResult,
			EvidenceObservation,
			EvidenceVerification,
			EvidenceAuditDispatch,
		},
		value.Type,
	) {
		problems = append(problems, fmt.Errorf("unknown evidence type %q", value.Type))
	}
	if !contains(
		[]EvidenceSeverity{EvidenceInfo, EvidenceWarning, EvidenceError},
		value.Severity,
	) {
		problems = append(problems, fmt.Errorf("unknown evidence severity %q", value.Severity))
	}
	if len(value.Attributes) > 64 {
		problems = append(problems, errors.New("evidence attributes cannot exceed 64 entries"))
	}
	for key, item := range value.Attributes {
		normalized := strings.ToLower(key)
		for _, fragment := range sensitiveKeyFragments {
			if strings.Contains(normalized, fragment) {
				problems = append(problems, fmt.Errorf("evidence attribute key %q is sensitive", key))
				break
			}
		}
		problems = append(problems,
			ValidateSafeExternalText("evidence attribute key", key, 128, true),
			ValidateSafeExternalText("evidence attribute value", item, 4096, false),
		)
	}
	return errors.Join(problems...)
}

func ValidateAdapterCommand(value AdapterCommandEnvelope) error {
	var problems []error
	problems = append(problems,
		ValidateID("operationId", string(value.OperationID)),
		ValidateID("commandId", string(value.CommandID)),
		ValidateResourceScope(value.Scope),
		ValidateID("executionTargetId", string(value.ExecutionTargetID)),
		ValidateDigest("requestDigest", value.RequestDigest),
		ValidateID("bindingRef", value.BindingRef),
		validateContractTime("deadline", value.Deadline),
	)
	if value.Attempt == 0 {
		problems = append(problems, errors.New("attempt must be positive"))
	}
	if !contains(adapterActions(), value.Action) {
		problems = append(problems, fmt.Errorf("unknown adapter action %q", value.Action))
	}
	if value.ApplicationID != "" {
		problems = append(problems, ValidateID("applicationId", string(value.ApplicationID)))
	}
	if value.ApplicationRevisionID != "" {
		problems = append(problems, ValidateID("applicationRevisionId", string(value.ApplicationRevisionID)))
	}
	if value.DeploymentID != "" {
		problems = append(problems, ValidateID("deploymentId", string(value.DeploymentID)))
	}
	switch value.Action {
	case AdapterCapabilities, AdapterInspectExecutionTarget, AdapterObserveExecutionTarget:
		if value.Scope.Kind != AuthorityPlatform {
			problems = append(problems, errors.New("infrastructure adapter action requires platform scope"))
		}
		if value.ApplicationID != "" || value.ApplicationRevisionID != "" || value.DeploymentID != "" {
			problems = append(problems, errors.New("infrastructure adapter action cannot contain application or deployment identity"))
		}
	case AdapterValidateDeployment, AdapterApplyDeployment, AdapterObserveDeployment,
		AdapterStopDeployment, AdapterRollbackDeployment, AdapterReconcileRoutes,
		AdapterObserveRoutes, AdapterDeleteRoutes:
		if value.Scope.Kind != AuthorityTenant {
			problems = append(problems, errors.New("deployment adapter action requires tenant scope"))
		}
		if value.ApplicationID == "" || value.ApplicationRevisionID == "" || value.DeploymentID == "" {
			problems = append(problems, errors.New("deployment adapter action requires application, revision, and deployment identity"))
		}
	}
	if value.TraceParent != "" {
		problems = append(
			problems,
			ValidateSafeExternalText("traceparent", value.TraceParent, 55, false),
		)
	}
	return errors.Join(problems...)
}

func ValidateInspectExecutionTargetRequest(value InspectExecutionTargetRequest) error {
	if err := ValidateAdapterCommand(value.Command); err != nil {
		return err
	}
	if value.Command.Action != AdapterInspectExecutionTarget {
		return fmt.Errorf(
			"inspect target request action = %q, want %q",
			value.Command.Action,
			AdapterInspectExecutionTarget,
		)
	}
	if value.Command.Scope.Kind != AuthorityPlatform {
		return errors.New("inspect target request requires platform scope")
	}
	return nil
}

func ValidateObserveExecutionTargetRequest(value ObserveExecutionTargetRequest) error {
	if err := ValidateAdapterCommand(value.Command); err != nil {
		return err
	}
	if value.Command.Action != AdapterObserveExecutionTarget {
		return fmt.Errorf(
			"observe target request action = %q, want %q",
			value.Command.Action,
			AdapterObserveExecutionTarget,
		)
	}
	if value.Command.Scope.Kind != AuthorityPlatform {
		return errors.New("observe target request requires platform scope")
	}
	return nil
}

func ValidateExecutionTargetObservation(value ExecutionTargetObservation) error {
	var problems []error
	problems = append(problems,
		ValidateID("executionTargetId", string(value.ExecutionTargetID)),
		ValidateDigest("identityFingerprint", value.IdentityFingerprint),
		validateLabels("labels", value.Labels),
		validateCapacity("capacity", value.Capacity),
		validateCapacity("allocatable", value.Allocatable),
		validateUniqueKnown(
			"supportedIsolationGuarantees",
			value.SupportedIsolationGuarantees,
			IsolationGuarantees(),
			false,
		),
		validateContractTime("observedAt", value.ObservedAt),
	)
	if !contains(
		[]ExecutionTargetHealth{
			ExecutionTargetHealthUnknown,
			ExecutionTargetHealthReady,
			ExecutionTargetHealthDegraded,
			ExecutionTargetHealthUnavailable,
		},
		value.Health,
	) {
		problems = append(problems, fmt.Errorf("unknown target health %q", value.Health))
	}
	if exceedsCapacity(value.Allocatable, value.Capacity) {
		problems = append(problems, errors.New("allocatable resources cannot exceed capacity"))
	}
	if value.Usage != nil {
		problems = append(problems, ValidateExecutionTargetUsage(*value.Usage))
	}
	return errors.Join(problems...)
}

const MaximumObservedFilesystems = 128

func ValidateExecutionTargetUsage(value ExecutionTargetUsage) error {
	invalid := errors.New("execution target usage is invalid")
	if validateContractTime("observedAt", value.ObservedAt) != nil ||
		validateContractTime("validUntil", value.ValidUntil) != nil ||
		!value.ValidUntil.After(value.ObservedAt) || value.ValidUntil.Sub(value.ObservedAt) > time.Minute ||
		!validMeasurement(value.CPU.State, value.CPU.Value != nil, true) ||
		!validMeasurement(value.Memory.State, value.Memory.Value != nil, false) ||
		!validMeasurement(value.FilesystemsState, len(value.Filesystems) > 0, false) ||
		len(value.Filesystems) > MaximumObservedFilesystems {
		return invalid
	}
	if cpu := value.CPU.Value; cpu != nil {
		if cpu.LogicalCPUs < 1 || cpu.LogicalCPUs > 4096 || cpu.WindowMillis < 1 || cpu.WindowMillis > 60000 ||
			!finiteNonnegative(cpu.UtilizationRatio) || !finiteNonnegative(cpu.IOWaitRatio) ||
			cpu.UtilizationRatio > 1 || cpu.IOWaitRatio > 1 ||
			cpu.UtilizationRatio+cpu.IOWaitRatio > 1.000000001 ||
			!finiteNonnegative(cpu.Load1) || !finiteNonnegative(cpu.Load5) || !finiteNonnegative(cpu.Load15) {
			return invalid
		}
	}
	if memory := value.Memory.Value; memory != nil {
		if !safeMeasurementInteger(memory.TotalBytes, memory.AvailableBytes, memory.UsedBytes,
			memory.SwapTotalBytes, memory.SwapFreeBytes) || memory.TotalBytes == 0 ||
			memory.AvailableBytes > memory.TotalBytes || memory.UsedBytes != memory.TotalBytes-memory.AvailableBytes ||
			memory.SwapFreeBytes > memory.SwapTotalBytes {
			return invalid
		}
	}
	seen := make(map[string]bool, len(value.Filesystems))
	for _, filesystem := range value.Filesystems {
		if !measurementLabel(filesystem.Device, 256) || !measurementLabel(filesystem.MountPoint, 1024) ||
			!strings.HasPrefix(filesystem.MountPoint, "/") || !measurementLabel(filesystem.FilesystemType, 64) ||
			!validMeasurement(filesystem.State, filesystem.Value != nil, false) {
			return invalid
		}
		key := filesystem.Device + "\x00" + filesystem.MountPoint + "\x00" + filesystem.FilesystemType
		if seen[key] {
			return invalid
		}
		seen[key] = true
		if usage := filesystem.Value; usage != nil {
			if !safeMeasurementInteger(usage.TotalBytes, usage.UsedBytes, usage.AvailableBytes) ||
				usage.UsedBytes > usage.TotalBytes || usage.AvailableBytes > usage.TotalBytes-usage.UsedBytes ||
				(usage.TotalInodes == nil) != (usage.FreeInodes == nil) ||
				!validMeasurement(usage.InodesState, usage.TotalInodes != nil, false) {
				return invalid
			}
			if usage.TotalInodes != nil && (!safeMeasurementInteger(*usage.TotalInodes, *usage.FreeInodes) ||
				*usage.TotalInodes == 0 || *usage.FreeInodes > *usage.TotalInodes) {
				return invalid
			}
		}
	}
	return nil
}

func validMeasurement(state MeasurementState, present, warming bool) bool {
	switch state {
	case MeasurementAvailable:
		return present
	case MeasurementStale:
		return true // Last known values may be retained, but never restamped.
	case MeasurementUnavailable, MeasurementUnsupported:
		return !present
	case MeasurementWarmingUp:
		return warming && !present
	default:
		return false
	}
}

func finiteNonnegative(value float64) bool {
	return !math.IsNaN(value) && !math.IsInf(value, 0) && value >= 0
}

func safeMeasurementInteger(values ...int64) bool {
	for _, value := range values {
		if value < 0 || value > 9007199254740991 {
			return false
		}
	}
	return true
}

func measurementLabel(value string, maximum int) bool {
	return value != "" && len(value) <= maximum && utf8.ValidString(value) &&
		strings.IndexFunc(value, func(r rune) bool { return r < 32 || r == 127 }) < 0
}

func ValidateAdapterCapabilities(value AdapterCapabilitiesContract) error {
	var problems []error
	problems = append(problems,
		validateAdapterRef("adapter", value.Adapter, value.Adapter.Kind),
		validateUniqueKnown(
			"actions",
			value.Actions,
			adapterActionsForKind(value.Adapter.Kind),
			true,
		),
		validateUniqueKnown("isolationGuarantees", value.IsolationGuarantees, IsolationGuarantees(), false),
		validateContractTime("observedAt", value.ObservedAt),
	)
	if !contains(
		[]AdapterKind{AdapterInfrastructure, AdapterDeploymentExecutor, AdapterGateway},
		value.Adapter.Kind,
	) {
		problems = append(problems, fmt.Errorf("unknown adapter kind %q", value.Adapter.Kind))
	}
	return errors.Join(problems...)
}

func ValidateNormalizedAdapterError(value NormalizedAdapterError) error {
	var problems []error
	if !contains(
		[]AdapterErrorClass{
			AdapterErrorValidation,
			AdapterErrorConflict,
			AdapterErrorPermissionDenied,
			AdapterErrorQuotaExceeded,
			AdapterErrorRateLimited,
			AdapterErrorTransient,
			AdapterErrorUnavailable,
			AdapterErrorTimeout,
			AdapterErrorNotFound,
			AdapterErrorUnknownOutcome,
			AdapterErrorInternal,
		},
		value.Class,
	) {
		problems = append(problems, fmt.Errorf("unknown adapter error class %q", value.Class))
	}
	if !contains(ErrorCodes(), value.Code) {
		problems = append(problems, fmt.Errorf("unknown adapter error code %q", value.Code))
	}
	problems = append(
		problems,
		ValidateSafeExternalText("adapter error message", value.Message, 1024, true),
	)
	if value.RetryAfterSeconds != nil &&
		(*value.RetryAfterSeconds == 0 || *value.RetryAfterSeconds > 86400) {
		problems = append(problems, errors.New("retryAfterSeconds must be between 1 and 86400"))
	}
	if value.Class == AdapterErrorUnknownOutcome && value.Code != ErrorAdapterOutcomeUnknown {
		problems = append(
			problems,
			errors.New("unknown-outcome class requires ADAPTER_OUTCOME_UNKNOWN"),
		)
	}
	if value.Code == ErrorAdapterOutcomeUnknown && value.Class != AdapterErrorUnknownOutcome {
		problems = append(
			problems,
			errors.New("ADAPTER_OUTCOME_UNKNOWN requires unknown-outcome class"),
		)
	}
	return errors.Join(problems...)
}

func ValidateAdapterResult(value AdapterResult) error {
	var problems []error
	problems = append(problems,
		ValidateID("commandId", string(value.CommandID)),
		ValidateSafeExternalText("receipt", value.Receipt, 2048, false),
		validateContractTime("observedAt", value.ObservedAt),
	)
	if !contains(
		[]AdapterResultState{
			AdapterResultSucceeded,
			AdapterResultInProgress,
			AdapterResultFailed,
			AdapterResultUnknown,
		},
		value.State,
	) {
		problems = append(problems, fmt.Errorf("unknown adapter result state %q", value.State))
	}
	if value.Error != nil {
		problems = append(problems, ValidateNormalizedAdapterError(*value.Error))
	}
	failed := value.State == AdapterResultFailed || value.State == AdapterResultUnknown
	if failed && value.Error == nil {
		problems = append(problems, errors.New("failed or unknown adapter result requires an error"))
	}
	if !failed && value.Error != nil {
		problems = append(problems, errors.New("successful or in-progress adapter result cannot contain an error"))
	}
	if value.State == AdapterResultUnknown &&
		value.Error != nil &&
		value.Error.Class != AdapterErrorUnknownOutcome {
		problems = append(problems, errors.New("unknown adapter result requires unknown-outcome error"))
	}
	if value.State == AdapterResultFailed &&
		value.Error != nil &&
		value.Error.Class == AdapterErrorUnknownOutcome {
		problems = append(problems, errors.New("failed adapter result cannot contain an unknown outcome"))
	}
	for index, evidence := range value.Evidence {
		if err := ValidateEvidence(evidence); err != nil {
			problems = append(problems, fmt.Errorf("evidence[%d]: %w", index, err))
		}
	}
	return errors.Join(problems...)
}

func validateAdapterRef(name string, value AdapterRef, expected AdapterKind) error {
	var problems []error
	if value.Kind != expected {
		problems = append(
			problems,
			fmt.Errorf("%s kind = %q, want %q", name, value.Kind, expected),
		)
	}
	if !namePattern.MatchString(value.Name) {
		problems = append(problems, fmt.Errorf("%s.name must be a DNS label", name))
	}
	if !contractVersionPattern.MatchString(value.ContractVersion) {
		problems = append(problems, fmt.Errorf("%s.contractVersion must be v1 or a later integer version", name))
	}
	return errors.Join(problems...)
}

func validateLabelSelector(name string, value LabelSelector) error {
	return validateLabels(name, value.MatchLabels)
}

// ValidateLabels validates the bounded portable label contract shared by
// public resources and internal adapter observations.
func ValidateLabels(value map[string]string) error {
	return validateLabels("labels", value)
}

func validateLabels(name string, value map[string]string) error {
	var problems []error
	if len(value) > 64 {
		problems = append(problems, fmt.Errorf("%s cannot exceed 64 entries", name))
	}
	for key, item := range value {
		if !namePattern.MatchString(key) {
			problems = append(problems, fmt.Errorf("%s label %q is invalid", name, key))
		}
		if err := ValidateSafeExternalText(name+" label "+key, item, 128, false); err != nil {
			problems = append(problems, err)
		}
	}
	return errors.Join(problems...)
}

func validateCapacity(name string, value Capacity) error {
	if value.CPUMillis < 0 ||
		value.MemoryBytes < 0 ||
		value.StorageBytes < 0 ||
		value.WorkloadSlots < 0 {
		return fmt.Errorf("%s values cannot be negative", name)
	}
	return nil
}

func exceedsCapacity(allocatable, capacity Capacity) bool {
	return allocatable.CPUMillis > capacity.CPUMillis ||
		allocatable.MemoryBytes > capacity.MemoryBytes ||
		allocatable.StorageBytes > capacity.StorageBytes ||
		allocatable.WorkloadSlots > capacity.WorkloadSlots
}

func validateUniqueKnown[T comparable](
	name string,
	values []T,
	allowed []T,
	required bool,
) error {
	var problems []error
	if required && len(values) == 0 {
		problems = append(problems, fmt.Errorf("%s must not be empty", name))
	}
	seen := make(map[T]struct{}, len(values))
	for index, value := range values {
		if !contains(allowed, value) {
			problems = append(problems, fmt.Errorf("%s[%d] is unknown", name, index))
		}
		if _, found := seen[value]; found {
			problems = append(problems, fmt.Errorf("%s[%d] is duplicated", name, index))
		}
		seen[value] = struct{}{}
	}
	return errors.Join(problems...)
}

func adapterActions() []AdapterAction {
	return []AdapterAction{
		AdapterCapabilities,
		AdapterInspectExecutionTarget,
		AdapterObserveExecutionTarget,
		AdapterValidateDeployment,
		AdapterApplyDeployment,
		AdapterObserveDeployment,
		AdapterStopDeployment,
		AdapterRollbackDeployment,
		AdapterReconcileRoutes,
		AdapterObserveRoutes,
		AdapterDeleteRoutes,
	}
}

func adapterActionsForKind(kind AdapterKind) []AdapterAction {
	switch kind {
	case AdapterInfrastructure:
		return []AdapterAction{
			AdapterCapabilities,
			AdapterInspectExecutionTarget,
			AdapterObserveExecutionTarget,
		}
	case AdapterDeploymentExecutor:
		return []AdapterAction{
			AdapterCapabilities,
			AdapterValidateDeployment,
			AdapterApplyDeployment,
			AdapterObserveDeployment,
			AdapterStopDeployment,
			AdapterRollbackDeployment,
		}
	case AdapterGateway:
		return []AdapterAction{
			AdapterCapabilities,
			AdapterReconcileRoutes,
			AdapterObserveRoutes,
			AdapterDeleteRoutes,
		}
	default:
		return nil
	}
}

func validateContractTime(name string, value time.Time) error {
	if value.IsZero() ||
		value.Location() != time.UTC ||
		value != value.Round(0) ||
		value.Nanosecond()%1_000 != 0 {
		return fmt.Errorf(
			"%s must be UTC with at most microsecond precision and no monotonic component",
			name,
		)
	}
	return nil
}

func validateImmutableMetadata(name string, value ResourceMetadata) error {
	var problems []error
	if value.ResourceVersion != 1 {
		problems = append(problems, fmt.Errorf("%s resourceVersion must remain 1", name))
	}
	if !value.UpdatedAt.Equal(value.CreatedAt) {
		problems = append(problems, fmt.Errorf("%s updatedAt must equal createdAt", name))
	}
	return errors.Join(problems...)
}

func validateBoundedText(name, value string, limit int, required bool) error {
	if required && strings.TrimSpace(value) == "" {
		return fmt.Errorf("%s is required", name)
	}
	if len([]byte(value)) > limit {
		return fmt.Errorf("%s exceeds %d bytes", name, limit)
	}
	return nil
}

// ValidateSafeExternalText rejects unsafe text before it can become a public
// problem, evidence value, label, or normalized adapter message.
func ValidateSafeExternalText(
	name string,
	value string,
	maxBytes int,
	required bool,
) error {
	if required && value == "" {
		return fmt.Errorf("%s is required", name)
	}
	if value == "" {
		return nil
	}
	if len([]byte(value)) > maxBytes ||
		!utf8.ValidString(value) ||
		strings.TrimSpace(value) != value {
		return fmt.Errorf("%s must be trimmed UTF-8 of at most %d bytes", name, maxBytes)
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return fmt.Errorf("%s contains a control character", name)
		}
	}
	normalized := strings.ToLower(value)
	for _, marker := range rawSensitiveMaterialMarkers {
		if strings.Contains(normalized, marker) {
			return fmt.Errorf("%s contains recognizable raw sensitive material", name)
		}
	}
	return nil
}

func contains[T comparable](values []T, target T) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
