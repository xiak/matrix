package nodeenrollment

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"maps"
	"math/big"
	"net"
	"net/url"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	paasv1 "github.com/xiak/matrix/api/paas/v1"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/port"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/usecase/executionadmission"
	"github.com/xiak/matrix/app/service/paas/internal/audit"
)

func TestCreatePersistsOneWrappedEnrollmentAndExactlyReplaysIt(t *testing.T) {
	service, repository, issuer := enrollmentFixture(t)
	command := createCommand(t)
	created, err := service.Create(context.Background(), command)
	if err != nil {
		t.Fatal(err)
	}
	if created.Replayed || paasv1.ValidateCreateNodeEnrollmentResponse(created.Response) != nil ||
		paasv1.ValidateOperation(created.Operation) != nil || created.Operation.State != paasv1.OperationAccepted ||
		issuer.calls != 1 || repository.insertCalls != 1 || len(repository.values) != 1 {
		t.Fatalf("created enrollment is incomplete: result=%#v issuer=%d inserts=%d", created, issuer.calls, repository.insertCalls)
	}
	stored := repository.values[created.Response.Enrollment.Metadata.ID]
	if stored.CredentialVerifier == stored.Join.CredentialDigest || len(stored.CredentialSalt) != 32 ||
		stored.Operation.Target.ID != created.Response.Enrollment.ExecutionTargetID {
		t.Fatal("enrollment did not persist a separate salted verifier and target Operation")
	}
	replayed, err := service.Create(context.Background(), command)
	if err != nil {
		t.Fatal(err)
	}
	if !replayed.Replayed || !reflect.DeepEqual(replayed, CreateResult{
		Response: created.Response, Operation: created.Operation, Replayed: true,
	}) || issuer.calls != 1 || repository.insertCalls != 1 {
		t.Fatalf("exact replay changed issuance: %#v", replayed)
	}

	changed := command
	changed.Request.Name = "host-b"
	if _, err := service.Create(context.Background(), changed); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("changed replay error = %v", err)
	}
	if issuer.calls != 1 || repository.insertCalls != 1 {
		t.Fatal("changed replay reached credential issuance or persistence")
	}
}

func TestEnrollmentReadsExpireWithoutReturningCredentialMaterial(t *testing.T) {
	service, repository, issuer := enrollmentFixture(t)
	command := createCommand(t)
	created, err := service.Create(context.Background(), command)
	if err != nil {
		t.Fatal(err)
	}
	repository.now = created.Response.Enrollment.ExpiresAt
	if _, err := service.Create(context.Background(), command); !errors.Is(err, ErrExpired) {
		t.Fatalf("expired create replay error = %v", err)
	}
	if repository.expireCalls != 1 {
		t.Fatal("expired create replay did not commit expiration")
	}
	enrollment, err := service.Get(context.Background(), command.Authorization, created.Response.Enrollment.Metadata.ID)
	if err != nil {
		t.Fatal(err)
	}
	if enrollment.State != paasv1.NodeEnrollmentExpired || enrollment.Diagnostic == nil ||
		enrollment.Diagnostic.Code != paasv1.NodeEnrollmentDiagnosticExpired || repository.expireCalls != 1 {
		t.Fatalf("overdue enrollment did not expire: %#v", enrollment)
	}
	stored := repository.values[enrollment.Metadata.ID]
	if stored.Operation.State != paasv1.OperationCancelled || stored.Operation.TerminalAt == nil ||
		stored.Enrollment.Metadata.ResourceVersion != 2 || len(stored.CredentialSalt) != 0 ||
		stored.CredentialVerifier != "" || stored.WrappedCredential != (paasv1.WrappedJoinCredential{}) {
		t.Fatal("expiration did not close the registration Operation atomically")
	}
	listed, err := service.List(context.Background(), command.Authorization)
	if err != nil || len(listed.Items) != 1 || listed.Items[0].State != paasv1.NodeEnrollmentExpired {
		t.Fatalf("expired enrollment list = %#v, %v", listed, err)
	}
	encoded := strings.ToLower(string(mustJSON(t, listed)))
	for _, forbidden := range []string{"wrappedcredential", "credentialsalt", "credentialverifier", "ciphertext", "privatekey"} {
		if strings.Contains(encoded, forbidden) {
			t.Fatalf("ordinary enrollment read exposed %s", forbidden)
		}
	}
	if issuer.calls != 1 {
		t.Fatal("expired replay issued another credential")
	}
}

func TestExchangeConsumesCredentialOnceAndPersistsOnlyNormalizedPublicIdentity(t *testing.T) {
	service, repository, issuer := enrollmentFixture(t)
	created, err := service.Create(context.Background(), createCommand(t))
	if err != nil {
		t.Fatal(err)
	}
	command := exchangeCommand(t, created, issuer, "a")
	repository.now = repository.now.Add(time.Minute)
	result, err := service.Exchange(context.Background(), command)
	if err != nil {
		t.Fatal(err)
	}
	stored := repository.values[created.Response.Enrollment.Metadata.ID]
	if result.Enrollment.State != paasv1.NodeEnrollmentVerifying ||
		result.Enrollment.Metadata.ResourceVersion != 2 || result.Enrollment.CredentialConsumedAt == nil ||
		stored.Operation.State != paasv1.OperationVerifying || stored.Exchange == nil ||
		stored.SealedExchangeResult == nil || repository.exchangeCalls != 1 || issuer.exchangeCalls != 1 {
		t.Fatalf("exchange result is incomplete: result=%#v stored=%#v", result, stored)
	}
	if len(stored.CredentialSalt) != 0 || stored.CredentialVerifier != "" ||
		stored.WrappedCredential != (paasv1.WrappedJoinCredential{}) ||
		stored.Exchange.ExchangeID != command.Request.ExchangeID ||
		stored.Exchange.MachineFingerprint != command.Request.MachineFingerprint ||
		stored.Exchange.NodePublicKey == "" || stored.Exchange.CollectorPublicKey == "" ||
		stored.Exchange.ResultDigest == "" || ValidateStoredEnrollment(stored, "installation-a") != nil {
		t.Fatalf("exchange persistence retained credential or lost identity: %#v", stored)
	}
	encoded := strings.ToLower(string(mustJSON(t, stored.Exchange)))
	for _, forbidden := range []string{strings.ToLower(command.Request.Credential), "certificaterequest", "credential", "privatekey"} {
		if strings.Contains(encoded, forbidden) {
			t.Fatalf("normalized exchange document leaked %q", forbidden)
		}
	}
	if _, err := service.Exchange(context.Background(), command); !errors.Is(err, ErrCredentialConsumed) {
		t.Fatalf("credential replay error = %v", err)
	}
	if repository.exchangeCalls != 1 || issuer.exchangeCalls != 1 {
		t.Fatal("credential replay reached issuance or persistence")
	}
}

func TestLostExchangeResponseRecoversOnlyWithBothPersistedRoleKeys(t *testing.T) {
	service, repository, issuer := enrollmentFixture(t)
	create := createCommand(t)
	created, err := service.Create(context.Background(), create)
	if err != nil {
		t.Fatal(err)
	}
	exchangeCommand, nodePrivateKey, collectorPrivateKey := exchangeCommandWithKeys(t, created, issuer, "a")
	defer clear(nodePrivateKey)
	defer clear(collectorPrivateKey)
	unexchanged := paasv1.CreateNodeEnrollmentRecoveryChallengeRequest{
		APIVersion:                    paasv1.NodeEnrollmentRecoveryAPIVersion,
		Kind:                          paasv1.NodeEnrollmentRecoveryChallengeRequestKind,
		EnrollmentID:                  exchangeCommand.Request.EnrollmentID,
		InstallationID:                exchangeCommand.Request.InstallationID,
		ExecutionTargetID:             exchangeCommand.Request.ExecutionTargetID,
		ExchangeID:                    exchangeCommand.Request.ExchangeID,
		MachineFingerprint:            exchangeCommand.Request.MachineFingerprint,
		RuntimeContractDigest:         exchangeCommand.Request.RuntimeContractDigest,
		NodePublicKeyFingerprint:      "sha256:" + strings.Repeat("a", 64),
		CollectorPublicKeyFingerprint: "sha256:" + strings.Repeat("b", 64),
	}
	if _, err := service.CreateRecoveryChallenge(context.Background(), RecoveryChallengeCommand{
		EnrollmentID:        created.Response.Enrollment.Metadata.ID,
		ObservedPeerAddress: "192.168.50.10",
		Request:             unexchanged,
	}); !errors.Is(err, ErrNotExchanged) || issuer.challengeCalls != 0 {
		t.Fatalf("unexchanged recovery challenge = %v", err)
	}
	repository.now = repository.now.Add(time.Minute)
	exchanged, err := service.Exchange(context.Background(), exchangeCommand)
	if err != nil {
		t.Fatal(err)
	}
	stored := repository.values[created.Response.Enrollment.Metadata.ID]
	challengeRequest := recoveryChallengeRequest(*stored.Exchange)
	challengeResult, err := service.CreateRecoveryChallenge(context.Background(), RecoveryChallengeCommand{
		EnrollmentID: stored.Enrollment.Metadata.ID, ObservedPeerAddress: "192.168.50.10",
		Request: challengeRequest,
	})
	if err != nil || challengeResult.Enrollment.Metadata.ResourceVersion != 2 ||
		challengeResult.Enrollment.State != paasv1.NodeEnrollmentVerifying ||
		paasv1.ValidateNodeEnrollmentRecoveryChallengeForRequest(challengeResult.Challenge, challengeRequest) != nil ||
		issuer.challengeCalls != 1 || repository.exchangeCalls != 1 {
		t.Fatalf("recovery challenge=%#v err=%v", challengeResult, err)
	}
	proof := recoveryProofRequest(t, challengeResult.Challenge, nodePrivateKey, collectorPrivateKey)
	commandFormatting := (RecoverExchangeCommand{Request: proof}).String()
	issueFormatting := (RecoverExchangeIssueRequest{Request: proof, Sealed: *stored.SealedExchangeResult}).String()
	if strings.Contains(commandFormatting, proof.NodeSignature) || strings.Contains(commandFormatting, proof.CollectorSignature) ||
		strings.Contains(issueFormatting, proof.NodeSignature) || strings.Contains(issueFormatting, proof.CollectorSignature) ||
		strings.Contains(issueFormatting, stored.SealedExchangeResult.Ciphertext) {
		t.Fatal("recovery workflow formatting leaked proof or sealed result")
	}
	recovered, err := service.RecoverExchange(context.Background(), RecoverExchangeCommand{
		EnrollmentID: stored.Enrollment.Metadata.ID, ObservedPeerAddress: "192.168.50.10", Request: proof,
	})
	if err != nil || !reflect.DeepEqual(recovered.Response, exchanged.Response) ||
		!reflect.DeepEqual(recovered.Enrollment, exchanged.Enrollment) || issuer.recoveryCalls != 1 ||
		repository.exchangeCalls != 1 {
		t.Fatalf("recovered exchange=%#v err=%v", recovered, err)
	}
	replayed, err := service.RecoverExchange(context.Background(), RecoverExchangeCommand{
		EnrollmentID: stored.Enrollment.Metadata.ID, ObservedPeerAddress: "192.168.50.10", Request: proof,
	})
	if err != nil || !reflect.DeepEqual(replayed, recovered) || issuer.recoveryCalls != 2 ||
		repository.values[stored.Enrollment.Metadata.ID].Enrollment.Metadata.ResourceVersion != 2 {
		t.Fatalf("replayed recovery=%#v err=%v", replayed, err)
	}

	for name, mutate := range map[string]func(*paasv1.RecoverNodeEnrollmentExchangeRequest){
		"node key": func(value *paasv1.RecoverNodeEnrollmentExchangeRequest) {
			value.NodeSignature = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x41}, ed25519.SignatureSize))
		},
		"collector key": func(value *paasv1.RecoverNodeEnrollmentExchangeRequest) {
			value.CollectorSignature = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, ed25519.SignatureSize))
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed := proof
			mutate(&changed)
			if _, err := service.RecoverExchange(context.Background(), RecoverExchangeCommand{
				EnrollmentID: stored.Enrollment.Metadata.ID, ObservedPeerAddress: "192.168.50.10", Request: changed,
			}); !errors.Is(err, ErrRecoveryProofRejected) {
				t.Fatalf("changed proof error = %v", err)
			}
		})
	}
	changedIntent := challengeRequest
	changedIntent.MachineFingerprint = "sha256:" + strings.Repeat("b", 64)
	if _, err := service.CreateRecoveryChallenge(context.Background(), RecoveryChallengeCommand{
		EnrollmentID: stored.Enrollment.Metadata.ID, ObservedPeerAddress: "192.168.50.10", Request: changedIntent,
	}); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed recovery intent error = %v", err)
	}
	if _, err := service.CreateRecoveryChallenge(context.Background(), RecoveryChallengeCommand{
		EnrollmentID: stored.Enrollment.Metadata.ID, ObservedPeerAddress: "192.168.50.11", Request: challengeRequest,
	}); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed recovery peer error = %v", err)
	}
	repository.now = challengeResult.Challenge.ExpiresAt
	if _, err := service.RecoverExchange(context.Background(), RecoverExchangeCommand{
		EnrollmentID: stored.Enrollment.Metadata.ID, ObservedPeerAddress: "192.168.50.10", Request: proof,
	}); !errors.Is(err, ErrRecoveryChallengeExpired) {
		t.Fatalf("expired recovery challenge error = %v", err)
	}
}

func TestCompletionProbesOutsideTransactionAndAtomicallyPublishesExactEnrollment(t *testing.T) {
	service, repository, issuer := enrollmentFixture(t)
	create := createCommand(t)
	created, err := service.Create(context.Background(), create)
	if err != nil {
		t.Fatal(err)
	}
	repository.now = repository.now.Add(time.Minute)
	if _, err := service.Exchange(context.Background(), exchangeCommand(t, created, issuer, "a")); err != nil {
		t.Fatal(err)
	}
	stored := repository.values[created.Response.Enrollment.Metadata.ID]
	request := completionRequest(t, stored)
	result, err := service.Complete(context.Background(), CompleteCommand{
		EnrollmentID: stored.Enrollment.Metadata.ID, ObservedPeerAddress: "192.168.50.10", Request: request,
	})
	if err != nil {
		t.Fatal(err)
	}
	current := repository.values[stored.Enrollment.Metadata.ID]
	registration := repository.registrations[stored.Enrollment.ExecutionTargetID]
	connection := repository.connections[stored.Enrollment.ExecutionTargetID]
	if result.Replayed || paasv1.ValidateCompleteNodeEnrollmentResponse(result.Response) != nil ||
		current.Enrollment.State != paasv1.NodeEnrollmentReady || current.Enrollment.Metadata.ResourceVersion != 3 ||
		current.Operation.ID != stored.Operation.ID || current.Operation.State != paasv1.OperationSucceeded ||
		current.SealedExchangeResult != nil || current.Exchange == nil ||
		registration.Target.Metadata.ID != stored.Enrollment.ExecutionTargetID ||
		registration.Target.Metadata.Labels["zone"] != "private-a" ||
		registration.IdentityFingerprint != stored.Exchange.MachineFingerprint ||
		connection != completionConnection(*stored.Exchange) || !connection.Enabled ||
		repository.pool.Metadata.ResourceVersion != 2 || repository.pool.Status.ExecutionTargetCount != 1 ||
		repository.completeCalls != 1 || repository.failCalls != 0 || len(repository.auditEvents) != 1 ||
		repository.probe.calls != 1 || repository.probe.probedInsideTransaction {
		t.Fatalf("completion did not publish one atomic enrollment: result=%#v stored=%#v registration=%#v connection=%#v", result, current, registration, connection)
	}
	if repository.probe.request.Command.OperationID != stored.Operation.ID ||
		repository.probe.request.Command.ExecutionTargetID != stored.Enrollment.ExecutionTargetID ||
		repository.probe.request.Command.BindingRef != stored.Exchange.BindingRef ||
		!repository.probe.request.Command.Deadline.Equal(repository.now.Add(5*time.Second)) {
		t.Fatalf("completion probe did not preserve stored authority: %#v", repository.probe.request)
	}
	replayed, err := service.Complete(context.Background(), CompleteCommand{
		EnrollmentID: stored.Enrollment.Metadata.ID, ObservedPeerAddress: "192.168.50.10", Request: request,
	})
	if err != nil || !replayed.Replayed || !reflect.DeepEqual(replayed.Response, result.Response) ||
		repository.probe.calls != 1 || repository.completeCalls != 1 || len(repository.auditEvents) != 1 {
		t.Fatalf("completion replay=%#v err=%v probes=%d commits=%d", replayed, err, repository.probe.calls, repository.completeCalls)
	}
}

func TestCompletionRejectsEveryChangedCommitmentBeforeProbe(t *testing.T) {
	for name, mutate := range map[string]func(*CompleteCommand){
		"peer":         func(value *CompleteCommand) { value.ObservedPeerAddress = "192.168.50.11" },
		"installation": func(value *CompleteCommand) { value.Request.InstallationID = "installation-b" },
		"target":       func(value *CompleteCommand) { value.Request.ExecutionTargetID = "target-other" },
		"exchange": func(value *CompleteCommand) {
			value.Request.ExchangeID = "node-exchange-" + strings.Repeat("b", 32)
		},
		"machine": func(value *CompleteCommand) {
			value.Request.MachineFingerprint = "sha256:" + strings.Repeat("b", 64)
		},
		"runtime": func(value *CompleteCommand) {
			value.Request.RuntimeContractDigest = "sha256:" + strings.Repeat("b", 64)
		},
		"controller": func(value *CompleteCommand) { value.Request.ControllerID = "paas-controller-v2" },
		"binding": func(value *CompleteCommand) {
			value.Request.BindingRef = "node-binding-" + strings.Repeat("b", 32)
		},
		"node endpoint": func(value *CompleteCommand) { value.Request.NodeListenAddress = "192.168.50.10:17443" },
		"collector endpoint": func(value *CompleteCommand) {
			value.Request.CollectorEndpoint = "https://127.0.0.1:19200"
		},
		"node key": func(value *CompleteCommand) {
			value.Request.NodePublicKeyFingerprint = "sha256:" + strings.Repeat("b", 64)
		},
		"collector key": func(value *CompleteCommand) {
			value.Request.CollectorPublicKeyFingerprint = "sha256:" + strings.Repeat("b", 64)
		},
	} {
		t.Run(name, func(t *testing.T) {
			service, repository, issuer := enrollmentFixture(t)
			created, err := service.Create(context.Background(), createCommand(t))
			if err != nil {
				t.Fatal(err)
			}
			repository.now = repository.now.Add(time.Minute)
			if _, err := service.Exchange(context.Background(), exchangeCommand(t, created, issuer, "a")); err != nil {
				t.Fatal(err)
			}
			stored := repository.values[created.Response.Enrollment.Metadata.ID]
			command := CompleteCommand{
				EnrollmentID: stored.Enrollment.Metadata.ID, ObservedPeerAddress: "192.168.50.10",
				Request: completionRequest(t, stored),
			}
			mutate(&command)
			if _, err := service.Complete(context.Background(), command); !errors.Is(err, ErrConflict) {
				t.Fatalf("changed completion error = %v", err)
			}
			current := repository.values[stored.Enrollment.Metadata.ID]
			if current.Enrollment.State != paasv1.NodeEnrollmentVerifying || current.Enrollment.Metadata.ResourceVersion != 2 ||
				current.SealedExchangeResult == nil || repository.probe.calls != 0 || repository.completeCalls != 0 ||
				repository.failCalls != 0 || len(repository.registrations) != 0 || len(repository.connections) != 0 {
				t.Fatal("changed completion reached probe or persistence")
			}
		})
	}
}

func TestCompletionKeepsRetryableProbeFailureVerifying(t *testing.T) {
	service, repository, issuer := enrollmentFixture(t)
	created, err := service.Create(context.Background(), createCommand(t))
	if err != nil {
		t.Fatal(err)
	}
	repository.now = repository.now.Add(time.Minute)
	if _, err := service.Exchange(context.Background(), exchangeCommand(t, created, issuer, "a")); err != nil {
		t.Fatal(err)
	}
	stored := repository.values[created.Response.Enrollment.Metadata.ID]
	repository.probe.err = paasv1.AdapterFault{Normalized: paasv1.NormalizedAdapterError{
		Class: paasv1.AdapterErrorUnavailable, Code: paasv1.ErrorAdapterUnavailable,
		Message: "private node detail must remain normalized", Retryable: true,
	}}
	_, err = service.Complete(context.Background(), CompleteCommand{
		EnrollmentID: stored.Enrollment.Metadata.ID, ObservedPeerAddress: "192.168.50.10",
		Request: completionRequest(t, stored),
	})
	current := repository.values[stored.Enrollment.Metadata.ID]
	if !errors.Is(err, ErrUnavailable) || current.Enrollment.State != paasv1.NodeEnrollmentVerifying ||
		current.Enrollment.Metadata.ResourceVersion != 2 || current.SealedExchangeResult == nil ||
		repository.probe.calls != 1 || repository.completeCalls != 0 || repository.failCalls != 0 ||
		len(repository.registrations) != 0 || len(repository.connections) != 0 || len(repository.auditEvents) != 0 {
		t.Fatalf("retryable completion failure was not retained: err=%v stored=%#v", err, current)
	}
}

func TestCompletionDefinitiveProbeFailureFailsClosed(t *testing.T) {
	service, repository, issuer := enrollmentFixture(t)
	created, err := service.Create(context.Background(), createCommand(t))
	if err != nil {
		t.Fatal(err)
	}
	repository.now = repository.now.Add(time.Minute)
	if _, err := service.Exchange(context.Background(), exchangeCommand(t, created, issuer, "a")); err != nil {
		t.Fatal(err)
	}
	stored := repository.values[created.Response.Enrollment.Metadata.ID]
	repository.probe.err = paasv1.AdapterFault{Normalized: paasv1.NormalizedAdapterError{
		Class: paasv1.AdapterErrorPermissionDenied, Code: paasv1.ErrorAdapterRejected,
		Message: "node mTLS identity was rejected", Retryable: false,
	}}
	_, err = service.Complete(context.Background(), CompleteCommand{
		EnrollmentID: stored.Enrollment.Metadata.ID, ObservedPeerAddress: "192.168.50.10",
		Request: completionRequest(t, stored),
	})
	current := repository.values[stored.Enrollment.Metadata.ID]
	if !errors.Is(err, ErrVerificationFailed) || current.Enrollment.State != paasv1.NodeEnrollmentFailed ||
		current.Enrollment.Metadata.ResourceVersion != 3 || current.Enrollment.Diagnostic == nil ||
		current.Enrollment.Diagnostic.Code != paasv1.NodeEnrollmentDiagnosticMTLS ||
		current.Operation.State != paasv1.OperationFailed || current.Operation.Error == nil ||
		current.SealedExchangeResult != nil || current.Exchange == nil || repository.failCalls != 1 ||
		repository.completeCalls != 0 || len(repository.registrations) != 0 || len(repository.connections) != 0 ||
		len(repository.auditEvents) != 0 {
		t.Fatalf("definitive completion failure did not fail closed: err=%v stored=%#v", err, current)
	}
}

func TestRevocationDuringCompletionProbePreventsPublication(t *testing.T) {
	service, repository, issuer := enrollmentFixture(t)
	create := createCommand(t)
	created, err := service.Create(context.Background(), create)
	if err != nil {
		t.Fatal(err)
	}
	repository.now = repository.now.Add(time.Minute)
	if _, err := service.Exchange(context.Background(), exchangeCommand(t, created, issuer, "a")); err != nil {
		t.Fatal(err)
	}
	stored := repository.values[created.Response.Enrollment.Metadata.ID]
	repository.probe.before = func() {
		_, revokeErr := service.Revoke(context.Background(), RevokeCommand{
			Authorization: create.Authorization, EnrollmentID: stored.Enrollment.Metadata.ID,
			ExpectedResourceVersion: 2, IdempotencyKey: "revoke-during-completion",
		})
		if revokeErr != nil {
			t.Errorf("revoke during probe: %v", revokeErr)
		}
	}
	_, err = service.Complete(context.Background(), CompleteCommand{
		EnrollmentID: stored.Enrollment.Metadata.ID, ObservedPeerAddress: "192.168.50.10",
		Request: completionRequest(t, stored),
	})
	current := repository.values[stored.Enrollment.Metadata.ID]
	if !errors.Is(err, ErrRevoked) || current.Enrollment.State != paasv1.NodeEnrollmentRevoked ||
		repository.probe.calls != 1 || repository.completeCalls != 0 || repository.failCalls != 0 ||
		len(repository.registrations) != 0 || len(repository.connections) != 0 || len(repository.auditEvents) != 0 {
		t.Fatalf("revocation race published completion: err=%v stored=%#v", err, current)
	}
}

func TestRevocationAfterRecoveryChallengePreventsResultRecovery(t *testing.T) {
	service, repository, issuer := enrollmentFixture(t)
	create := createCommand(t)
	created, err := service.Create(context.Background(), create)
	if err != nil {
		t.Fatal(err)
	}
	exchangeCommand, nodePrivateKey, collectorPrivateKey := exchangeCommandWithKeys(t, created, issuer, "a")
	defer clear(nodePrivateKey)
	defer clear(collectorPrivateKey)
	repository.now = repository.now.Add(time.Minute)
	if _, err := service.Exchange(context.Background(), exchangeCommand); err != nil {
		t.Fatal(err)
	}
	stored := repository.values[created.Response.Enrollment.Metadata.ID]
	challenge, err := service.CreateRecoveryChallenge(context.Background(), RecoveryChallengeCommand{
		EnrollmentID: stored.Enrollment.Metadata.ID, ObservedPeerAddress: "192.168.50.10",
		Request: recoveryChallengeRequest(*stored.Exchange),
	})
	if err != nil {
		t.Fatal(err)
	}
	proof := recoveryProofRequest(t, challenge.Challenge, nodePrivateKey, collectorPrivateKey)
	repository.now = repository.now.Add(time.Second)
	if _, err := service.Revoke(context.Background(), RevokeCommand{
		Authorization: create.Authorization, EnrollmentID: stored.Enrollment.Metadata.ID,
		ExpectedResourceVersion: 2, IdempotencyKey: "revoke-after-recovery-challenge",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := service.RecoverExchange(context.Background(), RecoverExchangeCommand{
		EnrollmentID: stored.Enrollment.Metadata.ID, ObservedPeerAddress: "192.168.50.10", Request: proof,
	}); !errors.Is(err, ErrRevoked) {
		t.Fatalf("recovery after revocation error = %v", err)
	}
	if issuer.recoveryCalls != 0 || repository.values[stored.Enrollment.Metadata.ID].Enrollment.State != paasv1.NodeEnrollmentRevoked {
		t.Fatal("revoked recovery reached cryptography or reopened enrollment")
	}
}

func TestExchangeRejectsWrongCredentialAndAuthorityBeforeIssuance(t *testing.T) {
	service, repository, issuer := enrollmentFixture(t)
	created, err := service.Create(context.Background(), createCommand(t))
	if err != nil {
		t.Fatal(err)
	}
	valid := exchangeCommand(t, created, issuer, "a")
	for name, scenario := range map[string]struct {
		mutate func(*ExchangeCommand)
		want   error
	}{
		"credential": {func(value *ExchangeCommand) {
			value.Request.Credential = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x99}, 32))
		}, ErrCredentialRejected},
		"installation": {func(value *ExchangeCommand) { value.Request.InstallationID = "installation-other" }, ErrConflict},
		"target":       {func(value *ExchangeCommand) { value.Request.ExecutionTargetID = "target-other" }, ErrConflict},
		"runtime": {func(value *ExchangeCommand) {
			value.Request.RuntimeContractDigest = "sha256:" + strings.Repeat("e", 64)
		}, ErrRuntimeUnsupported},
		"listener":    {func(value *ExchangeCommand) { value.Request.Listener.ManagementPort = 17443 }, ErrInvalidArgument},
		"public peer": {func(value *ExchangeCommand) { value.ObservedPeerAddress = "8.8.8.8" }, ErrInvalidArgument},
	} {
		t.Run(name, func(t *testing.T) {
			command := valid
			scenario.mutate(&command)
			if _, err := service.Exchange(context.Background(), command); !errors.Is(err, scenario.want) {
				t.Fatalf("exchange error = %v, want %v", err, scenario.want)
			}
			stored := repository.values[created.Response.Enrollment.Metadata.ID]
			if stored.Enrollment.State != paasv1.NodeEnrollmentWaitingInstall || issuer.exchangeCalls != 0 || repository.exchangeCalls != 0 {
				t.Fatal("rejected exchange changed state or reached certificate issuance")
			}
		})
	}
}

func TestExchangeCommitsExpiryWithoutCertificateIssuance(t *testing.T) {
	service, repository, issuer := enrollmentFixture(t)
	created, err := service.Create(context.Background(), createCommand(t))
	if err != nil {
		t.Fatal(err)
	}
	command := exchangeCommand(t, created, issuer, "a")
	repository.now = created.Response.Enrollment.ExpiresAt
	if _, err := service.Exchange(context.Background(), command); !errors.Is(err, ErrExpired) {
		t.Fatalf("expired exchange error = %v", err)
	}
	stored := repository.values[created.Response.Enrollment.Metadata.ID]
	if stored.Enrollment.State != paasv1.NodeEnrollmentExpired || repository.expireCalls != 1 ||
		repository.exchangeCalls != 0 || issuer.exchangeCalls != 0 || stored.Exchange != nil || stored.SealedExchangeResult != nil {
		t.Fatalf("expired exchange did not close safely: %#v", stored)
	}
}

func TestStoredEnrollmentCredentialMaterialOnlyExistsWhileWaitingInstall(t *testing.T) {
	service, repository, issuer := enrollmentFixture(t)
	created, err := service.Create(context.Background(), createCommand(t))
	if err != nil {
		t.Fatal(err)
	}
	waiting := cloneStored(repository.values[created.Response.Enrollment.Metadata.ID])
	repository.now = repository.now.Add(time.Minute)
	if _, err := service.Exchange(context.Background(), exchangeCommand(t, created, issuer, "a")); err != nil {
		t.Fatal(err)
	}
	stored := repository.values[created.Response.Enrollment.Metadata.ID]
	if ValidateStoredEnrollment(stored, "installation-a") != nil || stored.Exchange == nil || stored.SealedExchangeResult == nil {
		t.Fatal("valid verifying enrollment did not retain only its normalized and sealed exchange")
	}
	retaining := cloneStored(stored)
	retaining.CredentialSalt = bytes.Clone(waiting.CredentialSalt)
	retaining.CredentialVerifier = waiting.CredentialVerifier
	retaining.WrappedCredential = waiting.WrappedCredential
	if ValidateStoredEnrollment(retaining, "installation-a") == nil {
		t.Fatal("verifying enrollment retained one-time credential material")
	}
	nodePublicKey := stored.Exchange.NodePublicKey
	stored.Clear()
	if len(stored.CredentialSalt) != 0 || stored.CredentialVerifier != "" ||
		stored.WrappedCredential != (paasv1.WrappedJoinCredential{}) ||
		stored.Exchange != nil || stored.SealedExchangeResult != nil || nodePublicKey == "" {
		t.Fatal("clearing stored enrollment left credential material reachable")
	}
}

func TestRevokeClosesWaitingOrVerifyingEnrollmentAndExactlyReplays(t *testing.T) {
	service, repository, issuer := enrollmentFixture(t)
	create := createCommand(t)
	created, err := service.Create(context.Background(), create)
	if err != nil {
		t.Fatal(err)
	}
	repository.now = repository.now.Add(time.Minute)
	if _, err := service.Exchange(context.Background(), exchangeCommand(t, created, issuer, "a")); err != nil {
		t.Fatal(err)
	}
	stored := repository.values[created.Response.Enrollment.Metadata.ID]
	consumedAt := repository.now
	repository.now = consumedAt.Add(time.Minute)
	command := RevokeCommand{
		Authorization: create.Authorization, EnrollmentID: stored.Enrollment.Metadata.ID,
		ExpectedResourceVersion: 2, IdempotencyKey: "revoke-host-a",
	}
	revoked, err := service.Revoke(context.Background(), command)
	if err != nil {
		t.Fatal(err)
	}
	current := repository.values[stored.Enrollment.Metadata.ID]
	if revoked.Replayed || revoked.Enrollment.State != paasv1.NodeEnrollmentRevoked ||
		revoked.Enrollment.Metadata.ResourceVersion != 3 || revoked.Enrollment.CredentialConsumedAt == nil ||
		revoked.Enrollment.Diagnostic == nil || revoked.Enrollment.Diagnostic.Code != paasv1.NodeEnrollmentDiagnosticRevoked ||
		current.Operation.State != paasv1.OperationCancelled || current.Operation.TerminalAt == nil ||
		current.TerminationFingerprint == "" || current.TerminationRequestDigest == "" ||
		len(current.CredentialSalt) != 0 || current.CredentialVerifier != "" ||
		current.WrappedCredential != (paasv1.WrappedJoinCredential{}) || current.Exchange == nil ||
		current.SealedExchangeResult != nil || repository.revokeCalls != 1 {
		t.Fatalf("revoked enrollment = %#v stored=%#v", revoked, current)
	}
	replay, err := service.Revoke(context.Background(), command)
	if err != nil || !replay.Replayed || !reflect.DeepEqual(replay.Enrollment, revoked.Enrollment) || repository.revokeCalls != 1 {
		t.Fatalf("revoke replay = %#v err=%v calls=%d", replay, err, repository.revokeCalls)
	}
	changed := command
	changed.ExpectedResourceVersion = 3
	if _, err := service.Revoke(context.Background(), changed); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("changed revoke replay error = %v", err)
	}
	changed.IdempotencyKey = "revoke-host-a-again"
	if _, err := service.Revoke(context.Background(), changed); !errors.Is(err, ErrRevoked) {
		t.Fatalf("second revocation error = %v", err)
	}
	if _, err := service.Create(context.Background(), create); !errors.Is(err, ErrRevoked) {
		t.Fatalf("revoked create replay error = %v", err)
	}
	if issuer.calls != 1 {
		t.Fatal("revocation issued another credential")
	}
}

func TestRegenerateAtomicallyReplacesIdentityAndExactlyReplays(t *testing.T) {
	service, repository, issuer := enrollmentFixture(t)
	create := createCommand(t)
	created, err := service.Create(context.Background(), create)
	if err != nil {
		t.Fatal(err)
	}
	command := regenerateCommand(t, create, created.Response.Enrollment.Metadata.ID, 1)
	replacement, err := service.Regenerate(context.Background(), command)
	if err != nil {
		t.Fatal(err)
	}
	source := repository.values[created.Response.Enrollment.Metadata.ID]
	current := repository.values[replacement.Response.Enrollment.Metadata.ID]
	if replacement.Replayed || replacement.Response.Enrollment.Metadata.ID == created.Response.Enrollment.Metadata.ID ||
		replacement.Response.Enrollment.ExecutionTargetID == created.Response.Enrollment.ExecutionTargetID ||
		replacement.Response.Enrollment.Metadata.Name != created.Response.Enrollment.Metadata.Name ||
		!reflect.DeepEqual(replacement.Response.Enrollment.Metadata.Labels, created.Response.Enrollment.Metadata.Labels) ||
		replacement.Response.Enrollment.ExecutionPoolID != created.Response.Enrollment.ExecutionPoolID ||
		source.Enrollment.State != paasv1.NodeEnrollmentRevoked ||
		source.Enrollment.ReplacedByID != replacement.Response.Enrollment.Metadata.ID ||
		source.Operation.State != paasv1.OperationCancelled ||
		len(source.CredentialSalt) != 0 || source.CredentialVerifier != "" ||
		source.WrappedCredential != (paasv1.WrappedJoinCredential{}) ||
		len(current.CredentialSalt) != 32 || current.CredentialVerifier == "" ||
		paasv1.ValidateWrappedJoinCredential(current.WrappedCredential) != nil ||
		source.TerminationFingerprint != current.Operation.IdempotencyFingerprint ||
		source.TerminationRequestDigest != current.Operation.RequestDigest ||
		repository.replaceCalls != 1 || issuer.calls != 2 {
		t.Fatalf("regenerated enrollment = %#v source=%#v", replacement, source)
	}
	replay, err := service.Regenerate(context.Background(), command)
	if err != nil || !replay.Replayed || !reflect.DeepEqual(replay.Response, replacement.Response) ||
		repository.replaceCalls != 1 || issuer.calls != 2 {
		t.Fatalf("regeneration replay = %#v err=%v", replay, err)
	}
	changed := command
	changed.Request.WrappingPublicKey = createCommand(t).Request.WrappingPublicKey
	if _, err := service.Regenerate(context.Background(), changed); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("changed regeneration replay error = %v", err)
	}
	if repository.replaceCalls != 1 || issuer.calls != 2 {
		t.Fatal("changed regeneration replay reached issuance or persistence")
	}
}

func TestEnrollmentRejectsNonPlatformAuthorityBeforeEffects(t *testing.T) {
	service, repository, issuer := enrollmentFixture(t)
	command := createCommand(t)
	command.Authorization = port.Authorization{
		TenantID: "tenant-a", Subject: paasv1.SubjectRef{Type: paasv1.SubjectUser, ID: "user-a"},
		DecisionID: "decision-a", RequestID: "request-a",
	}
	if _, err := service.Create(context.Background(), command); !errors.Is(err, port.ErrPermissionDenied) {
		t.Fatalf("tenant authority error = %v", err)
	}
	if repository.transactionCalls != 0 || issuer.calls != 0 {
		t.Fatal("denied enrollment reached persistence or credential issuance")
	}
}

func TestEnrollmentCreationRetriesOnlyRetryableTransactions(t *testing.T) {
	service, repository, issuer := enrollmentFixture(t)
	repository.failures = []error{ErrRetryableTransaction, nil, ErrRetryableTransaction, nil}
	created, err := service.Create(context.Background(), createCommand(t))
	if err != nil {
		t.Fatal(err)
	}
	if created.Replayed || repository.transactionCalls != 4 || issuer.calls != 1 || repository.insertCalls != 1 {
		t.Fatalf("retry behavior = transactions %d issuer %d inserts %d", repository.transactionCalls, issuer.calls, repository.insertCalls)
	}
}

type fakeRepository struct {
	now              time.Time
	pool             paasv1.ExecutionPool
	values           map[paasv1.ResourceID]StoredEnrollment
	registrations    map[paasv1.ResourceID]executionadmission.Registration
	connections      map[paasv1.ResourceID]port.EnrolledNodeConnection
	auditEvents      []audit.Event
	probe            *fakeCompletionProbe
	failures         []error
	transactionCalls int
	insertCalls      int
	expireCalls      int
	revokeCalls      int
	replaceCalls     int
	exchangeCalls    int
	completeCalls    int
	failCalls        int
	active           bool
}

func (repository *fakeRepository) WithinInstallation(ctx context.Context, installationID string, callback func(context.Context, Transaction) error) error {
	repository.transactionCalls++
	if installationID != "installation-a" {
		return ErrConflict
	}
	if len(repository.failures) > 0 {
		err := repository.failures[0]
		repository.failures = repository.failures[1:]
		if err != nil {
			return err
		}
	}
	repository.active = true
	defer func() { repository.active = false }()
	return callback(ctx, repository)
}

func (repository *fakeRepository) TransactionTime(context.Context) (time.Time, error) {
	return repository.now, nil
}

func (repository *fakeRepository) FindByFingerprint(_ context.Context, fingerprint string) (StoredEnrollment, bool, error) {
	for _, stored := range repository.values {
		if stored.Operation.IdempotencyFingerprint == fingerprint {
			return cloneStored(stored), true, nil
		}
	}
	return StoredEnrollment{}, false, nil
}

func (repository *fakeRepository) FindByTerminationFingerprint(_ context.Context, fingerprint string) (StoredEnrollment, bool, error) {
	for _, stored := range repository.values {
		if stored.TerminationFingerprint == fingerprint {
			return cloneStored(stored), true, nil
		}
	}
	return StoredEnrollment{}, false, nil
}

func (repository *fakeRepository) LoadEnrollment(_ context.Context, id paasv1.ResourceID) (StoredEnrollment, bool, error) {
	stored, found := repository.values[id]
	return cloneStored(stored), found, nil
}

func (repository *fakeRepository) LoadExecutionPool(_ context.Context, id paasv1.ResourceID) (paasv1.ExecutionPool, bool, error) {
	return repository.pool, repository.pool.Metadata.ID == id, nil
}

func (repository *fakeRepository) LoadExecutionTarget(_ context.Context, id paasv1.ResourceID) (executionadmission.Registration, bool, error) {
	registration, found := repository.registrations[id]
	return registration, found, nil
}

func (repository *fakeRepository) ListExecutionTargets(context.Context) ([]executionadmission.Registration, error) {
	values := make([]executionadmission.Registration, 0, len(repository.registrations))
	for _, registration := range repository.registrations {
		values = append(values, registration)
	}
	sort.Slice(values, func(left, right int) bool {
		return values[left].Target.Metadata.ID < values[right].Target.Metadata.ID
	})
	return values, nil
}

func (repository *fakeRepository) ListExecutionPoolTargets(_ context.Context, poolID paasv1.ResourceID) ([]paasv1.ExecutionTarget, error) {
	values := make([]paasv1.ExecutionTarget, 0, len(repository.registrations))
	for _, registration := range repository.registrations {
		if registration.Target.Spec.ExecutionPoolID == poolID {
			values = append(values, registration.Target)
		}
	}
	sort.Slice(values, func(left, right int) bool {
		return values[left].Metadata.ID < values[right].Metadata.ID
	})
	return values, nil
}

func (repository *fakeRepository) LoadEnrolledNodeConnection(_ context.Context, id paasv1.ResourceID) (port.EnrolledNodeConnection, bool, error) {
	connection, found := repository.connections[id]
	return connection, found, nil
}

func (repository *fakeRepository) ListEnrollments(_ context.Context, limit int) ([]StoredEnrollment, error) {
	values := make([]StoredEnrollment, 0, len(repository.values))
	for _, stored := range repository.values {
		values = append(values, cloneStored(stored))
	}
	sort.Slice(values, func(left, right int) bool {
		return values[left].Enrollment.Metadata.ID < values[right].Enrollment.Metadata.ID
	})
	if len(values) > limit {
		values = values[:limit]
	}
	return values, nil
}

func (repository *fakeRepository) InsertEnrollment(_ context.Context, stored StoredEnrollment) error {
	if _, found := repository.values[stored.Enrollment.Metadata.ID]; found {
		return ErrConflict
	}
	repository.insertCalls++
	repository.values[stored.Enrollment.Metadata.ID] = cloneStored(stored)
	return nil
}

func (repository *fakeRepository) ExchangeEnrollment(_ context.Context, before StoredEnrollment, after StoredEnrollment) error {
	current, found := repository.values[before.Enrollment.Metadata.ID]
	if !found || current.Enrollment.Metadata.ResourceVersion != before.Enrollment.Metadata.ResourceVersion ||
		current.Enrollment.State != paasv1.NodeEnrollmentWaitingInstall ||
		ValidateStoredEnrollment(after, "installation-a") != nil || after.Exchange == nil {
		return ErrRetryableTransaction
	}
	for id, stored := range repository.values {
		if id == before.Enrollment.Metadata.ID || stored.Exchange == nil {
			continue
		}
		if stored.Exchange.ExchangeID == after.Exchange.ExchangeID ||
			stored.Exchange.MachineFingerprint == after.Exchange.MachineFingerprint ||
			stored.Exchange.NodePublicKeyFingerprint == after.Exchange.NodePublicKeyFingerprint ||
			stored.Exchange.CollectorPublicKeyFingerprint == after.Exchange.CollectorPublicKeyFingerprint {
			return ErrConflict
		}
	}
	repository.exchangeCalls++
	repository.values[after.Enrollment.Metadata.ID] = cloneStored(after)
	return nil
}

func (repository *fakeRepository) ExpireEnrollment(_ context.Context, before StoredEnrollment, enrollment paasv1.NodeEnrollment, operation paasv1.Operation) error {
	current, found := repository.values[before.Enrollment.Metadata.ID]
	if !found || current.Enrollment.Metadata.ResourceVersion != before.Enrollment.Metadata.ResourceVersion {
		return ErrRetryableTransaction
	}
	repository.expireCalls++
	current.Enrollment, current.Operation = enrollmentSnapshot(enrollment), operation
	clear(current.CredentialSalt)
	current.CredentialSalt = nil
	current.CredentialVerifier = ""
	current.WrappedCredential = paasv1.WrappedJoinCredential{}
	current.SealedExchangeResult = nil
	repository.values[enrollment.Metadata.ID] = current
	return nil
}

func (repository *fakeRepository) RevokeEnrollment(_ context.Context, before StoredEnrollment, after StoredEnrollment) error {
	current, found := repository.values[before.Enrollment.Metadata.ID]
	if !found || current.Enrollment.Metadata.ResourceVersion != before.Enrollment.Metadata.ResourceVersion ||
		ValidateStoredEnrollment(after, "installation-a") != nil {
		return ErrRetryableTransaction
	}
	for _, stored := range repository.values {
		if stored.TerminationFingerprint == after.TerminationFingerprint {
			return ErrRetryableTransaction
		}
	}
	repository.revokeCalls++
	repository.values[after.Enrollment.Metadata.ID] = cloneStored(after)
	return nil
}

func (repository *fakeRepository) ReplaceEnrollment(
	_ context.Context,
	before StoredEnrollment,
	after StoredEnrollment,
	replacement StoredEnrollment,
) error {
	current, found := repository.values[before.Enrollment.Metadata.ID]
	if !found || current.Enrollment.Metadata.ResourceVersion != before.Enrollment.Metadata.ResourceVersion ||
		ValidateStoredEnrollment(after, "installation-a") != nil ||
		ValidateStoredEnrollment(replacement, "installation-a") != nil ||
		after.Enrollment.ReplacedByID != replacement.Enrollment.Metadata.ID {
		return ErrRetryableTransaction
	}
	if _, found := repository.values[replacement.Enrollment.Metadata.ID]; found {
		return ErrRetryableTransaction
	}
	for _, stored := range repository.values {
		if stored.TerminationFingerprint == after.TerminationFingerprint ||
			stored.Operation.IdempotencyFingerprint == replacement.Operation.IdempotencyFingerprint {
			return ErrRetryableTransaction
		}
	}
	repository.replaceCalls++
	repository.values[after.Enrollment.Metadata.ID] = cloneStored(after)
	repository.values[replacement.Enrollment.Metadata.ID] = cloneStored(replacement)
	return nil
}

func (repository *fakeRepository) CompleteEnrollment(
	_ context.Context,
	before StoredEnrollment,
	after StoredEnrollment,
	registration executionadmission.Registration,
	connection port.EnrolledNodeConnection,
	expectedPoolVersion uint64,
	pool paasv1.ExecutionPool,
	event audit.Event,
) error {
	current, found := repository.values[before.Enrollment.Metadata.ID]
	if !found || current.Enrollment.Metadata.ResourceVersion != before.Enrollment.Metadata.ResourceVersion ||
		current.Enrollment.State != paasv1.NodeEnrollmentVerifying ||
		ValidateStoredEnrollment(after, "installation-a") != nil ||
		after.Enrollment.State != paasv1.NodeEnrollmentReady ||
		repository.pool.Metadata.ResourceVersion != expectedPoolVersion ||
		paasv1.ValidateExecutionPool(pool) != nil || pool.Metadata.ID != repository.pool.Metadata.ID ||
		paasv1.ValidateExecutionTarget(registration.Target) != nil ||
		registration.Target.Metadata.ID != after.Enrollment.ExecutionTargetID ||
		registration.Target.Spec.ExecutionPoolID != after.Enrollment.ExecutionPoolID ||
		port.ValidateEnrolledNodeConnection(connection) != nil ||
		connection.ExecutionTargetID != registration.Target.Metadata.ID ||
		connection.BindingRef != registration.BindingRef ||
		connection.IdentityFingerprint != registration.IdentityFingerprint ||
		audit.ValidateEvent(event) != nil || event.OperationID != after.Operation.ID {
		return ErrRetryableTransaction
	}
	if _, exists := repository.registrations[registration.Target.Metadata.ID]; exists {
		return ErrConflict
	}
	repository.completeCalls++
	repository.values[after.Enrollment.Metadata.ID] = cloneStored(after)
	repository.registrations[registration.Target.Metadata.ID] = registration
	repository.connections[connection.ExecutionTargetID] = connection
	repository.pool = pool
	repository.auditEvents = append(repository.auditEvents, event)
	return nil
}

func (repository *fakeRepository) FailEnrollment(_ context.Context, before StoredEnrollment, after StoredEnrollment) error {
	current, found := repository.values[before.Enrollment.Metadata.ID]
	if !found || current.Enrollment.Metadata.ResourceVersion != before.Enrollment.Metadata.ResourceVersion ||
		current.Enrollment.State != paasv1.NodeEnrollmentVerifying ||
		ValidateStoredEnrollment(after, "installation-a") != nil || after.Enrollment.State != paasv1.NodeEnrollmentFailed {
		return ErrRetryableTransaction
	}
	repository.failCalls++
	repository.values[after.Enrollment.Metadata.ID] = cloneStored(after)
	return nil
}

type fakeCompletionProbe struct {
	repository              *fakeRepository
	capabilities            paasv1.AdapterCapabilitiesContract
	observation             paasv1.ExecutionTargetObservation
	err                     error
	before                  func()
	calls                   int
	connection              port.EnrolledNodeConnection
	request                 paasv1.InspectExecutionTargetRequest
	probedInsideTransaction bool
}

func (probe *fakeCompletionProbe) Probe(
	_ context.Context,
	connection port.EnrolledNodeConnection,
	request paasv1.InspectExecutionTargetRequest,
) (paasv1.AdapterCapabilitiesContract, paasv1.ExecutionTargetObservation, error) {
	probe.calls++
	probe.probedInsideTransaction = probe.probedInsideTransaction || probe.repository.active
	probe.connection, probe.request = connection, request
	if probe.before != nil {
		probe.before()
	}
	if probe.err != nil {
		return paasv1.AdapterCapabilitiesContract{}, paasv1.ExecutionTargetObservation{}, probe.err
	}
	now := probe.repository.now
	capabilities := probe.capabilities
	if capabilities.Adapter.Name == "" {
		capabilities = paasv1.AdapterCapabilitiesContract{
			Adapter: paasv1.AdapterRef{Kind: paasv1.AdapterInfrastructure, Name: "nodehttps", ContractVersion: "v1"},
			Actions: []paasv1.AdapterAction{
				paasv1.AdapterCapabilities,
				paasv1.AdapterInspectExecutionTarget,
				paasv1.AdapterObserveExecutionTarget,
			},
			IsolationGuarantees: []paasv1.IsolationGuarantee{paasv1.IsolationWorkload},
			ObservedAt:          now,
		}
	}
	observation := probe.observation
	if observation.ExecutionTargetID == "" {
		observation = completionObservation(connection, now)
	}
	return capabilities, observation, nil
}

func completionObservation(connection port.EnrolledNodeConnection, now time.Time) paasv1.ExecutionTargetObservation {
	return paasv1.ExecutionTargetObservation{
		ExecutionTargetID: connection.ExecutionTargetID, IdentityFingerprint: connection.IdentityFingerprint,
		Health:                       paasv1.ExecutionTargetHealthReady,
		Capacity:                     paasv1.Capacity{CPUMillis: 4000, MemoryBytes: 8 << 30, StorageBytes: 100 << 30, WorkloadSlots: 32},
		Allocatable:                  paasv1.Capacity{CPUMillis: 3000, MemoryBytes: 6 << 30, StorageBytes: 80 << 30, WorkloadSlots: 24},
		SupportedIsolationGuarantees: []paasv1.IsolationGuarantee{paasv1.IsolationWorkload}, ObservedAt: now,
		Usage: &paasv1.ExecutionTargetUsage{
			ObservedAt: now, ValidUntil: now.Add(15 * time.Second),
			CPU:              paasv1.CPUUsage{State: paasv1.MeasurementUnavailable},
			Memory:           paasv1.MemoryUsage{State: paasv1.MeasurementUnavailable},
			FilesystemsState: paasv1.MeasurementUnavailable,
		},
	}
}

type unusedAdmissionRepository struct{}

func (unusedAdmissionRepository) WithinTransaction(
	context.Context,
	string,
	func(context.Context, executionadmission.Transaction) error,
) error {
	return executionadmission.ErrUnavailable
}

type fakeJoinIssuer struct {
	installationID string
	certificate    []byte
	privateKey     ed25519.PrivateKey
	calls          int
	exchangeCalls  int
	challengeCalls int
	recoveryCalls  int
	credentials    map[paasv1.ResourceID][]byte
	challenges     map[string]paasv1.NodeEnrollmentRecoveryChallenge
	responses      map[string]paasv1.NodeEnrollmentExchangeResponse
}

func (issuer *fakeJoinIssuer) IssueJoin(_ context.Context, request JoinIssueRequest) (IssuedJoin, error) {
	issuer.calls++
	if ValidateControlPlaneBaseURL(request.ControlPlaneBaseURL) != nil {
		return IssuedJoin{}, ErrInvalidArgument
	}
	credential := sha256.Sum256([]byte("credential-" + string(request.EnrollmentID) + "-" + string(rune(issuer.calls))))
	digest := sha256.Sum256(credential[:])
	join := paasv1.NodeEnrollmentJoin{
		APIVersion: paasv1.NodeEnrollmentJoinAPIVersion, Kind: paasv1.NodeEnrollmentJoinKind,
		EnrollmentID: request.EnrollmentID, InstallationID: issuer.installationID,
		ExecutionTargetID: request.ExecutionTargetID,
		ControlPlaneURL:   request.ControlPlaneBaseURL + "/node-enrollments/" + string(request.EnrollmentID) + "/exchange",
		CredentialDigest:  "sha256:" + hex.EncodeToString(digest[:]), ExpiresAt: request.ExpiresAt,
		IssuerCertificate:  base64.RawURLEncoding.EncodeToString(issuer.certificate),
		SignatureAlgorithm: paasv1.NodeJoinSignatureEd25519,
	}
	commitment, err := paasv1.NodeEnrollmentJoinSigningBytes(join)
	if err != nil {
		return IssuedJoin{}, err
	}
	join.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(issuer.privateKey, commitment))
	salt := bytes.Repeat([]byte{0x5a}, 32)
	verifierInput := append(bytes.Clone(salt), credential[:]...)
	verifier := sha256.Sum256(verifierInput)
	clear(verifierInput)
	issuer.credentials[request.EnrollmentID] = bytes.Clone(credential[:])
	return IssuedJoin{
		Join: join,
		WrappedCredential: paasv1.WrappedJoinCredential{
			Algorithm:  paasv1.JoinCredentialRSAOAEP256,
			Ciphertext: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{byte(issuer.calls)}, 384)),
		},
		CredentialSalt:     salt,
		CredentialVerifier: "sha256:" + hex.EncodeToString(verifier[:]),
	}, nil
}

func (issuer *fakeJoinIssuer) IssueExchange(_ context.Context, request ExchangeIssueRequest) (IssuedExchange, error) {
	issuer.exchangeCalls++
	issuerCertificate, err := x509.ParseCertificate(issuer.certificate)
	if err != nil {
		return IssuedExchange{}, err
	}
	parseKey := func(encoded []byte) (ed25519.PublicKey, error) {
		parsed, err := x509.ParsePKIXPublicKey(encoded)
		key, ok := parsed.(ed25519.PublicKey)
		if err != nil || !ok {
			return nil, ErrInvalidArgument
		}
		return key, nil
	}
	nodeKey, err := parseKey(request.NodePublicKey)
	if err != nil {
		return IssuedExchange{}, err
	}
	collectorKey, err := parseKey(request.CollectorPublicKey)
	if err != nil {
		return IssuedExchange{}, err
	}
	roleCertificate := func(role string, key ed25519.PublicKey, address net.IP, usages []x509.ExtKeyUsage, serial int64) (string, error) {
		identityURI, err := url.Parse("spiffe://matrix.xiak.com/installations/" + request.InstallationID + "/" + role + "/" + string(request.ExecutionTargetID))
		if err != nil {
			return "", err
		}
		template := &x509.Certificate{
			SerialNumber: big.NewInt(serial), NotBefore: request.CertificateNotBefore, NotAfter: request.CertificateNotAfter,
			BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature,
			ExtKeyUsage: usages, URIs: []*url.URL{identityURI}, IPAddresses: []net.IP{address},
		}
		encoded, err := x509.CreateCertificate(rand.Reader, template, issuerCertificate, key, issuer.privateKey)
		return base64.RawURLEncoding.EncodeToString(encoded), err
	}
	nodeCertificate, err := roleCertificate("nodes", nodeKey, net.ParseIP(request.ObservedPeerAddress), []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}, 2)
	if err != nil {
		return IssuedExchange{}, err
	}
	collectorCertificate, err := roleCertificate("collectors", collectorKey, net.ParseIP("127.0.0.1"), []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, 3)
	if err != nil {
		return IssuedExchange{}, err
	}
	response := paasv1.NodeEnrollmentExchangeResponse{
		APIVersion: paasv1.NodeEnrollmentExchangeAPIVersion, Kind: paasv1.NodeEnrollmentExchangeResponseKind,
		EnrollmentID: request.EnrollmentID, InstallationID: request.InstallationID,
		ExecutionTargetID: request.ExecutionTargetID, ExchangeID: request.ExchangeID,
		MachineFingerprint: request.MachineFingerprint, RuntimeContractDigest: request.RuntimeContractDigest,
		ControllerID: request.ControllerID, BindingRef: request.BindingRef,
		NodeListenAddress: net.JoinHostPort(request.ObservedPeerAddress, "16443"),
		CollectorEndpoint: "https://127.0.0.1:19100",
		NodeCertificate:   nodeCertificate, CollectorCertificate: collectorCertificate,
		IssuerCertificate:    base64.RawURLEncoding.EncodeToString(issuer.certificate),
		CertificateNotBefore: request.CertificateNotBefore, CertificateNotAfter: request.CertificateNotAfter,
	}
	if issuer.responses == nil {
		issuer.responses = map[string]paasv1.NodeEnrollmentExchangeResponse{}
	}
	issuer.responses[request.ExchangeID] = response
	return IssuedExchange{Response: response, Sealed: SealedExchangeResult{
		Algorithm: ExchangeResultSealAlgorithm, KeyID: "sha256:" + strings.Repeat("d", 64),
		Nonce:      base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x7a}, 12)),
		Ciphertext: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x6b}, 64)),
	}}, nil
}

func (issuer *fakeJoinIssuer) IssueRecoveryChallenge(
	_ context.Context,
	request RecoveryChallengeIssueRequest,
) (paasv1.NodeEnrollmentRecoveryChallenge, error) {
	issuer.challengeCalls++
	exchange := request.Exchange
	nonce := sha256.Sum256([]byte(exchange.ExchangeID + request.IssuedAt.String()))
	authenticator := sha256.Sum256(append([]byte("fake-recovery-authenticator\x00"), nonce[:]...))
	challenge := paasv1.NodeEnrollmentRecoveryChallenge{
		APIVersion:   paasv1.NodeEnrollmentRecoveryAPIVersion,
		Kind:         paasv1.NodeEnrollmentRecoveryChallengeKind,
		EnrollmentID: exchange.EnrollmentID, InstallationID: exchange.InstallationID,
		ExecutionTargetID: exchange.ExecutionTargetID, ExchangeID: exchange.ExchangeID,
		MachineFingerprint: exchange.MachineFingerprint, RuntimeContractDigest: exchange.RuntimeContractDigest,
		NodePublicKeyFingerprint:      exchange.NodePublicKeyFingerprint,
		CollectorPublicKeyFingerprint: exchange.CollectorPublicKeyFingerprint,
		Challenge:                     base64.RawURLEncoding.EncodeToString(nonce[:]),
		IssuedAt:                      request.IssuedAt, ExpiresAt: request.ExpiresAt,
		Authenticator: base64.RawURLEncoding.EncodeToString(authenticator[:]),
	}
	if paasv1.ValidateNodeEnrollmentRecoveryChallenge(challenge) != nil {
		return paasv1.NodeEnrollmentRecoveryChallenge{}, ErrInvalidArgument
	}
	if issuer.challenges == nil {
		issuer.challenges = map[string]paasv1.NodeEnrollmentRecoveryChallenge{}
	}
	issuer.challenges[exchange.ExchangeID] = challenge
	return challenge, nil
}

func (issuer *fakeJoinIssuer) RecoverExchange(
	_ context.Context,
	request RecoverExchangeIssueRequest,
) (paasv1.NodeEnrollmentExchangeResponse, error) {
	issuer.recoveryCalls++
	challenge, found := issuer.challenges[request.Exchange.ExchangeID]
	if !found || challenge != request.Request.Challenge ||
		!recoveryChallengeMatchesStored(challenge, request.Exchange) {
		return paasv1.NodeEnrollmentExchangeResponse{}, ErrRecoveryProofRejected
	}
	if !request.Now.Before(challenge.ExpiresAt) {
		return paasv1.NodeEnrollmentExchangeResponse{}, ErrRecoveryChallengeExpired
	}
	proof, err := paasv1.NodeEnrollmentRecoveryProofSigningBytes(challenge)
	if err != nil {
		return paasv1.NodeEnrollmentExchangeResponse{}, ErrInvalidArgument
	}
	defer clear(proof)
	nodeSignature, nodeSignatureErr := base64.RawURLEncoding.Strict().DecodeString(request.Request.NodeSignature)
	collectorSignature, collectorSignatureErr := base64.RawURLEncoding.Strict().DecodeString(request.Request.CollectorSignature)
	defer clear(nodeSignature)
	defer clear(collectorSignature)
	publicKey := func(value string) (ed25519.PublicKey, error) {
		encoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
		if err != nil {
			return nil, err
		}
		defer clear(encoded)
		parsed, err := x509.ParsePKIXPublicKey(encoded)
		key, ok := parsed.(ed25519.PublicKey)
		if err != nil || !ok {
			return nil, ErrUnavailable
		}
		return bytes.Clone(key), nil
	}
	nodeKey, nodeKeyErr := publicKey(request.Exchange.NodePublicKey)
	collectorKey, collectorKeyErr := publicKey(request.Exchange.CollectorPublicKey)
	if nodeSignatureErr != nil || collectorSignatureErr != nil || nodeKeyErr != nil || collectorKeyErr != nil {
		return paasv1.NodeEnrollmentExchangeResponse{}, ErrUnavailable
	}
	if !ed25519.Verify(nodeKey, proof, nodeSignature) ||
		!ed25519.Verify(collectorKey, proof, collectorSignature) {
		return paasv1.NodeEnrollmentExchangeResponse{}, ErrRecoveryProofRejected
	}
	response, found := issuer.responses[request.Exchange.ExchangeID]
	if !found {
		return paasv1.NodeEnrollmentExchangeResponse{}, ErrUnavailable
	}
	return response, nil
}

func enrollmentFixture(t *testing.T) (*Service, *fakeRepository, *fakeJoinIssuer) {
	t.Helper()
	now := time.Date(2026, 9, 6, 8, 0, 0, 0, time.UTC)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "matrix-enrollment-issuer"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(365 * 24 * time.Hour),
		BasicConstraintsValid: true, IsCA: true, MaxPathLenZero: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	issuerURI, err := paasv1.NodeEnrollmentIssuerURI("installation-a")
	if err != nil {
		t.Fatal(err)
	}
	template.URIs = append(template.URIs, issuerURI)
	certificate, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	repository := &fakeRepository{
		now: now, values: map[paasv1.ResourceID]StoredEnrollment{},
		registrations: map[paasv1.ResourceID]executionadmission.Registration{},
		connections:   map[paasv1.ResourceID]port.EnrolledNodeConnection{},
		pool: paasv1.ExecutionPool{
			APIVersion: paasv1.APIVersion, Kind: "ExecutionPool",
			Metadata: paasv1.ResourceMetadata{
				ID: "pool-a", Name: "pool-a", Scope: paasv1.ResourceScope{Kind: paasv1.AuthorityPlatform},
				ResourceVersion: 1, CreatedAt: now, UpdatedAt: now,
			},
			Spec:   paasv1.ExecutionPoolSpec{AllowedIsolationGuarantees: []paasv1.IsolationGuarantee{paasv1.IsolationWorkload}},
			Status: paasv1.ExecutionPoolStatus{Phase: paasv1.ExecutionPoolUnavailable, ObservedAt: now},
		},
	}
	repository.probe = &fakeCompletionProbe{repository: repository}
	admission, err := executionadmission.New(unusedAdmissionRepository{}, executionadmission.Config{
		InstallationID: "installation-a", ObservationTimeout: time.Second,
		MaximumObservationAge: 15 * time.Second, MaxTransactionAttempts: 3,
		Clock: func() time.Time { return repository.now },
	})
	if err != nil {
		t.Fatal(err)
	}
	issuer := &fakeJoinIssuer{installationID: "installation-a", certificate: certificate, privateKey: privateKey, credentials: map[paasv1.ResourceID][]byte{}}
	service, err := New(repository, issuer, Config{
		InstallationID: "installation-a", Lifetime: 15 * time.Minute,
		CertificateLifetime:            30 * 24 * time.Hour,
		RecoveryChallengeLifetime:      2 * time.Minute,
		SupportedRuntimeContractDigest: "sha256:" + strings.Repeat("c", 64),
		ControllerID:                   "paas-controller-v1", ManagementPort: 16443, CollectorPort: 19100,
		CompletionProbeTimeout: 5 * time.Second,
		CompletionProbe:        repository.probe,
		CompletionAdmission:    admission,
		MaxTransactionAttempts: 3,
	})
	if err != nil {
		t.Fatal(err)
	}
	return service, repository, issuer
}

func createCommand(t *testing.T) CreateCommand {
	t.Helper()
	wrappingKey, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := x509.MarshalPKIXPublicKey(&wrappingKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return CreateCommand{
		Authorization: port.Authorization{
			InstallationID: "installation-a",
			Subject:        paasv1.SubjectRef{Type: paasv1.SubjectUser, ID: "platform-user"},
			DecisionID:     "decision-a", RequestID: "request-a",
		},
		Request: paasv1.CreateNodeEnrollmentRequest{
			Name: "host-a", ExecutionPoolID: "pool-a", Labels: map[string]string{"zone": "private-a"},
			WrappingPublicKey: base64.RawURLEncoding.EncodeToString(encoded),
		},
		IdempotencyKey:      "create-host-a",
		ControlPlaneBaseURL: "https://matrix.internal/api/paas/v1",
	}
}

func regenerateCommand(
	t *testing.T,
	create CreateCommand,
	enrollmentID paasv1.ResourceID,
	expectedResourceVersion uint64,
) RegenerateCommand {
	t.Helper()
	wrapping := createCommand(t).Request.WrappingPublicKey
	return RegenerateCommand{
		Authorization: create.Authorization, EnrollmentID: enrollmentID,
		ExpectedResourceVersion: expectedResourceVersion,
		IdempotencyKey:          "regenerate-host-a",
		Request: paasv1.RegenerateNodeEnrollmentRequest{
			WrappingPublicKey: wrapping,
		},
		ControlPlaneBaseURL: create.ControlPlaneBaseURL,
	}
}

func exchangeCommand(
	t *testing.T,
	created CreateResult,
	issuer *fakeJoinIssuer,
	hexIdentity string,
) ExchangeCommand {
	t.Helper()
	command, nodePrivateKey, collectorPrivateKey := exchangeCommandWithKeys(t, created, issuer, hexIdentity)
	clear(nodePrivateKey)
	clear(collectorPrivateKey)
	return command
}

func exchangeCommandWithKeys(
	t *testing.T,
	created CreateResult,
	issuer *fakeJoinIssuer,
	hexIdentity string,
) (ExchangeCommand, ed25519.PrivateKey, ed25519.PrivateKey) {
	t.Helper()
	if len(hexIdentity) != 1 || !strings.Contains("0123456789abcdef", hexIdentity) {
		t.Fatal("test exchange identity must be one lowercase hex character")
	}
	nodePrivateKey := integrationTestEd25519PrivateKey(t)
	collectorPrivateKey := integrationTestEd25519PrivateKey(t)
	certificateRequest := func(privateKey ed25519.PrivateKey) string {
		encoded, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, privateKey)
		if err != nil {
			t.Fatal(err)
		}
		return base64.RawURLEncoding.EncodeToString(encoded)
	}
	credential := issuer.credentials[created.Response.Enrollment.Metadata.ID]
	if len(credential) != 32 {
		t.Fatal("test issuer did not retain its exchange fixture credential")
	}
	return ExchangeCommand{
		EnrollmentID:        created.Response.Enrollment.Metadata.ID,
		ObservedPeerAddress: "192.168.50.10",
		Request: paasv1.ExchangeNodeEnrollmentRequest{
			APIVersion: paasv1.NodeEnrollmentExchangeAPIVersion, Kind: paasv1.NodeEnrollmentExchangeRequestKind,
			EnrollmentID: created.Response.Enrollment.Metadata.ID, InstallationID: "installation-a",
			ExecutionTargetID:           created.Response.Enrollment.ExecutionTargetID,
			ExchangeID:                  "node-exchange-" + strings.Repeat(hexIdentity, 32),
			Credential:                  base64.RawURLEncoding.EncodeToString(credential),
			MachineFingerprint:          "sha256:" + strings.Repeat(hexIdentity, 64),
			RuntimeContractDigest:       "sha256:" + strings.Repeat("c", 64),
			Listener:                    paasv1.NodeEnrollmentListenerClaim{ManagementPort: 16443, CollectorPort: 19100},
			NodeCertificateRequest:      certificateRequest(nodePrivateKey),
			CollectorCertificateRequest: certificateRequest(collectorPrivateKey),
		},
	}, nodePrivateKey, collectorPrivateKey
}

func completionRequest(t *testing.T, stored StoredEnrollment) paasv1.CompleteNodeEnrollmentRequest {
	t.Helper()
	if stored.Exchange == nil {
		t.Fatal("completion fixture has no exchanged identity")
	}
	exchange := stored.Exchange
	return paasv1.CompleteNodeEnrollmentRequest{
		APIVersion: paasv1.NodeEnrollmentExchangeAPIVersion, Kind: paasv1.NodeEnrollmentCompletionRequestKind,
		EnrollmentID: exchange.EnrollmentID, InstallationID: exchange.InstallationID,
		ExecutionTargetID: exchange.ExecutionTargetID, ExchangeID: exchange.ExchangeID,
		MachineFingerprint: exchange.MachineFingerprint, RuntimeContractDigest: exchange.RuntimeContractDigest,
		ControllerID: exchange.ControllerID, BindingRef: exchange.BindingRef,
		NodeListenAddress: exchange.NodeListenAddress, CollectorEndpoint: exchange.CollectorEndpoint,
		NodePublicKeyFingerprint:      exchange.NodePublicKeyFingerprint,
		CollectorPublicKeyFingerprint: exchange.CollectorPublicKeyFingerprint,
	}
}

func integrationTestEd25519PrivateKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return privateKey
}

func recoveryChallengeRequest(exchange StoredExchange) paasv1.CreateNodeEnrollmentRecoveryChallengeRequest {
	return paasv1.CreateNodeEnrollmentRecoveryChallengeRequest{
		APIVersion:   paasv1.NodeEnrollmentRecoveryAPIVersion,
		Kind:         paasv1.NodeEnrollmentRecoveryChallengeRequestKind,
		EnrollmentID: exchange.EnrollmentID, InstallationID: exchange.InstallationID,
		ExecutionTargetID: exchange.ExecutionTargetID, ExchangeID: exchange.ExchangeID,
		MachineFingerprint: exchange.MachineFingerprint, RuntimeContractDigest: exchange.RuntimeContractDigest,
		NodePublicKeyFingerprint:      exchange.NodePublicKeyFingerprint,
		CollectorPublicKeyFingerprint: exchange.CollectorPublicKeyFingerprint,
	}
}

func recoveryProofRequest(
	t *testing.T,
	challenge paasv1.NodeEnrollmentRecoveryChallenge,
	nodePrivateKey ed25519.PrivateKey,
	collectorPrivateKey ed25519.PrivateKey,
) paasv1.RecoverNodeEnrollmentExchangeRequest {
	t.Helper()
	proof, err := paasv1.NodeEnrollmentRecoveryProofSigningBytes(challenge)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(proof)
	return paasv1.RecoverNodeEnrollmentExchangeRequest{
		APIVersion:         paasv1.NodeEnrollmentRecoveryAPIVersion,
		Kind:               paasv1.NodeEnrollmentRecoveryProofRequestKind,
		Challenge:          challenge,
		NodeSignature:      base64.RawURLEncoding.EncodeToString(ed25519.Sign(nodePrivateKey, proof)),
		CollectorSignature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(collectorPrivateKey, proof)),
	}
}

func cloneStored(value StoredEnrollment) StoredEnrollment {
	value.Enrollment = enrollmentSnapshot(value.Enrollment)
	value.Enrollment.Metadata.Labels = maps.Clone(value.Enrollment.Metadata.Labels)
	value.CredentialSalt = bytes.Clone(value.CredentialSalt)
	if value.Exchange != nil {
		exchange := *value.Exchange
		value.Exchange = &exchange
	}
	if value.SealedExchangeResult != nil {
		sealed := *value.SealedExchangeResult
		value.SealedExchangeResult = &sealed
	}
	return value
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}
