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
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	paasv1 "github.com/xiak/matrix/api/paas/v1"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/port"
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

func TestStoredEnrollmentCredentialMaterialOnlyExistsWhileWaitingInstall(t *testing.T) {
	service, repository, _ := enrollmentFixture(t)
	created, err := service.Create(context.Background(), createCommand(t))
	if err != nil {
		t.Fatal(err)
	}
	stored := repository.values[created.Response.Enrollment.Metadata.ID]
	consumedAt := repository.now.Add(time.Minute)
	stored.Enrollment.State = paasv1.NodeEnrollmentVerifying
	stored.Enrollment.CredentialConsumedAt = &consumedAt
	stored.Enrollment.Metadata.ResourceVersion++
	stored.Enrollment.Metadata.UpdatedAt = consumedAt
	stored.Operation.State = paasv1.OperationVerifying
	stored.Operation.UpdatedAt = consumedAt
	if ValidateStoredEnrollment(stored, "installation-a") == nil {
		t.Fatal("verifying enrollment retained one-time credential material")
	}
	salt := stored.CredentialSalt
	stored.Clear()
	if len(stored.CredentialSalt) != 0 || stored.CredentialVerifier != "" ||
		stored.WrappedCredential != (paasv1.WrappedJoinCredential{}) ||
		!bytes.Equal(salt, make([]byte, len(salt))) {
		t.Fatal("clearing stored enrollment left credential material reachable")
	}
	if err := ValidateStoredEnrollment(stored, "installation-a"); err != nil {
		t.Fatalf("cleared verifying enrollment is invalid: %v", err)
	}
}

func TestRevokeClosesWaitingOrVerifyingEnrollmentAndExactlyReplays(t *testing.T) {
	service, repository, issuer := enrollmentFixture(t)
	create := createCommand(t)
	created, err := service.Create(context.Background(), create)
	if err != nil {
		t.Fatal(err)
	}
	stored := repository.values[created.Response.Enrollment.Metadata.ID]
	consumedAt := repository.now.Add(time.Minute)
	stored.Enrollment.State = paasv1.NodeEnrollmentVerifying
	stored.Enrollment.CredentialConsumedAt = &consumedAt
	stored.Enrollment.Metadata.ResourceVersion = 2
	stored.Enrollment.Metadata.UpdatedAt = consumedAt
	stored.Operation.State = paasv1.OperationVerifying
	stored.Operation.UpdatedAt = consumedAt
	stored.CredentialSalt = nil
	stored.CredentialVerifier = ""
	stored.WrappedCredential = paasv1.WrappedJoinCredential{}
	repository.values[stored.Enrollment.Metadata.ID] = cloneStored(stored)
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
		current.WrappedCredential != (paasv1.WrappedJoinCredential{}) || repository.revokeCalls != 1 {
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
	failures         []error
	transactionCalls int
	insertCalls      int
	expireCalls      int
	revokeCalls      int
	replaceCalls     int
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

type fakeJoinIssuer struct {
	installationID string
	certificate    []byte
	privateKey     ed25519.PrivateKey
	calls          int
}

func (issuer *fakeJoinIssuer) Issue(_ context.Context, request JoinIssueRequest) (IssuedJoin, error) {
	issuer.calls++
	if ValidateControlPlaneBaseURL(request.ControlPlaneBaseURL) != nil {
		return IssuedJoin{}, ErrInvalidArgument
	}
	digest := sha256.Sum256([]byte("credential-" + string(request.EnrollmentID)))
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
	verifier := sha256.Sum256([]byte("salted-" + string(request.EnrollmentID)))
	return IssuedJoin{
		Join: join,
		WrappedCredential: paasv1.WrappedJoinCredential{
			Algorithm:  paasv1.JoinCredentialRSAOAEP256,
			Ciphertext: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{byte(issuer.calls)}, 384)),
		},
		CredentialSalt:     bytes.Repeat([]byte{0x5a}, 32),
		CredentialVerifier: "sha256:" + hex.EncodeToString(verifier[:]),
	}, nil
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
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		BasicConstraintsValid: true, IsCA: true,
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
	issuer := &fakeJoinIssuer{installationID: "installation-a", certificate: certificate, privateKey: privateKey}
	service, err := New(repository, issuer, Config{
		InstallationID: "installation-a", Lifetime: 15 * time.Minute, MaxTransactionAttempts: 3,
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

func cloneStored(value StoredEnrollment) StoredEnrollment {
	value.Enrollment = enrollmentSnapshot(value.Enrollment)
	value.Enrollment.Metadata.Labels = maps.Clone(value.Enrollment.Metadata.Labels)
	value.CredentialSalt = bytes.Clone(value.CredentialSalt)
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
