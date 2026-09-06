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
		stored.Enrollment.Metadata.ResourceVersion != 2 {
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
	if _, err := service.Create(context.Background(), command); !errors.Is(err, ErrExpired) {
		t.Fatalf("expired create replay error = %v", err)
	}
	if issuer.calls != 1 {
		t.Fatal("expired replay issued another credential")
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
	repository.values[enrollment.Metadata.ID] = current
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
	digest := sha256.Sum256([]byte("credential-" + string(request.EnrollmentID)))
	join := paasv1.NodeEnrollmentJoin{
		APIVersion: paasv1.NodeEnrollmentJoinAPIVersion, Kind: paasv1.NodeEnrollmentJoinKind,
		EnrollmentID: request.EnrollmentID, InstallationID: issuer.installationID,
		ExecutionTargetID: request.ExecutionTargetID,
		ControlPlaneURL:   "https://matrix.internal/api/paas/v1/node-enrollments/" + string(request.EnrollmentID) + "/exchange",
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
		IdempotencyKey: "create-host-a",
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
