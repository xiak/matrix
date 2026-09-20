package integration

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/mail"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	auditv1 "github.com/xiak/matrix/api/audit/v1"
	iamv1 "github.com/xiak/matrix/api/iam/v1"
	"github.com/xiak/matrix/app/service/iam/internal/authority"
	iampostgres "github.com/xiak/matrix/app/service/iam/internal/data/postgres"
	iamhttp "github.com/xiak/matrix/app/service/iam/internal/service/nethttp"
	"github.com/xiak/matrix/app/service/iam/internal/usecase/identityaccess"
	"github.com/xiak/matrix/app/service/iam/internal/usecase/notificationdispatch"
)

const iamNotificationTestPassword = "matrix-authority-process-test-only"

func TestIAMNotificationContactPostgres(t *testing.T) {
	dsn := os.Getenv("MATRIX_IAM_NOTIFICATION_POSTGRES_TEST_DSN")
	if dsn == "" {
		t.Skip("set MATRIX_IAM_NOTIFICATION_POSTGRES_TEST_DSN to an isolated PostgreSQL 18 database")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	config, err := pgx.ParseConfig(dsn)
	if err != nil || !strings.HasPrefix(config.Database, "matrix_iam_notification_") {
		t.Fatal("notification gate needs its own database")
	}
	config.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	database, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close(context.Background())
	assertIAMPostgres18(t, ctx, database)
	assertCleanIAMSchema(t, ctx, database)
	applyIAMSchema(t, ctx, database)
	createIAMHTTPRole(t, ctx, database)
	document := iamHTTPBootstrap(t)
	wrapping := iamHTTPAccessKeyWrapping(t, document)
	totp := iamHTTPTOTPKeyring(t, document)
	digest, err := iamv1.BootstrapDigest(document)
	if err != nil {
		t.Fatal(err)
	}
	mail := iamv1.EmailVerificationKeyring{APIVersion: iamv1.APIVersion, Kind: "EmailVerificationKeyring", Purpose: iamv1.EmailVerificationWrappingPurpose,
		Scope: iamv1.SecurityMailInstallationScope{InstallationID: document.InstallationID, BootstrapDigest: digest}, KeysetRevision: 1, ActiveKeyID: "email-test",
		Keys: []iamv1.EmailVerificationWrappingKey{{KeyID: "email-test", FormatVersion: 1, KeyMaterial: iamHTTPSecret(t, base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x63}, 32)))}}}
	newReplicaWithIDs := func(material *iamv1.EmailVerificationKeyring, issueID func(string) (string, error)) *identityaccess.Authority {
		t.Helper()
		pc, err := pgxpool.ParseConfig(dsn)
		if err != nil {
			t.Fatal(err)
		}
		pc.ConnConfig.User, pc.ConnConfig.Password = iamHTTPTestRole, iamHTTPTestPassword
		pc.MaxConns = 2
		pool, err := pgxpool.NewWithConfig(ctx, pc)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(pool.Close)
		repo, err := iampostgres.NewRepository(pool)
		if err != nil {
			t.Fatal(err)
		}
		service, err := identityaccess.NewAuthority(repo, identityaccess.Config{CursorKey: bytes.Repeat([]byte{0x39}, 32), AccessKeyWrapping: &wrapping, TOTPKeyring: &totp, EmailVerificationKeyring: material, NewID: issueID})
		if err != nil {
			t.Fatal(err)
		}
		return service
	}
	newReplica := func(material *iamv1.EmailVerificationKeyring) *identityaccess.Authority {
		return newReplicaWithIDs(material, nil)
	}
	first, second := newReplica(&mail), newReplica(&mail)
	if _, err := bootstrapIAMWithTOTP(t, ctx, first, document); err != nil {
		t.Fatal(err)
	}
	for _, service := range []*identityaccess.Authority{first, second} {
		if err := service.RegisterEmailVerificationKeyset(ctx); err != nil {
			t.Fatal("register email custody", err)
		}
	}
	login, err := first.Login(ctx, iamv1.LoginRequest{LoginName: "admin", Password: document.Administrator.Password, RequestID: "mail-root-login"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := first.NotificationContact(ctx, login.Credential); !errors.Is(err, identityaccess.ErrForbidden) {
		t.Fatal("forced password allowed contact", err)
	}
	if _, err := first.ChangePassword(ctx, login.Credential, iamv1.ChangePasswordRequest{CurrentPassword: document.Administrator.Password, NewPassword: iamHTTPSecret(t, changedAdminPassword), RequestID: "mail-root-password"}); err != nil {
		t.Fatal(err)
	}
	other, err := first.Login(ctx, iamv1.LoginRequest{LoginName: "admin", Password: iamHTTPSecret(t, changedAdminPassword), RequestID: "mail-other-session"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := newReplica(nil).NotificationContact(ctx, login.Credential); !errors.Is(err, identityaccess.ErrUnavailable) {
		t.Fatal("missing material allowed contact", err)
	}
	wrong := mail
	wrong.Keys = append([]iamv1.EmailVerificationWrappingKey(nil), mail.Keys...)
	wrong.Keys[0].KeyMaterial = iamHTTPSecret(t, base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x64}, 32)))
	if err := newReplica(&wrong).RegisterEmailVerificationKeyset(ctx); err == nil {
		t.Fatal("same key identity changed material")
	}
	handlers := make([]http.Handler, 2)
	for i, service := range []*identityaccess.Authority{first, second} {
		handlers[i], err = iamhttp.NewHandler(service, iamhttp.Config{})
		if err != nil {
			t.Fatal(err)
		}
	}
	call := func(replica int, method, path string, credential iamv1.Secret, body []byte, status int, result any) {
		t.Helper()
		response := performIAMRequest(handlers[replica], method, path, string(credential.CopyBytes()), body)
		if response.Code != status {
			t.Fatalf("notification HTTP %s status=%d want=%d body=%s", path, response.Code, status, response.Body.String())
		}
		if response.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("notification response was cacheable")
		}
		if result != nil && json.Unmarshal(response.Body.Bytes(), result) != nil {
			t.Fatal("invalid contact response")
		}
	}
	const path = "/v1/auth/notification-contact"
	var contact iamv1.NotificationContact
	call(0, http.MethodGet, path, login.Credential, nil, 200, &contact)
	if contact.State != "NONE" || contact.ResourceVersion != 0 {
		t.Fatal("invented contact")
	}
	start := iamv1.StartNotificationContactVerificationRequest{Email: "First.User@mail.example.test", Password: iamHTTPSecret(t, changedAdminPassword), RequestID: "mail-first-verification"}
	startBytes, err := iamv1.EncodeStartNotificationContactVerificationRequest(start)
	if err != nil {
		t.Fatal(err)
	}
	var pending, replayed iamv1.NotificationContactVerification
	call(0, http.MethodPost, path+"/verifications", login.Credential, startBytes, 200, &pending)
	call(1, http.MethodPost, path+"/verifications", login.Credential, startBytes, 200, &replayed)
	if pending.ID == "" || pending.ID != replayed.ID || pending.IssuedAt != replayed.IssuedAt || pending.Email != start.Email || pending.State != "PENDING" || pending.Delivery.State != "PENDING" {
		t.Fatal("verification intent replay changed")
	}
	var initialCount int
	if err := database.QueryRow(ctx, "SELECT count(*) FROM iam.security_notifications").Scan(&initialCount); err != nil || initialCount != 1 {
		t.Fatal("replay emitted another mail", err)
	}
	changed := start
	changed.Email = "Different@mail.example.test"
	changedBytes, _ := iamv1.EncodeStartNotificationContactVerificationRequest(changed)
	call(1, http.MethodPost, path+"/verifications", login.Credential, changedBytes, 409, nil)
	call(0, http.MethodGet, path+"?accountId=other", login.Credential, nil, 400, nil)
	call(0, http.MethodPost, path+"/verifications", login.Credential, []byte(`{"email":"x@mail.example.test","password":"private","requestId":"selector","userId":"other"}`), 400, nil)
	call(1, http.MethodGet, path+"/verifications/"+pending.ID, other.Credential, nil, 403, nil)
	call(1, http.MethodGet, path, iamHTTPSecret(t, paasCredential), nil, 401, nil)
	// Obtain only the original synthetic record through the test administrator,
	// then decrypt with its exact fixture key. No state/hash rewrite or forgery.
	var binding iamv1.EmailVerificationBinding
	var sealed authority.SealedEmailVerificationCode
	sealed.FormatVersion = 1
	binding.AccountID, binding.UserID, binding.VerificationID = pending.AccountID, pending.UserID, pending.ID
	if err := database.QueryRow(ctx, `SELECT installation_id,bootstrap_digest,email,credential_generation,contact_revision,issued_at,expires_at,key_id,nonce,ciphertext
		FROM iam.notification_contact_verifications WHERE tenant_id=$1 AND id=$2`, pending.AccountID, pending.ID).Scan(&binding.InstallationID, &binding.BootstrapDigest, &binding.Recipient,
		&binding.CredentialGeneration, &binding.ContactRevision, &binding.IssuedAt, &binding.ExpiresAt, &sealed.KeyID, &sealed.Nonce, &sealed.Ciphertext); err != nil {
		t.Fatal(err)
	}
	binding.IssuedAt, binding.ExpiresAt = binding.IssuedAt.UTC(), binding.ExpiresAt.UTC()
	protector, err := authority.NewEmailVerificationProtector(mail)
	if err != nil {
		t.Fatal(err)
	}
	code, err := protector.Open(binding, sealed)
	if err != nil {
		t.Fatal(err)
	}
	wrongCode := code.CopyBytes()
	wrongCode[0] = '0' + (wrongCode[0]-'0'+1)%10
	bad := iamv1.ConfirmNotificationContactVerificationRequest{Code: iamHTTPSecret(t, string(wrongCode)), RequestID: "mail-wrong-code"}
	clear(wrongCode)
	badBytes, _ := iamv1.EncodeConfirmNotificationContactVerificationRequest(bad)
	call(0, http.MethodPost, path+"/verifications/"+pending.ID+":confirm", login.Credential, badBytes, 422, nil)
	var debited bool
	if err := database.QueryRow(ctx, "SELECT used=1 AND state='REJECTED' FROM iam.notification_confirmation_attempts WHERE tenant_id=$1 AND user_id=$2", pending.AccountID, pending.UserID).Scan(&debited); err != nil || !debited {
		t.Fatal("wrong code refunded its attempt", err)
	}
	// The exact dedicated login exercises real restricted claim/completion.
	// SMTP observations below are storage fixtures, not a delivery assertion.
	if _, err := database.Exec(ctx, `DO $role$ BEGIN IF NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='matrix_iam_notification_worker_login') THEN
		CREATE ROLE matrix_iam_notification_worker_login LOGIN PASSWORD '`+iamNotificationTestPassword+`'; END IF; END $role$;
		GRANT matrix_iam_notification_worker TO matrix_iam_notification_worker_login;`); err != nil {
		t.Fatal(err)
	}
	workerConfig, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	workerConfig.ConnConfig.User, workerConfig.ConnConfig.Password = "matrix_iam_notification_worker_login", iamNotificationTestPassword
	workerConfig.MaxConns = 2
	workerPool, err := pgxpool.NewWithConfig(ctx, workerConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer workerPool.Close()
	workerRepo, err := iampostgres.NewNotificationRepository(workerPool)
	if err != nil {
		t.Fatal(err)
	}
	claimMessage := func(workerID string) (notificationdispatch.Claim, bool) {
		t.Helper()
		var claimed notificationdispatch.Claim
		var found bool
		err := workerRepo.WithinTransaction(ctx, func(ctx context.Context, tx notificationdispatch.Transaction) error {
			stored, err := tx.ReadKeyset(ctx)
			if err != nil {
				return err
			}
			if stored == nil || !protector.Matches(*stored) {
				return notificationdispatch.ErrUnavailable
			}
			claimed, found, err = tx.Claim(ctx, workerID)
			return err
		})
		if err != nil {
			t.Fatal("restricted notification claim", err)
		}
		return claimed, found
	}
	claimed, found := claimMessage("mail-worker-a")
	if !found || claimed.Kind != authority.MailAddressVerification || claimed.Binding.VerificationID != pending.ID || claimed.Recipient != pending.Email || claimed.Fence != 1 {
		t.Fatal("wrong original notification claim")
	}
	if _, found := claimMessage("mail-worker-b"); found {
		t.Fatal("two workers held one notification")
	}
	stale := claimed
	stale.Fence++
	if err := workerRepo.WithinTransaction(ctx, func(ctx context.Context, tx notificationdispatch.Transaction) error {
		return tx.Complete(ctx, stale, "mail-worker-a", authority.MailSubmission{State: authority.MailAccepted, SMTPCode: 250})
	}); !errors.Is(err, notificationdispatch.ErrStaleLease) {
		t.Fatal("forged fence completed", err)
	}
	if err := workerRepo.WithinTransaction(ctx, func(ctx context.Context, tx notificationdispatch.Transaction) error {
		return tx.Complete(ctx, claimed, "mail-worker-b", authority.MailSubmission{State: authority.MailAccepted, SMTPCode: 250})
	}); !errors.Is(err, notificationdispatch.ErrStaleLease) {
		t.Fatal("another worker completed", err)
	}
	// A lost process may already have submitted DATA. Wait on the actual
	// database lease (no timestamp rewrite); the first claimant reconciles
	// UNKNOWN and cannot immediately send a duplicate under a new fence.
	t.Run("lost_lease_and_durable_retry", func(t *testing.T) {
		waitUntil := func(deadline time.Time) {
			t.Helper()
			timer := time.NewTimer(max(time.Duration(0), time.Until(deadline)+20*time.Millisecond))
			defer timer.Stop()
			select {
			case <-timer.C:
			case <-ctx.Done():
				t.Fatal("notification lease gate timed out")
			}
		}
		waitUntil(claimed.LeaseExpiresAt)
		if _, found := claimMessage("mail-worker-b"); found {
			t.Fatal("expired unknown submission was immediately repeated")
		}
		var retryAt time.Time
		var observation, deliveryState string
		var attemptCount int
		if err := database.QueryRow(ctx, `SELECT state,last_outcome,attempts,next_attempt_at FROM iam.security_notifications
		WHERE tenant_id=$1 AND id=$2`, claimed.AccountID, claimed.NotificationID).Scan(&deliveryState, &observation, &attemptCount, &retryAt); err != nil ||
			deliveryState != "RETRY_WAIT" || observation != "UNKNOWN" || attemptCount != 1 {
			t.Fatal("lost lease did not retain durable uncertainty", err)
		}
		if err := workerRepo.WithinTransaction(ctx, func(ctx context.Context, tx notificationdispatch.Transaction) error {
			return tx.Complete(ctx, claimed, "mail-worker-a", authority.MailSubmission{State: authority.MailAccepted, SMTPCode: 250})
		}); !errors.Is(err, notificationdispatch.ErrStaleLease) {
			t.Fatal("expired worker completed", err)
		}
		if _, found := claimMessage("mail-worker-a"); found {
			t.Fatal("retry bypassed its durable backoff")
		}
		waitUntil(retryAt)
		retried, found := claimMessage("mail-worker-a")
		if !found || retried.NotificationID != claimed.NotificationID || retried.Binding != claimed.Binding || retried.Fence != 2 ||
			!bytes.Equal(retried.Sealed.Ciphertext, claimed.Sealed.Ciphertext) || !bytes.Equal(retried.Sealed.Nonce, claimed.Sealed.Nonce) {
			t.Fatal("retry changed original secret, recipient, expiry or intent")
		}
		if err := workerRepo.WithinTransaction(ctx, func(ctx context.Context, tx notificationdispatch.Transaction) error {
			return tx.Complete(ctx, claimed, "mail-worker-a", authority.MailSubmission{State: authority.MailRejected, SMTPCode: 550})
		}); !errors.Is(err, notificationdispatch.ErrStaleLease) {
			t.Fatal("old fence changed a new attempt", err)
		}
		claimed = retried
	})
	if err := workerRepo.WithinTransaction(ctx, func(ctx context.Context, tx notificationdispatch.Transaction) error {
		return tx.Complete(ctx, claimed, "mail-worker-a", authority.MailSubmission{State: authority.MailAccepted, SMTPCode: 250})
	}); err != nil {
		t.Fatal("original mail completion", err)
	}
	if err := workerRepo.WithinTransaction(ctx, func(ctx context.Context, tx notificationdispatch.Transaction) error {
		return tx.Complete(ctx, claimed, "mail-worker-a", authority.MailSubmission{State: authority.MailRejected, SMTPCode: 550})
	}); !errors.Is(err, notificationdispatch.ErrStaleLease) {
		t.Fatal("late observation overwrote acceptance", err)
	}
	correct := iamv1.ConfirmNotificationContactVerificationRequest{Code: code, RequestID: "mail-confirm"}
	confirmBytes, _ := iamv1.EncodeConfirmNotificationContactVerificationRequest(correct)
	var complete iamv1.NotificationContactVerification
	call(1, http.MethodPost, path+"/verifications/"+pending.ID+":confirm", login.Credential, confirmBytes, 200, &complete)
	if complete.State != "VERIFIED" || complete.CompletedAt == nil {
		t.Fatal("contact was not completed")
	}
	call(0, http.MethodPost, path+"/verifications/"+pending.ID+":confirm", login.Credential, confirmBytes, 409, nil)
	call(0, http.MethodGet, path+"/verifications/"+pending.ID, login.Credential, nil, 200, &replayed)
	if replayed.CompletedAt == nil || *replayed.CompletedAt != *complete.CompletedAt {
		t.Fatal("history query repeated confirmation")
	}
	call(1, http.MethodGet, path, login.Credential, nil, 200, &contact)
	if contact.State != "VERIFIED" || contact.Email != start.Email || contact.ResourceVersion != 1 || contact.PendingVerificationID != "" {
		t.Fatal("verified contact projection changed")
	}
	securityNotice, found := claimMessage("mail-worker-b")
	if !found || securityNotice.Kind != authority.MailContactVerified || securityNotice.Recipient != contact.Email || securityNotice.Sealed.KeyID != "" || len(securityNotice.Sealed.Ciphertext) != 0 {
		t.Fatal("security notice disclosed verification material")
	}
	if err := workerRepo.WithinTransaction(ctx, func(ctx context.Context, tx notificationdispatch.Transaction) error {
		return tx.Complete(ctx, securityNotice, "mail-worker-b", authority.MailSubmission{State: authority.MailRejected, SMTPCode: 550})
	}); err != nil {
		t.Fatal("terminal SMTP rejection", err)
	}
	if _, found := claimMessage("mail-worker-a"); found {
		t.Fatal("terminal notice was retried")
	}
	for _, attack := range []string{"SELECT * FROM iam.notification_contacts", "SELECT * FROM iam.user_credentials", "SELECT * FROM iam.lookup_session('x')", "SELECT * FROM iam.claim_audit_event('mail',15)", "SELECT iam.register_email_verification_keyset('{}')"} {
		_, err := workerPool.Exec(ctx, attack)
		var failure *pgconn.PgError
		if !errors.As(err, &failure) || failure.Code != "42501" {
			t.Fatal("mail worker gained another authority", err)
		}
	}
	var facts, notices, contacts int
	if err := database.QueryRow(ctx, `SELECT (SELECT count(*) FROM iam.audit_outbox WHERE event_document->>'action' LIKE 'iam.notification-contact.%'),
		(SELECT count(*) FROM iam.security_notifications),(SELECT count(*) FROM iam.notification_contacts)`).Scan(&facts, &notices, &contacts); err != nil || facts != 2 || notices != 2 || contacts != 1 {
		t.Fatal("notification atomicity/count", err, facts, notices, contacts)
	}
	var leaked bool
	if err := database.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM iam.audit_outbox WHERE event_document::text LIKE '%'||$1||'%' OR event_document::text LIKE '%'||$2||'%')", start.Email, string(code.CopyBytes())).Scan(&leaked); err != nil || leaked {
		t.Fatal("contact secret entered Audit", err)
	}
	apiConfig := config.Copy()
	apiConfig.User, apiConfig.Password = iamHTTPTestRole, iamHTTPTestPassword
	api, err := pgx.ConnectConfig(ctx, apiConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer api.Close(context.Background())
	for _, attack := range []string{"SELECT * FROM iam.notification_contacts", "SELECT * FROM iam.notification_contact_verifications", "UPDATE iam.security_notifications SET state='ACCEPTED'", "SELECT * FROM iam.claim_security_notification('api')", "SELECT iam.complete_security_notification('x','y','api',1,'ACCEPTED',250)"} {
		_, err := api.Exec(ctx, attack)
		var failure *pgconn.PgError
		if !errors.As(err, &failure) || failure.Code != "42501" {
			t.Fatal("API gained mail database authority", err)
		}
	}
	// Equal schema/bootstrap/material replay and a fresh authority preserve the
	// verified state and original facts; none are recreated as side effects.
	applyIAMSchema(t, ctx, database)
	restarted := newReplica(&mail)
	if _, err := bootstrapIAMWithTOTP(t, ctx, restarted, document); err != nil {
		t.Fatal(err)
	}
	if err := restarted.RegisterEmailVerificationKeyset(ctx); err != nil {
		t.Fatal(err)
	}
	after, err := restarted.NotificationContact(ctx, login.Credential)
	if err != nil || after.ResourceVersion != contact.ResourceVersion || after.Email != contact.Email {
		t.Fatal("restart changed contact", err)
	}
	assertContactProof := func(account iamv1.AccountID, user iamv1.PrincipalID) {
		t.Helper()
		rows, err := database.Query(ctx, `SELECT event_document FROM iam.audit_outbox WHERE tenant_id=$1
		 AND event_document#>>'{actor,id}'=$2 AND event_document->>'action' IN ('iam.notification-contact.verification-started','iam.notification-contact.verified')`, account, user)
		if err != nil {
			t.Fatal("read committed contact facts")
		}
		var events []auditv1.Event
		for rows.Next() {
			var document []byte
			var event auditv1.Event
			if rows.Scan(&document) != nil || json.Unmarshal(document, &event) != nil {
				rows.Close()
				t.Fatal("invalid contact fact")
			}
			events = append(events, event)
		}
		rows.Close()
		if rows.Err() != nil || len(events) != 2 {
			t.Fatal("contact has no exact pair of committed facts")
		}
		for _, event := range events {
			proof, err := restarted.ResolveAuditProducer(ctx, iamHTTPSecret(t, iamProducerCredential), iamv1.ResolveAuditProducerRequest{Event: event})
			_, digest, canonicalErr := auditv1.CanonicalizeEvent(auditv1.SourceIAM, event)
			if err != nil || canonicalErr != nil || iamv1.ValidateAuditProducerAuthorization(proof) != nil || proof.ContentDigest != digest {
				t.Fatal("committed contact fact lost its exact historical proof")
			}
			forged := event
			forged.RequestID += "-forged"
			if _, err := restarted.ResolveAuditProducer(ctx, iamHTTPSecret(t, iamProducerCredential), iamv1.ResolveAuditProducerRequest{Event: forged}); !errors.Is(err, identityaccess.ErrForbidden) {
				t.Fatal("altered contact fact obtained historical authority", err)
			}
		}
	}
	assertContactProof(contact.AccountID, contact.UserID)
	t.Run("real_postfix_http_contact_and_historical_notice", func(t *testing.T) {
		channel, receive := iamNotificationPostfix(t, mail.Scope)
		initialPassword := iamHTTPSecret(t, "Mail-Initial-User-Password-472!")
		currentPassword := iamHTTPSecret(t, "Mail-Current-User-Password-739!")
		user, err := first.CreateUser(ctx, login.Credential, iamv1.CreateUserRequest{LoginName: "mail-delivery", DisplayName: "Mail delivery gate", InitialPassword: initialPassword, RequestID: "mail-delivery-create"})
		if err != nil {
			t.Fatal(err)
		}
		userLogin, err := first.Login(ctx, iamv1.LoginRequest{LoginName: user.LoginName + "@" + string(user.AccountID), Password: initialPassword, RequestID: "mail-delivery-login"})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := first.ChangePassword(ctx, userLogin.Credential, iamv1.ChangePasswordRequest{CurrentPassword: initialPassword, NewPassword: currentPassword, RequestID: "mail-delivery-password"}); err != nil {
			t.Fatal(err)
		}
		server := httptest.NewServer(handlers[0])
		defer server.Close()
		httpClient := server.Client()
		httpClient.Timeout = 10 * time.Second
		wireCall := func(method, route string, body []byte, status int, result any) {
			t.Helper()
			request, err := http.NewRequestWithContext(ctx, method, server.URL+route, bytes.NewReader(body))
			if err != nil {
				t.Fatal(err)
			}
			request.Header.Set("Authorization", "Bearer "+string(userLogin.Credential.CopyBytes()))
			if body != nil {
				request.Header.Set("Content-Type", "application/json")
			}
			response, err := httpClient.Do(request)
			if err != nil {
				t.Fatal("notification HTTP unavailable")
			}
			defer response.Body.Close()
			encoded, err := io.ReadAll(io.LimitReader(response.Body, 32769))
			defer clear(encoded)
			if err != nil || len(encoded) > 32768 || response.StatusCode != status || response.Header.Get("Cache-Control") != "no-store" {
				t.Fatalf("notification HTTP status=%d want=%d", response.StatusCode, status)
			}
			if result != nil && json.Unmarshal(encoded, result) != nil {
				t.Fatal("invalid notification HTTP projection")
			}
		}
		requestBytes, err := iamv1.EncodeStartNotificationContactVerificationRequest(iamv1.StartNotificationContactVerificationRequest{Email: "receiver@matrix.test", Password: currentPassword, RequestID: "mail-delivery-verify"})
		if err != nil {
			t.Fatal(err)
		}
		var verification iamv1.NotificationContactVerification
		wireCall(http.MethodPost, path+"/verifications", requestBytes, 200, &verification)
		startDelivery := iamNotificationProcess(t, ctx, database, dsn, channel, mail)
		stopDelivery := startDelivery()
		awaitSubmission := func(id string) {
			t.Helper()
			deadline := time.Now().Add(5 * time.Second)
			for time.Now().Before(deadline) {
				var accepted bool
				if err := database.QueryRow(ctx, "SELECT state='ACCEPTED' AND last_outcome='ACCEPTED' AND last_smtp_code=250 FROM iam.security_notifications WHERE tenant_id=$1 AND id=$2", verification.AccountID, id).Scan(&accepted); err != nil {
					t.Fatal(err)
				}
				if accepted {
					return
				}
				time.Sleep(25 * time.Millisecond)
			}
			t.Fatal("actual submission observation was not committed")
		}
		var notificationID string
		if err := database.QueryRow(ctx, "SELECT notification_id FROM iam.notification_contact_verifications WHERE tenant_id=$1 AND id=$2", verification.AccountID, verification.ID).Scan(&notificationID); err != nil {
			t.Fatal(err)
		}
		// The confirmation code comes ONLY from the real delivered Maildir, not
		// from an IAM row, decryption fixture, fake contact or injected digest.
		body, verificationMessageID := receive(notificationID)
		match := regexp.MustCompile(`(?m)^Verification code: ([0-9]{8})\r?$`).FindSubmatch(body)
		if len(match) != 2 {
			t.Fatal("real verification mail has no exact code")
		}
		receivedCode := iamHTTPSecret(t, string(match[1]))
		clear(body)
		awaitSubmission(notificationID)
		stopDelivery()
		confirmationBytes, err := iamv1.EncodeConfirmNotificationContactVerificationRequest(iamv1.ConfirmNotificationContactVerificationRequest{Code: receivedCode, RequestID: "mail-delivery-confirm"})
		if err != nil {
			t.Fatal(err)
		}
		wireCall(http.MethodPost, path+"/verifications/"+verification.ID+":confirm", confirmationBytes, 200, &verification)
		if verification.State != "VERIFIED" {
			t.Fatal("mailbox possession did not verify contact")
		}
		var verified iamv1.NotificationContact
		wireCall(http.MethodGet, path, nil, 200, &verified)
		if verified.State != "VERIFIED" || verified.Email != "receiver@matrix.test" || verified.ResourceVersion != 1 {
			t.Fatal("unexpected verified contact")
		}
		current, err := first.GetUser(ctx, login.Credential, user.ID, "mail-delivery-current-user")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := first.SetUserStatus(ctx, login.Credential, user.ID, iamv1.SetUserStatusRequest{Status: iamv1.PrincipalDisabled, ResourceVersion: current.User.ResourceVersion, RequestID: "mail-delivery-disable"}); err != nil {
			t.Fatal(err)
		}
		wireCall(http.MethodGet, path, nil, 401, nil)
		// Current authentication is closed, but the committed historical security
		// notice must still go to its original recipient without old code material.
		stopDelivery = startDelivery()
		if err := database.QueryRow(ctx, "SELECT id FROM iam.security_notifications WHERE tenant_id=$1 AND verification_id=$2 AND kind='CONTACT_VERIFIED'", verification.AccountID, verification.ID).Scan(&notificationID); err != nil {
			t.Fatal(err)
		}
		body, noticeMessageID := receive(notificationID)
		if noticeMessageID == verificationMessageID || bytes.Contains(body, receivedCode.CopyBytes()) || bytes.Contains(body, []byte("Verification code:")) {
			t.Fatal("historical notice reused verification material")
		}
		clear(body)
		awaitSubmission(notificationID)
		stopDelivery()
		var accepted int
		if err := database.QueryRow(ctx, "SELECT count(*) FROM iam.security_notifications WHERE tenant_id=$1 AND verification_id=$2 AND state='ACCEPTED' AND attempts=1 AND last_outcome='ACCEPTED' AND last_smtp_code=250", verification.AccountID, verification.ID).Scan(&accepted); err != nil || accepted != 2 {
			t.Fatal("actual worker did not persist both exact submission observations", err)
		}
		assertContactProof(user.AccountID, user.ID)
		t.Log("real HTTP + independent restricted notification executable + authenticated STARTTLS Postfix: mailbox code consumed once; historical security notice received after USER disable/restart")
	})
	newMailUser := func(name string, administrator iamv1.Secret) (iamv1.User, iamv1.LoginResponse, iamv1.Secret) {
		t.Helper()
		initial := iamHTTPSecret(t, "Mail-Matrix-Initial-User-583!")
		password := iamHTTPSecret(t, "Mail-Matrix-Current-User-682!")
		user, err := first.CreateUser(ctx, administrator, iamv1.CreateUserRequest{LoginName: name, DisplayName: "Mail matrix", InitialPassword: initial, RequestID: "mail-create-" + name})
		if err != nil {
			t.Fatal(err)
		}
		access, err := first.Login(ctx, iamv1.LoginRequest{LoginName: name + "@" + string(user.AccountID), Password: initial, RequestID: "mail-login-" + name})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := first.ChangePassword(ctx, access.Credential, iamv1.ChangePasswordRequest{CurrentPassword: initial, NewPassword: password, RequestID: "mail-password-" + name}); err != nil {
			t.Fatal(err)
		}
		return user, access, password
	}
	t.Run("computed_confirmation_rechecks_current_identity_and_intent", func(t *testing.T) {
		for _, mutation := range []string{"password", "disabled-user", "logout", "new-intent"} {
			t.Run(mutation, func(t *testing.T) {
				user, access, password := newMailUser("mail-race-"+mutation, login.Credential)
				request := iamv1.StartNotificationContactVerificationRequest{Email: mutation + "@mail.example.test", Password: password, RequestID: "mail-race-first"}
				verification, err := first.StartNotificationVerification(ctx, access.Credential, request)
				if err != nil {
					t.Fatal(err)
				}
				code := iamNotificationStorageCode(t, ctx, database, protector, verification)
				arrived, resume := make(chan struct{}), make(chan struct{})
				var release sync.Once
				defer release.Do(func() { close(resume) })
				var ids atomic.Int64
				var paused atomic.Bool
				// The existing ID boundary pauses after the committed debit and
				// code comparison, before the final transaction. This still runs
				// real SQL and actual concurrent user/session commands; no stored
				// credential, confirmation or lifecycle state is injected.
				stalled := newReplicaWithIDs(&mail, func(prefix string) (string, error) {
					if prefix == "notification" && paused.CompareAndSwap(false, true) {
						close(arrived)
						select {
						case <-resume:
						case <-ctx.Done():
							return "", ctx.Err()
						}
					}
					return fmt.Sprintf("%s-mail-%s-%d", prefix, mutation, ids.Add(1)), nil
				})
				finished := make(chan error, 1)
				go func() {
					_, err := stalled.ConfirmNotificationContact(ctx, access.Credential, verification.ID, iamv1.ConfirmNotificationContactVerificationRequest{Code: code, RequestID: "mail-race-confirm"})
					finished <- err
				}()
				select {
				case <-arrived:
				case <-ctx.Done():
					t.Fatal("confirmation did not reach the current-authority race boundary")
				}
				var reserved bool
				if err := database.QueryRow(ctx, "SELECT used=1 AND state='RESERVED' FROM iam.notification_confirmation_attempts WHERE tenant_id=$1 AND user_id=$2", user.AccountID, user.ID).Scan(&reserved); err != nil || !reserved {
					t.Fatal("confirmation comparison preceded its committed debit", err)
				}
				want := identityaccess.ErrUnauthenticated
				switch mutation {
				case "password":
					_, err = second.ChangePassword(ctx, access.Credential, iamv1.ChangePasswordRequest{CurrentPassword: password,
						NewPassword: iamHTTPSecret(t, "Mail-Concurrent-New-Password-946!"), RequestID: "mail-race-password"})
				case "disabled-user":
					var current iamv1.UserAccess
					current, err = second.GetUser(ctx, login.Credential, user.ID, "mail-race-current-user")
					if err == nil {
						_, err = second.SetUserStatus(ctx, login.Credential, user.ID, iamv1.SetUserStatusRequest{Status: iamv1.PrincipalDisabled,
							ResourceVersion: current.User.ResourceVersion, RequestID: "mail-race-disable"})
					}
				case "logout":
					_, err = second.Logout(ctx, access.Credential, iamv1.LogoutRequest{RequestID: "mail-race-logout"})
				case "new-intent":
					request.RequestID = "mail-race-replacement"
					_, err = second.StartNotificationVerification(ctx, access.Credential, request)
					want = identityaccess.ErrConflict
				}
				if err != nil {
					t.Fatal("concurrent mutation could not commit outside the confirmation transaction", err)
				}
				release.Do(func() { close(resume) })
				select {
				case err := <-finished:
					if !errors.Is(err, want) {
						t.Fatal("stale confirmation bypassed current state", err)
					}
				case <-ctx.Done():
					t.Fatal("stale confirmation did not finish")
				}
				var effects, used int
				if err := database.QueryRow(ctx, `SELECT
				 (SELECT count(*) FROM iam.notification_contacts WHERE tenant_id=$1 AND user_id=$2)+
				 (SELECT count(*) FROM iam.security_notifications WHERE tenant_id=$1 AND user_id=$2 AND kind='CONTACT_VERIFIED')+
				 (SELECT count(*) FROM iam.audit_outbox WHERE tenant_id=$1 AND event_document#>>'{actor,id}'=$2 AND event_document->>'action'='iam.notification-contact.verified'),
				 (SELECT used FROM iam.notification_confirmation_attempts WHERE tenant_id=$1 AND user_id=$2)`, user.AccountID, user.ID).Scan(&effects, &used); err != nil || effects != 0 || used != 1 {
					t.Fatal("stale confirmation left a partial success or refunded its debit", err)
				}
			})
		}
	})
	t.Run("budgets_survive_other_replica_new_intent_and_session", func(t *testing.T) {
		user, access, password := newMailUser("mail-budget", login.Credential)
		startRequest := iamv1.StartNotificationContactVerificationRequest{Email: "budget@mail.example.test", Password: password, RequestID: "mail-budget-first"}
		verification, err := first.StartNotificationVerification(ctx, access.Credential, startRequest)
		if err != nil {
			t.Fatal(err)
		}
		for attempt := range 5 {
			if attempt == 2 {
				startRequest.RequestID = "mail-budget-second"
				verification, err = second.StartNotificationVerification(ctx, access.Credential, startRequest)
				if err != nil {
					t.Fatal(err)
				}
			}
			actual := iamNotificationStorageCode(t, ctx, database, protector, verification)
			wrong := actual.CopyBytes()
			wrong[0] = '0' + (wrong[0]-'0'+1)%10
			request := iamv1.ConfirmNotificationContactVerificationRequest{Code: iamHTTPSecret(t, string(wrong)), RequestID: fmt.Sprintf("mail-budget-attempt-%d", attempt)}
			clear(wrong)
			workflow := []*identityaccess.Authority{first, second}[attempt%2]
			if _, err := workflow.ConfirmNotificationContact(ctx, access.Credential, verification.ID, request); !errors.Is(err, identityaccess.ErrVerificationRejected) {
				t.Fatal("wrong-code attempt did not persist a rejection", err)
			}
		}
		actual := iamNotificationStorageCode(t, ctx, database, protector, verification)
		restarted := newReplica(&mail)
		if _, err := restarted.ConfirmNotificationContact(ctx, access.Credential, verification.ID, iamv1.ConfirmNotificationContactVerificationRequest{Code: actual, RequestID: "mail-budget-after-restart"}); !errors.Is(err, identityaccess.ErrOverloaded) {
			t.Fatal("restart refunded a confirmation budget", err)
		}
		fresh, err := first.Login(ctx, iamv1.LoginRequest{LoginName: user.LoginName + "@" + string(user.AccountID), Password: password, RequestID: "mail-budget-fresh-session"})
		if err != nil {
			t.Fatal(err)
		}
		startRequest.RequestID = "mail-budget-third"
		verification, err = restarted.StartNotificationVerification(ctx, fresh.Credential, startRequest)
		if err != nil {
			t.Fatal(err)
		}
		actual = iamNotificationStorageCode(t, ctx, database, protector, verification)
		if _, err := second.ConfirmNotificationContact(ctx, fresh.Credential, verification.ID, iamv1.ConfirmNotificationContactVerificationRequest{Code: actual, RequestID: "mail-budget-after-new-intent"}); !errors.Is(err, identityaccess.ErrOverloaded) {
			t.Fatal("new intent/session refunded a confirmation budget", err)
		}
		startRequest.RequestID = "mail-budget-fourth"
		if _, err := first.StartNotificationVerification(ctx, fresh.Credential, startRequest); !errors.Is(err, identityaccess.ErrOverloaded) {
			t.Fatal("per-USER send budget not shared", err)
		}
		var used, messages, contacts int
		if err := database.QueryRow(ctx, `SELECT (SELECT used FROM iam.notification_confirmation_attempts WHERE tenant_id=$1 AND user_id=$2),
			(SELECT count(*) FROM iam.security_notifications WHERE tenant_id=$1 AND user_id=$2),(SELECT count(*) FROM iam.notification_contacts WHERE tenant_id=$1 AND user_id=$2)`, user.AccountID, user.ID).Scan(&used, &messages, &contacts); err != nil || used != 5 || messages != 3 || contacts != 0 {
			t.Fatal("budget refusal left partial contact/notification effects", err)
		}
	})
	t.Run("cross_account_same_name_and_single_consumption", func(t *testing.T) {
		initial := iamHTTPSecret(t, "Mail-Other-Account-Initial-394!")
		account, err := first.CreateAccount(ctx, login.Credential, iamv1.CreateAccountRequest{ID: "account-mail-b", DisplayName: "Mail account B", RootLoginName: "mail-root-b", RootDisplayName: "Mail B root", InitialPassword: initial, RequestID: "mail-account-b"})
		if err != nil {
			t.Fatal(err)
		}
		root, err := first.Login(ctx, iamv1.LoginRequest{LoginName: account.RootIdentity.LoginName, Password: initial, RequestID: "mail-b-root-login"})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := first.ChangePassword(ctx, root.Credential, iamv1.ChangePasswordRequest{CurrentPassword: initial, NewPassword: iamHTTPSecret(t, "Mail-Other-Account-Current-536!"), RequestID: "mail-b-root-password"}); err != nil {
			t.Fatal(err)
		}
		userA, accessA, passwordA := newMailUser("mail-peer", login.Credential)
		userB, accessB, passwordB := newMailUser("mail-peer", root.Credential)
		request := iamv1.StartNotificationContactVerificationRequest{Email: "shared@mail.example.test", Password: passwordA, RequestID: "mail-peer-first"}
		verificationA, err := first.StartNotificationVerification(ctx, accessA.Credential, request)
		if err != nil {
			t.Fatal(err)
		}
		request.Password = passwordB
		verificationB, err := second.StartNotificationVerification(ctx, accessB.Credential, request)
		if err != nil {
			t.Fatal(err)
		}
		if userA.AccountID == userB.AccountID || userA.ID == userB.ID || userA.LoginName != userB.LoginName {
			t.Fatal("not independent same-name users")
		}
		codeA := iamNotificationStorageCode(t, ctx, database, protector, verificationA)
		codeB := iamNotificationStorageCode(t, ctx, database, protector, verificationB)
		if _, err := first.NotificationVerification(ctx, accessA.Credential, verificationB.ID); !errors.Is(err, identityaccess.ErrForbidden) {
			t.Fatal("cross-account verification read", err)
		}
		if _, err := second.ConfirmNotificationContact(ctx, accessA.Credential, verificationB.ID, iamv1.ConfirmNotificationContactVerificationRequest{Code: codeB, RequestID: "mail-peer-cross"}); !errors.Is(err, identityaccess.ErrForbidden) {
			t.Fatal("cross-account mailbox confirmation", err)
		}
		results := make(chan error, 2)
		for i, workflow := range []*identityaccess.Authority{first, second} {
			go func() {
				_, err := workflow.ConfirmNotificationContact(ctx, accessA.Credential, verificationA.ID, iamv1.ConfirmNotificationContactVerificationRequest{Code: codeA, RequestID: fmt.Sprintf("mail-peer-concurrent-%d", i)})
				results <- err
			}()
		}
		successes := 0
		for range 2 {
			err := <-results
			if err == nil {
				successes++
			} else if !errors.Is(err, identityaccess.ErrConflict) && !errors.Is(err, identityaccess.ErrOverloaded) {
				t.Fatal("unexpected concurrent confirmation", err)
			}
		}
		if successes != 1 {
			t.Fatal("same mailbox code consumed more than once")
		}
		if _, err := second.ConfirmNotificationContact(ctx, accessB.Credential, verificationB.ID, iamv1.ConfirmNotificationContactVerificationRequest{Code: codeB, RequestID: "mail-peer-b-confirm"}); err != nil {
			t.Fatal("independent account code was lost", err)
		}
		var contacts, facts int
		if err := database.QueryRow(ctx, `SELECT (SELECT count(*) FROM iam.notification_contacts WHERE (tenant_id,user_id) IN (($1,$2),($3,$4))),
			(SELECT count(*) FROM iam.audit_outbox WHERE event_document->>'action'='iam.notification-contact.verified' AND (tenant_id,event_document#>>'{actor,id}') IN (($1,$2),($3,$4)))`, userA.AccountID, userA.ID, userB.AccountID, userB.ID).Scan(&contacts, &facts); err != nil || contacts != 2 || facts != 2 {
			t.Fatal("same-name account completion/fact isolation differs", err)
		}
	})
	t.Run("schema_and_privilege_damage_fails_closed", func(t *testing.T) {
		for _, attack := range []string{
			"GRANT SELECT ON iam.notification_contacts TO matrix_iam_api",
			"GRANT EXECUTE ON FUNCTION iam.claim_security_notification(text) TO matrix_iam_api",
			"GRANT EXECUTE ON FUNCTION iam.lock_notification_subject(text,text,text) TO matrix_iam_notification_worker",
			"ALTER FUNCTION iam.claim_security_notification(text) SECURITY INVOKER",
			"ALTER TABLE iam.security_notifications DISABLE TRIGGER notification_delivery_link",
			"ALTER TABLE iam.notification_contacts DISABLE TRIGGER cannot_update",
			"ALTER TABLE iam.notification_contact_verifications NO FORCE ROW LEVEL SECURITY",
			"GRANT matrix_iam_api TO matrix_iam_notification_worker",
			"ALTER ROLE matrix_iam_notification_worker LOGIN",
		} {
			func() {
				tx, err := database.Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer tx.Rollback(context.Background())
				if _, err := tx.Exec(ctx, attack); err != nil {
					t.Fatal("isolated schema attack failed to apply", err)
				}
				var ready bool
				if err := tx.QueryRow(ctx, "SELECT iam.notification_contract_ready()").Scan(&ready); err != nil || ready {
					t.Fatal("notification authority accepted damaged privileges/schema", err)
				}
			}()
		}
		if readiness, err := first.Readiness(ctx); err != nil || readiness.State != iamv1.ReadinessReady {
			t.Fatal("rolled-back damage changed readiness", err)
		}
	})
}

// Storage-only attack gates need the exact synthetic candidate. This never
// substitutes for the real mailbox-only success path above or changes a row.
func iamNotificationStorageCode(t *testing.T, ctx context.Context, database *pgx.Conn, protector *authority.EmailVerificationProtector, verification iamv1.NotificationContactVerification) iamv1.Secret {
	t.Helper()
	binding := iamv1.EmailVerificationBinding{AccountID: verification.AccountID, UserID: verification.UserID, VerificationID: verification.ID}
	sealed := authority.SealedEmailVerificationCode{FormatVersion: 1}
	if err := database.QueryRow(ctx, `SELECT installation_id,bootstrap_digest,email,credential_generation,contact_revision,issued_at,expires_at,key_id,nonce,ciphertext
		FROM iam.notification_contact_verifications WHERE tenant_id=$1 AND user_id=$2 AND id=$3`, verification.AccountID, verification.UserID, verification.ID).Scan(&binding.InstallationID, &binding.BootstrapDigest, &binding.Recipient, &binding.CredentialGeneration, &binding.ContactRevision, &binding.IssuedAt, &binding.ExpiresAt, &sealed.KeyID, &sealed.Nonce, &sealed.Ciphertext); err != nil {
		t.Fatal(err)
	}
	defer clear(sealed.Nonce)
	defer clear(sealed.Ciphertext)
	binding.IssuedAt, binding.ExpiresAt = binding.IssuedAt.UTC(), binding.ExpiresAt.UTC()
	code, err := protector.Open(binding, sealed)
	if err != nil {
		t.Fatal(err)
	}
	return code
}

// Only an explicitly named, local, task-owned Postfix fixture is admissible.
// This reader observes a real Maildir; it cannot write IAM state or deliver mail.
func iamNotificationPostfix(t *testing.T, scope iamv1.SecurityMailInstallationScope) (iamv1.SecurityMailSMTPChannel, func(string) ([]byte, string)) {
	t.Helper()
	container, task := os.Getenv("MATRIX_IAM_SMTP_POSTFIX_CONTAINER"), os.Getenv("MATRIX_IAM_SMTP_POSTFIX_TASK")
	if container == "" && task == "" {
		t.Skip("dedicated Postfix is absent; storage success is not notification delivery")
	}
	if !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(container) || !regexp.MustCompile(`^iam012-smtp-[a-f0-9]{32}$`).MatchString(task) {
		t.Fatal("invalid dedicated SMTP fixture identity")
	}
	docker := func(arguments ...string) []byte {
		t.Helper()
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		defer cancel()
		output, err := exec.CommandContext(ctx, "docker", arguments...).Output()
		if err != nil || len(output) > 65536 {
			t.Fatal("dedicated SMTP fixture observation failed")
		}
		return output
	}
	dockerContext := strings.TrimSpace(string(docker("context", "show")))
	if !regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$`).MatchString(dockerContext) {
		t.Fatal("invalid local Docker context")
	}
	endpoint := strings.TrimSpace(string(docker("context", "inspect", dockerContext, "--format", "{{.Endpoints.docker.Host}}")))
	if !strings.HasPrefix(endpoint, "npipe:///") && !strings.HasPrefix(endpoint, "unix:///") {
		t.Fatal("remote SMTP fixture forbidden")
	}
	localDocker := func(arguments ...string) []byte {
		t.Helper()
		return docker(append([]string{"--context", dockerContext}, arguments...)...)
	}
	var fixture struct {
		ID                          string
		Running                     bool
		Labels                      map[string]string
		NanoCPUs, Memory, PidsLimit int64
		Ports                       map[string][]struct{ HostIP, HostPort string }
	}
	projection := `{"ID":{{json .Id}},"Running":{{json .State.Running}},"Labels":{{json .Config.Labels}},"NanoCPUs":{{json .HostConfig.NanoCpus}},"Memory":{{json .HostConfig.Memory}},"PidsLimit":{{json .HostConfig.PidsLimit}},"Ports":{{json .NetworkSettings.Ports}}}`
	if json.Unmarshal(localDocker("inspect", "--format", projection, container), &fixture) != nil {
		t.Fatal("invalid SMTP fixture metadata")
	}
	ports := fixture.Ports["25/tcp"]
	if fixture.ID != container || !fixture.Running || fixture.Labels["matrix.task"] != task || fixture.Labels["matrix.owner"] != "feat-iam" ||
		fixture.NanoCPUs <= 0 || fixture.NanoCPUs > 2_000_000_000 || fixture.Memory <= 0 || fixture.Memory > 1024*1024*1024 || fixture.PidsLimit <= 0 || fixture.PidsLimit > 128 || len(ports) != 1 || ports[0].HostIP != "127.0.0.1" {
		t.Fatal("SMTP fixture must be isolated, bounded and loopback-only")
	}
	port, err := strconv.ParseUint(ports[0].HostPort, 10, 16)
	if err != nil || port == 0 {
		t.Fatal("invalid SMTP fixture port")
	}
	certificate := localDocker("exec", container, "head", "-c", "16385", "/etc/matrix-smtp-test/server.crt")
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certificate) {
		t.Fatal("invalid SMTP fixture public trust")
	}
	channel := iamv1.SecurityMailSMTPChannel{APIVersion: iamv1.APIVersion, Kind: "SecurityMailSMTPChannel", Purpose: iamv1.SecurityMailSubmissionPurpose, Scope: scope,
		Host: "127.0.0.1", Port: uint16(port), TLSMode: iamv1.SecurityMailSTARTTLS, Username: "smtp-user@matrix.test", Password: iamHTTPSecret(t, "smtp-test-password"),
		From: "sender@matrix.test", TrustedCAPEM: string(certificate)}
	receive := func(reference string) ([]byte, string) {
		t.Helper()
		referenceLine := regexp.MustCompile(`(?m)^Notification reference: ` + regexp.QuoteMeta(reference) + `\r?$`)
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			files := strings.Fields(string(localDocker("exec", container, "find", "/home/receiver/Maildir/new", "/home/receiver/Maildir/cur", "-maxdepth", "1", "-type", "f", "-print")))
			if len(files) > 100 {
				t.Fatal("synthetic mailbox bound exceeded")
			}
			for _, path := range files {
				if !regexp.MustCompile(`^/home/receiver/Maildir/(new|cur)/[a-zA-Z0-9_.,:=+-]+$`).MatchString(path) {
					t.Fatal("unexpected fixture mailbox path")
				}
				encoded := localDocker("exec", container, "head", "-c", "16385", "--", path)
				if len(encoded) > 16384 || bytes.Contains(encoded, []byte("smtp-test-password")) {
					t.Fatal("unsafe mailbox content")
				}
				message, err := mail.ReadMessage(bytes.NewReader(encoded))
				if err != nil {
					t.Fatal("invalid actual mail")
				}
				body, err := io.ReadAll(message.Body)
				if err != nil {
					t.Fatal("invalid actual mail body")
				}
				if !referenceLine.Match(body) {
					clear(body)
					continue
				}
				if message.Header.Get("To") != "receiver@matrix.test" || message.Header.Get("From") != "sender@matrix.test" || message.Header.Get("Received") == "" || message.Header.Get("Message-ID") == "" {
					t.Fatal("actual recipient or submission identity differs")
				}
				return body, message.Header.Get("Message-ID")
			}
			time.Sleep(100 * time.Millisecond)
		}
		t.Fatal("SMTP acceptance did not reach the real mailbox")
		return nil, ""
	}
	return channel, receive
}

// Exercise the production executable and protected FILE consumers, not a
// second dispatcher implementation. Only this child and its temp files are
// stopped/removed. The parent IAM handlers and PostgreSQL remain separate.
func iamNotificationProcess(t *testing.T, ctx context.Context, database *pgx.Conn, adminDSN string, channel iamv1.SecurityMailSMTPChannel, keyring iamv1.EmailVerificationKeyring) func() func() {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", "..", "..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	binary := filepath.Join(directory, "notification-dispatcher")
	if runtime.GOOS == "windows" {
		binary += ".exe"
	}
	build := exec.CommandContext(ctx, "go", "build", "-p", "2", "-trimpath", "-o", binary, "./app/service/iam/cmd/matrix-iam-notification-dispatcher")
	build.Dir = root
	build.Env = append(os.Environ(), "GOMAXPROCS=2", "GOMEMLIMIT=512MiB")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build notification executable: %v %s", err, output)
	}
	write := func(name string, encoded []byte) string {
		t.Helper()
		path := filepath.Join(directory, name)
		if err := os.WriteFile(path, encoded, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	encoded, err := iamv1.EncodeSecurityMailSMTPChannel(channel)
	if err != nil {
		t.Fatal(err)
	}
	channelPath := write("smtp-channel.json", encoded)
	clear(encoded)
	encoded, err = iamv1.EncodeEmailVerificationKeyring(keyring)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := write("email-keyring.json", encoded)
	clear(encoded)
	dsn, err := url.Parse(adminDSN)
	if err != nil || (dsn.Scheme != "postgres" && dsn.Scheme != "postgresql") {
		t.Fatal("notification test DSN must be an explicit PostgreSQL URL")
	}
	dsn.User = url.UserPassword("matrix_iam_notification_worker_login", iamNotificationTestPassword)
	query := dsn.Query()
	query.Del("user")
	query.Del("password")
	query.Set("application_name", "matrix-iam-notification-process-gate")
	dsn.RawQuery = query.Encode()
	dsnPath := write("notification-dsn", []byte(dsn.String()))
	return func() func() {
		t.Helper()
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		address := listener.Addr().String()
		if err := listener.Close(); err != nil {
			t.Fatal(err)
		}
		child := exec.CommandContext(ctx, binary)
		child.Dir = root
		for _, entry := range os.Environ() {
			if !strings.HasPrefix(entry, "MATRIX_") && !strings.HasPrefix(entry, "GOMAXPROCS=") && !strings.HasPrefix(entry, "GOMEMLIMIT=") {
				child.Env = append(child.Env, entry)
			}
		}
		child.Env = append(child.Env, "GOMAXPROCS=2", "GOMEMLIMIT=512MiB", "MATRIX_IAM_NOTIFICATION_DATABASE_DSN_FILE="+dsnPath,
			"MATRIX_IAM_SECURITY_MAIL_SMTP_CHANNEL_FILE="+channelPath, "MATRIX_IAM_EMAIL_VERIFICATION_KEYRING_FILE="+keyPath,
			"MATRIX_IAM_NOTIFICATION_WORKER_ID=mail-real-process", "MATRIX_IAM_NOTIFICATION_LISTEN_ADDRESS="+address)
		var stdout, stderr bytes.Buffer
		child.Stdout, child.Stderr = &stdout, &stderr
		if err := child.Start(); err != nil {
			t.Fatal("start notification executable")
		}
		done := make(chan error, 1)
		go func() { done <- child.Wait() }()
		var stopOnce sync.Once
		stop := func() {
			stopOnce.Do(func() {
				_ = child.Process.Kill()
				select {
				case <-done:
				case <-time.After(5 * time.Second):
					t.Error("notification child did not stop")
					return
				}
				for _, private := range []string{"smtp-test-password", iamNotificationTestPassword, string(keyring.Keys[0].KeyMaterial.CopyBytes()), "receiver@matrix.test"} {
					if strings.Contains(stdout.String(), private) || strings.Contains(stderr.String(), private) {
						t.Error("notification executable leaked protected material")
					}
				}
			})
		}
		t.Cleanup(stop)
		client := &http.Client{Timeout: time.Second, Transport: &http.Transport{Proxy: nil}}
		defer client.CloseIdleConnections()
		ready := false
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			response, err := client.Get("http://" + address + "/ready")
			if err == nil {
				_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
				_ = response.Body.Close()
				if response.StatusCode == 200 {
					ready = true
					break
				}
			}
			time.Sleep(50 * time.Millisecond)
		}
		if !ready {
			t.Fatal("notification executable never became ready")
		}
		var restricted bool
		if err := database.QueryRow(ctx, `SELECT count(*) BETWEEN 1 AND 2 AND bool_and(usename='matrix_iam_notification_worker_login')
			FROM pg_stat_activity WHERE application_name='matrix-iam-notification-process-gate' AND datname=current_database()`).Scan(&restricted); err != nil || !restricted {
			t.Fatal("actual notification process used an unproven database login", err)
		}
		return stop
	}
}
