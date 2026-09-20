package identityaccess

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	auditv1 "github.com/xiak/matrix/api/audit/v1"
	iamv1 "github.com/xiak/matrix/api/iam/v1"
	"github.com/xiak/matrix/app/service/iam/internal/authority"
)

type passwordEntropyProbe struct {
	testing    *testing.T
	repository *coreRepository
}

func coreTOTPKeyring() iamv1.TOTPKeyring {
	material, _ := iamv1.NewSecret(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x76}, 32)))
	return iamv1.TOTPKeyring{APIVersion: iamv1.APIVersion, Kind: "TOTPKeyring", Purpose: iamv1.TOTPWrappingPurpose,
		Scope:          iamv1.TOTPWrappingScope{InstallationID: "installation-example", BootstrapDigest: "sha256:" + strings.Repeat("a", 64)},
		KeysetRevision: 1, ActiveKeyID: "totp-test", Keys: []iamv1.TOTPWrappingKey{{KeyID: "totp-test", FormatVersion: 1, KeyMaterial: material}}}
}

func newCoreAuthority(repository Repository, config Config) (*Authority, error) {
	keyring := coreTOTPKeyring()
	config.TOTPKeyring = &keyring
	return NewAuthority(repository, config)
}

func TestTOTPCustodyFencesActualLoginAndSessionNotOnlyReadiness(t *testing.T) {
	tx := newCoreTransaction()
	repository := &coreRepository{transaction: tx}
	service, err := newCoreAuthority(repository, Config{})
	if err != nil {
		t.Fatal(err)
	}
	bootstrap := coreBootstrap(t)
	if _, err := service.Bootstrap(t.Context(), bootstrap); err != nil {
		t.Fatal(err)
	}
	request := iamv1.LoginRequest{LoginName: "admin", Password: bootstrap.Administrator.Password, RequestID: "request-custody"}
	login, err := service.Login(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	baseline, err := tx.ReadTOTPCustody(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for _, variant := range []string{"missing-material", "scope", "revision", "digest", "key", "commitment", "unsupported-factor", "database"} {
		t.Run(variant, func(t *testing.T) {
			candidate := *service
			stored := baseline
			stored.Keyset.Keys = append([]TOTPKeyCommitment(nil), baseline.Keyset.Keys...)
			tx.totpCustodyErr = nil
			switch variant {
			case "missing-material":
				candidate.totp = nil
			case "scope":
				stored.Keyset.Scope.InstallationID = "another-installation"
			case "revision":
				stored.Keyset.KeysetRevision++
			case "digest":
				stored.Keyset.ContentDigest = "sha256:" + strings.Repeat("d", 64)
			case "key":
				stored.Keyset.Keys[0].KeyID = "another-key"
			case "commitment":
				stored.Keyset.Keys[0].MaterialCommitment = "sha256:" + strings.Repeat("e", 64)
			case "unsupported-factor":
				stored.HasAuthenticators = true
			case "database":
				tx.totpCustodyErr = ErrUnavailable
			}
			tx.totpCustody = &stored
			before := tx.attemptSequence
			if _, err := candidate.Login(t.Context(), request); !errors.Is(err, ErrUnavailable) {
				t.Fatal("login was not closed", err)
			}
			if tx.attemptSequence != before || len(tx.sessions) != 1 {
				t.Fatal("failed custody spent a guess or issued another session")
			}
			if _, err := candidate.authenticateSession(t.Context(), tx, login.Credential, tx.now); !errors.Is(err, ErrUnavailable) {
				t.Fatal("existing bearer bypassed custody", err)
			}
			if _, err := candidate.authenticateRoleSession(t.Context(), tx, login.Credential, tx.now); !errors.Is(err, ErrUnavailable) {
				t.Fatal("role authentication bypassed custody", err)
			}
		})
	}
	tx.totpCustody, tx.totpCustodyErr = &baseline, nil
	if _, err := service.authenticateSession(t.Context(), tx, login.Credential, tx.now); err != nil {
		t.Fatal("valid custody rejected existing bearer", err)
	}
}

func (probe passwordEntropyProbe) Read(value []byte) (int, error) {
	if probe.repository.inTransaction {
		probe.testing.Fatal("expensive new-password hashing held a transaction")
	}
	for i := range value {
		value[i] = byte(i + 17)
	}
	return len(value), nil
}

func TestPasswordAttemptsCommitBeforeVerificationAndNeverReuseAStaleResult(t *testing.T) {
	tx := newCoreTransaction()
	repository := &coreRepository{transaction: tx}
	service, err := newCoreAuthority(repository, Config{})
	if err != nil {
		t.Fatal(err)
	}
	document := coreBootstrap(t)
	if _, err := service.Bootstrap(t.Context(), document); err != nil {
		t.Fatal(err)
	}
	loginRequest := iamv1.LoginRequest{LoginName: "admin", Password: document.Administrator.Password, RequestID: "same-public-id"}
	wrong := loginRequest
	wrong.Password = coreSecret(t, "Wrong-Candidate-Password-86!")
	for range 2 {
		if _, err := service.Login(t.Context(), wrong); !errors.Is(err, ErrUnauthenticated) {
			t.Fatal("wrong candidate", err)
		}
	}
	if len(tx.rejectedAttempts) != 2 || tx.rejectedAttempts[0] == tx.rejectedAttempts[1] || len(tx.sessions) != 0 {
		t.Fatal("caller request identity reused a guess or rejection issued a Session")
	}
	// A reservation commit can be unknown. It cannot be treated as admission,
	// and no expensive verifier/final issuing transaction may follow it.
	commits := 0
	repository.afterTransaction = func(err error) error {
		commits++
		if err != nil {
			t.Fatal(err)
		}
		return ErrUnavailable
	}
	if _, err := service.Login(t.Context(), loginRequest); !errors.Is(err, ErrUnavailable) || commits != 1 || len(tx.sessions) != 0 {
		t.Fatal("unknown reservation commit was accepted", err)
	}
	repository.afterTransaction = nil
	current, err := service.Login(t.Context(), loginRequest)
	if err != nil {
		t.Fatal(err)
	}
	service.passwords = authority.NewPasswordHasher(passwordEntropyProbe{t, repository})
	if _, err := service.ChangePassword(t.Context(), current.Credential, iamv1.ChangePasswordRequest{
		CurrentPassword: document.Administrator.Password, NewPassword: coreSecret(t, "After-Reservation-Password-46!"), RequestID: "outside-lock"}); err != nil {
		t.Fatal(err)
	}
	// Moving the slow verifier out must not preserve a once-correct result after
	// a concurrent mutation. The actual SQL generation/status races are PG gates.
	loginRequest.Password = coreSecret(t, "After-Reservation-Password-46!")
	repository.afterTransaction = func(err error) error {
		if len(tx.passwordAttempts) > 0 {
			tx.passwords[tx.principal.ID] = dummyPasswordHash
		}
		return err
	}
	before := len(tx.sessions)
	if _, err := service.Login(t.Context(), loginRequest); !errors.Is(err, ErrUnauthenticated) || len(tx.sessions) != before {
		t.Fatal("stale computed password result issued a Session", err)
	}
}

func TestPasswordWorkHasNoQueueAndPrivateAttemptsCannotSerialize(t *testing.T) {
	service, err := newCoreAuthority(&coreRepository{transaction: newCoreTransaction()}, Config{})
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := service.acquirePasswordWork(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	if err := service.acquirePasswordWork(t.Context()); !errors.Is(err, ErrOverloaded) {
		t.Fatal("unbounded crypto work", err)
	}
	service.releasePasswordWork()
	if err := service.acquirePasswordWork(t.Context()); err != nil {
		t.Fatal("slot was not released", err)
	}
	service.releasePasswordWork()
	service.releasePasswordWork()
	attempt := PasswordAttempt{PasswordHash: authority.PasswordHash("private-verifier")}
	if encoded, err := json.Marshal(attempt); err == nil || strings.Contains(string(encoded), "private-verifier") || strings.Contains(fmt.Sprintf("%+v %#v", attempt, attempt), "private-verifier") {
		t.Fatal("private attempt exposed the verifier")
	}
}

func TestOwnLoginSessionWorkflowBindsTheActualCallerAndRejectsBadStorage(t *testing.T) {
	tx := newCoreTransaction()
	service, err := newCoreAuthority(&coreRepository{transaction: tx}, Config{CursorKey: bytes.Repeat([]byte{0x31}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	bootstrap := coreBootstrap(t)
	if _, err := service.Bootstrap(t.Context(), bootstrap); err != nil {
		t.Fatal(err)
	}
	login := func() iamv1.LoginResponse {
		t.Helper()
		result, err := service.Login(t.Context(), iamv1.LoginRequest{LoginName: "admin", Password: bootstrap.Administrator.Password, RequestID: "own-login"})
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	a, b := login(), login()
	// Neither ordinary grants nor clearing forced-change is necessary for this
	// possession-bound reduction. SQL concurrency/history is proved in PG18.
	tx.attachments = map[iamv1.PolicyAttachmentID]iamv1.PolicyAttachment{}
	page, err := service.ListOwnSessions(t.Context(), a.Credential, "")
	if err != nil || iamv1.ValidateSessionList(page) != nil || len(page.Items) != 2 || page.CurrentSessionID != a.Session.ID ||
		page.UserID != a.Session.PrincipalID || !page.ObservedAt.Equal(tx.now) || len(tx.authorizations) != 0 {
		t.Fatal("self directory invented management authority or a caller", err)
	}
	if _, err := service.RevokeOwnSession(t.Context(), a.Credential, a.Session.ID, iamv1.RevokeSessionRequest{RequestID: "own-current"}); !errors.Is(err, ErrConflict) || tx.sessionRevocation != nil {
		t.Fatal("current session bypassed logout", err)
	}
	for _, purpose := range []authority.CredentialType{authority.CredentialService, authority.CredentialRoleSession} {
		wrong, err := authority.NewCredentialIssuer(nil).Issue(purpose, "own-other-carrier")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := service.ListOwnSessions(t.Context(), wrong.Credential, ""); !errors.Is(err, ErrUnauthenticated) {
			t.Fatal("non-login directory", err)
		}
		if _, err := service.RevokeOwnSession(t.Context(), wrong.Credential, b.Session.ID, iamv1.RevokeSessionRequest{RequestID: "own-wrong"}); !errors.Is(err, ErrUnauthenticated) || tx.sessionRevocation != nil {
			t.Fatal("non-login revocation", err)
		}
	}
	for _, variant := range []string{"null", "cross-account", "cross-user", "duplicate", "expired", "lookahead"} {
		t.Run(variant, func(t *testing.T) {
			items := []iamv1.Session{a.Session}
			switch variant {
			case "null":
				items = nil
			case "cross-account":
				items[0].AccountID = "unrelated-account"
			case "cross-user":
				items[0].PrincipalID = "unrelated-user"
			case "duplicate":
				items = append(items, items[0])
			case "expired":
				items[0].ExpiresAt = tx.now
			case "lookahead":
				items = make([]iamv1.Session, 101)
				for i := range items {
					items[i] = a.Session
					items[i].ID = iamv1.SessionID(fmt.Sprintf("own-%03d", i))
				}
				items[100].PrincipalID = "unrelated-lookahead"
			}
			tx.ownSessionItems = &items
			defer func() { tx.ownSessionItems = nil }()
			if _, err := service.ListOwnSessions(t.Context(), a.Credential, ""); !errors.Is(err, ErrUnavailable) {
				t.Fatal("untrusted storage became a public page", err)
			}
		})
	}
	request := iamv1.RevokeSessionRequest{RequestID: "own-revoke"}
	result, err := service.RevokeOwnSession(t.Context(), a.Credential, b.Session.ID, request)
	if err != nil || result.Outcome != "APPLIED" || result.Revocation.ID != string(b.Session.ID) || tx.sessionRevocation == nil || len(tx.authorizations) != 0 {
		t.Fatal("self reduction required or created a business permit", err)
	}
	mutation := *tx.sessionRevocation
	if mutation.AccountID != a.Session.AccountID || mutation.ActorPrincipalID != a.Session.PrincipalID || mutation.ActorSessionID != a.Session.ID || mutation.SessionID != b.Session.ID ||
		mutation.DecisionID != "" || mutation.AuditEvent.IAMDecisionID != "" || mutation.AuditEvent.Actor.Type != auditv1.ActorUser ||
		mutation.AuditEvent.Actor.ID != auditv1.ActorID(a.Session.PrincipalID) || mutation.AuditEvent.Target.ID != string(b.Session.ID) ||
		mutation.AuditEvent.RequestID != request.RequestID || auditv1.ValidateEventForSource(auditv1.SourceIAM, mutation.AuditEvent) != nil {
		t.Fatal("self reduction lost actual caller/target or fabricated an audit decision")
	}
	if _, err := service.ListOwnSessions(t.Context(), b.Credential, ""); !errors.Is(err, ErrUnauthenticated) {
		t.Fatal("ended caller reached directory", err)
	}
}

func TestOtherSessionWorkflowRequiresActualCallerAndExactCompletion(t *testing.T) {
	tx := newCoreTransaction()
	service, err := newCoreAuthority(&coreRepository{transaction: tx}, Config{})
	if err != nil {
		t.Fatal(err)
	}
	bootstrap := coreBootstrap(t)
	if _, err := service.Bootstrap(t.Context(), bootstrap); err != nil {
		t.Fatal(err)
	}
	login, err := service.Login(t.Context(), iamv1.LoginRequest{LoginName: "admin", Password: bootstrap.Administrator.Password, RequestID: "other-login"})
	if err != nil {
		t.Fatal(err)
	}
	tx.attachments = map[iamv1.PolicyAttachmentID]iamv1.PolicyAttachment{}
	request := iamv1.RevokeSessionRequest{RequestID: "other-revoke"}
	valid := iamv1.RevokeOtherSessionsResponse{APIVersion: iamv1.APIVersion, Kind: "OtherSessionsRevocation", Outcome: "APPLIED",
		AccountID: login.Session.AccountID, UserID: login.Session.PrincipalID, CurrentSessionID: login.Session.ID,
		RequestID: request.RequestID, RevokedCount: 0, CompletedAt: tx.now}
	tx.otherSessionResult = valid
	result, err := service.RevokeOtherSessions(t.Context(), login.Credential, request)
	if err != nil || result != valid || tx.otherSessionRevocation == nil || len(tx.authorizations) != 0 {
		t.Fatal("forced-change self reduction invented management authority", err)
	}
	mutation := *tx.otherSessionRevocation
	if mutation.AccountID != valid.AccountID || mutation.UserID != valid.UserID || mutation.ActorSessionID != valid.CurrentSessionID ||
		mutation.AuditEvent.Action != auditv1.ActionIAMOtherSessionsRevoked || mutation.AuditEvent.Target.ID != string(valid.UserID) ||
		mutation.AuditEvent.Actor.ID != auditv1.ActorID(valid.UserID) || mutation.AuditEvent.IAMDecisionID != "" ||
		mutation.AuditEvent.RequestID != request.RequestID || auditv1.ValidateEventForSource(auditv1.SourceIAM, mutation.AuditEvent) != nil {
		t.Fatal("other session intent lost its actual owner")
	}
	for _, mutate := range []func(*iamv1.RevokeOtherSessionsResponse){
		func(v *iamv1.RevokeOtherSessionsResponse) { v.AccountID = "foreign" },
		func(v *iamv1.RevokeOtherSessionsResponse) { v.UserID = "foreign" },
		func(v *iamv1.RevokeOtherSessionsResponse) { v.CurrentSessionID = "foreign" },
		func(v *iamv1.RevokeOtherSessionsResponse) { v.RequestID = "foreign" },
		func(v *iamv1.RevokeOtherSessionsResponse) { v.CompletedAt = v.CompletedAt.Add(time.Microsecond) },
		func(v *iamv1.RevokeOtherSessionsResponse) { v.CompletedAt = v.CompletedAt.Add(-time.Microsecond) },
		func(v *iamv1.RevokeOtherSessionsResponse) { v.Outcome = "UNKNOWN" },
	} {
		tx.otherSessionResult = valid
		mutate(&tx.otherSessionResult)
		if _, err := service.RevokeOtherSessions(t.Context(), login.Credential, request); !errors.Is(err, ErrUnavailable) {
			t.Fatal("invalid storage completion escaped", err)
		}
	}
	tx.otherSessionResult = valid
	tx.otherSessionResult.Outcome = "EQUAL_REPLAY"
	tx.otherSessionResult.CompletedAt = tx.now.Add(-time.Second)
	if _, err := service.RevokeOtherSessions(t.Context(), login.Credential, request); err != nil {
		t.Fatal(err)
	}
	for _, purpose := range []authority.CredentialType{authority.CredentialService, authority.CredentialRoleSession} {
		wrong, err := authority.NewCredentialIssuer(nil).Issue(purpose, "wrong-carrier")
		if err != nil {
			t.Fatal(err)
		}
		tx.otherSessionRevocation = nil
		if _, err := service.RevokeOtherSessions(t.Context(), wrong.Credential, request); !errors.Is(err, ErrUnauthenticated) || tx.otherSessionRevocation != nil {
			t.Fatal("non-login carrier reached reduction", err)
		}
	}
	tx.otherSessionError = ErrConflict
	if _, err := service.RevokeOtherSessions(t.Context(), login.Credential, request); !errors.Is(err, ErrConflict) {
		t.Fatal(err)
	}
	tx.otherSessionRevocation = nil
	if _, err := service.RevokeOtherSessions(t.Context(), login.Credential, iamv1.RevokeSessionRequest{}); !errors.Is(err, ErrInvalidArgument) || tx.otherSessionRevocation != nil {
		t.Fatal("bad intent reached storage", err)
	}
}

func TestRoleSelfExitUsesOnlyExactCredentialPossession(t *testing.T) {
	tx := newCoreTransaction()
	service, err := newCoreAuthority(&coreRepository{transaction: tx}, Config{})
	if err != nil {
		t.Fatal(err)
	}
	issued, err := authority.NewCredentialIssuer(nil).Issue(authority.CredentialRoleSession, "exit-session")
	if err != nil {
		t.Fatal(err)
	}
	// Expired by construction, with no USER/login/PDP context in this adapter.
	// Possession is deliberately not a business authentication substitute.
	session := iamv1.RoleSession{APIVersion: iamv1.APIVersion, Kind: "RoleSession", ID: "exit-session", AccountID: "exit-account",
		RoleID: "exit-role", SourceUserID: "exit-source", Status: iamv1.SessionActive, IssuedAt: tx.now.Add(-2 * time.Hour), ExpiresAt: tx.now.Add(-time.Hour)}
	tx.roleExitCredentials = map[string]RoleSessionExitCredential{issued.LookupDigest: {Session: session, VerificationDigest: issued.VerificationDigest}}
	result, err := service.LogoutRoleSession(t.Context(), issued.Credential, iamv1.LogoutRequest{RequestID: "exit-intent"})
	if err != nil || result.Status != iamv1.SessionRevoked || len(tx.roleExitEvents) != 1 || len(tx.authorizations) != 0 || len(tx.sessions) != 0 {
		t.Fatal("self-exit required current business authority or issued a login", err)
	}
	fact := tx.roleExitEvents[0]
	if auditv1.ValidateEventForSource(auditv1.SourceIAM, fact) != nil || fact.Action != auditv1.ActionIAMRoleSessionExited || fact.IAMDecisionID != "" ||
		fact.Actor.Type != auditv1.ActorRole || fact.Actor.ID != auditv1.ActorID(session.RoleID) || fact.Actor.RoleSession == nil ||
		fact.Actor.RoleSession.SessionID != string(session.ID) || fact.Actor.RoleSession.SourceUserID != auditv1.ActorID(session.SourceUserID) || fact.Target.ID != string(session.ID) {
		t.Fatal("self-exit lost immutable actor/session linkage")
	}
	for _, purpose := range []authority.CredentialType{authority.CredentialSession, authority.CredentialService} {
		other, err := authority.NewCredentialIssuer(nil).Issue(purpose, string(session.ID))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := service.LogoutRoleSession(t.Context(), other.Credential, iamv1.LogoutRequest{RequestID: "exit-wrong-purpose"}); !errors.Is(err, ErrUnauthenticated) {
			t.Fatal("non-role credential reached self-exit", err)
		}
	}
	tx.roleExitCredentials[issued.LookupDigest] = RoleSessionExitCredential{Session: session, VerificationDigest: "sha256:" + strings.Repeat("0", 64)}
	if _, err := service.LogoutRoleSession(t.Context(), issued.Credential, iamv1.LogoutRequest{RequestID: "exit-wrong-proof"}); !errors.Is(err, ErrUnauthenticated) || len(tx.roleExitEvents) != 1 {
		t.Fatal("lookup alone proved possession", err)
	}
}

func TestAuthorizationProfileDiscoveryRequiresCurrentAuthorityAndNoPermitCache(t *testing.T) {
	tx := newCoreTransaction()
	service, err := newCoreAuthority(&coreRepository{transaction: tx}, Config{})
	if err != nil {
		t.Fatal(err)
	}
	bootstrap := coreBootstrap(t)
	if _, err := service.Bootstrap(t.Context(), bootstrap); err != nil {
		t.Fatal(err)
	}
	login, err := service.Login(t.Context(), iamv1.LoginRequest{LoginName: "admin", Password: bootstrap.Administrator.Password, RequestID: "catalog-login"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.ListAuthorizationProfiles(t.Context(), login.Credential, "catalog-forced"); !errors.Is(err, ErrForbidden) {
		t.Fatal("temporary forced-change session obtained product metadata")
	}
	if _, err := service.ChangePassword(t.Context(), login.Credential, iamv1.ChangePasswordRequest{CurrentPassword: bootstrap.Administrator.Password, NewPassword: coreSecret(t, "Catalog-Changed-Password-57!"), RequestID: "catalog-change"}); err != nil {
		t.Fatal(err)
	}
	result, err := service.ListAuthorizationProfiles(t.Context(), login.Credential, "catalog-allowed")
	if err != nil || iamv1.ValidateAuthorizationProfileList(result) != nil || result.AccountID != bootstrap.Organization.ID || len(result.Items) != len(iamv1.AllAuthorizationProfiles()) {
		t.Fatalf("authenticated complete directory failed: %v", err)
	}
	last := tx.authorizations[len(tx.authorizations)-1]
	if last.Decision.Action != iamv1.ActionIAMPolicyList || last.Decision.Resource.Kind != iamv1.ResourceAccount || last.Decision.Resource.ID != string(result.AccountID) || last.Decision.ResourceMode != iamv1.AuthorizationResourceInstance || last.AuditEvent.Action != auditv1.ActionIAMAuthorizationDecided {
		t.Fatal("discovery substituted an installation scope or invented catalog authority")
	}
	result.Items[0].Profile.Actions[0].ResourceKind = "MUTATED"
	fresh, err := service.ListAuthorizationProfiles(t.Context(), login.Credential, "catalog-fresh")
	if err != nil || fresh.Items[0].Profile.Actions[0].ResourceKind == "MUTATED" {
		t.Fatal("caller mutated source profile")
	}
	before := len(tx.authorizations)
	tx.profileErr = ErrUnavailable
	if _, err := service.ListAuthorizationProfiles(t.Context(), login.Credential, "catalog-drift"); !errors.Is(err, ErrUnavailable) || len(tx.authorizations) != before {
		t.Fatal("discovery bypassed registry verification or recorded an ordinary decision for drift")
	}
	tx.profileErr = nil
	if _, err := service.ListAuthorizationProfiles(t.Context(), coreServiceCredential(t, bootstrap, iamv1.ServicePaaS), "catalog-service"); !errors.Is(err, ErrUnauthenticated) {
		t.Fatal("service credential substituted for a user")
	}
	if _, err := service.Logout(t.Context(), login.Credential, iamv1.LogoutRequest{RequestID: "catalog-logout"}); err != nil {
		t.Fatal(err)
	}
	if _, err := service.ListAuthorizationProfiles(t.Context(), login.Credential, "catalog-revoked"); !errors.Is(err, ErrUnauthenticated) {
		t.Fatal("revoked session reused catalog access")
	}
}

func TestTransactionRetryYieldsToContendingCommit(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		service, err := newCoreAuthority(&coreRepository{transaction: newCoreTransaction()}, Config{})
		if err != nil {
			t.Fatal(err)
		}
		started := time.Now()
		// A concurrent commit is not yet visible. Each whole-transaction retry
		// must obtain a fresh observation, eventually discovering the conflict.
		attempts := 0
		err = service.withinTransaction(t.Context(), func(context.Context, Transaction) error {
			attempts++
			if time.Since(started) < 120*time.Millisecond {
				return fmt.Errorf("serialization: %w", ErrRetryableTransaction)
			}
			return ErrConflict
		})
		if !errors.Is(err, ErrConflict) || attempts > defaultMaxTransactionAttempts {
			t.Fatalf("contending commit was not reobserved within budget: attempts=%d err=%v", attempts, err)
		}
		if elapsed := time.Since(started); elapsed < 120*time.Millisecond || elapsed > 550*time.Millisecond {
			t.Fatalf("retry wait outside bounded contention budget: %s", elapsed)
		}
	})
}

func TestTransactionRetryCancellationAndTerminalResults(t *testing.T) {
	for _, terminal := range []error{nil, ErrConflict, ErrForbidden, ErrUnavailable} {
		t.Run(fmt.Sprint(terminal), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				service, err := newCoreAuthority(&coreRepository{transaction: newCoreTransaction()}, Config{})
				if err != nil {
					t.Fatal(err)
				}
				started, attempts := time.Now(), 0
				err = service.withinTransaction(t.Context(), func(context.Context, Transaction) error { attempts++; return terminal })
				if !errors.Is(err, terminal) || attempts != 1 || time.Since(started) != 0 {
					t.Fatalf("terminal result retried or delayed: attempts=%d err=%v", attempts, err)
				}
			})
		})
	}
	t.Run("cancel during backoff", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			service, err := newCoreAuthority(&coreRepository{transaction: newCoreTransaction()}, Config{})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), time.Millisecond)
			defer cancel()
			started, attempts := time.Now(), 0
			err = service.withinTransaction(ctx, func(context.Context, Transaction) error { attempts++; return ErrRetryableTransaction })
			if !errors.Is(err, context.DeadlineExceeded) || attempts != 1 || time.Since(started) != time.Millisecond {
				t.Fatalf("cancellation failed to bound retry: attempts=%d err=%v", attempts, err)
			}
		})
	})
	for _, limit := range []int{1, defaultMaxTransactionAttempts, 10} {
		t.Run(fmt.Sprintf("exhaustion-%d", limit), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				service, err := newCoreAuthority(&coreRepository{transaction: newCoreTransaction()}, Config{MaxTransactionAttempts: limit})
				if err != nil {
					t.Fatal(err)
				}
				started, attempts := time.Now(), 0
				err = service.withinTransaction(t.Context(), func(context.Context, Transaction) error { attempts++; return ErrRetryableTransaction })
				if !errors.Is(err, ErrRetryableTransaction) || errors.Is(err, ErrConflict) || attempts != limit {
					t.Fatalf("exhaustion substituted a business outcome: attempts=%d err=%v", attempts, err)
				}
				elapsed := time.Since(started)
				if limit == 1 && elapsed != 0 || elapsed > time.Duration(limit-1)*200*time.Millisecond {
					t.Fatalf("exhausted transaction waited beyond budget: %s", elapsed)
				}
			})
		})
	}
}

func TestLocalRecoveryWorkflowBindsOnePrivateIntentToOneSanitizedFact(t *testing.T) {
	secret := func(value string) iamv1.Secret {
		result, err := iamv1.NewSecret(value)
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	local := iamv1.LocalCredentialRecoveryAuthority{APIVersion: iamv1.APIVersion, Kind: "LocalCredentialRecoveryAuthority", Purpose: iamv1.LocalCredentialRecoveryPurpose,
		Scope:         iamv1.LocalCredentialRecoveryScope{InstallationID: "installation-local", BootstrapDigest: "sha256:" + strings.Repeat("b", 64), AccountID: "organization-local", PrincipalID: "principal-original"},
		CapabilityKey: secret(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x47}, 32)))}
	request, err := iamv1.SignLocalCredentialRecoveryRequest(local, iamv1.LocalCredentialRecoveryRequest{APIVersion: iamv1.APIVersion, Kind: "LocalCredentialRecoveryRequest", Purpose: iamv1.LocalCredentialRecoveryPurpose,
		Scope: local.Scope, CommandID: "command-local", Expected: iamv1.LocalCredentialRecoveryExpected{OrganizationResourceVersion: 1, PrincipalResourceVersion: 2, CredentialGeneration: 3, PlatformBindingID: "binding-original", PlatformBindingResourceVersion: 4},
		NewPassword: secret("Unit-Local-Private-Password-67!")})
	if err != nil {
		t.Fatal(err)
	}
	commitment, err := iamv1.VerifyLocalCredentialRecoveryRequest(local, request)
	if err != nil {
		t.Fatal(err)
	}
	repository := &coreRepository{transaction: newCoreTransaction()}
	transaction := repository.transaction
	completed := iamv1.LocalCredentialRecoveryResult{APIVersion: iamv1.APIVersion, Kind: "LocalCredentialRecoveryResult", State: "APPLIED", Scope: local.Scope,
		CommandID: request.CommandID, InputCommitment: commitment, PreviousCredentialGeneration: 3, CredentialGeneration: 4, PrincipalResourceVersion: 3,
		RevokedSessions: 2, AuditEventID: "event-local", CompletedAt: transaction.now}
	transaction.localRecoveryResult = completed
	service, err := newCoreAuthority(repository, Config{NewID: func(string) (string, error) { return "event-local", nil }})
	if err != nil {
		t.Fatal(err)
	}
	result, err := service.RecoverLocalCredentials(context.Background(), local, request)
	if err != nil || result != completed || transaction.localRecoveryMutation == nil {
		t.Fatalf("local workflow rejected its exact result: %v", err)
	}
	mutation := *transaction.localRecoveryMutation
	if mutation.Scope != local.Scope || mutation.Expected != request.Expected || mutation.InputCommitment != commitment || mutation.CommandID != request.CommandID {
		t.Fatal("local mutation substituted its authority or expected intent")
	}
	if matched, err := authority.NewPasswordHasher(nil).Verify(request.NewPassword, mutation.PasswordHash); err != nil || !matched {
		t.Fatal("local workflow did not use the established password hash profile")
	}
	event := mutation.AuditEvent
	if auditv1.ValidateEventForSource(auditv1.SourceIAM, event) != nil || event.Action != auditv1.ActionIAMInstallationPrimaryCredentialsRecovered ||
		event.Actor != (auditv1.ActorReference{Type: auditv1.ActorSystem, ID: iamv1.LocalCredentialRecoveryActor}) || event.InstallationID != local.Scope.InstallationID || event.TenantID != "" ||
		event.Target.ID != string(local.Scope.PrincipalID) || event.Target.TenantID != auditv1.TenantID(local.Scope.AccountID) || event.RequestID != request.CommandID || event.CorrelationID != request.CommandID || event.OccurredAt != transaction.now || event.IAMDecisionID != "" {
		t.Fatal("local workflow broadened or fabricated security authority")
	}
	encoded, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	for _, private := range []string{string(request.NewPassword.CopyBytes()), string(request.Capability.CopyBytes()), string(local.CapabilityKey.CopyBytes()), string(mutation.PasswordHash)} {
		if bytes.Contains(encoded, []byte(private)) {
			t.Fatal("local security fact contains private recovery material")
		}
	}
	transaction.localRecoveryMutation = nil
	forged := request
	forged.Expected.CredentialGeneration++
	if _, err := service.RecoverLocalCredentials(context.Background(), local, forged); !errors.Is(err, ErrForbidden) || transaction.localRecoveryMutation != nil {
		t.Fatal("unproved recovery intent reached the transaction")
	}
	transaction.localRecoveryResult.Scope.PrincipalID = "principal-substituted"
	if _, err := service.RecoverLocalCredentials(context.Background(), local, request); !errors.Is(err, ErrUnavailable) {
		t.Fatal("workflow accepted a substituted completion")
	}
	transaction.localRecoveryInspection = iamv1.LocalCredentialRecoveryInspection{APIVersion: iamv1.APIVersion, Kind: "LocalCredentialRecoveryInspection", Scope: local.Scope, State: "ELIGIBLE", Expected: &request.Expected}
	if _, err := service.InspectLocalCredentialRecovery(context.Background(), local, nil); err != nil {
		t.Fatal(err)
	}
	transaction.localRecoveryInspection.Scope.AccountID = "organization-substituted"
	if _, err := service.InspectLocalCredentialRecovery(context.Background(), local, nil); !errors.Is(err, ErrUnavailable) {
		t.Fatal("inspection returned another tenant's authority")
	}
}

func TestAuditProofClosedHistoricalMappings(t *testing.T) {
	for _, mapping := range []struct {
		event    auditv1.Action
		action   iamv1.Action
		resource string
	}{
		{auditv1.ActionPaaSApplicationCreated, iamv1.ActionPaaSApplicationCreate, "collection"},
		{auditv1.ActionPaaSConfigurationCreated, iamv1.ActionPaaSConfigurationCreate, "collection"},
		{auditv1.ActionPaaSConfigurationRevisionCreated, iamv1.ActionPaaSConfigurationRevisionCreate, "collection"},
		{auditv1.ActionPaaSApplicationRevisionCreated, iamv1.ActionPaaSApplicationRevisionCreate, "collection"},
		{auditv1.ActionPaaSDeploymentCreated, iamv1.ActionPaaSDeploymentCreate, "collection"},
		{auditv1.ActionPaaSDeploymentUpdated, iamv1.ActionPaaSDeploymentUpdate, "resource-proof"},
		{auditv1.ActionPaaSDeploymentStopped, iamv1.ActionPaaSDeploymentStop, "resource-proof"},
		{auditv1.ActionPaaSDeploymentRolledBack, iamv1.ActionPaaSDeploymentRollback, "resource-proof"},
		{auditv1.ActionPaaSExecutionPoolCreated, iamv1.ActionPaaSExecutionPoolCreate, "resource-proof"},
		{auditv1.ActionPaaSExecutionTargetRegistered, iamv1.ActionPaaSExecutionTargetRegister, "resource-proof"},
		{auditv1.ActionPaaSExecutionTargetRegistered, iamv1.ActionPaaSNodeEnrollmentCreate, "collection"},
		{auditv1.ActionPaaSExecutionTargetDrained, iamv1.ActionPaaSExecutionTargetDrain, "resource-proof"},
		{auditv1.ActionPaaSExecutionTargetActivated, iamv1.ActionPaaSExecutionTargetActivate, "resource-proof"},
		{auditv1.ActionPaaSExecutionTargetRemoved, iamv1.ActionPaaSExecutionTargetRemove, "resource-proof"},
		{auditv1.ActionManagedServiceQuotaEntitlementActivated, iamv1.ActionManagedServiceQuotaEntitlementActivate, "collection"},
		{auditv1.ActionManagedServiceInstallationCreated, iamv1.ActionManagedServiceInstallationCreate, "collection"},
		{auditv1.ActionManagedServiceInstallationReady, iamv1.ActionManagedServiceInstallationCreate, "collection"},
		{auditv1.ActionAuditRecordsRead, iamv1.ActionAuditRecordRead, "records"},
		{auditv1.ActionAuditIntegrityVerified, iamv1.ActionAuditIntegrityVerify, "chain"},
		{auditv1.ActionAuditPlatformRecordsRead, iamv1.ActionAuditPlatformRecordRead, "records"},
		{auditv1.ActionAuditPlatformIntegrityVerified, iamv1.ActionAuditPlatformIntegrityVerify, "chain"},
	} {
		t.Run(string(mapping.event), func(t *testing.T) {
			identity, event, evidence := historicalAuditFixture(mapping.event, mapping.action, mapping.resource)
			_, expected, err := auditv1.CanonicalizeEvent(mustAuditSource(t, mapping.event), event)
			got, proofErr := auditContentDigest(identity, event, evidence)
			if err != nil || proofErr != nil || got != expected {
				t.Fatalf("valid historical proof rejected: %v/%v", err, proofErr)
			}
			unmarked := evidence
			unmarked.DecisionContractVersion = 0
			if _, err := auditContentDigest(identity, event, unmarked); !errors.Is(err, ErrForbidden) {
				t.Fatal("missing fields alone granted legacy eligibility")
			}
			// Exercise the same immutable business fact with a separately stored v2
			// decision and exact frozen declaration, including a noncurrent revision.
			current := evidence
			decision := *evidence.Decision
			current.Decision = &decision
			current.DecisionContractVersion = 2
			action, id, mode, usage := auditDecisionTarget(event, decision.Action, 2)
			request := coreAuthorizationRequest(t, iamv1.AuthorizationRequest{Action: action,
				Resource:  iamv1.ResourceReference{Kind: decision.Resource.Kind, ID: id},
				RequestID: event.RequestID, CorrelationID: event.CorrelationID}, mode, usage)
			profile, found := iamv1.LookupAuthorizationProfile(request.Profile.Product)
			if !found {
				t.Fatal("missing fixture profile")
			}
			profile.Revision += 10 // Pure archived fixture, never registered or made current.
			_, digest, err := iamv1.CanonicalizeAuthorizationProfile(profile)
			if err != nil {
				t.Fatal(err)
			}
			request.Profile.Revision, request.Profile.ContentDigest = profile.Revision, digest
			current.DecisionProfile = &profile
			decision.Profile, decision.Resource = &request.Profile, request.Resource
			decision.ResourceMode, decision.CollectionUsage, decision.CorrelationID = mode, usage, request.CorrelationID
			if got, err := auditContentDigest(identity, event, current); err != nil || got != expected {
				t.Fatalf("frozen v2 proof borrowed current head or changed fact: %v", err)
			}
			if contract, _ := auditv1.ContractForAction(event.Action); contract.AccessKeyActorPermitted {
				keyProfile, _ := iamv1.LookupAuthorizationProfile(profile.Product)
				keyProfile.Revision = profile.Revision
				for index := range keyProfile.Actions {
					if keyProfile.Actions[index].Action == decision.Action {
						keyProfile.Actions[index].UserAuthenticationMethods = []iamv1.UserAuthenticationMethod{iamv1.UserAuthenticationLoginSession, iamv1.UserAuthenticationAccessKey}
					}
				}
				_, keyDigest, err := iamv1.CanonicalizeAuthorizationProfile(keyProfile)
				if err != nil {
					t.Fatal(err)
				}
				keyDecision := decision
				keyDecision.Subject = &iamv1.Subject{Type: iamv1.SubjectUser, ID: decision.Subject.ID, AccessKeyID: "key-forged-history"}
				keyDecision.Profile = &iamv1.AuthorizationProfileReference{Product: keyProfile.Product, Revision: keyProfile.Revision, ContentDigest: keyDigest}
				if iamv1.ValidateAuthorizationDecisionForProfile(keyDecision, keyProfile) != nil {
					t.Fatal("key history attack must have a self-consistent public declaration")
				}
				for _, contractVersion := range []int{2, 3} {
					forged := current
					forged.Decision, forged.DecisionProfile, forged.DecisionContractVersion = &keyDecision, &keyProfile, contractVersion
					if validHistoricalDecision(forged) {
						t.Fatal("pre-key protected contract acquired a credential lineage")
					}
				}
				keyEvidence := current
				keyEvidence.Decision, keyEvidence.DecisionProfile, keyEvidence.DecisionContractVersion = &keyDecision, &keyProfile, 4
				keyEvent := event
				keyEvent.Actor.AccessKeyID = string(keyDecision.Subject.AccessKeyID)
				keyEvidence.Event.Actor = keyEvent.Actor
				_, expectedKeyDigest, err := auditv1.CanonicalizeEvent(mustAuditSource(t, mapping.event), keyEvent)
				if digest, proofErr := auditContentDigest(identity, keyEvent, keyEvidence); err != nil || proofErr != nil || digest != expectedKeyDigest {
					t.Fatal("contract4 key attribution or archived carrier rejected", err, proofErr)
				}
				keyEvent.Actor.AccessKeyID = "another-key"
				if _, err := auditContentDigest(identity, keyEvent, keyEvidence); !errors.Is(err, ErrForbidden) {
					t.Fatal("key substitution borrowed historical authority")
				}
			}
			// Exact archive validation must also govern producer admission: a
			// coherent frozen declaration with a different caller cannot borrow
			// the current catalog's permission for this producer.
			wrongProducerProfile := profile
			wrongProducerProfile.CallingService = iamv1.ServiceIAM
			_, wrongProducerDigest, err := iamv1.CanonicalizeAuthorizationProfile(wrongProducerProfile)
			if err != nil {
				t.Fatal(err)
			}
			wrongProducerEvidence, wrongProducerDecision := current, *current.Decision
			wrongProducerReference := *current.Decision.Profile
			wrongProducerReference.ContentDigest = wrongProducerDigest
			wrongProducerDecision.Profile = &wrongProducerReference
			wrongProducerEvidence.Decision, wrongProducerEvidence.DecisionProfile = &wrongProducerDecision, &wrongProducerProfile
			if _, err := auditContentDigest(identity, event, wrongProducerEvidence); !errors.Is(err, ErrForbidden) {
				t.Fatal("historical producer borrowed current calling-service authority")
			}
			for name, mutate := range map[string]func(*AuditEvidence){
				"version absent":      func(e *AuditEvidence) { e.DecisionContractVersion = 0 },
				"version unknown":     func(e *AuditEvidence) { e.DecisionContractVersion = 5 },
				"downgrade to legacy": func(e *AuditEvidence) { e.DecisionContractVersion = 1 },
				"archive absent":      func(e *AuditEvidence) { e.DecisionProfile = nil },
				"profile absent":      func(e *AuditEvidence) { e.Decision.Profile = nil },
				"request correlation": func(e *AuditEvidence) { e.Decision.CorrelationID = "another-correlation" },
				"mode absent":         func(e *AuditEvidence) { e.Decision.ResourceMode = "" },
			} {
				t.Run("v2/"+name, func(t *testing.T) {
					changed := current
					copyDecision := *current.Decision
					changed.Decision = &copyDecision
					mutate(&changed)
					if _, err := auditContentDigest(identity, event, changed); !errors.Is(err, ErrForbidden) {
						t.Fatal("inconsistent protected contract accepted")
					}
				})
			}
			for name, attack := range map[string]func(*iamv1.ServiceIdentity, *auditv1.Event, *AuditEvidence){
				"producer purpose": func(i *iamv1.ServiceIdentity, e *auditv1.Event, a *AuditEvidence) {
					i.Purpose = iamv1.ServiceInstallationVerifier
				},
				"producer installation": func(i *iamv1.ServiceIdentity, e *auditv1.Event, a *AuditEvidence) {
					i.InstallationID = "installation-other"
				},
				"historical installation": func(i *iamv1.ServiceIdentity, e *auditv1.Event, a *AuditEvidence) {
					a.InstallationID = "installation-other"
				},
				"event scope": func(i *iamv1.ServiceIdentity, e *auditv1.Event, a *AuditEvidence) {
					if e.InstallationID != "" {
						e.InstallationID = "installation-other"
					} else {
						e.TenantID = "tenant-other"
					}
				},
				"actor": func(i *iamv1.ServiceIdentity, e *auditv1.Event, a *AuditEvidence) { e.Actor.ID = "principal-forged" },
				"decision id": func(i *iamv1.ServiceIdentity, e *auditv1.Event, a *AuditEvidence) {
					e.IAMDecisionID = "decision-forged"
				},
				"request": func(i *iamv1.ServiceIdentity, e *auditv1.Event, a *AuditEvidence) { e.RequestID = "request-forged" },
				"correlation": func(i *iamv1.ServiceIdentity, e *auditv1.Event, a *AuditEvidence) {
					e.CorrelationID = "correlation-forged"
				},
				"original decision": func(i *iamv1.ServiceIdentity, e *auditv1.Event, a *AuditEvidence) { a.Decision = nil },
				"original fact": func(i *iamv1.ServiceIdentity, e *auditv1.Event, a *AuditEvidence) {
					a.Event.Target.ID = "decision-forged"
				},
				"before authority": func(i *iamv1.ServiceIdentity, e *auditv1.Event, a *AuditEvidence) {
					e.OccurredAt = a.Decision.DecidedAt.Add(-time.Microsecond)
				},
			} {
				t.Run(name, func(t *testing.T) {
					i, e, a := identity, event, evidence
					attack(&i, &e, &a)
					if _, err := auditContentDigest(i, e, a); !errors.Is(err, ErrForbidden) {
						t.Fatalf("forged proof error=%v", err)
					}
				})
			}
			wrongTarget := event
			wrongTarget.Target.ID = "resource-forged"
			_, err = auditContentDigest(identity, wrongTarget, evidence)
			if mapping.resource == "resource-proof" && !errors.Is(err, ErrForbidden) {
				t.Fatal("exact-target decision admitted a substituted resource")
			}
			if mapping.resource == "collection" && err != nil {
				t.Fatal("collection authority was incorrectly claimed to bind a final target")
			}
			// This is intentionally not a source transaction/payload receipt. The
			// immutable authority is proved; payload/Operation truth stays at source.
			changedPayload := event
			changedPayload.RequestDigest = "sha256:" + strings.Repeat("b", 64)
			if _, err := auditContentDigest(identity, changedPayload, evidence); err != nil {
				t.Fatal("proof exceeded its declared historical authority boundary")
			}
		})
	}
}

func TestAuditProofEnrollmentCannotAuthorizeAnotherMutation(t *testing.T) {
	identity, event, evidence := historicalAuditFixture(auditv1.ActionPaaSExecutionTargetRegistered, iamv1.ActionPaaSNodeEnrollmentCreate, "collection")
	for name, attack := range map[string]func(*auditv1.Event, *AuditEvidence){
		"read ceremony": func(_ *auditv1.Event, proof *AuditEvidence) {
			proof.Decision.Action = iamv1.ActionPaaSNodeEnrollmentRead
		},
		"revoke ceremony": func(_ *auditv1.Event, proof *AuditEvidence) {
			proof.Decision.Action = iamv1.ActionPaaSNodeEnrollmentRevoke
		},
		"regenerate ceremony": func(_ *auditv1.Event, proof *AuditEvidence) {
			proof.Decision.Action = iamv1.ActionPaaSNodeEnrollmentRegenerate
		},
		"wrong original ID": func(_ *auditv1.Event, proof *AuditEvidence) { proof.Decision.Resource.ID = "enrollment-forged" },
		"wrong original kind": func(_ *auditv1.Event, proof *AuditEvidence) {
			proof.Decision.Resource.Kind = iamv1.ResourceExecutionTarget
		},
		"drain target": func(event *auditv1.Event, _ *AuditEvidence) { event.Action = auditv1.ActionPaaSExecutionTargetDrained },
		"activate target": func(event *auditv1.Event, _ *AuditEvidence) {
			event.Action = auditv1.ActionPaaSExecutionTargetActivated
		},
		"remove target": func(event *auditv1.Event, _ *AuditEvidence) { event.Action = auditv1.ActionPaaSExecutionTargetRemoved },
	} {
		t.Run(name, func(t *testing.T) {
			forged, proof := event, evidence
			decision := *evidence.Decision
			proof.Decision = &decision
			attack(&forged, &proof)
			if _, err := auditContentDigest(identity, forged, proof); !errors.Is(err, ErrForbidden) {
				t.Fatalf("unrelated enrollment proof accepted: %v", err)
			}
		})
	}
}

func TestAuditProofVerifierIsNotGenericServiceAuthority(t *testing.T) {
	for _, probe := range []struct {
		event  auditv1.Action
		target string
	}{
		{auditv1.ActionPaaSApplicationCreated, "installation-verification-app-"},
		{auditv1.ActionPaaSConfigurationCreated, "installation-verification-config-"},
		{auditv1.ActionPaaSConfigurationRevisionCreated, "installation-verification-config-rev-"},
		{auditv1.ActionPaaSApplicationRevisionCreated, "installation-verification-app-rev-"},
		{auditv1.ActionPaaSDeploymentCreated, "installation-verification-deploy-"},
		{auditv1.ActionPaaSDeploymentUpdated, "installation-verification-deploy-"},
		{auditv1.ActionAuditIntegrityVerified, "installation-verification"},
	} {
		t.Run(string(probe.event), func(t *testing.T) {
			identity, event, evidence := historicalAuditFixture(probe.event, iamv1.ActionInstallationVerify, "installation-proof")
			event.TenantID = auditv1.TenantID(identity.AccountID)
			event.Actor = auditv1.ActorReference{Type: auditv1.ActorServiceAccount, ID: "service-verifier"}
			event.Target.ID = probe.target
			if probe.event != auditv1.ActionAuditIntegrityVerified {
				event.Target.ID += strings.Repeat("a", 24)
			}
			evidence.Decision.TenantID = identity.AccountID
			evidence.Decision.Subject = &iamv1.Subject{Type: iamv1.SubjectServiceAccount, ID: "service-verifier"}
			evidence.Event.TenantID = event.TenantID
			evidence.Event.Actor = event.Actor
			evidence.VerifierPrincipalID = "service-verifier"
			if _, err := auditContentDigest(identity, event, evidence); err != nil {
				t.Fatalf("fixed verifier fact rejected: %v", err)
			}
			wrong := event
			wrong.Target.ID = "arbitrary-business-resource"
			if _, err := auditContentDigest(identity, wrong, evidence); !errors.Is(err, ErrForbidden) {
				t.Fatal("probe authorized ordinary business target")
			}
			evidence.VerifierPrincipalID = "service-arbitrary"
			if _, err := auditContentDigest(identity, event, evidence); !errors.Is(err, ErrForbidden) {
				t.Fatal("ordinary service impersonated installation verifier")
			}
		})
	}
}

func historicalAuditFixture(eventAction auditv1.Action, decisionAction iamv1.Action, resource string) (iamv1.ServiceIdentity, auditv1.Event, AuditEvidence) {
	now := time.Date(2026, 8, 27, 5, 6, 7, 0, time.UTC)
	contract, _ := auditv1.ContractForAction(eventAction)
	resourceKind, _ := iamv1.ResourceKindForAction(decisionAction)
	identity := iamv1.ServiceIdentity{APIVersion: iamv1.APIVersion, Kind: "ServiceIdentity", InstallationID: "installation-proof", AccountID: "tenant-platform", PrincipalID: "service-producer", Purpose: iamv1.ServicePaaS}
	if contract.Source == auditv1.SourceAudit {
		identity.Purpose = iamv1.ServiceAudit
	}
	decision := iamv1.AuthorizationDecision{APIVersion: iamv1.APIVersion, Kind: "AuthorizationDecision", ID: "decision-proof", Allowed: true, Reason: iamv1.DecisionAllowed, TenantID: "tenant-customer", Subject: &iamv1.Subject{Type: iamv1.SubjectUser, ID: "principal-actor"}, Action: decisionAction, Resource: iamv1.ResourceReference{Kind: resourceKind, ID: resource}, RequestID: "request-proof", DecidedAt: now}
	event := auditv1.Event{APIVersion: auditv1.APIVersion, Kind: "AuditEvent", EventID: "event-proof", TenantID: auditv1.TenantID(decision.TenantID), Actor: auditv1.ActorReference{Type: auditv1.ActorUser, ID: "principal-actor"}, IAMDecisionID: "decision-proof", Action: eventAction, Target: auditv1.TargetReference{Kind: contract.Target, ID: "resource-proof"}, Result: contract.Results[0], RequestDigest: "sha256:" + strings.Repeat("a", 64), RequestID: "request-proof", CorrelationID: "correlation-proof", OccurredAt: now.Add(time.Second)}
	if contract.OperationRequired {
		event.OperationID = "operation-proof"
	}
	if resource == "records" || resource == "chain" {
		event.Target.ID = resource
	}
	if contract.PlatformOnly {
		event.TenantID = ""
		event.InstallationID = identity.InstallationID
		decision.TenantID = ""
		decision.InstallationID = identity.InstallationID
	}
	original := event
	original.EventID = "event-original"
	original.Action = auditv1.ActionIAMAuthorizationDecided
	original.Target = auditv1.TargetReference{Kind: auditv1.TargetAuthorizationDecision, ID: "decision-proof"}
	original.Result = auditv1.ResultAllowed
	original.OperationID = ""
	original.OccurredAt = now
	original.InstallationID = ""
	if contract.PlatformOnly {
		original.TenantID = auditv1.TenantID(identity.AccountID)
	}
	return identity, event, AuditEvidence{InstallationID: identity.InstallationID, Event: original, Decision: &decision, DecisionContractVersion: 1}
}

func mustAuditSource(t *testing.T, action auditv1.Action) auditv1.Source {
	t.Helper()
	contract, known := auditv1.ContractForAction(action)
	if !known {
		t.Fatal("unknown Audit action")
	}
	return contract.Source
}

func TestPasswordChangeRetainsCurrentAndHonorsEffectiveSessionPolicy(t *testing.T) {
	keep, revoke := false, true
	for _, scenario := range []struct {
		name       string
		forced     bool
		option     *bool
		otherValid bool
	}{
		{"forced overrides false", true, &keep, false},
		{"ordinary defaults true", false, nil, false},
		{"ordinary explicit true", false, &revoke, false},
		{"ordinary explicit false", false, &keep, true},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			repository := &coreRepository{transaction: newCoreTransaction()}
			sequence := 0
			service, err := newCoreAuthority(repository, Config{NewID: func(prefix string) (string, error) {
				sequence++
				return fmt.Sprintf("%s-policy-%d", prefix, sequence), nil
			}})
			if err != nil {
				t.Fatal(err)
			}
			document := coreBootstrap(t)
			if _, err := service.Bootstrap(context.Background(), document); err != nil {
				t.Fatal(err)
			}
			// This is the unit fixture for ordinary versus required replacement;
			// real first-login/reset/recovery transitions are owned by the PG gate.
			principal := repository.transaction.users[document.Administrator.ID]
			principal.MustChangePassword = scenario.forced
			repository.transaction.users[principal.ID] = principal
			repository.transaction.principal = principal
			login := func() iamv1.LoginResponse {
				t.Helper()
				result, err := service.Login(context.Background(), iamv1.LoginRequest{
					LoginName: "admin", Password: document.Administrator.Password, RequestID: "request-policy-login",
				})
				if err != nil {
					t.Fatal(err)
				}
				return result
			}
			current, other, loggedOut := login(), login(), login()
			if _, err := service.Logout(context.Background(), loggedOut.Credential, iamv1.LogoutRequest{RequestID: "request-policy-logout"}); err != nil {
				t.Fatal(err)
			}
			if _, err := service.ChangePassword(context.Background(), current.Credential, iamv1.ChangePasswordRequest{
				CurrentPassword: document.Administrator.Password, NewPassword: coreSecret(t, "Policy-Replacement-Password-73!"),
				RequestID: "request-policy-change", RevokeOtherSessions: scenario.option,
			}); err != nil {
				t.Fatal(err)
			}
			for _, check := range []struct {
				session iamv1.LoginResponse
				valid   bool
			}{{current, true}, {other, scenario.otherValid}, {loggedOut, false}} {
				decision, err := service.Authorize(context.Background(), coreServiceCredential(t, document, iamv1.ServicePaaS), check.session.Credential,
					coreAuthorizationRequest(t, iamv1.AuthorizationRequest{Action: iamv1.ActionPaaSApplicationRead, Resource: iamv1.ResourceReference{Kind: iamv1.ResourceApplication, ID: "application-policy"}, RequestID: "request-policy-authorize", CorrelationID: "correlation-policy"}, iamv1.AuthorizationResourceInstance, ""))
				if check.valid && (err != nil || !decision.Allowed) || !check.valid && !errors.Is(err, ErrUnauthenticated) {
					t.Fatalf("password policy current=%t valid=%t allowed=%t error=%v", check.session.Session.ID == current.Session.ID, check.valid, decision.Allowed, err)
				}
			}
		})
	}
}

func TestIAMCoreUsecasesBindCredentialsAndRecordClosedAuthorization(t *testing.T) {
	repository := &coreRepository{transaction: newCoreTransaction()}
	sequence := 0
	service, err := newCoreAuthority(repository, Config{
		SessionLifetime: time.Hour,
		NewID: func(prefix string) (string, error) {
			sequence++
			return fmt.Sprintf("%s-test-%d", prefix, sequence), nil
		},
	})
	if err != nil {
		t.Fatalf("create IAM authority: %v", err)
	}
	document := coreBootstrap(t)
	status, err := service.Bootstrap(context.Background(), document)
	if err != nil || status.State != iamv1.BootstrapReady {
		t.Fatalf("bootstrap IAM: status=%#v err=%v", status, err)
	}
	replayed, err := service.Bootstrap(context.Background(), document)
	if err != nil || replayed != status {
		t.Fatalf("replay IAM bootstrap: status=%#v err=%v", replayed, err)
	}

	paasCredential := coreServiceCredential(t, document, iamv1.ServicePaaS)
	storedStatus, err := service.BootstrapStatus(context.Background(), paasCredential)
	if err != nil || storedStatus != status {
		t.Fatalf("read IAM bootstrap status: status=%#v err=%v", storedStatus, err)
	}
	identity, err := service.ServiceIdentity(context.Background(), paasCredential)
	if err != nil || identity.Purpose != iamv1.ServicePaaS || identity.PrincipalID != "service-paas" {
		t.Fatalf("resolve PaaS service identity: identity=%#v err=%v", identity, err)
	}
	verifierCredential := coreServiceCredential(t, document, iamv1.ServiceInstallationVerifier)
	verificationRequest := coreAuthorizationRequest(t, iamv1.AuthorizationRequest{
		Action: iamv1.ActionInstallationVerify,
		Resource: iamv1.ResourceReference{
			Kind: iamv1.ResourceInstallation, ID: document.InstallationID,
		},
		RequestID: "request-installation-verify", CorrelationID: "correlation-installation-verify",
	}, iamv1.AuthorizationResourceInstance, "")
	verificationDecision, err := service.VerifyInstallation(
		context.Background(), verifierCredential, verificationRequest,
	)
	if err != nil || !verificationDecision.Allowed || verificationDecision.Subject == nil ||
		verificationDecision.Subject.Type != iamv1.SubjectServiceAccount ||
		verificationDecision.Subject.ID != "service-verifier" {
		t.Fatalf("installation verification decision=%#v err=%v", verificationDecision, err)
	}
	verificationRequest.Resource.ID = "installation-other"
	verificationRequest.RequestID = "request-installation-other"
	verificationRequest.CorrelationID = verificationRequest.RequestID
	verificationDecision, err = service.VerifyInstallation(
		context.Background(), verifierCredential, verificationRequest,
	)
	if err != nil || verificationDecision.Allowed {
		t.Fatalf("cross-installation verification decision=%#v err=%v", verificationDecision, err)
	}
	verificationRequest.Resource.ID = document.InstallationID

	wrongPassword := coreSecret(t, "Wrong-Admin-Password-73!")
	if _, err := service.Login(context.Background(), iamv1.LoginRequest{
		LoginName: "admin", Password: wrongPassword, RequestID: "request-login-wrong",
	}); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("wrong password error = %v, want unauthenticated", err)
	}
	login, err := service.Login(context.Background(), iamv1.LoginRequest{
		LoginName: "admin",
		Password:  document.Administrator.Password,
		RequestID: "request-login",
	})
	if err != nil {
		t.Fatalf("log in initial administrator: %v", err)
	}
	if !login.MustChangePassword {
		t.Fatal("initial administrator login did not require a password change")
	}
	request := coreAuthorizationRequest(t, iamv1.AuthorizationRequest{
		Action:        iamv1.ActionPaaSApplicationCreate,
		Resource:      iamv1.ResourceReference{Kind: iamv1.ResourceApplication, ID: "collection"},
		RequestID:     "request-authorize-before-password",
		CorrelationID: "correlation-authorize-before-password",
	}, iamv1.AuthorizationResourceCollection, iamv1.AuthorizationCollectionCreate)
	decision, err := service.Authorize(
		context.Background(),
		paasCredential,
		login.Credential,
		request,
	)
	if err != nil || decision.Allowed {
		t.Fatalf("initial administrator decision = %#v err=%v, want deny", decision, err)
	}

	changed, err := service.ChangePassword(context.Background(), login.Credential, iamv1.ChangePasswordRequest{
		CurrentPassword: document.Administrator.Password,
		NewPassword:     coreSecret(t, "Changed-Admin-Password-73!"),
		RequestID:       "request-admin-password-change",
	})
	if err != nil || !changed.BootstrapFileRetirable || changed.ChangedAt != repository.transaction.now {
		t.Fatalf("change bootstrap administrator password: response=%#v err=%v", changed, err)
	}
	request.RequestID = "request-authorize-allowed"
	request.CorrelationID = "correlation-authorize-allowed"
	decision, err = service.Authorize(
		context.Background(),
		paasCredential,
		login.Credential,
		request,
	)
	if err != nil || !decision.Allowed || decision.TenantID != "organization-example" ||
		decision.Subject == nil || decision.Subject.ID != "principal-admin" {
		t.Fatalf("PaaS decision = %#v err=%v, want allowed", decision, err)
	}
	// This workflow intentionally has no directory key. Even an authorized
	// administrator cannot fall back to raw IDs or an in-memory signing key.
	if _, err := service.ListGroups(context.Background(), login.Credential, "", "request-no-cursor-key"); !errors.Is(err, ErrUnavailable) {
		t.Fatal("unconfigured directory did not fail closed")
	}

	request.RequestID = "request-authorize-wrong-service"
	request.CorrelationID = "correlation-authorize-wrong-service"
	decision, err = service.Authorize(
		context.Background(),
		coreServiceCredential(t, document, iamv1.ServiceAudit),
		login.Credential,
		request,
	)
	if err != nil || decision.Allowed {
		t.Fatalf("Audit-to-PaaS decision = %#v err=%v, want deny", decision, err)
	}

	created, err := service.CreateUser(context.Background(), login.Credential, iamv1.CreateUserRequest{
		LoginName:       "developer",
		DisplayName:     "Platform Developer",
		InitialPassword: coreSecret(t, "Initial-Developer-Password-84!"),
		RequestID:       "request-create-developer",
	})
	if err != nil || created.LoginName != "developer" || !created.MustChangePassword {
		t.Fatalf("create organization user: principal=%#v err=%v", created, err)
	}
	binding, err := service.CreatePolicyAttachment(context.Background(), login.Credential, iamv1.CreatePolicyAttachmentRequest{
		Target:   iamv1.PolicyAttachmentTarget{Kind: iamv1.PolicyTargetUser, ID: string(created.ID)},
		PolicyID: iamv1.SystemPolicyPaaSDeveloper, PolicyResourceVersion: 1,
		RequestID: "request-bind-developer",
	})
	if err != nil || binding.Target.ID != string(created.ID) || binding.PolicyID != iamv1.SystemPolicyPaaSDeveloper {
		t.Fatalf("bind organization user: binding=%#v err=%v", binding, err)
	}
	if repository.transaction.attachmentSession != login.Session.ID {
		t.Fatal("attachment creation did not forward the authenticated bearer session")
	}
	developerLogin, err := service.Login(context.Background(), iamv1.LoginRequest{
		LoginName: "developer@organization-example",
		Password:  coreSecret(t, "Initial-Developer-Password-84!"),
		RequestID: "request-login-developer",
	})
	if err != nil {
		t.Fatalf("log in organization user: %v", err)
	}
	if !developerLogin.MustChangePassword {
		t.Fatal("initial organization user login did not require a password change")
	}
	request.RequestID = "request-developer-before-password"
	request.CorrelationID = request.RequestID
	decision, err = service.Authorize(context.Background(), paasCredential, developerLogin.Credential, request)
	if err != nil || decision.Allowed {
		t.Fatalf("initial developer decision=%#v err=%v, want deny", decision, err)
	}
	developerPassword, err := service.ChangePassword(
		context.Background(),
		developerLogin.Credential,
		iamv1.ChangePasswordRequest{
			CurrentPassword: coreSecret(t, "Initial-Developer-Password-84!"),
			NewPassword:     coreSecret(t, "Changed-Developer-Password-95!"),
			RequestID:       "request-developer-password-change",
		},
	)
	if err != nil || developerPassword.BootstrapFileRetirable {
		t.Fatalf("change organization user password: response=%#v err=%v", developerPassword, err)
	}
	request.RequestID = "request-developer-allowed"
	request.CorrelationID = request.RequestID
	decision, err = service.Authorize(context.Background(), paasCredential, developerLogin.Credential, request)
	if err != nil || !decision.Allowed || decision.Subject == nil || decision.Subject.ID != string(created.ID) {
		t.Fatalf("developer decision=%#v err=%v, want allowed", decision, err)
	}
	revokedBinding, err := service.RevokePolicyAttachment(
		context.Background(),
		login.Credential,
		binding.ID,
		iamv1.RevokePolicyAttachmentRequest{ResourceVersion: 1, RequestID: "request-revoke-developer-binding"},
	)
	if err != nil || revokedBinding.ID != string(binding.ID) || revokedBinding.ResourceVersion != 2 {
		t.Fatalf("revoke developer binding: revocation=%#v err=%v", revokedBinding, err)
	}
	if repository.transaction.revocationSession != login.Session.ID {
		t.Fatal("attachment revocation did not forward the authenticated bearer session")
	}
	request.RequestID = "request-developer-after-binding-revoke"
	request.CorrelationID = request.RequestID
	decision, err = service.Authorize(context.Background(), paasCredential, developerLogin.Credential, request)
	if err != nil || decision.Allowed {
		t.Fatalf("revoked-role decision=%#v err=%v, want deny", decision, err)
	}
	revokedSession, err := service.RevokeSession(
		context.Background(),
		login.Credential,
		developerLogin.Session.ID,
		iamv1.RevokeSessionRequest{RequestID: "request-revoke-developer-session"},
	)
	if err != nil || revokedSession.ID != string(developerLogin.Session.ID) {
		t.Fatalf("revoke developer session: revocation=%#v err=%v", revokedSession, err)
	}
	request.RequestID = "request-developer-after-session-revoke"
	request.CorrelationID = request.RequestID
	if _, err := service.Authorize(context.Background(), paasCredential, developerLogin.Credential, request); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("revoked developer session error=%v, want unauthenticated", err)
	}
	verifierRevocation, err := service.RevokePolicyAttachment(
		context.Background(),
		login.Credential,
		"bootstrap-verifier-binding",
		iamv1.RevokePolicyAttachmentRequest{ResourceVersion: 1, RequestID: "request-revoke-verifier-binding"},
	)
	if !errors.Is(err, ErrForbidden) || verifierRevocation.ID != "" {
		t.Fatalf("revoke installation verifier binding: revocation=%#v err=%v", verifierRevocation, err)
	}
	// Online user attachment management cannot revoke the sealed service probe.
	// Independently revoke the fixture to retain current service-authority coverage.
	probe := repository.transaction.attachments["bootstrap-verifier-binding"]
	probe.ResourceVersion++
	probe.UpdatedAt = repository.transaction.now
	probe.RevokedAt = &probe.UpdatedAt
	repository.transaction.attachments[probe.ID] = probe
	verificationRequest.RequestID = "request-installation-after-role-revoke"
	verificationRequest.CorrelationID = verificationRequest.RequestID
	verificationDecision, err = service.VerifyInstallation(
		context.Background(), verifierCredential, verificationRequest,
	)
	if err != nil || verificationDecision.Allowed {
		t.Fatalf("revoked installation verifier decision=%#v err=%v", verificationDecision, err)
	}
	logout, err := service.Logout(
		context.Background(), login.Credential, iamv1.LogoutRequest{RequestID: "request-admin-logout"},
	)
	if err != nil || logout.RevokedAt != repository.transaction.now {
		t.Fatalf("logout administrator: response=%#v err=%v", logout, err)
	}
	expectedDecisions := map[string]bool{
		"request-bind-developer": true, "request-revoke-developer-binding": true,
		"request-developer-before-password": false, "request-developer-allowed": true,
		"request-developer-after-binding-revoke": false,
	}
	for _, mutation := range repository.transaction.authorizations {
		if _, current := iamv1.LookupActionDefinition(mutation.Decision.Action); !current {
			t.Fatal("management wrote a retired action")
		}
		if allowed, expected := expectedDecisions[mutation.Decision.RequestID]; expected {
			if mutation.Decision.Allowed != allowed {
				t.Fatalf("unexpected authority for %s", mutation.Decision.RequestID)
			}
			delete(expectedDecisions, mutation.Decision.RequestID)
		}
		if mutation.AuditEvent.IAMDecisionID != auditv1.DecisionID(mutation.Decision.ID) ||
			mutation.AuditEvent.Target.ID != string(mutation.Decision.ID) ||
			mutation.AuditEvent.TenantID != "organization-example" {
			t.Fatalf("authorization Audit fact differs from decision: %#v", mutation)
		}
	}
	if len(expectedDecisions) != 0 {
		t.Fatalf("management path lost decisions: %v", expectedDecisions)
	}
	readiness, err := service.Readiness(context.Background())
	if !errors.Is(err, ErrUnavailable) || readiness.State == iamv1.ReadinessReady {
		t.Fatal("local authority without AccessKey custody advertised network readiness")
	}
}

type coreRepository struct {
	transaction      *coreTransaction
	inTransaction    bool
	afterTransaction func(error) error
}

func (repository *coreRepository) WithinTransaction(
	ctx context.Context,
	callback func(context.Context, Transaction) error,
) error {
	repository.inTransaction = true
	err := callback(ctx, repository.transaction)
	repository.inTransaction = false
	if repository.afterTransaction != nil {
		return repository.afterTransaction(err)
	}
	return err
}

type coreTransaction struct {
	Transaction
	now                     time.Time
	status                  iamv1.BootstrapStatus
	contentDigest           string
	organization            iamv1.Organization
	principal               iamv1.Principal
	services                map[string]ServiceCredential
	sessions                map[string]SessionCredential
	roleSessions            map[string]RoleSessionCredential
	roleExitCredentials     map[string]RoleSessionExitCredential
	roleExitEvents          []auditv1.Event
	authorizations          []AuthorizationMutation
	passwords               map[iamv1.PrincipalID]authority.PasswordHash
	passwordAttempts        map[iamv1.PrincipalID]PasswordAttempt
	attemptSequence         uint64
	rejectedAttempts        []string
	users                   map[iamv1.PrincipalID]iamv1.Principal
	attachments             map[iamv1.PolicyAttachmentID]iamv1.PolicyAttachment
	attachmentSession       iamv1.SessionID
	revocationSession       iamv1.SessionID
	sessionRevocation       *SessionRevocationMutation
	otherSessionRevocation  *OtherSessionRevocationMutation
	otherSessionResult      iamv1.RevokeOtherSessionsResponse
	otherSessionError       error
	ownSessionItems         *[]iamv1.Session
	localRecoveryInspection iamv1.LocalCredentialRecoveryInspection
	localRecoveryResult     iamv1.LocalCredentialRecoveryResult
	localRecoveryMutation   *LocalCredentialRecoveryMutation
	profileErr              error
	accessKeyCustody        *AccessKeyCustody
	accessKeyCustodyErr     error
	totpCustody             *TOTPCustody
	totpCustodyErr          error
}

func (transaction *coreTransaction) RegisterTOTPKeyset(_ context.Context, value TOTPKeysetRegistration) error {
	transaction.totpCustody = &TOTPCustody{Keyset: value}
	return transaction.totpCustodyErr
}

func (transaction *coreTransaction) ReadTOTPCustody(context.Context) (TOTPCustody, error) {
	if transaction.totpCustodyErr != nil {
		return TOTPCustody{}, transaction.totpCustodyErr
	}
	if transaction.totpCustody != nil {
		return *transaction.totpCustody, nil
	}
	keyring := coreTOTPKeyring()
	wrapping, err := newTOTPRegistration(&keyring)
	if err != nil {
		return TOTPCustody{}, err
	}
	return TOTPCustody{Keyset: *wrapping}, nil
}

func (transaction *coreTransaction) RevokeOtherSessions(_ context.Context, mutation OtherSessionRevocationMutation) (iamv1.RevokeOtherSessionsResponse, error) {
	transaction.otherSessionRevocation = &mutation
	return transaction.otherSessionResult, transaction.otherSessionError
}

func (transaction *coreTransaction) ReadEmailVerificationKeyset(context.Context) (*authority.EmailVerificationKeyset, error) {
	return nil, nil
}

func (transaction *coreTransaction) ReadAccessKeyCustody(context.Context) (AccessKeyCustody, error) {
	if transaction.accessKeyCustodyErr != nil {
		return AccessKeyCustody{}, transaction.accessKeyCustodyErr
	}
	if transaction.accessKeyCustody == nil {
		return AccessKeyCustody{}, ErrUnavailable
	}
	return *transaction.accessKeyCustody, nil
}

func TestIAMReadinessRequiresCompleteMatchingAccessKeyCustody(t *testing.T) {
	tx := newCoreTransaction()
	tx.status.State = iamv1.BootstrapReady
	document := iamv1.AccessKeyWrappingKeyring{APIVersion: iamv1.APIVersion, Kind: "AccessKeyWrappingKeyring", Purpose: iamv1.AccessKeyWrappingPurpose,
		Scope:               iamv1.AccessKeyWrappingScope{InstallationID: "custody-install", BootstrapDigest: "sha256:" + strings.Repeat("a", 64)},
		ActiveWrappingKeyID: "custody-key", Keys: []iamv1.AccessKeyWrappingKey{{WrappingKeyID: "custody-key", FormatVersion: 1,
			KeyMaterial: coreSecret(t, base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x57}, 32)))}}}
	commitment, err := iamv1.AccessKeyWrappingKeyCommitment(document, document.ActiveWrappingKeyID)
	if err != nil {
		t.Fatal(err)
	}
	service, err := newCoreAuthority(&coreRepository{transaction: tx}, Config{AccessKeyWrapping: &document})
	if err != nil {
		t.Fatal(err)
	}
	// Constructor must own material and scope; callers cannot replace its KEK.
	document.Scope.InstallationID = "changed-install"
	document.Keys[0].KeyMaterial = coreSecret(t, base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x58}, 32)))
	if service.config.AccessKeyWrapping != nil || !bytes.Equal(service.accessKeys.material, bytes.Repeat([]byte{0x57}, 32)) {
		t.Fatal("authority retained mutable wrapping configuration")
	}
	for _, variant := range []string{"empty", "matching", "missing-file", "missing-registry", "installation", "bootstrap", "key-id", "commitment", "extra-history", "unavailable", "uninitialized"} {
		t.Run(variant, func(t *testing.T) {
			var custody AccessKeyCustody
			if err := json.Unmarshal([]byte(`{"installationId":"custody-install","bootstrapDigest":"sha256:`+strings.Repeat("a", 64)+`","keys":[{"wrappingKeyId":"custody-key","materialCommitment":"`+commitment+`"}]}`), &custody); err != nil {
				t.Fatal(err)
			}
			tx.accessKeyCustody, tx.accessKeyCustodyErr, tx.status.State = &custody, nil, iamv1.BootstrapReady
			current := service
			switch variant {
			case "empty":
				custody.Keys = custody.Keys[:0]
			case "missing-file":
				var err error
				current, err = newCoreAuthority(&coreRepository{transaction: tx}, Config{})
				if err != nil {
					t.Fatal(err)
				}
			case "missing-registry":
				custody.Keys = nil
			case "installation":
				custody.InstallationID = "other-install"
			case "bootstrap":
				custody.BootstrapDigest = "sha256:" + strings.Repeat("b", 64)
			case "key-id":
				custody.Keys[0].WrappingKeyID = "other-key"
			case "commitment":
				custody.Keys[0].MaterialCommitment = "sha256:" + strings.Repeat("b", 64)
			case "extra-history":
				custody.Keys = append(custody.Keys, custody.Keys[0])
			case "unavailable":
				tx.accessKeyCustodyErr = ErrUnavailable
			case "uninitialized":
				tx.status.State, tx.accessKeyCustody = iamv1.BootstrapUninitialized, nil
			}
			readiness, err := current.Readiness(t.Context())
			if variant == "empty" || variant == "matching" {
				if err != nil || readiness.State != iamv1.ReadinessReady || readiness.CheckedAt != tx.now || readiness.SchemaVersion != SchemaVersion {
					t.Fatal("valid process custody rejected", err)
				}
			} else if variant == "uninitialized" {
				if err != nil || readiness.State != iamv1.ReadinessNotReady || readiness.SchemaVersion != SchemaVersion {
					t.Fatal("uninitialized schema cannot be checked before bootstrap", err)
				}
			} else if !errors.Is(err, ErrUnavailable) || readiness.State == iamv1.ReadinessReady {
				t.Fatal("incomplete process custody advertised ready")
			}
		})
	}
}

func (transaction *coreTransaction) LookupRoleSession(_ context.Context, digest string) (RoleSessionCredential, bool, error) {
	value, found := transaction.roleSessions[digest]
	return value, found, nil
}

func (transaction *coreTransaction) LookupRoleSessionForExit(_ context.Context, digest string) (RoleSessionExitCredential, bool, error) {
	value, found := transaction.roleExitCredentials[digest]
	return value, found, nil
}

func (transaction *coreTransaction) ExitRoleSession(_ context.Context, digest string, event auditv1.Event) (iamv1.RoleSession, error) {
	transaction.roleExitEvents = append(transaction.roleExitEvents, event)
	result := transaction.roleExitCredentials[digest].Session
	result.Status, result.RevokedAt = iamv1.SessionRevoked, &transaction.now
	return result, nil
}

func (transaction *coreTransaction) InspectLocalCredentialRecovery(context.Context, iamv1.LocalCredentialRecoveryScope, *iamv1.LocalCredentialRecoveryReceiptQuery) (iamv1.LocalCredentialRecoveryInspection, error) {
	return transaction.localRecoveryInspection, nil
}

func (transaction *coreTransaction) RecoverLocalCredentials(_ context.Context, mutation LocalCredentialRecoveryMutation) (iamv1.LocalCredentialRecoveryResult, error) {
	transaction.localRecoveryMutation = &mutation
	return transaction.localRecoveryResult, nil
}

func newCoreTransaction() *coreTransaction {
	return &coreTransaction{
		now:         time.Date(2026, 8, 26, 8, 9, 10, 123000, time.UTC),
		services:    make(map[string]ServiceCredential),
		sessions:    make(map[string]SessionCredential),
		passwords:   make(map[iamv1.PrincipalID]authority.PasswordHash),
		users:       make(map[iamv1.PrincipalID]iamv1.Principal),
		attachments: make(map[iamv1.PolicyAttachmentID]iamv1.PolicyAttachment),
	}
}

func (transaction *coreTransaction) TransactionTime(context.Context) (time.Time, error) {
	return transaction.now, nil
}

func (transaction *coreTransaction) BootstrapStatus(context.Context) (iamv1.BootstrapStatus, error) {
	if transaction.status.State == "" {
		return iamv1.BootstrapStatus{
			APIVersion: iamv1.APIVersion,
			Kind:       "BootstrapStatus",
			State:      iamv1.BootstrapUninitialized,
		}, nil
	}
	return transaction.status, nil
}

func (transaction *coreTransaction) ApplyBootstrap(
	_ context.Context,
	mutation BootstrapMutation,
) (authority.BootstrapOutcome, error) {
	if transaction.contentDigest != "" {
		if transaction.contentDigest != mutation.ContentDigest {
			return "", ErrConflict
		}
		return authority.BootstrapEqualReplay, nil
	}
	transaction.contentDigest = mutation.ContentDigest
	appliedAt := transaction.now
	transaction.status = iamv1.BootstrapStatus{
		APIVersion:     iamv1.APIVersion,
		Kind:           "BootstrapStatus",
		State:          iamv1.BootstrapReady,
		InstallationID: mutation.InstallationID,
		AccountID:      mutation.Organization.ID,
		ContentDigest:  mutation.ContentDigest,
		AppliedAt:      &appliedAt,
	}
	transaction.organization = iamv1.Organization{
		APIVersion:      iamv1.APIVersion,
		Kind:            "Organization",
		ID:              mutation.Organization.ID,
		DisplayName:     mutation.Organization.DisplayName,
		Status:          iamv1.AccountActive,
		ResourceVersion: 1,
		CreatedAt:       transaction.now,
		UpdatedAt:       transaction.now,
	}
	transaction.principal = iamv1.Principal{
		APIVersion:         iamv1.APIVersion,
		Kind:               "Principal",
		ID:                 mutation.Administrator.ID,
		AccountID:          mutation.Organization.ID,
		Type:               iamv1.PrincipalUser,
		LoginName:          mutation.Administrator.LoginName,
		DisplayName:        mutation.Administrator.DisplayName,
		Status:             iamv1.PrincipalActive,
		MustChangePassword: true,
		ResourceVersion:    1,
		CreatedAt:          transaction.now,
		UpdatedAt:          transaction.now,
	}
	transaction.passwords[mutation.Administrator.ID] = mutation.Administrator.PasswordHash
	transaction.users[mutation.Administrator.ID] = transaction.principal
	transaction.attachments["bootstrap-admin-binding"] = transaction.bootstrapPolicyAttachment("bootstrap-admin-binding", mutation.Administrator.ID, iamv1.SystemPolicyAccountAdministrator, iamv1.PolicyTargetUser)
	transaction.attachments["bootstrap-platform-operator-binding"] = transaction.bootstrapPolicyAttachment("bootstrap-platform-operator-binding", mutation.Administrator.ID, iamv1.SystemPolicyPlatformOperator, iamv1.PolicyTargetUser)
	for _, service := range mutation.Services {
		transaction.services[service.LookupDigest] = ServiceCredential{
			Identity: iamv1.ServiceIdentity{
				APIVersion:     iamv1.APIVersion,
				Kind:           "ServiceIdentity",
				InstallationID: mutation.InstallationID,
				AccountID:      mutation.Organization.ID,
				PrincipalID:    service.PrincipalID,
				Purpose:        service.Purpose,
			},
			VerificationDigest: service.VerificationDigest,
		}
		if service.Purpose == iamv1.ServiceInstallationVerifier {
			transaction.attachments["bootstrap-verifier-binding"] = transaction.bootstrapPolicyAttachment("bootstrap-verifier-binding", service.PrincipalID, iamv1.SystemPolicyInstallationVerifier, iamv1.PolicyTargetService)
		}
	}
	return authority.BootstrapApply, nil
}

func (transaction *coreTransaction) ReservePasswordAttempt(_ context.Context, request PasswordAttemptRequest) (PasswordAttempt, bool, error) {
	var selected iamv1.Principal
	if request.LoginName != "" {
		localName, suffix, qualified := strings.Cut(request.LoginName, "@")
		for principalID, principal := range transaction.users {
			primary := principalID == transaction.principal.ID
			if principal.LoginName == localName && qualified != primary && (!qualified || suffix == string(principal.AccountID)) {
				selected = principal
			}
		}
	} else if request.AccountID == transaction.organization.ID {
		for _, binding := range transaction.sessions {
			if binding.Subject.Session.ID == request.SessionID && binding.Subject.Principal.ID == request.UserID &&
				binding.Subject.Session.Status == iamv1.SessionActive && transaction.now.Before(binding.Subject.Session.ExpiresAt) {
				selected = transaction.users[request.UserID]
			}
		}
	}
	if selected.ID == "" || selected.Status != iamv1.PrincipalActive || transaction.organization.Status != iamv1.AccountActive {
		return PasswordAttempt{}, false, nil
	}
	if transaction.passwordAttempts == nil {
		transaction.passwordAttempts = make(map[iamv1.PrincipalID]PasswordAttempt)
	}
	transaction.attemptSequence++
	attempt := PasswordAttempt{ID: request.ID, Sequence: transaction.attemptSequence, AccountID: selected.AccountID, PrincipalID: selected.ID,
		SessionID: request.SessionID, PasswordHash: transaction.passwords[selected.ID], CredentialGeneration: 1,
		MustChangePassword: selected.MustChangePassword, ExpiresAt: transaction.now.Add(30 * time.Second)}
	transaction.passwordAttempts[selected.ID] = attempt
	return attempt, true, nil
}

func (transaction *coreTransaction) RejectPasswordAttempt(_ context.Context, attempt PasswordAttempt) error {
	transaction.rejectedAttempts = append(transaction.rejectedAttempts, attempt.ID)
	if current := transaction.passwordAttempts[attempt.PrincipalID]; current.ID == attempt.ID && current.Sequence == attempt.Sequence {
		delete(transaction.passwordAttempts, attempt.PrincipalID)
	}
	return nil
}

func (transaction *coreTransaction) IssueSession(
	_ context.Context,
	mutation SessionMutation,
) (iamv1.Session, error) {
	principal, found := transaction.users[mutation.Session.PrincipalID]
	if !found {
		return iamv1.Session{}, ErrUnauthenticated
	}
	attempt := transaction.passwordAttempts[principal.ID]
	if attempt.ID != mutation.AttemptID || attempt.Sequence != mutation.AttemptSequence || attempt.SessionID != "" ||
		transaction.passwords[principal.ID] != attempt.PasswordHash || !transaction.now.Before(attempt.ExpiresAt) {
		return iamv1.Session{}, ErrUnauthenticated
	}
	delete(transaction.passwordAttempts, principal.ID)
	transaction.sessions[mutation.LookupDigest] = SessionCredential{
		Subject: authority.SubjectContext{
			Organization: transaction.organization,
			Principal:    principal,
			Session:      mutation.Session,
			Policies:     transaction.attachedPolicies(principal.ID),
		},
		VerificationDigest:   mutation.VerificationDigest,
		CredentialGeneration: 1,
	}
	return mutation.Session, nil
}

func (transaction *coreTransaction) LookupSession(
	_ context.Context,
	lookupDigest string,
) (SessionCredential, bool, error) {
	binding, found := transaction.sessions[lookupDigest]
	if !found {
		return SessionCredential{}, false, nil
	}
	if binding.Subject.Session.Status != iamv1.SessionActive {
		return SessionCredential{}, false, nil
	}
	principal, found := transaction.users[binding.Subject.Principal.ID]
	if !found {
		return SessionCredential{}, false, nil
	}
	binding.Subject.Principal = principal
	binding.Subject.Policies = transaction.attachedPolicies(principal.ID)
	binding.Subject.Boundary = &authority.ResolvedUserBoundary{State: "NONE", AccountID: principal.AccountID, UserID: principal.ID, UserResourceVersion: principal.ResourceVersion}
	return binding, true, nil
}

func (transaction *coreTransaction) ListOwnSessions(_ context.Context, read OwnSessionRead) ([]iamv1.Session, error) {
	if transaction.ownSessionItems != nil {
		return *transaction.ownSessionItems, nil
	}
	items := make([]iamv1.Session, 0)
	for _, binding := range transaction.sessions {
		item := binding.Subject.Session
		if item.AccountID == read.AccountID && item.PrincipalID == read.UserID && item.Status == iamv1.SessionActive &&
			transaction.now.Before(item.ExpiresAt) && string(item.ID) > read.After {
			items = append(items, item)
		}
	}
	slices.SortFunc(items, func(a, b iamv1.Session) int { return strings.Compare(string(a.ID), string(b.ID)) })
	return items[:min(len(items), iamv1.DirectoryPageSize+1)], nil
}

func (transaction *coreTransaction) LookupService(
	_ context.Context,
	lookupDigest string,
) (ServiceCredential, bool, error) {
	binding, found := transaction.services[lookupDigest]
	return binding, found, nil
}

func (transaction *coreTransaction) LookupServicePolicies(
	_ context.Context,
	organizationID iamv1.AccountID,
	principalID iamv1.PrincipalID,
) ([]authority.AttachedPolicy, error) {
	if organizationID != transaction.organization.ID {
		return nil, ErrUnavailable
	}
	return transaction.attachedPolicies(principalID), nil
}

func (transaction *coreTransaction) bootstrapPolicyAttachment(id iamv1.PolicyAttachmentID, principal iamv1.PrincipalID, policyID iamv1.PolicyID, kind iamv1.PolicyAttachmentTargetKind) iamv1.PolicyAttachment {
	version, err := authority.SystemPolicyVersion(policyID)
	if err != nil {
		panic(err)
	}
	attachment := iamv1.PolicyAttachment{APIVersion: iamv1.APIVersion, Kind: "PolicyAttachment", ID: id, AccountID: transaction.organization.ID,
		Target: iamv1.PolicyAttachmentTarget{Kind: kind, ID: string(principal)}, PolicyID: policyID, Scope: version.Document.Scope,
		ResourceVersion: 1, CreatedAt: transaction.now, UpdatedAt: transaction.now}
	if attachment.Scope != iamv1.AuthorityScopeTenant {
		attachment.InstallationID = transaction.status.InstallationID
	}
	return attachment
}

func (transaction *coreTransaction) attachedPolicies(principalID iamv1.PrincipalID) []authority.AttachedPolicy {
	result := make([]authority.AttachedPolicy, 0)
	for _, attachment := range transaction.attachments {
		if attachment.Target.ID != string(principalID) || attachment.RevokedAt != nil {
			continue
		}
		policy, found, err := transaction.LookupPolicy(context.Background(), attachment.AccountID, attachment.PolicyID)
		if err != nil || !found {
			panic("missing test policy")
		}
		version, err := authority.SystemPolicyVersion(attachment.PolicyID)
		if err != nil {
			panic(err)
		}
		result = append(result, authority.AttachedPolicy{Attachment: attachment, Policy: policy, Version: version, Profiles: iamv1.AllAuthorizationProfiles()})
	}
	return result
}

func (transaction *coreTransaction) RecordAuthorization(
	_ context.Context,
	mutation AuthorizationMutation,
) error {
	if iamv1.CheckAuthorizationDecisionForRequest(mutation.Decision, mutation.Request) != nil {
		return ErrInvalidArgument
	}
	transaction.authorizations = append(transaction.authorizations, mutation)
	return nil
}

func (transaction *coreTransaction) ChangePassword(
	_ context.Context,
	mutation PasswordMutation,
) (iamv1.ChangePasswordResponse, error) {
	attempt := transaction.passwordAttempts[mutation.PrincipalID]
	if attempt.ID != mutation.AttemptID || attempt.Sequence != mutation.AttemptSequence || attempt.SessionID != mutation.SessionID ||
		!transaction.now.Before(attempt.ExpiresAt) {
		return iamv1.ChangePasswordResponse{}, ErrUnauthenticated
	}
	if transaction.passwords[mutation.PrincipalID] != mutation.ExpectedPasswordHash {
		return iamv1.ChangePasswordResponse{}, ErrUnauthenticated
	}
	delete(transaction.passwordAttempts, mutation.PrincipalID)
	transaction.passwords[mutation.PrincipalID] = mutation.NewPasswordHash
	principal := transaction.users[mutation.PrincipalID]
	for lookup, binding := range transaction.sessions {
		if binding.Subject.Principal.ID == mutation.PrincipalID && binding.Subject.Session.ID != mutation.SessionID &&
			(principal.MustChangePassword || mutation.RevokeOtherSessions) && binding.Subject.Session.Status == iamv1.SessionActive {
			binding.Subject.Session.Status = iamv1.SessionRevoked
			now := transaction.now
			binding.Subject.Session.RevokedAt = &now
			transaction.sessions[lookup] = binding
		}
	}
	principal.MustChangePassword = false
	principal.ResourceVersion++
	principal.UpdatedAt = transaction.now
	transaction.users[mutation.PrincipalID] = principal
	if mutation.PrincipalID == transaction.principal.ID {
		transaction.principal = principal
	}
	return iamv1.ChangePasswordResponse{
		ChangedAt: transaction.now, BootstrapFileRetirable: mutation.PrincipalID == transaction.principal.ID,
	}, nil
}

func (transaction *coreTransaction) RevokeSession(
	_ context.Context,
	mutation SessionRevocationMutation,
) (iamv1.Revocation, bool, error) {
	transaction.sessionRevocation = &mutation
	for lookup, binding := range transaction.sessions {
		if binding.Subject.Session.ID != mutation.SessionID {
			continue
		}
		if binding.Subject.Session.Status == iamv1.SessionRevoked {
			return iamv1.Revocation{
				APIVersion: iamv1.APIVersion, Kind: "Revocation", ID: string(mutation.SessionID),
				ResourceVersion: 2, RevokedAt: *binding.Subject.Session.RevokedAt,
			}, false, nil
		}
		revokedAt := transaction.now
		binding.Subject.Session.Status = iamv1.SessionRevoked
		binding.Subject.Session.RevokedAt = &revokedAt
		transaction.sessions[lookup] = binding
		return iamv1.Revocation{
			APIVersion: iamv1.APIVersion, Kind: "Revocation", ID: string(mutation.SessionID),
			ResourceVersion: 2, RevokedAt: revokedAt,
		}, true, nil
	}
	return iamv1.Revocation{}, false, ErrForbidden
}

func (transaction *coreTransaction) CreateUser(
	_ context.Context,
	mutation UserMutation,
) (iamv1.User, error) {
	for _, existing := range transaction.users {
		if existing.LoginName == mutation.User.LoginName {
			return iamv1.User{}, ErrConflict
		}
	}
	transaction.users[mutation.User.ID] = iamv1.Principal{
		APIVersion: mutation.User.APIVersion, Kind: "Principal", ID: mutation.User.ID,
		AccountID: mutation.User.AccountID, Type: iamv1.PrincipalUser, LoginName: mutation.User.LoginName,
		DisplayName: mutation.User.DisplayName, Status: mutation.User.Status,
		MustChangePassword: mutation.User.MustChangePassword, ResourceVersion: mutation.User.ResourceVersion,
		CreatedAt: mutation.User.CreatedAt, UpdatedAt: mutation.User.UpdatedAt,
	}
	transaction.passwords[mutation.User.ID] = mutation.PasswordHash
	return mutation.User, nil
}

func (transaction *coreTransaction) LookupPolicy(_ context.Context, account iamv1.AccountID, id iamv1.PolicyID) (iamv1.Policy, bool, error) {
	version, err := authority.SystemPolicyVersion(id)
	if err != nil || account != transaction.organization.ID {
		return iamv1.Policy{}, false, nil
	}
	return iamv1.Policy{APIVersion: iamv1.APIVersion, Kind: "Policy", ID: id, Management: iamv1.PolicySystemManaged, DisplayName: string(id),
		Scope: version.Document.Scope, Status: iamv1.PolicyActive, DefaultVersionID: version.ID, ResourceVersion: 1,
		CreatedAt: transaction.organization.CreatedAt, UpdatedAt: transaction.organization.CreatedAt}, true, nil
}

func (transaction *coreTransaction) LookupPolicyAttachment(_ context.Context, account iamv1.AccountID, id iamv1.PolicyAttachmentID) (iamv1.PolicyAttachment, bool, error) {
	attachment, found := transaction.attachments[id]
	return attachment, found && attachment.AccountID == account, nil
}

func (transaction *coreTransaction) CreatePolicyAttachment(_ context.Context, mutation PolicyAttachmentMutation) (iamv1.PolicyAttachment, error) {
	transaction.attachmentSession = mutation.ActorSessionID
	if _, found := transaction.users[iamv1.PrincipalID(mutation.Attachment.Target.ID)]; !found {
		return iamv1.PolicyAttachment{}, ErrForbidden
	}
	if mutation.PolicyResourceVersion != 1 {
		return iamv1.PolicyAttachment{}, ErrConflict
	}
	if existing, found := transaction.attachments[mutation.Attachment.ID]; found {
		if existing.RevokedAt != nil || existing.PolicyID != mutation.Attachment.PolicyID || existing.Target != mutation.Attachment.Target {
			return iamv1.PolicyAttachment{}, ErrConflict
		}
		return existing, nil
	}
	transaction.attachments[mutation.Attachment.ID] = mutation.Attachment
	return mutation.Attachment, nil
}

func (transaction *coreTransaction) RevokePolicyAttachment(_ context.Context, mutation PolicyAttachmentRevocationMutation) (iamv1.Revocation, bool, error) {
	transaction.revocationSession = mutation.ActorSessionID
	attachment, found := transaction.attachments[mutation.AttachmentID]
	if !found || attachment.AccountID != mutation.AccountID {
		return iamv1.Revocation{}, false, ErrForbidden
	}
	if attachment.ResourceVersion != mutation.ResourceVersion || attachment.RevokedAt != nil {
		return iamv1.Revocation{}, false, ErrConflict
	}
	attachment.ResourceVersion++
	attachment.UpdatedAt = transaction.now
	now := transaction.now
	attachment.RevokedAt = &now
	transaction.attachments[attachment.ID] = attachment
	return iamv1.Revocation{APIVersion: iamv1.APIVersion, Kind: "Revocation", ID: string(attachment.ID), ResourceVersion: attachment.ResourceVersion, RevokedAt: now}, true, nil
}

func (transaction *coreTransaction) Readiness(context.Context) (ReadinessSnapshot, error) {
	return ReadinessSnapshot{
		Ready:         transaction.status.State == iamv1.BootstrapReady,
		SchemaVersion: SchemaVersion,
		CheckedAt:     transaction.now,
	}, nil
}

func (transaction *coreTransaction) CheckCurrentAuthorizationProfiles(context.Context) error {
	return transaction.profileErr
}

func (*coreTransaction) LookupAuthorizationProfile(_ context.Context, reference iamv1.AuthorizationProfileReference) (iamv1.AuthorizationProfile, bool, error) {
	profile, found := iamv1.LookupAuthorizationProfile(reference.Product)
	if !found || iamv1.CheckAuthorizationProfileReference(profile, reference) != nil {
		return iamv1.AuthorizationProfile{}, false, nil
	}
	return profile, true, nil
}

func coreBootstrap(t *testing.T) iamv1.BootstrapDocument {
	t.Helper()
	service := func(purpose iamv1.ServicePurpose, principalID, credential string) iamv1.BootstrapServiceCredential {
		return iamv1.BootstrapServiceCredential{
			Purpose:     purpose,
			PrincipalID: iamv1.PrincipalID(principalID),
			Credential:  coreSecret(t, credential),
		}
	}
	return iamv1.BootstrapDocument{
		APIVersion:     iamv1.APIVersion,
		Kind:           "IAMBootstrap",
		InstallationID: "installation-example",
		Organization:   iamv1.InitialOrganization{ID: "organization-example", DisplayName: "Example Organization"},
		Administrator: iamv1.InitialAdministrator{
			ID:          "principal-admin",
			LoginName:   "admin",
			DisplayName: "Initial Administrator",
			Password:    coreSecret(t, "Initial-Admin-Password-49!"),
		},
		Services: []iamv1.BootstrapServiceCredential{
			service(iamv1.ServiceIAM, "service-iam", "mx1.IAMCoreCredential00000000000000000000001"),
			service(iamv1.ServicePaaS, "service-paas", "mx1.PaaSCoreCredential0000000000000000000001"),
			service(iamv1.ServiceAudit, "service-audit", "mx1.AuditCoreCredential000000000000000000001"),
			service(iamv1.ServiceInstallationVerifier, "service-verifier", "mx1.VerifierCoreCredential000000000000000001"),
		},
	}
}

func coreServiceCredential(
	t *testing.T,
	document iamv1.BootstrapDocument,
	purpose iamv1.ServicePurpose,
) iamv1.Secret {
	t.Helper()
	for _, service := range document.Services {
		if service.Purpose == purpose {
			return service.Credential
		}
	}
	t.Fatalf("bootstrap service purpose %q is absent", purpose)
	return iamv1.Secret{}
}

func coreSecret(t *testing.T, value string) iamv1.Secret {
	t.Helper()
	secret, err := iamv1.NewSecret(value)
	if err != nil {
		t.Fatalf("create IAM test secret: %v", err)
	}
	return secret
}

func coreAuthorizationRequest(t *testing.T, request iamv1.AuthorizationRequest, mode iamv1.AuthorizationResourceMode, usage iamv1.AuthorizationCollectionUsage) iamv1.AuthorizationRequest {
	t.Helper()
	result, err := iamv1.NewAuthorizationRequest(request.Action, request.Resource, mode, usage, request.RequestID, request.CorrelationID)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestAuthorizationRequestDigestCommitsEveryBindingAndDomain(t *testing.T) {
	request := coreAuthorizationRequest(t, iamv1.AuthorizationRequest{Action: iamv1.ActionIAMAccountRead,
		Resource: iamv1.ResourceReference{Kind: iamv1.ResourceAccount, ID: "collection"}, RequestID: "request-digest", CorrelationID: "correlation-digest"},
		iamv1.AuthorizationResourceCollection, iamv1.AuthorizationCollectionList)
	for _, domain := range []string{"authorization", "installation-verification"} {
		baseline, err := digestSanitized(domain, request)
		if err != nil {
			t.Fatal(err)
		}
		for name, mutate := range map[string]func(*iamv1.AuthorizationRequest){
			"product":      func(r *iamv1.AuthorizationRequest) { r.Profile.Product = "other" },
			"revision":     func(r *iamv1.AuthorizationRequest) { r.Profile.Revision++ },
			"digest":       func(r *iamv1.AuthorizationRequest) { r.Profile.ContentDigest = "sha256:" + strings.Repeat("0", 64) },
			"mode":         func(r *iamv1.AuthorizationRequest) { r.ResourceMode = iamv1.AuthorizationResourceInstance },
			"usage":        func(r *iamv1.AuthorizationRequest) { r.CollectionUsage = iamv1.AuthorizationCollectionCreate },
			"usage absent": func(r *iamv1.AuthorizationRequest) { r.CollectionUsage = "" },
			"action":       func(r *iamv1.AuthorizationRequest) { r.Action = iamv1.ActionIAMAccountCreate },
			"kind":         func(r *iamv1.AuthorizationRequest) { r.Resource.Kind = iamv1.ResourceUser },
			"id":           func(r *iamv1.AuthorizationRequest) { r.Resource.ID = "account-other" },
			"request":      func(r *iamv1.AuthorizationRequest) { r.RequestID = "request-other" },
			"correlation":  func(r *iamv1.AuthorizationRequest) { r.CorrelationID = "correlation-other" },
		} {
			t.Run(domain+"/"+name, func(t *testing.T) {
				changed := request
				mutate(&changed)
				digest, err := digestSanitized(domain, changed)
				if err != nil || digest == baseline {
					t.Fatalf("binding not committed: %v", err)
				}
			})
		}
		repeated, err := digestSanitized(domain, request)
		if err != nil || repeated != baseline {
			t.Fatal("original digest changed")
		}
	}
	ordinary, _ := digestSanitized("authorization", request)
	probe, _ := digestSanitized("installation-verification", request)
	if ordinary == probe {
		t.Fatal("probe and ordinary authorization share a digest domain")
	}
}
