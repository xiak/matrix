package identityaccess

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
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

func TestLoginChallengeIssuerRequiresExactLockedCeremony(t *testing.T) {
	tx := newCoreTransaction()
	service, err := newCoreAuthority(&coreRepository{transaction: tx}, Config{NewID: func(string) (string, error) { return "challenge-issued", nil }})
	if err != nil {
		t.Fatal(err)
	}
	for _, original := range []struct {
		state         LoginAuthenticationState
		forced        bool
		purpose, step string
	}{
		{LoginAuthenticationState{State: "BOUND", Revision: 2, FactorID: "factor-one"}, false, "LOGIN", "TOTP"},
		{LoginAuthenticationState{State: "RECOVERY_REQUIRED", Revision: 3}, false, "LOGIN", "RECOVER"},
		{LoginAuthenticationState{State: "NEVER_BOUND", Revision: 1, EnrollmentRequired: true}, false, "ENROLLMENT", "ENROLLMENT"},
		{LoginAuthenticationState{State: "NEVER_BOUND", Revision: 1, EnrollmentRequired: true}, true, "ENROLLMENT", "PASSWORD_CHANGE"},
		{LoginAuthenticationState{State: "NEVER_BOUND", Revision: 1}, false, "", ""},
		{LoginAuthenticationState{State: "BOUND", Revision: 2, FactorID: "factor-one", EnrollmentRequired: true}, false, "", ""},
		{LoginAuthenticationState{State: "NEVER_BOUND", Revision: 1, PasswordResetReason: iamv1.PasswordResetExpired}, false, "LOGIN", "PASSWORD_CHANGE"},
		{LoginAuthenticationState{State: "REMOVED", Revision: 3, PasswordResetReason: iamv1.PasswordResetAgeUnknown}, false, "LOGIN", "PASSWORD_CHANGE"},
		{LoginAuthenticationState{State: "NEVER_BOUND", Revision: 1, EnrollmentRequired: true, PasswordResetReason: iamv1.PasswordResetExpired}, false, "ENROLLMENT", "PASSWORD_CHANGE"},
		{LoginAuthenticationState{State: "NEVER_BOUND", Revision: 1, PasswordExpiryMode: iamv1.PasswordExpiryAdminReset, PasswordResetReason: iamv1.PasswordResetExpired}, true, "", ""},
		{LoginAuthenticationState{State: "NEVER_BOUND", Revision: 1, EnrollmentRequired: true, PasswordExpiryMode: iamv1.PasswordExpiryAdminReset, PasswordResetReason: iamv1.PasswordResetAgeUnknown}, true, "", ""},
		{LoginAuthenticationState{State: "BOUND", Revision: 2, FactorID: "factor-one", PasswordExpiryMode: iamv1.PasswordExpiryAdminReset, PasswordResetReason: iamv1.PasswordResetExpired}, false, "LOGIN", "TOTP"},
		{LoginAuthenticationState{State: "RECOVERY_REQUIRED", Revision: 3, PasswordResetReason: iamv1.PasswordResetExpired}, false, "LOGIN", "RECOVER"},
		{LoginAuthenticationState{State: "NEVER_BOUND", Revision: 1, PasswordResetReason: "UNKNOWN"}, false, "", ""},
		{LoginAuthenticationState{State: "NEVER_BOUND", Revision: 1, PasswordExpiryMode: "UNKNOWN", PasswordResetReason: iamv1.PasswordResetExpired}, false, "", ""},
	} {
		if original.state.PasswordExpiryMode == "" {
			original.state.PasswordExpiryMode = iamv1.PasswordExpiryChange
		}
		for _, sample := range []struct{ purpose, step string }{
			{"LOGIN", "TOTP"}, {"LOGIN", "RECOVER"}, {"LOGIN", "PASSWORD_CHANGE"},
			{"ENROLLMENT", "ENROLLMENT"}, {"ENROLLMENT", "PASSWORD_CHANGE"}, {"RECOVERY", "ENROLLMENT"},
		} {
			tx.loginChallenge = iamv1.AuthenticationChallenge{APIVersion: iamv1.APIVersion, Kind: "AuthenticationChallenge", ID: "challenge-issued",
				Purpose: sample.purpose, NextStep: sample.step, ExpiresAt: tx.now.Add(5 * time.Minute)}
			result, err := service.createLoginChallenge(t.Context(), tx, PasswordAttempt{MustChangePassword: original.forced}, original.state,
				"request-one", "sha256:"+strings.Repeat("a", 64))
			if sample.purpose == original.purpose && sample.step == original.step {
				if err != nil || iamv1.ValidateLoginResponse(result) != nil || result.Credential.Present() || result.Session != (iamv1.Session{}) {
					t.Fatalf("exact ceremony was not issued as a restricted challenge: state=%+v: %v", original.state, err)
				}
			} else if !errors.Is(err, ErrUnavailable) || result.ChallengeCredential.Present() || result.Credential.Present() || result.Challenge != nil {
				t.Fatalf("issuer leaked another ceremony or secret: state=%+v: %v", original.state, err)
			}
		}
	}
}

func TestEnrollmentInspectionRequiresExactCeremonyAndPrivateSubject(t *testing.T) {
	tx := newCoreTransaction()
	service, err := newCoreAuthority(&coreRepository{transaction: tx}, Config{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Bootstrap(t.Context(), coreBootstrap(t)); err != nil {
		t.Fatal(err)
	}
	issued, err := service.credentials.Issue(authority.CredentialAuthenticationChallenge, "first-enrollment")
	if err != nil {
		t.Fatal(err)
	}
	tx.challengeLookupDigest = issued.LookupDigest
	for _, step := range []string{"PASSWORD_CHANGE", "ENROLLMENT"} {
		t.Run(step, func(t *testing.T) {
			tx.challengeCredential = AuthenticationChallengeCredential{AccountID: tx.organization.ID, UserID: tx.principal.ID,
				ID: "first-enrollment", Purpose: "ENROLLMENT", NextStep: step, VerificationDigest: issued.VerificationDigest}
			original := EnrollmentChallengeInspection{CredentialGeneration: 1, FactorRevision: 1, State: iamv1.EnrollmentChallengeState{
				Challenge: iamv1.AuthenticationChallenge{APIVersion: iamv1.APIVersion, Kind: "AuthenticationChallenge", ID: "first-enrollment",
					Purpose: "ENROLLMENT", NextStep: step, ExpiresAt: tx.now.Add(5 * time.Minute)}}}
			contact := iamv1.NotificationContact{APIVersion: iamv1.APIVersion, Kind: "NotificationContact", AccountID: tx.organization.ID,
				UserID: tx.principal.ID, State: "NONE", ResourceVersion: 0}
			if step == "ENROLLMENT" {
				original.State.NotificationContact = &contact
			}
			tx.enrollmentInspection = original
			request := iamv1.InspectEnrollmentChallengeRequest{ChallengeCredential: issued.Credential}
			response, err := service.InspectEnrollmentChallenge(t.Context(), "first-enrollment", request)
			if err != nil || iamv1.ValidateEnrollmentChallengeState(response) != nil || response.Challenge.NextStep != step {
				t.Fatal("exact original enrollment ceremony could not be observed", err)
			}
			for name, mutate := range map[string]func(*EnrollmentChallengeInspection){
				"missing_generation": func(v *EnrollmentChallengeInspection) { v.CredentialGeneration = 0 },
				"wrong_challenge":    func(v *EnrollmentChallengeInspection) { v.State.Challenge.ID = "another-challenge" },
				"wrong_purpose":      func(v *EnrollmentChallengeInspection) { v.State.Challenge.Purpose = "RECOVERY" },
				"wrong_step":         func(v *EnrollmentChallengeInspection) { v.State.Challenge.NextStep = "TOTP" },
				"foreign_contact": func(v *EnrollmentChallengeInspection) {
					foreign := contact
					foreign.AccountID = "foreign-account"
					v.State.NotificationContact = &foreign
				},
				"foreign_user": func(v *EnrollmentChallengeInspection) {
					foreign := contact
					foreign.UserID = "another-user"
					v.State.NotificationContact = &foreign
				},
				"wrong_stage_projection": func(v *EnrollmentChallengeInspection) {
					if step == "PASSWORD_CHANGE" {
						v.State.NotificationContact = &contact
					} else {
						v.State.NotificationContact = nil
					}
				},
			} {
				t.Run(name, func(t *testing.T) {
					tx.enrollmentInspection = original
					mutate(&tx.enrollmentInspection)
					result, err := service.InspectEnrollmentChallenge(t.Context(), "first-enrollment", request)
					if !errors.Is(err, ErrUnavailable) || result.Challenge.ID != "" || result.NotificationContact != nil || result.Enrollment != nil {
						t.Fatal("invalid authority projection escaped to the caller", err)
					}
				})
			}
		})
	}
	for _, purpose := range []string{"LOGIN", "RECOVERY"} {
		tx.challengeCredential.Purpose = purpose
		tx.enrollmentReads = 0
		_, err := service.InspectEnrollmentChallenge(t.Context(), "first-enrollment", iamv1.InspectEnrollmentChallengeRequest{ChallengeCredential: issued.Credential})
		if !errors.Is(err, ErrUnauthenticated) || tx.enrollmentReads != 0 {
			t.Fatal("another ceremony acquired initial enrollment observation", err)
		}
	}
	if len(tx.sessions) != 0 || len(tx.totpReservations) != 0 {
		t.Fatal("read-only enrollment inspection created authentication authority")
	}
}

func TestRequiredInitialEnrollmentNeverFallsBackToPasswordSession(t *testing.T) {
	for _, forced := range []bool{false, true} {
		t.Run(fmt.Sprintf("forced_%t", forced), func(t *testing.T) {
			tx := newCoreTransaction()
			service, err := newCoreAuthority(&coreRepository{transaction: tx}, Config{NewID: func(prefix string) (string, error) { return prefix + "-test", nil }})
			if err != nil {
				t.Fatal(err)
			}
			document := coreBootstrap(t)
			if _, err := service.Bootstrap(t.Context(), document); err != nil {
				t.Fatal(err)
			}
			user := tx.users[document.Administrator.ID]
			user.MustChangePassword = forced
			tx.users[user.ID] = user
			tx.loginAuthenticationState = &LoginAuthenticationState{State: "NEVER_BOUND", Revision: 1, EnrollmentRequired: true, PasswordExpiryMode: iamv1.PasswordExpiryChange}
			step := "ENROLLMENT"
			if forced {
				step = "PASSWORD_CHANGE"
			}
			tx.loginChallenge = iamv1.AuthenticationChallenge{APIVersion: iamv1.APIVersion, Kind: "AuthenticationChallenge", ID: "authentication-challenge-test",
				Purpose: "ENROLLMENT", NextStep: step, ExpiresAt: tx.now.Add(5 * time.Minute)}
			response, err := service.Login(t.Context(), iamv1.LoginRequest{LoginName: document.Administrator.LoginName, Password: document.Administrator.Password, RequestID: "initial-login"})
			if err != nil || iamv1.ValidateLoginResponse(response) != nil || response.Outcome != "CHALLENGE_REQUIRED" ||
				response.Challenge.NextStep != step || response.Credential.Present() || response.Session != (iamv1.Session{}) || len(tx.sessions) != 0 {
				t.Fatal("required first enrollment created or leaked a password Session", err)
			}
		})
	}
}

func TestPasswordOnlyExpiryCannotIssueOrdinarySession(t *testing.T) {
	for _, sample := range []struct {
		name, state, purpose string
		revision             uint64
		enrollment           bool
		mode                 iamv1.PasswordExpiryMode
		reason               iamv1.PasswordResetReason
	}{
		{"expired", "NEVER_BOUND", "LOGIN", 1, false, iamv1.PasswordExpiryChange, iamv1.PasswordResetExpired},
		{"unknown_age", "REMOVED", "LOGIN", 3, false, iamv1.PasswordExpiryChange, iamv1.PasswordResetAgeUnknown},
		{"required_enrollment", "NEVER_BOUND", "ENROLLMENT", 1, true, iamv1.PasswordExpiryChange, iamv1.PasswordResetExpired},
		{"missing_mode", "NEVER_BOUND", "", 1, false, "", ""},
		{"invalid_reason", "NEVER_BOUND", "", 1, false, iamv1.PasswordExpiryChange, "UNKNOWN"},
	} {
		t.Run(sample.name, func(t *testing.T) {
			tx := newCoreTransaction()
			service, err := newCoreAuthority(&coreRepository{transaction: tx}, Config{NewID: func(prefix string) (string, error) { return prefix + "-expiry", nil }})
			if err != nil {
				t.Fatal(err)
			}
			document := coreBootstrap(t)
			if _, err := service.Bootstrap(t.Context(), document); err != nil {
				t.Fatal(err)
			}
			tx.loginAuthenticationState = &LoginAuthenticationState{State: sample.state, Revision: sample.revision,
				EnrollmentRequired: sample.enrollment, PasswordExpiryMode: sample.mode, PasswordResetReason: sample.reason}
			tx.loginChallenge = iamv1.AuthenticationChallenge{APIVersion: iamv1.APIVersion, Kind: "AuthenticationChallenge",
				ID: "authentication-challenge-expiry", Purpose: sample.purpose, NextStep: "PASSWORD_CHANGE", ExpiresAt: tx.now.Add(5 * time.Minute)}
			response, err := service.Login(t.Context(), iamv1.LoginRequest{LoginName: document.Administrator.LoginName,
				Password: document.Administrator.Password, RequestID: "expiry-login"})
			if response.Credential.Present() || response.Session != (iamv1.Session{}) || len(tx.sessions) != 0 || len(tx.totpReservations) != 0 {
				t.Fatal("password-only expiry created ordinary or synthetic MFA authority")
			}
			if sample.purpose == "" {
				if !errors.Is(err, ErrUnavailable) || response.Challenge != nil || response.ChallengeCredential.Present() {
					t.Fatal("missing or unknown expiry authority became a password-only fallback", err)
				}
			} else if err != nil || response.Outcome != iamv1.LoginChallengeRequired || response.Challenge == nil ||
				response.Challenge.Purpose != sample.purpose || response.Challenge.NextStep != "PASSWORD_CHANGE" || !response.ChallengeCredential.Present() {
				t.Fatal("password expiry did not preserve its exact restricted next step", err)
			}
		})
	}
}

func TestPasswordResetTerminalRequiresCommittedProofAndContainsNoAuthority(t *testing.T) {
	for _, sample := range []struct {
		name                                  string
		reason                                iamv1.PasswordResetReason
		enrollment, wrongPassword, failCommit bool
	}{
		{"expired", iamv1.PasswordResetExpired, false, false, false},
		{"age_unknown_required_enrollment", iamv1.PasswordResetAgeUnknown, true, false, false},
		{"wrong_password", iamv1.PasswordResetExpired, false, true, false},
		{"unknown_commit", iamv1.PasswordResetExpired, false, false, true},
		{"invalid_result", "UNKNOWN", false, false, false},
	} {
		t.Run(sample.name, func(t *testing.T) {
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
			tx.loginAuthenticationState = &LoginAuthenticationState{State: "NEVER_BOUND", Revision: 1,
				EnrollmentRequired: sample.enrollment, PasswordExpiryMode: iamv1.PasswordExpiryAdminReset, PasswordResetReason: iamv1.PasswordResetExpired}
			tx.passwordResetReason = sample.reason
			if sample.failCommit {
				repository.afterTransaction = func(err error) error {
					if tx.passwordResetRequirement != nil {
						return ErrUnavailable
					}
					return err
				}
			}
			password := document.Administrator.Password
			if sample.wrongPassword {
				password, err = iamv1.NewSecret("Wrong-Password-For-Expiry-73!")
				if err != nil {
					t.Fatal(err)
				}
			}
			response, err := service.Login(t.Context(), iamv1.LoginRequest{LoginName: document.Administrator.LoginName, Password: password, RequestID: "terminal-login"})
			if response.Session != (iamv1.Session{}) || response.Credential.Present() || response.Challenge != nil || response.ChallengeCredential.Present() ||
				response.MustChangePassword || len(tx.sessions) != 0 || len(tx.totpReservations) != 0 {
				t.Fatal("administrator reset instruction created authentication authority")
			}
			if sample.wrongPassword {
				if !errors.Is(err, ErrUnauthenticated) || tx.passwordResetRequirement != nil || len(tx.rejectedAttempts) != 1 {
					t.Fatal("wrong password disclosed age or created terminal evidence", err)
				}
				return
			}
			if sample.failCommit || sample.reason == "UNKNOWN" {
				if !errors.Is(err, ErrUnavailable) || response != (iamv1.LoginResponse{}) {
					t.Fatal("uncommitted/invalid terminal leaked", err)
				}
			} else if err != nil || response.Outcome != iamv1.LoginAdminResetRequired || response.PasswordResetReason != sample.reason || iamv1.ValidateLoginResponse(response) != nil {
				t.Fatal("committed terminal was not returned", err)
			}
			mutation := tx.passwordResetRequirement
			if mutation == nil || mutation.PasswordAttempt == nil || mutation.TOTPAttempt != nil || mutation.VerifiedStep != 0 ||
				mutation.PasswordAttempt.ID == "" || mutation.PasswordAttempt.Purpose != PasswordAttemptLogin ||
				mutation.AuditEvent.Action != auditv1.ActionIAMUserPasswordResetRequired || mutation.AuditEvent.Result != auditv1.ResultDenied ||
				mutation.AuditEvent.Actor.ID != auditv1.ActorID(document.Administrator.ID) || mutation.AuditEvent.Target.ID != string(document.Administrator.ID) ||
				mutation.AuditEvent.RequestID != "terminal-login" || auditv1.ValidateEventForSource(auditv1.SourceIAM, mutation.AuditEvent) != nil {
				t.Fatal("terminal omitted its exact password origin or closed denial")
			}
		})
	}
}

func TestChallengePurposeRejectsCrossCeremonyBeforeAttemptReservation(t *testing.T) {
	for _, sample := range []struct{ purpose, step, operation string }{
		{"ENROLLMENT", "ENROLLMENT", "RECOVERY_CONFIRM"},
		{"LOGIN", "ENROLLMENT", "RECOVERY_CONFIRM"},
		{"RECOVERY", "TOTP", "RECOVERY_CODE"},
		{"ENROLLMENT", "TOTP", "RECOVERY_CODE"},
		{"RECOVERY", "ENROLLMENT", "LOGIN"},
		{"ENROLLMENT", "TOTP", "LOGIN"},
		{"", "TOTP", "LOGIN"},
	} {
		t.Run(sample.purpose+"_"+sample.step+"_"+sample.operation, func(t *testing.T) {
			tx := newCoreTransaction()
			service, err := newCoreAuthority(&coreRepository{transaction: tx}, Config{})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := service.Bootstrap(t.Context(), coreBootstrap(t)); err != nil {
				t.Fatal(err)
			}
			issued, err := service.credentials.Issue(authority.CredentialAuthenticationChallenge, "challenge-purpose")
			if err != nil {
				t.Fatal(err)
			}
			tx.challengeLookupDigest = issued.LookupDigest
			tx.challengeCredential = AuthenticationChallengeCredential{AccountID: tx.organization.ID, UserID: tx.principal.ID,
				ID: "challenge-purpose", Purpose: sample.purpose, NextStep: sample.step, VerificationDigest: issued.VerificationDigest}
			if sample.operation == "LOGIN" {
				code, _ := iamv1.NewSecret("123456")
				var response iamv1.LoginResponse
				response, err = service.VerifyAuthenticationChallenge(t.Context(), "challenge-purpose", iamv1.VerifyAuthenticationChallengeRequest{
					RequestID: "request-purpose", ChallengeCredential: issued.Credential, Code: code})
				if response.Credential.Present() || response.ChallengeCredential.Present() || response.Session != (iamv1.Session{}) {
					t.Fatal("cross-purpose challenge returned authentication material")
				}
			} else {
				_, err = service.reserveRecoveryAttempt(t.Context(), "challenge-purpose", issued.Credential, sample.operation)
			}
			want := ErrUnauthenticated
			if sample.purpose == "" {
				want = ErrUnavailable
			}
			if !errors.Is(err, want) || len(tx.totpReservations) != 0 || tx.totpAttemptReads != 0 {
				t.Fatal("another ceremony reached the attempt budget or factor material", err)
			}
		})
	}
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
				stored.HasUnrecognizedAuthenticators = true
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

func TestPasswordChangeRejectsRecentHistoryAndAStalePreparedHead(t *testing.T) {
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
	login, err := service.Login(t.Context(), iamv1.LoginRequest{LoginName: "admin", Password: document.Administrator.Password, RequestID: "history-login"})
	if err != nil {
		t.Fatal(err)
	}
	service.passwords = authority.NewPasswordHasher(passwordEntropyProbe{t, repository})
	current := document.Administrator.Password
	sequence := 0
	change := func(next iamv1.Secret) error {
		sequence++
		_, err := service.ChangePassword(t.Context(), login.Credential, iamv1.ChangePasswordRequest{
			CurrentPassword: current, NewPassword: next, RequestID: fmt.Sprintf("history-change-%d", sequence)})
		if err == nil {
			current = next
		}
		return err
	}
	if err := change(coreSecret(t, "History-First-Replacement-93!")); err != nil {
		t.Fatal(err)
	}
	beforeHash, beforeVersion := tx.passwords[tx.principal.ID], tx.principal.ResourceVersion
	if err := change(document.Administrator.Password); !errors.Is(err, ErrInvalidArgument) ||
		tx.passwords[tx.principal.ID] != beforeHash || tx.principal.ResourceVersion != beforeVersion ||
		len(tx.passwordHistories[tx.principal.ID]) != 1 || len(tx.rejectedAttempts) != 1 {
		t.Fatal("recent password reuse was accepted, mutated state or left its reservation live", err)
	}
	if err := change(coreSecret(t, "History-Second-Replacement-94!")); err != nil {
		t.Fatal("rejected replacement prevented a new bounded attempt", err)
	}
	// Default one means one retired password, not every retained verifier.
	if err := change(document.Administrator.Password); err != nil {
		t.Fatal("history outside the selected window became an extra rule", err)
	}
	beforeHash, beforeVersion = tx.passwords[tx.principal.ID], tx.principal.ResourceVersion
	prepared := false
	repository.afterTransaction = func(err error) error {
		if !prepared && err == nil {
			prepared = true
			// A corrupt/stale read is not a new authorization. The final
			// comparison must reject it even if the current hash is unchanged.
			tx.passwordHistories[tx.principal.ID] = []authority.PasswordHash{dummyPasswordHash}
		}
		return err
	}
	if err := change(coreSecret(t, "History-Final-Replacement-95!")); !errors.Is(err, ErrUnauthenticated) ||
		tx.passwords[tx.principal.ID] != beforeHash || tx.principal.ResourceVersion != beforeVersion {
		t.Fatal("stale prepared history changed a credential", err)
	}
}

func TestUserCreationUsesAccountRulesOutsideTheTransaction(t *testing.T) {
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
	login, err := service.Login(t.Context(), iamv1.LoginRequest{LoginName: "admin", Password: document.Administrator.Password, RequestID: "creation-rules-login"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.ChangePassword(t.Context(), login.Credential, iamv1.ChangePasswordRequest{CurrentPassword: document.Administrator.Password,
		NewPassword: coreSecret(t, "Creation-Actor-Password-74!"), RequestID: "creation-rules-password"}); err != nil {
		t.Fatal(err)
	}
	rules := iamv1.AccountPasswordSettings{ExpiryMode: iamv1.PasswordExpiryChange, MinimumLength: 28, RequireDigit: true, HistoryCount: 24}
	prepared := false
	tx.userCreationSettings = func(read AccountRead) (iamv1.AccountPasswordSettings, uint64, error) {
		prepared = true
		return rules, 7, nil
	}
	service.passwords = authority.NewPasswordHasher(passwordEntropyProbe{t, repository})
	request := iamv1.CreateUserRequest{LoginName: "rules.target", DisplayName: "Rules target", RequestID: "rules-create",
		InitialPassword: coreSecret(t, "short but baseline valid 7")}
	before := len(tx.users)
	if _, err := service.CreateUser(t.Context(), login.Credential, request); !errors.Is(err, ErrInvalidArgument) || len(tx.users) != before {
		t.Fatal("creation ignored the current Account length rule", err)
	}
	request.InitialPassword = coreSecret(t, "a sufficiently long passphrase without digits")
	if _, err := service.CreateUser(t.Context(), login.Credential, request); !errors.Is(err, ErrInvalidArgument) || len(tx.users) != before {
		t.Fatal("creation ignored explicit Account composition", err)
	}
	request.InitialPassword = coreSecret(t, "a sufficiently long passphrase with 7")
	repository.afterTransaction = func(err error) error { return ErrUnavailable }
	if _, err := service.CreateUser(t.Context(), login.Credential, request); !errors.Is(err, ErrUnavailable) || len(tx.users) != before {
		t.Fatal("unknown preparation produced a user", err)
	}
	repository.afterTransaction = func(err error) error {
		if prepared && err == nil {
			tx.profileErr = ErrUnavailable
		}
		return err
	}
	if _, err := service.CreateUser(t.Context(), login.Credential, request); !errors.Is(err, ErrUnavailable) || len(tx.users) != before {
		t.Fatal("creation reused an earlier authorization after preparation", err)
	}
	repository.afterTransaction, tx.profileErr = nil, nil
	created, err := service.CreateUser(t.Context(), login.Credential, request)
	if err != nil || created.LoginName != request.LoginName || tx.userCreationMutation == nil || tx.userCreationMutation.ExpectedSettingsVersion != 7 {
		t.Fatal("creation lost its exact rule version", err)
	}
}

func TestAdministratorPasswordResetPreparesOutsideLocksAndRechecksAuthority(t *testing.T) {
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
	login, err := service.Login(t.Context(), iamv1.LoginRequest{LoginName: "admin", Password: document.Administrator.Password, RequestID: "reset-login"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.ChangePassword(t.Context(), login.Credential, iamv1.ChangePasswordRequest{CurrentPassword: document.Administrator.Password,
		NewPassword: coreSecret(t, "Reset-Actor-Password-73!"), RequestID: "reset-actor-change"}); err != nil {
		t.Fatal(err)
	}
	current, recent, replacement := coreSecret(t, "Reset-Target-Current-85!"), coreSecret(t, "Reset-Target-History-86!"), coreSecret(t, "Reset-Target-Replacement-87!")
	user, err := service.CreateUser(t.Context(), login.Credential, iamv1.CreateUserRequest{LoginName: "reset.target", DisplayName: "Reset target", InitialPassword: current, RequestID: "reset-target-create"})
	if err != nil {
		t.Fatal(err)
	}
	historyHash, err := service.passwords.Hash(recent)
	if err != nil {
		t.Fatal(err)
	}
	material := PasswordReplacementMaterial{PasswordHash: tx.passwords[user.ID], CredentialGeneration: 2,
		PasswordHistory: []authority.PasswordHash{historyHash}, HistoryDigest: "sha256:" + strings.Repeat("b", 64),
		PasswordSettings: authority.DefaultPasswordSettings(), SettingsVersion: 1}
	prepared, writes := false, 0
	tx.passwordResetRead = func(read AccountRead, target iamv1.PrincipalID, version uint64) (PasswordReplacementMaterial, error) {
		if read.AccountID != user.AccountID || read.ActorPrincipalID != tx.principal.ID || target != user.ID || version != user.ResourceVersion || read.DecisionID == "" {
			t.Fatal("password material read was not bound to the authorized original target")
		}
		prepared = true
		return material, nil
	}
	tx.userChange = func(mutation UserChange) (iamv1.User, error) {
		if !prepared || mutation.ExpectedPassword == nil || mutation.ExpectedPassword.PasswordHash != material.PasswordHash ||
			mutation.ExpectedPassword.CredentialGeneration != material.CredentialGeneration || mutation.ExpectedPassword.HistoryDigest != material.HistoryDigest ||
			!slices.Equal(mutation.ExpectedPassword.PasswordHistory, material.PasswordHistory) ||
			mutation.AccountID != user.AccountID || mutation.PrincipalID != user.ID || mutation.Status != nil || mutation.PasswordHash == nil {
			t.Fatal("final reset lost exact preparation")
		}
		matches, err := authority.NewPasswordHasher(nil).Verify(replacement, *mutation.PasswordHash)
		if err != nil || !matches {
			t.Fatal("final reset did not carry the actual newly computed verifier")
		}
		writes++
		return user, nil
	}
	service.passwords = authority.NewPasswordHasher(passwordEntropyProbe{t, repository})
	request := iamv1.ResetUserPasswordRequest{InitialPassword: replacement, ResourceVersion: user.ResourceVersion, RequestID: "reset-request"}
	for _, secret := range []iamv1.Secret{current, recent} {
		request.InitialPassword = secret
		if _, err := service.ResetUserPassword(t.Context(), login.Credential, user.ID, request); !errors.Is(err, ErrInvalidArgument) || writes != 0 {
			t.Fatal("reset accepted current/recent password", err)
		}
	}
	request.InitialPassword = replacement
	prepared = false
	repository.afterTransaction = func(err error) error { return ErrUnavailable }
	if _, err := service.ResetUserPassword(t.Context(), login.Credential, user.ID, request); !errors.Is(err, ErrUnavailable) || writes != 0 {
		t.Fatal("unknown preparation committed a reset", err)
	}
	repository.afterTransaction = func(err error) error {
		if prepared && err == nil {
			tx.profileErr = ErrUnavailable
		}
		return err
	}
	if _, err := service.ResetUserPassword(t.Context(), login.Credential, user.ID, request); !errors.Is(err, ErrUnavailable) || writes != 0 {
		t.Fatal("reset reused past authority after preparation", err)
	}
	repository.afterTransaction, tx.profileErr = nil, nil
	if _, err := service.ResetUserPassword(t.Context(), login.Credential, user.ID, request); err != nil || writes != 1 {
		t.Fatal("valid prepared reset failed", err)
	}
	if encoded, err := json.Marshal(material); err == nil || len(encoded) != 0 || strings.Contains(fmt.Sprintf("%+v %#v", material, material), string(material.PasswordHash)) {
		t.Fatal("password preparation was serializable")
	}
}

func TestPasswordResetCompletionUsesCurrentActorAndOnlyOriginalHistory(t *testing.T) {
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
	login, err := service.Login(t.Context(), iamv1.LoginRequest{LoginName: "admin", Password: document.Administrator.Password, RequestID: "reset-history-login"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.ChangePassword(t.Context(), login.Credential, iamv1.ChangePasswordRequest{CurrentPassword: document.Administrator.Password,
		NewPassword: coreSecret(t, "Reset-History-Actor-Password-73!"), RequestID: "reset-history-change"}); err != nil {
		t.Fatal(err)
	}
	// No target USER or password material exists in this fake. Historical
	// lookup must not consult a mutable target or call either reset phase.
	original := iamv1.UserPasswordResetCompletion{APIVersion: iamv1.APIVersion, Kind: "UserPasswordResetCompletion",
		AccountID: tx.organization.ID, ActorPrincipalID: tx.principal.ID, UserID: "reset-history-target", RequestID: "reset-original",
		ExpectedResourceVersion: 4, ResultingResourceVersion: 5, EventID: "reset-original-event", OccurredAt: tx.now.Add(-time.Minute)}
	reads := 0
	result, readErr := original, error(nil)
	tx.passwordResetCompletionRead = func(read AccountRead, target iamv1.PrincipalID, command string, version uint64) (iamv1.UserPasswordResetCompletion, error) {
		reads++
		if !repository.inTransaction || read.AccountID != original.AccountID || read.ActorPrincipalID != original.ActorPrincipalID ||
			read.DecisionID == "" || target != original.UserID || command != original.RequestID || version != 4 {
			t.Fatal("completion lookup lost its credential-derived exact scope")
		}
		decision := tx.authorizations[len(tx.authorizations)-1].Decision
		if !decision.Allowed || decision.Action != iamv1.ActionIAMUserPasswordReset || decision.Resource.Kind != iamv1.ResourceUser || decision.Resource.ID != string(target) {
			t.Fatal("completion lookup reused unrelated authority")
		}
		return result, readErr
	}
	query := func() (iamv1.UserPasswordResetCompletion, error) {
		return service.UserPasswordResetCompletion(t.Context(), login.Credential, original.UserID, original.RequestID, 4, "read-original")
	}
	if got, err := query(); err != nil || got != original {
		t.Fatal("exact historical completion failed", err)
	}
	for _, mutate := range []func(*iamv1.UserPasswordResetCompletion){
		func(v *iamv1.UserPasswordResetCompletion) { v.AccountID = "other-account" },
		func(v *iamv1.UserPasswordResetCompletion) { v.ActorPrincipalID = "other-actor" },
		func(v *iamv1.UserPasswordResetCompletion) { v.UserID = "other-target" },
		func(v *iamv1.UserPasswordResetCompletion) { v.RequestID = "other-command" },
		func(v *iamv1.UserPasswordResetCompletion) {
			v.ExpectedResourceVersion, v.ResultingResourceVersion = 5, 6
		},
		func(v *iamv1.UserPasswordResetCompletion) { v.OccurredAt = tx.now.Add(time.Second) },
	} {
		result = original
		mutate(&result)
		if got, err := query(); !errors.Is(err, ErrUnavailable) || got != (iamv1.UserPasswordResetCompletion{}) {
			t.Fatal("unbound history escaped", err)
		}
	}
	result, readErr = original, ErrUserPasswordResetCompletionNotFound
	if got, err := query(); !errors.Is(err, ErrUserPasswordResetCompletionNotFound) || got != (iamv1.UserPasswordResetCompletion{}) {
		t.Fatal("missing history was invented", err)
	}
	readErr = nil
	repository.afterTransaction = func(error) error { return ErrUnavailable }
	if got, err := query(); !errors.Is(err, ErrUnavailable) || got != (iamv1.UserPasswordResetCompletion{}) {
		t.Fatal("unknown transaction exposed a completion", err)
	}
	repository.afterTransaction = nil
	before := reads
	tx.profileErr = ErrUnavailable
	if _, err := query(); !errors.Is(err, ErrUnavailable) || reads != before {
		t.Fatal("unavailable current authority read history", err)
	}
	tx.profileErr = nil
	principal := tx.users[tx.principal.ID]
	principal.MustChangePassword = true
	tx.users[principal.ID] = principal
	if _, err := query(); !errors.Is(err, ErrForbidden) || reads != before {
		t.Fatal("temporary session read reset history", err)
	}
	for digest, binding := range tx.sessions {
		binding.Subject.Session.Status = iamv1.SessionRevoked
		tx.sessions[digest] = binding
	}
	if _, err := query(); !errors.Is(err, ErrUnauthenticated) || reads != before {
		t.Fatal("revoked session read reset history", err)
	}
}

func TestRootPasswordRecoveryPreservesPreparedIdentityAndCurrentAuthority(t *testing.T) {
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
	login, err := service.Login(t.Context(), iamv1.LoginRequest{LoginName: "admin", Password: document.Administrator.Password, RequestID: "root-recover-login"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.ChangePassword(t.Context(), login.Credential, iamv1.ChangePasswordRequest{CurrentPassword: document.Administrator.Password,
		NewPassword: coreSecret(t, "Root-Recovery-Actor-Password-73!"), RequestID: "root-recover-actor-change"}); err != nil {
		t.Fatal(err)
	}
	current, recent := coreSecret(t, "Root-Recovery-Current-85!"), coreSecret(t, "Root-Recovery-History-86!")
	currentHash, err := service.passwords.Hash(current)
	if err != nil {
		t.Fatal(err)
	}
	historyHash, err := service.passwords.Hash(recent)
	if err != nil {
		t.Fatal(err)
	}
	material := PasswordReplacementMaterial{PasswordHash: currentHash, CredentialGeneration: 3,
		PasswordHistory: []authority.PasswordHash{historyHash}, HistoryDigest: "sha256:" + strings.Repeat("c", 64)}
	root := iamv1.RootIdentity{PrincipalID: "root-target", LoginName: "root.target"}
	target := iamv1.AccountID("root-recovery-target")
	prepared, writes := false, 0
	tx.rootPasswordRead = func(read AccountRead, account iamv1.AccountID, version uint64) (iamv1.RootIdentity, PasswordReplacementMaterial, error) {
		if read.AccountID != tx.organization.ID || read.ActorPrincipalID != tx.principal.ID || account != target || version != 7 || read.DecisionID == "" {
			t.Fatal("root preparation did not retain the actor/target authority boundary")
		}
		prepared = true
		return root, material, nil
	}
	tx.rootCredentialRecovery = func(mutation RootCredentialRecovery) (iamv1.Account, error) {
		if !prepared || mutation.ActorAccountID != tx.organization.ID || mutation.AccountID != target || mutation.PrincipalID != root.PrincipalID ||
			mutation.ExpectedPassword.PasswordHash != material.PasswordHash || mutation.ExpectedPassword.CredentialGeneration != material.CredentialGeneration ||
			mutation.ExpectedPassword.HistoryDigest != material.HistoryDigest || !slices.Equal(mutation.ExpectedPassword.PasswordHistory, material.PasswordHistory) ||
			mutation.AuditEvent.Target.TenantID != auditv1.TenantID(target) || mutation.AuditEvent.Target.ID != string(root.PrincipalID) {
			t.Fatal("root finalization lost exact target/preparation")
		}
		writes++
		return iamv1.Account{ID: target, RootIdentity: root}, nil
	}
	service.passwords = authority.NewPasswordHasher(passwordEntropyProbe{t, repository})
	request := iamv1.RecoverRootCredentialsRequest{InitialPassword: current, ResourceVersion: 7, RequestID: "root-recover-intent"}
	for _, secret := range []iamv1.Secret{current, recent} {
		request.InitialPassword = secret
		if _, err := service.RecoverRootCredentials(t.Context(), login.Credential, target, request); !errors.Is(err, ErrInvalidArgument) || writes != 0 {
			t.Fatal("root recovery bypassed current/recent history", err)
		}
	}
	request.InitialPassword = coreSecret(t, "Root-Recovery-Replacement-87!")
	repository.afterTransaction = func(error) error { return ErrUnavailable }
	if _, err := service.RecoverRootCredentials(t.Context(), login.Credential, target, request); !errors.Is(err, ErrUnavailable) || writes != 0 {
		t.Fatal("unknown preparation admitted root recovery", err)
	}
	repository.afterTransaction = func(err error) error {
		if prepared && err == nil {
			tx.profileErr = ErrUnavailable
		}
		return err
	}
	if _, err := service.RecoverRootCredentials(t.Context(), login.Credential, target, request); !errors.Is(err, ErrUnavailable) || writes != 0 {
		t.Fatal("root recovery reused old authority", err)
	}
	repository.afterTransaction, tx.profileErr = nil, nil
	if _, err := service.RecoverRootCredentials(t.Context(), login.Credential, target, request); err != nil || writes != 1 {
		t.Fatal("valid root recovery preparation failed", err)
	}
}

func TestTOTPRemovalWorkflowKeepsCallerAndDoesNotExposeUncertainCompletion(t *testing.T) {
	tx := newCoreTransaction()
	repository := &coreRepository{transaction: tx}
	mail := iamv1.EmailVerificationKeyring{APIVersion: iamv1.APIVersion, Kind: "EmailVerificationKeyring", Purpose: iamv1.EmailVerificationWrappingPurpose,
		Scope:          iamv1.SecurityMailInstallationScope{InstallationID: coreTOTPKeyring().Scope.InstallationID, BootstrapDigest: coreTOTPKeyring().Scope.BootstrapDigest},
		KeysetRevision: 1, ActiveKeyID: "mail-test", Keys: []iamv1.EmailVerificationWrappingKey{{KeyID: "mail-test", FormatVersion: 1,
			KeyMaterial: coreSecret(t, base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x37}, 32)))}}}
	service, err := newCoreAuthority(repository, Config{EmailVerificationKeyring: &mail})
	if err != nil {
		t.Fatal(err)
	}
	registration := service.email.Registration()
	tx.emailKeyset = &registration
	bootstrap := coreBootstrap(t)
	if _, err := service.Bootstrap(t.Context(), bootstrap); err != nil {
		t.Fatal(err)
	}
	login, err := service.Login(t.Context(), iamv1.LoginRequest{LoginName: "admin", Password: bootstrap.Administrator.Password, RequestID: "remove-login"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.ChangePassword(t.Context(), login.Credential, iamv1.ChangePasswordRequest{CurrentPassword: bootstrap.Administrator.Password,
		NewPassword: coreSecret(t, "Removal-Current-Password-92!"), RequestID: "remove-initial-password"}); err != nil {
		t.Fatal(err)
	}
	request := iamv1.RemoveTOTPRequest{RequestID: "remove-original", StepUpID: "remove-proof", ExpectedFactorRevision: 2}
	// This fake proves workflow/port checks, not database eligibility. Protected
	// identities, proof consumption and rollback are exercised with real PG.
	for _, scenario := range []string{"applied", "replay", "wrong-request", "wrong-revision", "wrong-id", "replay-transition", "storage-denied", "unknown-commit"} {
		t.Run(scenario, func(t *testing.T) {
			repository.afterTransaction = nil
			tx.removalEffect = func(mutation AuthenticatorRemovalMutation) (iamv1.RemoveTOTPResponse, error) {
				if !repository.inTransaction || mutation.Session.ID != login.Session.ID || mutation.Request != request ||
					mutation.AuditEvent.Action != auditv1.ActionIAMAuthenticatorRemoved || mutation.AuditEvent.Actor.Type != auditv1.ActorUser ||
					string(mutation.AuditEvent.Actor.ID) != string(login.Session.PrincipalID) || mutation.AuditEvent.Target.ID != string(login.Session.PrincipalID) ||
					string(mutation.AuditEvent.TenantID) != string(login.Session.AccountID) || mutation.AuditEvent.RequestID != request.RequestID {
					t.Fatal("removal changed the actual authenticated subject or command")
				}
				result := iamv1.RemoveTOTPResponse{Outcome: "APPLIED", NextStep: "REAUTHENTICATE", Removal: iamv1.AuthenticatorRemoval{
					APIVersion: iamv1.APIVersion, Kind: "AuthenticatorRemoval", ID: mutation.ID, RequestID: request.RequestID,
					FactorID: "factor-original", FactorRevision: 3, RemovedAt: tx.now}}
				switch scenario {
				case "replay":
					result.Outcome, result.NextStep, result.Removal.ID = "EQUAL_REPLAY", "", "old-completion"
				case "wrong-request":
					result.Removal.RequestID = "other-command"
				case "wrong-revision":
					result.Removal.FactorRevision = 4
				case "wrong-id":
					result.Removal.ID = "other-completion"
				case "replay-transition":
					result.Outcome = "EQUAL_REPLAY"
				case "storage-denied":
					return result, ErrUnauthenticated
				}
				return result, nil
			}
			if scenario == "unknown-commit" {
				repository.afterTransaction = func(error) error { return ErrUnavailable }
			}
			result, err := service.RemoveTOTP(t.Context(), login.Credential, request)
			want := error(ErrUnavailable)
			if scenario == "applied" || scenario == "replay" {
				want = nil
			} else if scenario == "storage-denied" {
				want = ErrUnauthenticated
			}
			if !errors.Is(err, want) || (want != nil && result != (iamv1.RemoveTOTPResponse{})) || (want == nil && iamv1.ValidateRemoveTOTPResponse(result) != nil) {
				t.Fatal("untrusted or uncertain removal was disclosed", err)
			}
		})
	}
}

func TestTOTPReplacementStartKeepsOriginalCallerProofAndOneTimeMaterial(t *testing.T) {
	// These exercise workflow/port boundaries only. MFA eligibility, atomic
	// proof consumption and survival of the old factor require the PG gate.
	for _, scenario := range []string{"applied", "replay", "wrong-purpose", "wrong-request", "wrong-proof", "unproved",
		"revoked", "generation", "first-commit-unknown", "final-commit-unknown", "storage-denied", "other-factor",
		"initial-projection", "renewed-deadline", "different-request", "different-revision", "consumed-new-factor"} {
		t.Run(scenario, func(t *testing.T) {
			tx := newCoreTransaction()
			repository := &coreRepository{transaction: tx}
			material := coreSecret(t, base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x37}, 32)))
			mail := iamv1.EmailVerificationKeyring{APIVersion: iamv1.APIVersion, Kind: "EmailVerificationKeyring", Purpose: iamv1.EmailVerificationWrappingPurpose,
				Scope:          iamv1.SecurityMailInstallationScope{InstallationID: coreTOTPKeyring().Scope.InstallationID, BootstrapDigest: coreTOTPKeyring().Scope.BootstrapDigest},
				KeysetRevision: 1, ActiveKeyID: "mail-test", Keys: []iamv1.EmailVerificationWrappingKey{{KeyID: "mail-test", FormatVersion: 1, KeyMaterial: material}}}
			service, err := newCoreAuthority(repository, Config{EmailVerificationKeyring: &mail})
			if err != nil {
				t.Fatal(err)
			}
			registration := service.email.Registration()
			tx.emailKeyset = &registration
			bootstrap := coreBootstrap(t)
			if _, err := service.Bootstrap(t.Context(), bootstrap); err != nil {
				t.Fatal(err)
			}
			login, err := service.Login(t.Context(), iamv1.LoginRequest{LoginName: "admin", Password: bootstrap.Administrator.Password, RequestID: "replace-login"})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := service.ChangePassword(t.Context(), login.Credential, iamv1.ChangePasswordRequest{CurrentPassword: bootstrap.Administrator.Password,
				NewPassword: coreSecret(t, "Replacement-Current-Password-82!"), RequestID: "replace-initial-password"}); err != nil {
				t.Fatal(err)
			}
			request := iamv1.StartTOTPReplacementRequest{RequestID: "replace-original", StepUpID: "replace-proof", ExpectedFactorRevision: 2}
			proved := tx.now.Add(-10 * time.Second)
			tx.stepUpStartResult = iamv1.StepUp{APIVersion: iamv1.APIVersion, Kind: "StepUp", ID: request.StepUpID, RequestID: request.RequestID,
				Operation: iamv1.StepUpReplaceTOTP, ExpectedFactorRevision: 2, State: "PROVED", CreatedAt: tx.now.Add(-30 * time.Second),
				ExpiresAt: tx.now.Add(90 * time.Second), ProvedAt: &proved}
			want := ErrUnavailable
			calls := 1
			switch scenario {
			case "applied", "replay":
				want = nil
			case "wrong-purpose":
				tx.stepUpStartResult.Operation = iamv1.StepUpRegenerateRecoveryCodes
				want, calls = ErrConflict, 0
			case "wrong-request":
				tx.stepUpStartResult.RequestID = "another-command"
				want, calls = ErrConflict, 0
			case "wrong-proof":
				tx.stepUpStartResult.ID = "another-proof"
				want, calls = ErrConflict, 0
			case "unproved":
				tx.stepUpStartResult.State, tx.stepUpStartResult.ProvedAt = "PENDING", nil
				want, calls = ErrConflict, 0
			case "revoked", "generation":
				want, calls = ErrUnauthenticated, 0
			case "first-commit-unknown":
				calls = 0
			case "storage-denied":
				want = ErrForbidden
			}
			if scenario == "replay" || scenario == "consumed-new-factor" {
				tx.stepUpStartResult.State, tx.stepUpStartResult.ConsumedAt = "CONSUMED", &tx.now
			}
			preflight := true
			repository.afterTransaction = func(callbackErr error) error {
				if callbackErr != nil {
					return callbackErr
				}
				if !preflight {
					if scenario == "final-commit-unknown" {
						return ErrUnavailable
					}
					return nil
				}
				preflight = false
				if scenario == "first-commit-unknown" {
					return ErrUnavailable
				}
				for digest, binding := range tx.sessions {
					if binding.Subject.Session.ID == login.Session.ID {
						if scenario == "revoked" {
							binding.Subject.Session.Status = iamv1.SessionRevoked
						}
						if scenario == "generation" {
							binding.CredentialGeneration++
						}
						tx.sessions[digest] = binding
					}
				}
				return nil
			}
			tx.replacementStart = func(mutation TOTPReplacementStart) (TOTPEnrollmentStartResult, error) {
				if mutation.Session.ID != login.Session.ID || mutation.Session.PrincipalID != login.Session.PrincipalID ||
					mutation.Session.AccountID != login.Session.AccountID || mutation.Request != request || mutation.Sealed.FormatVersion != 1 ||
					mutation.FactorID == "" || len(mutation.Sealed.Nonce) != 12 || len(mutation.Sealed.Ciphertext) != 36 {
					t.Fatal("replacement did not carry the exact authenticated intent and sealed factor")
				}
				if scenario == "storage-denied" {
					return TOTPEnrollmentStartResult{}, ErrForbidden
				}
				result := TOTPEnrollmentStartResult{Outcome: "APPLIED", Enrollment: iamv1.TOTPEnrollment{APIVersion: iamv1.APIVersion, Kind: "TOTPEnrollment",
					ID: mutation.FactorID, RequestID: request.RequestID, Purpose: "REPLACEMENT", FactorRevision: 2, State: "PENDING",
					CreatedAt: tx.now, ExpiresAt: tx.stepUpStartResult.ExpiresAt}}
				switch scenario {
				case "replay":
					result.Outcome, result.Enrollment.ID = "EQUAL_REPLAY", "original-factor"
				case "other-factor":
					result.Enrollment.ID = "unrelated-factor"
				case "initial-projection":
					result.Enrollment.Purpose = "INITIAL"
				case "renewed-deadline":
					result.Enrollment.ExpiresAt = tx.now.Add(120 * time.Second)
				case "different-request":
					result.Enrollment.RequestID = "unrelated-request"
				case "different-revision":
					result.Enrollment.FactorRevision++
				}
				return result, nil
			}
			result, err := service.StartTOTPReplacement(t.Context(), login.Credential, request)
			if !errors.Is(err, want) || tx.replacementCalls != calls {
				t.Fatalf("replacement result error=%v calls=%d; want error=%v calls=%d", err, tx.replacementCalls, want, calls)
			}
			if want != nil {
				if result != (iamv1.StartTOTPEnrollmentResponse{}) {
					t.Fatal("failed or unknown transaction returned provisioning")
				}
				return
			}
			if iamv1.ValidateStartTOTPEnrollmentResponse(result) != nil || result.Enrollment.Purpose != "REPLACEMENT" ||
				!result.Enrollment.ExpiresAt.Equal(tx.stepUpStartResult.ExpiresAt) || (result.Provisioning != nil) != (scenario == "applied") {
				t.Fatal("replacement returned the wrong ceremony or replayed secrets")
			}
		})
	}
}

func TestStartStepUpRejectsChangedSettingsIntent(t *testing.T) {
	// The storage port must return the exact non-secret intent, not merely a
	// syntactically valid proof. Real MFA eligibility remains a PostgreSQL gate.
	for _, changed := range []string{"none", "missing", "version", "value", "password", "missing password", "session", "missing session", "operation"} {
		t.Run(changed, func(t *testing.T) {
			tx := newCoreTransaction()
			service, err := newCoreAuthority(&coreRepository{transaction: tx}, Config{})
			if err != nil {
				t.Fatal(err)
			}
			bootstrap := coreBootstrap(t)
			if _, err := service.Bootstrap(t.Context(), bootstrap); err != nil {
				t.Fatal(err)
			}
			login, err := service.Login(t.Context(), iamv1.LoginRequest{LoginName: "admin", Password: bootstrap.Administrator.Password, RequestID: "settings-proof-login"})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := service.ChangePassword(t.Context(), login.Credential, iamv1.ChangePasswordRequest{CurrentPassword: bootstrap.Administrator.Password,
				NewPassword: coreSecret(t, "Settings-Proof-Current-Password-92!"), RequestID: "settings-proof-initial-password"}); err != nil {
				t.Fatal(err)
			}
			passwordSettings := authority.DefaultPasswordSettings()
			sessionSettings := iamv1.AccountSessionSettings{IdleTimeoutMinutes: 30}
			intent := iamv1.SecuritySettingsUpdateIntent{ExpectedResourceVersion: 1, MFA: iamv1.AccountMFASettings{RequiredForUsers: true}, Password: &passwordSettings, Session: &sessionSettings}
			request := iamv1.StartStepUpRequest{RequestID: "settings-original", Operation: iamv1.StepUpUpdateSecuritySettings, ExpectedFactorRevision: 2, SecuritySettings: &intent}
			returnedIntent := intent
			returnedPassword := passwordSettings
			returnedSession := sessionSettings
			returnedIntent.Password = &returnedPassword
			returnedIntent.Session = &returnedSession
			tx.stepUpStartResult = iamv1.StepUp{APIVersion: iamv1.APIVersion, Kind: "StepUp", ID: "settings-proof", RequestID: request.RequestID,
				Operation: request.Operation, ExpectedFactorRevision: request.ExpectedFactorRevision, SecuritySettings: &returnedIntent,
				State: "PENDING", CreatedAt: tx.now, ExpiresAt: tx.now.Add(120 * time.Second)}
			switch changed {
			case "missing":
				tx.stepUpStartResult.SecuritySettings = nil
			case "version":
				returnedIntent.ExpectedResourceVersion++
			case "value":
				returnedIntent.MFA.RequiredForUsers = false
			case "password":
				returnedPassword.HistoryCount = 24
			case "missing password":
				returnedIntent.Password = nil
			case "session":
				returnedSession.IdleTimeoutMinutes = 60
			case "missing session":
				returnedIntent.Session = nil
			case "operation":
				tx.stepUpStartResult.Operation, tx.stepUpStartResult.SecuritySettings = iamv1.StepUpRegenerateRecoveryCodes, nil
			}
			result, err := service.StartStepUp(t.Context(), login.Credential, request)
			if changed == "none" {
				if err != nil || !reflect.DeepEqual(result.SecuritySettings, &intent) {
					t.Fatal("exact settings proof rejected", err)
				}
			} else if !errors.Is(err, ErrUnavailable) || result != (iamv1.StepUp{}) {
				t.Fatal("changed proof intent escaped authority boundary", err)
			}
		})
	}
}

func TestStepUpStopsAtUnknownAdmissionOrChangedCaller(t *testing.T) {
	// This proves the staged use-case boundary, not SQL durability or MFA
	// eligibility. Real consumption, budget and lock races remain PG18 gates.
	for _, scenario := range []struct {
		name, after, mutation string
		wrongPassword         bool
		denyOTP               bool
		want                  error
		otpReservations       int
		passwordRejections    int
	}{
		{name: "wrong-password", wrongPassword: true, want: ErrUnauthenticated, passwordRejections: 1},
		{name: "password-rejection-unknown", wrongPassword: true, after: "rejection", mutation: "unknown", want: ErrUnavailable, passwordRejections: 1},
		{name: "password-reservation-unknown", after: "password", mutation: "unknown", want: ErrUnavailable},
		{name: "revoked-after-password", after: "password", mutation: "revoke", want: ErrUnauthenticated},
		{name: "generation-changed-after-password", after: "password", mutation: "generation", want: ErrUnauthenticated},
		{name: "otp-reservation-unknown", after: "otp", mutation: "unknown", want: ErrUnavailable, otpReservations: 1},
		{name: "revoked-after-otp", after: "otp", mutation: "revoke", want: ErrUnauthenticated, otpReservations: 1},
		{name: "generation-changed-after-otp", after: "otp", mutation: "generation", want: ErrUnauthenticated, otpReservations: 1},
		{name: "otp-budget-denied", denyOTP: true, want: ErrUnauthenticated, otpReservations: 1, passwordRejections: 1},
		{name: "otp-denial-commit-unknown", denyOTP: true, after: "rejection", mutation: "unknown", want: ErrUnavailable, otpReservations: 1, passwordRejections: 1},
	} {
		t.Run(scenario.name, func(t *testing.T) {
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
			login, err := service.Login(t.Context(), iamv1.LoginRequest{LoginName: "admin", Password: bootstrap.Administrator.Password, RequestID: "step-up-login"})
			if err != nil {
				t.Fatal(err)
			}
			password := coreSecret(t, "Step-Up-Current-Password-92!")
			if _, err := service.ChangePassword(t.Context(), login.Credential, iamv1.ChangePasswordRequest{
				CurrentPassword: bootstrap.Administrator.Password, NewPassword: password, RequestID: "step-up-initial-change"}); err != nil {
				t.Fatal(err)
			}
			tx.stepUpForVerification = iamv1.StepUp{APIVersion: iamv1.APIVersion, Kind: "StepUp", ID: "original-step-up",
				RequestID: "original-sensitive-command", Operation: "RECOVERY_CODES_REGENERATE", ExpectedFactorRevision: 2,
				State: "PENDING", CreatedAt: tx.now, ExpiresAt: tx.now.Add(120 * time.Second)}
			tx.denyTOTPReservation = scenario.denyOTP
			beforeAttempts, beforeSessions, beforeDecisions := tx.attemptSequence, len(tx.sessions), len(tx.authorizations)
			tx.rejectedAttempts = nil
			injected := false
			repository.afterTransaction = func(callbackErr error) error {
				if callbackErr != nil || injected {
					return callbackErr
				}
				ready := scenario.after == "password" && tx.attemptSequence > beforeAttempts ||
					scenario.after == "otp" && len(tx.totpReservations) > 0 ||
					scenario.after == "rejection" && len(tx.rejectedAttempts) > 0
				if !ready {
					return nil
				}
				injected = true
				if scenario.mutation == "unknown" {
					return ErrUnavailable
				}
				for digest, binding := range tx.sessions {
					if binding.Subject.Session.ID != login.Session.ID {
						continue
					}
					if scenario.mutation == "revoke" {
						binding.Subject.Session.Status = iamv1.SessionRevoked
					} else {
						binding.CredentialGeneration++
					}
					tx.sessions[digest] = binding
				}
				return nil
			}
			if scenario.wrongPassword {
				password = coreSecret(t, "Step-Up-Wrong-Password-38!")
			}
			result, err := service.VerifyStepUp(t.Context(), login.Credential, tx.stepUpForVerification.ID, iamv1.VerifyStepUpRequest{
				RequestID: "original-proof-attempt", Password: password, Code: coreSecret(t, "123456")})
			if !errors.Is(err, scenario.want) || result != (iamv1.StepUp{}) {
				t.Fatal("uncertain or stale proof returned authority", err)
			}
			if scenario.after != "" && !injected {
				t.Fatal("test never reached its actual admission boundary")
			}
			if tx.attemptSequence != beforeAttempts+1 || len(tx.rejectedAttempts) != scenario.passwordRejections ||
				len(tx.totpReservations) != scenario.otpReservations || tx.totpAttemptReads != 0 ||
				len(tx.sessions) != beforeSessions || len(tx.authorizations) != beforeDecisions || tx.stepUpForVerification.State != "PENDING" {
				t.Fatal("failure retried a reservation, read a seed, proved an operation or issued authority")
			}
			for _, attempt := range tx.totpReservations {
				if attempt.AccountID != login.Session.AccountID || attempt.UserID != login.Session.PrincipalID ||
					attempt.SessionID != login.Session.ID || attempt.ReferenceID != tx.stepUpForVerification.ID || attempt.Purpose != "STEP_UP" {
					t.Fatal("OTP reservation lost the original Session or operation")
				}
			}
			// Even exceptional exits must return the bounded expensive-work slot.
			for range 2 {
				if err := service.acquirePasswordWork(t.Context()); err != nil {
					t.Fatal("failed proof leaked password-work capacity", err)
				}
			}
			service.releasePasswordWork()
			service.releasePasswordWork()
		})
	}
}

func TestPasswordRequirementsUseOnlyTheAuthenticatedSelfOrPasswordChallenge(t *testing.T) {
	tx := newCoreTransaction()
	service, err := newCoreAuthority(&coreRepository{transaction: tx}, Config{})
	if err != nil {
		t.Fatal(err)
	}
	bootstrap := coreBootstrap(t)
	if _, err := service.Bootstrap(t.Context(), bootstrap); err != nil {
		t.Fatal(err)
	}
	login, err := service.Login(t.Context(), iamv1.LoginRequest{LoginName: "admin", Password: bootstrap.Administrator.Password, RequestID: "requirements-login"})
	if err != nil || !login.MustChangePassword {
		t.Fatal("forced Session fixture", err)
	}
	tx.attachments = map[iamv1.PolicyAttachmentID]iamv1.PolicyAttachment{}
	valid := iamv1.PasswordRequirements{APIVersion: iamv1.APIVersion, Kind: "PasswordRequirements",
		Password: iamv1.AccountPasswordSettings{ExpiryMode: iamv1.PasswordExpiryChange, MinimumLength: 15, HistoryCount: 1}, MaximumLength: 128, MaximumUTF8Bytes: 512, SettingsVersion: 3, Source: "PROTECTED_IDENTITY"}
	tx.passwordRequirements = valid
	got, err := service.PasswordRequirements(t.Context(), login.Credential)
	if err != nil || got != valid || tx.passwordRequirementsSession != login.Session || len(tx.authorizations) != 0 {
		t.Fatal("self observation requires an invented permission or changes identity", err)
	}
	for _, purpose := range []authority.CredentialType{authority.CredentialService, authority.CredentialRoleSession, authority.CredentialAuthenticationChallenge} {
		wrong, err := service.credentials.Issue(purpose, "requirements-wrong-carrier")
		if err != nil {
			t.Fatal(err)
		}
		before := tx.passwordRequirementsReads
		if _, err := service.PasswordRequirements(t.Context(), wrong.Credential); !errors.Is(err, ErrUnauthenticated) || tx.passwordRequirementsReads != before {
			t.Fatal("non-Session reached self rules", err)
		}
	}
	issued, err := service.credentials.Issue(authority.CredentialAuthenticationChallenge, "requirements-challenge")
	if err != nil {
		t.Fatal(err)
	}
	tx.challengeLookupDigest = issued.LookupDigest
	request := iamv1.ChallengePasswordRequirementsRequest{ChallengeCredential: issued.Credential}
	for _, purpose := range []string{"LOGIN", "ENROLLMENT", "RECOVERY"} {
		for _, step := range []string{"TOTP", "ENROLLMENT", "PASSWORD_CHANGE"} {
			tx.challengeCredential = AuthenticationChallengeCredential{AccountID: tx.organization.ID, UserID: tx.principal.ID,
				ID: "requirements-challenge", Purpose: purpose, NextStep: step, VerificationDigest: issued.VerificationDigest}
			before := tx.passwordRequirementsReads
			got, err := service.ChallengePasswordRequirements(t.Context(), "requirements-challenge", request)
			if step == "PASSWORD_CHANGE" && purpose != "RECOVERY" {
				if err != nil || got != valid || tx.passwordRequirementsChallenge != tx.challengeCredential {
					t.Fatal("exact password ceremony rejected", err)
				}
			} else if !errors.Is(err, ErrUnauthenticated) || got != (iamv1.PasswordRequirements{}) || tx.passwordRequirementsReads != before {
				t.Fatal("wrong ceremony reached rules", err)
			}
		}
	}
	tx.challengeCredential.Purpose, tx.challengeCredential.NextStep = "LOGIN", "PASSWORD_CHANGE"
	for _, wrong := range []iamv1.ChallengePasswordRequirementsRequest{{ChallengeCredential: login.Credential}, {ChallengeCredential: coreSecret(t, "unknown-capability")}} {
		before := tx.passwordRequirementsReads
		if _, err := service.ChallengePasswordRequirements(t.Context(), "requirements-challenge", wrong); !errors.Is(err, ErrUnauthenticated) || tx.passwordRequirementsReads != before {
			t.Fatal("wrong credential reached challenge rules", err)
		}
	}
	if _, err := service.ChallengePasswordRequirements(t.Context(), "another-challenge", request); !errors.Is(err, ErrUnauthenticated) {
		t.Fatal("path substituted ceremony", err)
	}
	for _, read := range []func() (iamv1.PasswordRequirements, error){
		func() (iamv1.PasswordRequirements, error) {
			return service.PasswordRequirements(t.Context(), login.Credential)
		},
		func() (iamv1.PasswordRequirements, error) {
			return service.ChallengePasswordRequirements(t.Context(), "requirements-challenge", request)
		},
	} {
		for _, failure := range []error{ErrUnauthenticated, ErrUnavailable} {
			tx.passwordRequirements, tx.passwordRequirementsError = valid, failure
			if result, err := read(); !errors.Is(err, failure) || result != (iamv1.PasswordRequirements{}) {
				t.Fatal("failed locked observation escaped", err)
			}
		}
		tx.passwordRequirementsError = nil
		tx.passwordRequirements = valid
		tx.passwordRequirements.Source = "UNKNOWN"
		if result, err := read(); !errors.Is(err, ErrUnavailable) || result != (iamv1.PasswordRequirements{}) {
			t.Fatal("invalid storage projected", err)
		}
	}
	if len(tx.authorizations) != 0 || len(tx.totpReservations) != 0 || len(tx.sessions) != 1 || len(tx.passwordAttempts) != 0 {
		t.Fatalf("read effects: authorizations=%d totpReservations=%d sessions=%d attempts=%d", len(tx.authorizations), len(tx.totpReservations), len(tx.sessions), len(tx.passwordAttempts))
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
	activity, err := service.TouchCurrentSession(t.Context(), a.Credential)
	if err != nil || iamv1.ValidateSessionActivity(activity) != nil || activity.SessionID != a.Session.ID ||
		activity.AccountID != a.Session.AccountID || activity.UserID != a.Session.PrincipalID ||
		!activity.AbsoluteExpiresAt.Equal(a.Session.ExpiresAt) || len(tx.sessionTouches) != 1 || tx.sessionTouches[0] != a.Session ||
		len(tx.authorizations) != 0 {
		t.Fatal("session activity invented management authority or another caller", err)
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
		before := len(tx.sessionTouches)
		if _, err := service.TouchCurrentSession(t.Context(), wrong.Credential); !errors.Is(err, ErrUnauthenticated) || len(tx.sessionTouches) != before {
			t.Fatal("non-login activity touch", err)
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
	validActivity := activity
	for name, alter := range map[string]func(*iamv1.SessionActivity){
		"session":  func(value *iamv1.SessionActivity) { value.SessionID = "unrelated-session" },
		"account":  func(value *iamv1.SessionActivity) { value.AccountID = "unrelated-account" },
		"user":     func(value *iamv1.SessionActivity) { value.UserID = "unrelated-user" },
		"idle":     func(value *iamv1.SessionActivity) { value.IdleExpiresAt = value.LastActivityAt.Add(4 * time.Minute) },
		"absolute": func(value *iamv1.SessionActivity) { value.AbsoluteExpiresAt = value.AbsoluteExpiresAt.Add(time.Second) },
		"time":     func(value *iamv1.SessionActivity) { value.LastActivityAt = time.Time{} },
	} {
		t.Run("activity-"+name, func(t *testing.T) {
			candidate := validActivity
			alter(&candidate)
			tx.sessionActivity = &candidate
			defer func() { tx.sessionActivity = nil }()
			if result, err := service.TouchCurrentSession(t.Context(), a.Credential); !errors.Is(err, ErrUnavailable) || result != (iamv1.SessionActivity{}) {
				t.Fatal("untrusted session activity became a public result", err)
			}
		})
	}
	tx.sessionActivityError = ErrConflict
	if result, err := service.TouchCurrentSession(t.Context(), a.Credential); !errors.Is(err, ErrConflict) || result != (iamv1.SessionActivity{}) {
		t.Fatal("failed activity touch escaped", err)
	}
	tx.sessionActivityError = nil
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

func TestAccountSecuritySettingsCannotBypassCurrentSessionAndExplicitAuthority(t *testing.T) {
	tx := newCoreTransaction()
	service, err := newCoreAuthority(&coreRepository{transaction: tx}, Config{})
	if err != nil {
		t.Fatal(err)
	}
	bootstrap := coreBootstrap(t)
	if _, err := service.Bootstrap(t.Context(), bootstrap); err != nil {
		t.Fatal(err)
	}
	login, err := service.Login(t.Context(), iamv1.LoginRequest{LoginName: "admin", Password: bootstrap.Administrator.Password, RequestID: "settings-login"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.ChangePassword(t.Context(), login.Credential, iamv1.ChangePasswordRequest{CurrentPassword: bootstrap.Administrator.Password,
		NewPassword: coreSecret(t, "Settings-Changed-Password-57!"), RequestID: "settings-password"}); err != nil {
		t.Fatal(err)
	}
	if result, err := service.AccountSecuritySettings(t.Context(), login.Credential, "settings-denied"); !errors.Is(err, ErrForbidden) || result.AccountID != "" {
		t.Fatal("root/platform membership substituted for explicit settings authority", err)
	}
	last := tx.authorizations[len(tx.authorizations)-1]
	if last.Decision.Allowed || last.Decision.Action != iamv1.ActionIAMSecuritySettingsRead ||
		last.Decision.Resource != (iamv1.ResourceReference{Kind: iamv1.ResourceAccount, ID: string(bootstrap.Organization.ID)}) || last.AuditEvent.Action != auditv1.ActionIAMAuthorizationDecided {
		t.Fatal("settings denial did not bind the current real Account and audit decision")
	}
	update := iamv1.UpdateAccountSecuritySettingsRequest{RequestID: "settings-denied-write", StepUpID: "not-a-permit",
		ExpectedResourceVersion: 1, MFA: iamv1.AccountMFASettings{RequiredForUsers: true}, Password: authority.DefaultPasswordSettings(),
		Session: iamv1.AccountSessionSettings{IdleTimeoutMinutes: 30}}
	if _, err := service.UpdateAccountSecuritySettings(t.Context(), login.Credential, update); !errors.Is(err, ErrForbidden) {
		t.Fatal("settings proof ID substituted for current write permission", err)
	}
	last = tx.authorizations[len(tx.authorizations)-1]
	if last.Decision.Allowed || last.Decision.Action != iamv1.ActionIAMSecuritySettingsUpdate ||
		last.Decision.Resource.ID != string(bootstrap.Organization.ID) || tx.settingsMutationCalled {
		t.Fatal("denied settings command reached mutation")
	}
	beforeLockFailure := len(tx.authorizations)
	tx.settingsLockError = ErrUnauthenticated
	if _, err := service.UpdateAccountSecuritySettings(t.Context(), login.Credential, update); !errors.Is(err, ErrUnauthenticated) || len(tx.authorizations) != beforeLockFailure || tx.settingsMutationCalled {
		t.Fatal("locked authentication failure was used to make a new permission decision")
	}
	tx.settingsLockError = nil
	before := len(tx.authorizations)
	tx.profileErr = ErrUnavailable
	if _, err := service.AccountSecuritySettings(t.Context(), login.Credential, "settings-drift"); !errors.Is(err, ErrUnavailable) || len(tx.authorizations) != before {
		t.Fatal("unavailable product authority produced an ordinary settings result")
	}
	tx.profileErr = nil
	if _, err := service.AccountSecuritySettings(t.Context(), coreServiceCredential(t, bootstrap, iamv1.ServicePaaS), "settings-service"); !errors.Is(err, ErrUnauthenticated) {
		t.Fatal("service credential reached settings authority")
	}
	if _, err := service.Logout(t.Context(), login.Credential, iamv1.LogoutRequest{RequestID: "settings-logout"}); err != nil {
		t.Fatal(err)
	}
	if _, err := service.AccountSecuritySettings(t.Context(), login.Credential, "settings-old-session"); !errors.Is(err, ErrUnauthenticated) {
		t.Fatal("revoked session reached settings authority")
	}
	if _, err := service.UpdateAccountSecuritySettings(t.Context(), login.Credential, update); !errors.Is(err, ErrUnauthenticated) || tx.settingsMutationCalled {
		t.Fatal("revoked session reached settings mutation")
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
	currentPassword, err := authority.NewPasswordHasher(nil).Hash(secret("Current-Local-Password-77!"))
	if err != nil {
		t.Fatal(err)
	}
	transaction.localRecoveryMaterial = PasswordReplacementMaterial{PasswordHash: currentPassword, CredentialGeneration: 3,
		PasswordHistory: []authority.PasswordHash{}, HistoryDigest: "sha256:" + strings.Repeat("c", 64)}
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
	if mutation.Scope != local.Scope || mutation.Expected != request.Expected || mutation.InputCommitment != commitment || mutation.CommandID != request.CommandID ||
		mutation.ExpectedPassword.PasswordHash != currentPassword || mutation.ExpectedPassword.CredentialGeneration != 3 ||
		mutation.ExpectedPassword.HistoryDigest != transaction.localRecoveryMaterial.HistoryDigest {
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
	t.Run("new input admission uses prepared history outside transaction", func(t *testing.T) {
		transaction.localRecoveryInspection = iamv1.LocalCredentialRecoveryInspection{}
		transaction.localRecoveryMutation = nil
		transaction.localRecoveryResult = completed
		entropy := &passwordEntropyProbe{testing: t, repository: repository}
		service.passwords = authority.NewPasswordHasher(entropy)
		recent := secret("Recent-Local-Password-78!")
		hash, err := authority.NewPasswordHasher(nil).Hash(recent)
		if err != nil {
			t.Fatal(err)
		}
		transaction.localRecoveryMaterial.PasswordHistory = []authority.PasswordHash{hash}
		for _, password := range []iamv1.Secret{secret("Current-Local-Password-77!"), recent} {
			reused := request
			reused.NewPassword = password
			reused, err = iamv1.SignLocalCredentialRecoveryRequest(local, reused)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := service.RecoverLocalCredentials(t.Context(), local, reused); !errors.Is(err, ErrInvalidArgument) || transaction.localRecoveryMutation != nil {
				t.Fatal("new recovery admitted current/recent password", err)
			}
		}
		if _, err := service.RecoverLocalCredentials(t.Context(), local, request); err != nil {
			t.Fatal("fresh local recovery rejected", err)
		}
	})
	t.Run("unknown preparation commit cannot reach hashing or final write", func(t *testing.T) {
		transaction.localRecoveryInspection = iamv1.LocalCredentialRecoveryInspection{}
		transaction.localRecoveryMutation = nil
		var entropy bytes.Buffer
		service.passwords = authority.NewPasswordHasher(io.TeeReader(passwordEntropyProbe{t, repository}, &entropy))
		prepared := false
		transaction.onLocalRecoveryPrepare = func() { prepared = true }
		repository.afterTransaction = func(err error) error {
			if prepared {
				return ErrUnavailable
			}
			return err
		}
		defer func() { transaction.onLocalRecoveryPrepare = nil; repository.afterTransaction = nil }()
		if _, err := service.RecoverLocalCredentials(t.Context(), local, request); !errors.Is(err, ErrUnavailable) || !prepared || entropy.Len() != 0 || transaction.localRecoveryMutation != nil {
			t.Fatal("uncertain preparation reached recovery write", err)
		}
	})
	t.Run("historical input is not a new password write", func(t *testing.T) {
		old := request
		old.CommandID, old.NewPassword = "historical-local", secret("Old-Secret-49!")
		old, err = iamv1.SignLocalCredentialRecoveryRequest(local, old)
		if err != nil {
			t.Fatal(err)
		}
		oldCommitment, err := iamv1.VerifyLocalCredentialRecoveryRequest(local, old)
		if err != nil {
			t.Fatal(err)
		}
		historical := completed
		historical.CommandID, historical.InputCommitment = old.CommandID, oldCommitment
		transaction.localRecoveryInspection = iamv1.LocalCredentialRecoveryInspection{APIVersion: iamv1.APIVersion,
			Kind: "LocalCredentialRecoveryInspection", Scope: local.Scope, State: "COMPLETED", CommandID: old.CommandID,
			InputCommitment: oldCommitment, Expected: &old.Expected, Result: &historical}
		transaction.localRecoveryMutation = nil
		service.passwords = authority.NewPasswordHasher(bytes.NewReader(nil))
		for range cap(service.passwordWork) {
			if err := service.acquirePasswordWork(t.Context()); err != nil {
				t.Fatal(err)
			}
		}
		replayed, err := service.RecoverLocalCredentials(t.Context(), local, old)
		for range cap(service.passwordWork) {
			service.releasePasswordWork()
		}
		want := historical
		want.State = "EQUAL_REPLAY"
		if err != nil || replayed != want || transaction.localRecoveryMutation != nil {
			t.Fatal("historical completion rehashed or rewrote the password", err)
		}
		changed := old
		changed.Expected.CredentialGeneration++
		changed, err = iamv1.SignLocalCredentialRecoveryRequest(local, changed)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := service.RecoverLocalCredentials(t.Context(), local, changed); err == nil || transaction.localRecoveryMutation != nil {
			t.Fatal("replay accepted altered expected authority")
		}
		transaction.localRecoveryInspection = iamv1.LocalCredentialRecoveryInspection{}
		transaction.onLocalRecoveryPrepare = func() {
			transaction.localRecoveryPrepared = iamv1.LocalCredentialRecoveryInspection{APIVersion: iamv1.APIVersion,
				Kind: "LocalCredentialRecoveryInspection", Scope: local.Scope, State: "COMPLETED", CommandID: old.CommandID,
				InputCommitment: oldCommitment, Expected: &old.Expected, Result: &historical}
		}
		replayed, err = service.RecoverLocalCredentials(t.Context(), local, old)
		if err != nil || replayed != want || transaction.localRecoveryMutation != nil {
			t.Fatal("completion between inspection and preparation rehashed or rejected historical intent", err)
		}
		transaction.onLocalRecoveryPrepare = nil
		transaction.localRecoveryPrepared = iamv1.LocalCredentialRecoveryInspection{}
		if _, err := service.RecoverLocalCredentials(t.Context(), local, old); !errors.Is(err, ErrInvalidArgument) || transaction.localRecoveryMutation != nil {
			t.Fatal("NOT_FOUND admitted a new weak password", err)
		}
	})
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
			if _, supported := iamv1.LookupActionConditionDefinition(decision.Action, iamv1.ConditionRequestSourceIP); supported {
				withNetwork := current
				networkDecision := *current.Decision
				networkDecision.NetworkContext = &iamv1.AuthorizationNetworkContext{SourceIP: "192.0.2.10"}
				withNetwork.Decision = &networkDecision
				withNetwork.DecisionContractVersion = 5
				if got, err := auditContentDigest(identity, event, withNetwork); err != nil || got != expected {
					t.Fatalf("contract5 historical network fact rejected: %v", err)
				}

				legacyWithNetwork := withNetwork
				legacyWithNetwork.DecisionContractVersion = 4
				if _, err := auditContentDigest(identity, event, legacyWithNetwork); !errors.Is(err, ErrForbidden) {
					t.Fatal("contract4 borrowed the contract5 network context")
				}

				corruptNetwork := withNetwork
				corruptDecision := networkDecision
				corruptDecision.NetworkContext = &iamv1.AuthorizationNetworkContext{SourceIP: "192.0.2.010"}
				corruptNetwork.Decision = &corruptDecision
				if _, err := auditContentDigest(identity, event, corruptNetwork); !errors.Is(err, ErrForbidden) {
					t.Fatal("contract5 accepted a noncanonical historical network fact")
				}
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
				"version unknown":     func(e *AuditEvidence) { e.DecisionContractVersion = 6 },
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

func TestBootstrapReplayUsesSealedInputWithoutReadmittingItsPassword(t *testing.T) {
	repository := &coreRepository{transaction: newCoreTransaction()}
	service, err := newCoreAuthority(repository, Config{})
	if err != nil {
		t.Fatal(err)
	}
	document := coreBootstrap(t)
	if _, err := service.Bootstrap(t.Context(), document); err != nil {
		t.Fatal(err)
	}
	// This unit fixture describes a real predecessor-shaped sealed document;
	// retained-binary PostgreSQL coverage owns proof of its actual creation.
	document.Administrator.Password = coreSecret(t, "Old-Secret-49!")
	digest, err := iamv1.BootstrapDigest(document)
	if err != nil {
		t.Fatal(err)
	}
	tx := repository.transaction
	tx.status.ContentDigest, tx.contentDigest = digest, digest
	original, hash := tx.status, tx.passwords[document.Administrator.ID]
	service.passwords = authority.NewPasswordHasher(bytes.NewReader(nil))
	result, err := service.Bootstrap(t.Context(), document)
	if err != nil || result != original || tx.passwords[document.Administrator.ID] != hash {
		t.Fatal("exact sealed replay re-admitted or replaced its old password", err)
	}
	variant := document
	variant.Administrator.DisplayName = "Different initial owner"
	if _, err := service.Bootstrap(t.Context(), variant); !errors.Is(err, ErrConflict) {
		t.Fatal("different bootstrap input acquired the historical replay path", err)
	}
	if tx.status != original || tx.passwords[document.Administrator.ID] != hash {
		t.Fatal("conflicting bootstrap changed existing authority")
	}
	fresh := &coreRepository{transaction: newCoreTransaction()}
	service, err = newCoreAuthority(fresh, Config{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Bootstrap(t.Context(), document); !errors.Is(err, ErrInvalidArgument) || fresh.transaction.contentDigest != "" {
		t.Fatal("missing receipt allowed a new weak bootstrap", err)
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
	return repository.run(ctx, callback)
}

func (repository *coreRepository) WithinLocalCredentialRecoveryTransaction(
	ctx context.Context,
	callback func(context.Context, Transaction) error,
) error {
	return repository.run(ctx, callback)
}

func (repository *coreRepository) run(
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

func TestRecoveryCodeMatchUsesCompleteOriginalBatchAndScope(t *testing.T) {
	issuer := authority.NewCredentialIssuer(nil)
	attempt := TOTPAttempt{AccountID: "account-one", UserID: "user-one", Purpose: "RECOVERY_CODE"}
	material := RecoveryCodeVerification{InstallationID: "installation-one", BatchID: "batch-one", Codes: make([]RecoveryCodeCandidate, 10)}
	secrets := make([]iamv1.Secret, 10)
	for i := range material.Codes {
		id := fmt.Sprintf("code-%02d", i)
		code, err := issuer.IssueMFARecoveryCode()
		if err != nil {
			t.Fatal(err)
		}
		digest, err := authority.DigestMFARecoveryCode(authority.MFARecoveryCodeScope{InstallationID: material.InstallationID, AccountID: attempt.AccountID, UserID: attempt.UserID, BatchID: material.BatchID, CodeID: id}, code)
		if err != nil {
			t.Fatal(err)
		}
		secrets[i], material.Codes[i] = code, RecoveryCodeCandidate{ID: id, VerificationDigest: digest}
	}
	for i, secret := range secrets {
		matched, ok, err := matchRecoveryCode(attempt, material, secret)
		if err != nil || !ok || matched.ID != material.Codes[i].ID {
			t.Fatal("original scoped code not found", err)
		}
	}
	material.Codes[0].Consumed = true
	if _, ok, err := matchRecoveryCode(attempt, material, secrets[0]); err != nil || ok {
		t.Fatal("consumed code matched", err)
	}
	malformed, _ := iamv1.NewSecret("not-a-recovery-code")
	if _, ok, err := matchRecoveryCode(attempt, material, malformed); err != nil || ok {
		t.Fatal("malformed candidate matched", err)
	}
	for _, alter := range []func(*TOTPAttempt, *RecoveryCodeVerification){
		func(a *TOTPAttempt, _ *RecoveryCodeVerification) { a.AccountID = "account-other" },
		func(a *TOTPAttempt, _ *RecoveryCodeVerification) { a.UserID = "user-other" },
		func(_ *TOTPAttempt, m *RecoveryCodeVerification) { m.InstallationID = "installation-other" },
		func(_ *TOTPAttempt, m *RecoveryCodeVerification) { m.BatchID = "batch-other" },
	} {
		a, m := attempt, material
		alter(&a, &m)
		if _, ok, err := matchRecoveryCode(a, m, secrets[9]); err != nil || ok {
			t.Fatal("another scope matched a recovery code", err)
		}
	}
	for _, alter := range []func(*RecoveryCodeVerification){
		func(m *RecoveryCodeVerification) { m.Codes = m.Codes[:9] },
		func(m *RecoveryCodeVerification) { m.Codes[9].ID = m.Codes[1].ID },
		func(m *RecoveryCodeVerification) { m.Codes[9].VerificationDigest = "invalid" },
	} {
		m := material
		m.Codes = append([]RecoveryCodeCandidate(nil), material.Codes...)
		alter(&m)
		if _, ok, err := matchRecoveryCode(attempt, m, secrets[1]); !errors.Is(err, ErrUnavailable) || ok {
			t.Fatal("incomplete or corrupt tail accepted an early match", err)
		}
	}
}

type coreTransaction struct {
	Transaction
	passwordRequirements          iamv1.PasswordRequirements
	passwordRequirementsError     error
	passwordRequirementsReads     int
	passwordRequirementsSession   iamv1.Session
	passwordRequirementsChallenge AuthenticationChallengeCredential
	loginChallenge                iamv1.AuthenticationChallenge
	enrollmentInspection          EnrollmentChallengeInspection
	loginAuthenticationState      *LoginAuthenticationState
	passwordResetRequirement      *PasswordResetRequirement
	passwordResetReason           iamv1.PasswordResetReason
	enrollmentReads               int
	challengeCredential           AuthenticationChallengeCredential
	challengeLookupDigest         string
	now                           time.Time
	status                        iamv1.BootstrapStatus
	contentDigest                 string
	organization                  iamv1.Organization
	principal                     iamv1.Principal
	services                      map[string]ServiceCredential
	sessions                      map[string]SessionCredential
	roleSessions                  map[string]RoleSessionCredential
	roleExitCredentials           map[string]RoleSessionExitCredential
	roleExitEvents                []auditv1.Event
	authorizations                []AuthorizationMutation
	passwords                     map[iamv1.PrincipalID]authority.PasswordHash
	passwordHistories             map[iamv1.PrincipalID][]authority.PasswordHash
	passwordAttempts              map[iamv1.PrincipalID]PasswordAttempt
	attemptSequence               uint64
	rejectedAttempts              []string
	users                         map[iamv1.PrincipalID]iamv1.Principal
	attachments                   map[iamv1.PolicyAttachmentID]iamv1.PolicyAttachment
	attachmentSession             iamv1.SessionID
	revocationSession             iamv1.SessionID
	sessionRevocation             *SessionRevocationMutation
	otherSessionRevocation        *OtherSessionRevocationMutation
	otherSessionResult            iamv1.RevokeOtherSessionsResponse
	otherSessionError             error
	ownSessionItems               *[]iamv1.Session
	sessionActivity               *iamv1.SessionActivity
	sessionActivityError          error
	sessionTouches                []iamv1.Session
	localRecoveryInspection       iamv1.LocalCredentialRecoveryInspection
	localRecoveryResult           iamv1.LocalCredentialRecoveryResult
	localRecoveryMutation         *LocalCredentialRecoveryMutation
	localRecoveryMaterial         PasswordReplacementMaterial
	localRecoveryPrepared         iamv1.LocalCredentialRecoveryInspection
	onLocalRecoveryPrepare        func()
	profileErr                    error
	accessKeyCustody              *AccessKeyCustody
	accessKeyCustodyErr           error
	totpCustody                   *TOTPCustody
	totpCustodyErr                error
	stepUpForVerification         iamv1.StepUp
	stepUpStartResult             iamv1.StepUp
	emailKeyset                   *authority.EmailVerificationKeyset
	replacementStart              func(TOTPReplacementStart) (TOTPEnrollmentStartResult, error)
	removalEffect                 func(AuthenticatorRemovalMutation) (iamv1.RemoveTOTPResponse, error)
	replacementCalls              int
	totpReservations              []TOTPAttempt
	denyTOTPReservation           bool
	totpAttemptReads              int
	settingsLockError             error
	settingsMutationCalled        bool
	passwordResetRead             func(AccountRead, iamv1.PrincipalID, uint64) (PasswordReplacementMaterial, error)
	passwordResetCompletionRead   func(AccountRead, iamv1.PrincipalID, string, uint64) (iamv1.UserPasswordResetCompletion, error)
	userCreationSettings          func(AccountRead) (iamv1.AccountPasswordSettings, uint64, error)
	userCreationMutation          *UserMutation
	userChange                    func(UserChange) (iamv1.User, error)
	rootPasswordRead              func(AccountRead, iamv1.AccountID, uint64) (iamv1.RootIdentity, PasswordReplacementMaterial, error)
	rootCredentialRecovery        func(RootCredentialRecovery) (iamv1.Account, error)
}

func (transaction *coreTransaction) ReadUserCreationPasswordSettings(_ context.Context, read AccountRead) (iamv1.AccountPasswordSettings, uint64, error) {
	if read.AccountID != transaction.organization.ID || read.ActorPrincipalID != transaction.principal.ID || read.DecisionID == "" {
		return iamv1.AccountPasswordSettings{}, 0, ErrForbidden
	}
	if transaction.userCreationSettings != nil {
		return transaction.userCreationSettings(read)
	}
	return authority.DefaultPasswordSettings(), 1, nil
}

func (transaction *coreTransaction) ReadPasswordReset(_ context.Context, read AccountRead, user iamv1.PrincipalID, version uint64) (PasswordReplacementMaterial, error) {
	return transaction.passwordResetRead(read, user, version)
}

func (transaction *coreTransaction) ReadUserPasswordResetCompletion(_ context.Context, read AccountRead, user iamv1.PrincipalID, request string, version uint64) (iamv1.UserPasswordResetCompletion, error) {
	return transaction.passwordResetCompletionRead(read, user, request, version)
}

func (transaction *coreTransaction) ChangeUser(_ context.Context, mutation UserChange) (iamv1.User, error) {
	return transaction.userChange(mutation)
}

func (transaction *coreTransaction) ReadRootPasswordRecovery(_ context.Context, read AccountRead, account iamv1.AccountID, version uint64) (iamv1.RootIdentity, PasswordReplacementMaterial, error) {
	return transaction.rootPasswordRead(read, account, version)
}

func (transaction *coreTransaction) RecoverRootCredentials(_ context.Context, mutation RootCredentialRecovery) (iamv1.Account, error) {
	return transaction.rootCredentialRecovery(mutation)
}

func (transaction *coreTransaction) LockAccountSecuritySettings(_ context.Context, caller iamv1.Session) error {
	if caller.AccountID != transaction.organization.ID || caller.PrincipalID != transaction.principal.ID {
		return ErrUnauthenticated
	}
	return transaction.settingsLockError
}

func (transaction *coreTransaction) UpdateAccountSecuritySettings(context.Context, SecuritySettingsMutation) (iamv1.UpdateAccountSecuritySettingsResponse, error) {
	transaction.settingsMutationCalled = true
	return iamv1.UpdateAccountSecuritySettingsResponse{}, ErrUnavailable
}

func (tx *coreTransaction) CreateLoginChallenge(context.Context, LoginChallengeCreation) (iamv1.AuthenticationChallenge, error) {
	return tx.loginChallenge, nil
}

func (tx *coreTransaction) RequirePasswordReset(_ context.Context, mutation PasswordResetRequirement) (iamv1.PasswordResetReason, error) {
	tx.passwordResetRequirement = &mutation
	return tx.passwordResetReason, nil
}

func (tx *coreTransaction) ReadPasswordRequirements(_ context.Context, session iamv1.Session) (iamv1.PasswordRequirements, error) {
	tx.passwordRequirementsReads++
	tx.passwordRequirementsSession = session
	return tx.passwordRequirements, tx.passwordRequirementsError
}

func (tx *coreTransaction) ReadChallengePasswordRequirements(_ context.Context, identity AuthenticationChallengeCredential) (iamv1.PasswordRequirements, error) {
	tx.passwordRequirementsReads++
	tx.passwordRequirementsChallenge = identity
	return tx.passwordRequirements, tx.passwordRequirementsError
}

func (tx *coreTransaction) LookupAuthenticationChallenge(_ context.Context, digest string) (AuthenticationChallengeCredential, bool, error) {
	return tx.challengeCredential, digest == tx.challengeLookupDigest, nil
}

func (transaction *coreTransaction) ReadStepUpForVerification(_ context.Context, caller iamv1.Session, id string) (iamv1.StepUp, error) {
	if id != transaction.stepUpForVerification.ID || caller.PrincipalID != transaction.principal.ID {
		return iamv1.StepUp{}, ErrStepUpNotFound
	}
	return transaction.stepUpForVerification, nil
}

func (transaction *coreTransaction) StartStepUp(_ context.Context, mutation StepUpStart) (iamv1.StepUp, error) {
	if mutation.Session.PrincipalID != transaction.principal.ID || mutation.Request.RequestID != transaction.stepUpStartResult.RequestID {
		return iamv1.StepUp{}, ErrUnavailable
	}
	return transaction.stepUpStartResult, nil
}

func (transaction *coreTransaction) ReadStepUpByRequest(context.Context, iamv1.Session, string) (iamv1.StepUp, error) {
	return transaction.stepUpStartResult, nil
}

func (transaction *coreTransaction) StartTOTPReplacement(_ context.Context, mutation TOTPReplacementStart) (TOTPEnrollmentStartResult, error) {
	transaction.replacementCalls++
	if transaction.replacementStart == nil {
		return TOTPEnrollmentStartResult{}, ErrUnavailable
	}
	return transaction.replacementStart(mutation)
}

func (transaction *coreTransaction) RemoveTOTP(_ context.Context, mutation AuthenticatorRemovalMutation) (iamv1.RemoveTOTPResponse, error) {
	return transaction.removalEffect(mutation)
}

func (transaction *coreTransaction) ReserveTOTPAttempt(_ context.Context, attempt TOTPAttempt) (TOTPAttempt, bool, error) {
	transaction.totpReservations = append(transaction.totpReservations, attempt)
	attempt.Sequence = uint64(len(transaction.totpReservations))
	return attempt, !transaction.denyTOTPReservation, nil
}

func (transaction *coreTransaction) ReadTOTPAttempt(context.Context, TOTPAttempt) (TOTPVerification, error) {
	transaction.totpAttemptReads++
	return TOTPVerification{}, ErrUnavailable
}

func (transaction *coreTransaction) ReadLoginAuthenticationState(context.Context, iamv1.AccountID, iamv1.PrincipalID) (LoginAuthenticationState, error) {
	if transaction.loginAuthenticationState != nil {
		return *transaction.loginAuthenticationState, nil
	}
	return LoginAuthenticationState{State: "NEVER_BOUND", Revision: 1, PasswordExpiryMode: iamv1.PasswordExpiryChange}, nil
}

func (*coreTransaction) ReadAuthenticatorState(context.Context, iamv1.Session) (iamv1.AuthenticatorState, error) {
	return iamv1.AuthenticatorState{}, ErrUnavailable
}
func (tx *coreTransaction) ReadEnrollmentChallenge(context.Context, AuthenticationChallengeCredential) (EnrollmentChallengeInspection, error) {
	tx.enrollmentReads++
	return tx.enrollmentInspection, nil
}
func (*coreTransaction) StartTOTPEnrollment(context.Context, TOTPEnrollmentStart) (TOTPEnrollmentStartResult, error) {
	return TOTPEnrollmentStartResult{}, ErrUnavailable
}
func (*coreTransaction) ReadTOTPEnrollment(context.Context, iamv1.Session, string) (iamv1.TOTPEnrollment, error) {
	return iamv1.TOTPEnrollment{}, ErrUnavailable
}
func (*coreTransaction) ReadTOTPEnrollmentByRequest(context.Context, iamv1.Session, string) (iamv1.TOTPEnrollment, error) {
	return iamv1.TOTPEnrollment{}, ErrUnavailable
}
func (*coreTransaction) CancelTOTPEnrollment(context.Context, iamv1.Session, string) (iamv1.TOTPEnrollment, error) {
	return iamv1.TOTPEnrollment{}, ErrUnavailable
}
func (*coreTransaction) ConfirmTOTPEnrollment(context.Context, TOTPBindingConfirmation) (iamv1.TOTPEnrollment, error) {
	return iamv1.TOTPEnrollment{}, ErrUnavailable
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
	return transaction.emailKeyset, nil
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

func (transaction *coreTransaction) InspectLocalCredentialRecovery(_ context.Context, scope iamv1.LocalCredentialRecoveryScope, query *iamv1.LocalCredentialRecoveryReceiptQuery) (iamv1.LocalCredentialRecoveryInspection, error) {
	if transaction.localRecoveryInspection.State == "" && query != nil {
		return iamv1.LocalCredentialRecoveryInspection{APIVersion: iamv1.APIVersion, Kind: "LocalCredentialRecoveryInspection",
			Scope: scope, State: "NOT_FOUND", CommandID: query.CommandID, InputCommitment: query.InputCommitment}, nil
	}
	return transaction.localRecoveryInspection, nil
}

func (transaction *coreTransaction) PrepareLocalCredentialRecovery(ctx context.Context, scope iamv1.LocalCredentialRecoveryScope, _ iamv1.LocalCredentialRecoveryExpected, query iamv1.LocalCredentialRecoveryReceiptQuery) (iamv1.LocalCredentialRecoveryInspection, PasswordReplacementMaterial, error) {
	if transaction.onLocalRecoveryPrepare != nil {
		transaction.onLocalRecoveryPrepare()
	}
	if transaction.localRecoveryPrepared.State != "" {
		return transaction.localRecoveryPrepared, PasswordReplacementMaterial{}, nil
	}
	inspection, err := transaction.InspectLocalCredentialRecovery(ctx, scope, &query)
	return inspection, transaction.localRecoveryMaterial, err
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
		Purpose: request.Purpose, IntentDigest: request.IntentDigest,
		MustChangePassword: selected.MustChangePassword, ExpiresAt: transaction.now.Add(30 * time.Second)}
	if request.Purpose == PasswordAttemptChange {
		attempt.PasswordHistory = append([]authority.PasswordHash{}, transaction.passwordHistories[selected.ID]...)
		attempt.HistoryDigest = transaction.passwordHistoryCommitment(selected.ID)
		attempt.PasswordSettings = authority.DefaultPasswordSettings()
		attempt.SettingsVersion = 1
	}
	transaction.passwordAttempts[selected.ID] = attempt
	return attempt, true, nil
}

// The fake models an opaque changing head, not PostgreSQL's private encoding.
// Real history validity, scope and final CAS are tested through the SQL owner.
func (transaction *coreTransaction) passwordHistoryCommitment(user iamv1.PrincipalID) string {
	material := append([]authority.PasswordHash{transaction.passwords[user]}, transaction.passwordHistories[user]...)
	encoded, _ := json.Marshal(material)
	defer clear(encoded)
	return fmt.Sprintf("sha256:%x", sha256.Sum256(encoded))
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

func (transaction *coreTransaction) TouchSession(_ context.Context, session iamv1.Session) (iamv1.SessionActivity, error) {
	transaction.sessionTouches = append(transaction.sessionTouches, session)
	if transaction.sessionActivityError != nil {
		return iamv1.SessionActivity{}, transaction.sessionActivityError
	}
	if transaction.sessionActivity != nil {
		return *transaction.sessionActivity, nil
	}
	return iamv1.SessionActivity{APIVersion: iamv1.APIVersion, Kind: "SessionActivity", SessionID: session.ID,
		AccountID: session.AccountID, UserID: session.PrincipalID, LastActivityAt: transaction.now,
		IdleExpiresAt: transaction.now.Add(30 * time.Minute), AbsoluteExpiresAt: session.ExpiresAt}, nil
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
	if transaction.passwords[mutation.PrincipalID] != mutation.ExpectedPasswordHash ||
		transaction.passwordHistoryCommitment(mutation.PrincipalID) != mutation.ExpectedHistoryDigest {
		return iamv1.ChangePasswordResponse{}, ErrUnauthenticated
	}
	delete(transaction.passwordAttempts, mutation.PrincipalID)
	if transaction.passwordHistories == nil {
		transaction.passwordHistories = make(map[iamv1.PrincipalID][]authority.PasswordHash)
	}
	history := append([]authority.PasswordHash{transaction.passwords[mutation.PrincipalID]}, transaction.passwordHistories[mutation.PrincipalID]...)
	transaction.passwordHistories[mutation.PrincipalID] = history[:min(24, len(history))]
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
	transaction.userCreationMutation = &mutation
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
