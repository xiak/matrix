package identityaccess

import (
	"context"
	"time"

	auditv1 "github.com/xiak/matrix/api/audit/v1"
	iamv1 "github.com/xiak/matrix/api/iam/v1"
	"github.com/xiak/matrix/app/service/iam/internal/authority"
)

// This private tuple is derived from one actual LOGIN_SESSION or the closed
// initial ENROLLMENT ceremony. Both fields together, or neither, are invalid.
// It is never a caller account/user selector or another principal.
type NotificationContactSubject struct {
	AccountID   iamv1.AccountID
	UserID      iamv1.PrincipalID
	SessionID   iamv1.SessionID
	ChallengeID string
}

type NotificationVerificationStart struct {
	Subject         NotificationContactSubject
	PasswordAttempt PasswordAttempt
	IntentDigest    string
	RequestID       string
	NotificationID  string
	Binding         iamv1.EmailVerificationBinding
	Sealed          authority.SealedEmailVerificationCode
	AuditEvent      auditv1.Event
}

type NotificationConfirmationAttempt struct {
	Subject  NotificationContactSubject
	ID       string
	Sequence uint64
	Binding  iamv1.EmailVerificationBinding
	Sealed   authority.SealedEmailVerificationCode
}

type NotificationConfirmation struct {
	Attempt        NotificationConfirmationAttempt
	NotificationID string
	AuditEvent     auditv1.Event
}

func (NotificationVerificationStart) String() string { return "[REDACTED]" }
func (NotificationVerificationStart) GoString() string {
	return "identityaccess.NotificationVerificationStart{[REDACTED]}"
}
func (NotificationVerificationStart) MarshalJSON() ([]byte, error) { return nil, ErrUnavailable }
func (NotificationConfirmationAttempt) String() string             { return "[REDACTED]" }
func (NotificationConfirmationAttempt) GoString() string {
	return "identityaccess.NotificationConfirmationAttempt{[REDACTED]}"
}
func (NotificationConfirmationAttempt) MarshalJSON() ([]byte, error) { return nil, ErrUnavailable }

func notificationSubject(subject SessionCredential) NotificationContactSubject {
	return NotificationContactSubject{AccountID: subject.Subject.Organization.ID, UserID: subject.Subject.Principal.ID, SessionID: subject.Subject.Session.ID}
}

func (service *Authority) enrollmentNotificationSubject(ctx context.Context, tx Transaction, id string, credential iamv1.Secret) (NotificationContactSubject, EnrollmentChallengeInspection, error) {
	identity, err := service.authenticateChallenge(ctx, tx, id, credential)
	if err != nil {
		return NotificationContactSubject{}, EnrollmentChallengeInspection{}, err
	}
	if identity.Purpose != "ENROLLMENT" || identity.NextStep != "ENROLLMENT" {
		return NotificationContactSubject{}, EnrollmentChallengeInspection{}, ErrUnauthenticated
	}
	inspection, err := readEnrollmentChallenge(ctx, tx, identity)
	if err != nil {
		return NotificationContactSubject{}, EnrollmentChallengeInspection{}, err
	}
	if err := service.checkEmailVerificationCustody(ctx, tx); err != nil {
		return NotificationContactSubject{}, EnrollmentChallengeInspection{}, err
	}
	return NotificationContactSubject{AccountID: identity.AccountID, UserID: identity.UserID, ChallengeID: identity.ID}, inspection, nil
}

// Startup registration only. Public requests cannot choose material or scope.
func (service *Authority) RegisterEmailVerificationKeyset(ctx context.Context) error {
	if service == nil || service.email == nil {
		return ErrUnavailable
	}
	return service.withinTransaction(ctx, func(ctx context.Context, tx Transaction) error {
		if err := tx.RegisterEmailVerificationKeyset(ctx, service.email.Registration()); err != nil {
			return err
		}
		return service.checkEmailVerificationCustody(ctx, tx)
	})
}

func (service *Authority) checkEmailVerificationCustody(ctx context.Context, tx Transaction) error {
	if service == nil || service.email == nil {
		return ErrUnavailable
	}
	actual, err := tx.ReadEmailVerificationKeyset(ctx)
	if err != nil {
		return err
	}
	if actual == nil || !service.email.Matches(*actual) {
		return ErrUnavailable
	}
	return nil
}

func (service *Authority) notificationSession(ctx context.Context, tx Transaction, credential iamv1.Secret) (SessionCredential, error) {
	now, err := transactionTime(ctx, tx)
	if err != nil {
		return SessionCredential{}, err
	}
	subject, err := service.authenticateSession(ctx, tx, credential, now)
	if err != nil {
		return SessionCredential{}, err
	}
	if subject.Subject.Principal.MustChangePassword {
		return SessionCredential{}, ErrForbidden
	}
	if err := service.checkEmailVerificationCustody(ctx, tx); err != nil {
		return SessionCredential{}, err
	}
	return subject, nil
}

func (service *Authority) NotificationContact(ctx context.Context, credential iamv1.Secret) (iamv1.NotificationContact, error) {
	var result iamv1.NotificationContact
	err := service.withinTransaction(ctx, func(ctx context.Context, tx Transaction) error {
		subject, err := service.notificationSession(ctx, tx, credential)
		if err != nil {
			return err
		}
		result, err = tx.ReadNotificationContact(ctx, notificationSubject(subject))
		return err
	})
	if err != nil {
		return iamv1.NotificationContact{}, err
	}
	if iamv1.ValidateNotificationContact(result) != nil {
		return iamv1.NotificationContact{}, ErrUnavailable
	}
	return result, nil
}

func (service *Authority) NotificationVerification(ctx context.Context, credential iamv1.Secret, id string) (iamv1.NotificationContactVerification, error) {
	if iamv1.ValidateID("verificationId", id) != nil {
		return iamv1.NotificationContactVerification{}, ErrInvalidArgument
	}
	var result iamv1.NotificationContactVerification
	err := service.withinTransaction(ctx, func(ctx context.Context, tx Transaction) error {
		subject, err := service.notificationSession(ctx, tx, credential)
		if err != nil {
			return err
		}
		result, err = tx.ReadNotificationVerification(ctx, notificationSubject(subject), id)
		return err
	})
	if err != nil {
		return iamv1.NotificationContactVerification{}, err
	}
	if iamv1.ValidateNotificationContactVerification(result) != nil {
		return iamv1.NotificationContactVerification{}, ErrUnavailable
	}
	return result, nil
}

func (service *Authority) StartNotificationVerification(ctx context.Context, credential iamv1.Secret, request iamv1.StartNotificationContactVerificationRequest) (iamv1.NotificationContactVerification, error) {
	if iamv1.ValidateStartNotificationContactVerificationRequest(request) != nil {
		return iamv1.NotificationContactVerification{}, ErrInvalidArgument
	}
	if err := service.acquirePasswordWork(ctx); err != nil {
		return iamv1.NotificationContactVerification{}, err
	}
	defer service.releasePasswordWork()
	attemptID, err := service.config.NewID("password-attempt")
	if err != nil {
		return iamv1.NotificationContactVerification{}, ErrUnavailable
	}
	var attempt PasswordAttempt
	var admitted bool
	err = service.withinTransaction(ctx, func(ctx context.Context, tx Transaction) error {
		subject, err := service.notificationSession(ctx, tx, credential)
		if err != nil {
			return err
		}
		// Private intent commitment, not an Audit digest or address directory.
		intent, err := digestSanitized("notification-contact-password", struct {
			SessionID        iamv1.SessionID
			RequestID, Email string
		}{subject.Subject.Session.ID, request.RequestID, request.Email})
		if err != nil {
			return err
		}
		attempt, admitted, err = tx.ReservePasswordAttempt(ctx, PasswordAttemptRequest{ID: attemptID,
			AccountID: subject.Subject.Organization.ID, UserID: subject.Subject.Principal.ID, SessionID: subject.Subject.Session.ID,
			Purpose: PasswordAttemptNotificationContact, IntentDigest: intent})
		return err
	})
	if err != nil {
		return iamv1.NotificationContactVerification{}, err
	}
	if err := service.verifyReservedPassword(ctx, request.Password, attempt, admitted); err != nil {
		return iamv1.NotificationContactVerification{}, err
	}
	verificationID, err := service.config.NewID("email-verification")
	if err != nil {
		return iamv1.NotificationContactVerification{}, ErrUnavailable
	}
	notificationID, err := service.config.NewID("notification")
	if err != nil {
		return iamv1.NotificationContactVerification{}, ErrUnavailable
	}
	code, err := service.credentials.IssueEmailVerificationCode()
	if err != nil {
		return iamv1.NotificationContactVerification{}, ErrUnavailable
	}
	var result iamv1.NotificationContactVerification
	err = service.withinTransaction(ctx, func(ctx context.Context, tx Transaction) error {
		subject, err := service.notificationSession(ctx, tx, credential)
		if err != nil {
			return err
		}
		if notificationSubject(subject) != (NotificationContactSubject{AccountID: attempt.AccountID, UserID: attempt.PrincipalID, SessionID: attempt.SessionID}) ||
			subject.CredentialGeneration != attempt.CredentialGeneration || attempt.Purpose != PasswordAttemptNotificationContact {
			return ErrUnauthenticated
		}
		now, err := transactionTime(ctx, tx)
		if err != nil {
			return err
		}
		result, err = service.recordNotificationVerification(ctx, tx, NotificationVerificationStart{Subject: notificationSubject(subject), PasswordAttempt: attempt,
			IntentDigest: attempt.IntentDigest, RequestID: request.RequestID, NotificationID: notificationID,
			Binding: iamv1.EmailVerificationBinding{AccountID: attempt.AccountID, UserID: attempt.PrincipalID, VerificationID: verificationID,
				Recipient: request.Email, CredentialGeneration: attempt.CredentialGeneration, IssuedAt: now, ExpiresAt: now.Add(10 * time.Minute)}}, code)
		return err
	})
	if err != nil {
		return iamv1.NotificationContactVerification{}, err
	}
	if iamv1.ValidateNotificationContactVerification(result) != nil {
		return iamv1.NotificationContactVerification{}, ErrUnavailable
	}
	return result, nil
}

func (service *Authority) StartChallengeNotificationVerification(ctx context.Context, id string, request iamv1.StartChallengeNotificationContactVerificationRequest) (iamv1.NotificationContactVerification, error) {
	if iamv1.ValidateID("challengeId", id) != nil || iamv1.ValidateStartChallengeNotificationContactVerificationRequest(request) != nil {
		return iamv1.NotificationContactVerification{}, ErrInvalidArgument
	}
	verificationID, err := service.config.NewID("email-verification")
	if err != nil {
		return iamv1.NotificationContactVerification{}, ErrUnavailable
	}
	notificationID, err := service.config.NewID("notification")
	if err != nil {
		return iamv1.NotificationContactVerification{}, ErrUnavailable
	}
	code, err := service.credentials.IssueEmailVerificationCode()
	if err != nil {
		return iamv1.NotificationContactVerification{}, ErrUnavailable
	}
	var result iamv1.NotificationContactVerification
	err = service.withinTransaction(ctx, func(ctx context.Context, tx Transaction) error {
		subject, inspection, err := service.enrollmentNotificationSubject(ctx, tx, id, request.ChallengeCredential)
		if err != nil {
			return err
		}
		now, err := transactionTime(ctx, tx)
		if err != nil {
			return err
		}
		// Private binding of the already password-proved ceremony, not a new
		// password attempt or an authorization decision for another identity.
		intent, err := digestSanitized("initial-enrollment-contact", struct{ ChallengeID, RequestID, Email string }{id, request.RequestID, request.Email})
		if err != nil {
			return err
		}
		result, err = service.recordNotificationVerification(ctx, tx, NotificationVerificationStart{Subject: subject, IntentDigest: intent,
			RequestID: request.RequestID, NotificationID: notificationID,
			Binding: iamv1.EmailVerificationBinding{AccountID: subject.AccountID, UserID: subject.UserID, VerificationID: verificationID,
				Recipient: request.Email, CredentialGeneration: inspection.CredentialGeneration, IssuedAt: now, ExpiresAt: inspection.State.Challenge.ExpiresAt}}, code)
		return err
	})
	if err != nil {
		return iamv1.NotificationContactVerification{}, err
	}
	if iamv1.ValidateNotificationContactVerification(result) != nil {
		return iamv1.NotificationContactVerification{}, ErrUnavailable
	}
	return result, nil
}

func (service *Authority) recordNotificationVerification(ctx context.Context, tx Transaction, change NotificationVerificationStart, code iamv1.Secret) (iamv1.NotificationContactVerification, error) {
	scope := service.email.Registration().Scope
	change.Binding.InstallationID, change.Binding.BootstrapDigest = scope.InstallationID, scope.BootstrapDigest
	sealed, err := service.email.Seal(change.Binding, code)
	if err != nil {
		return iamv1.NotificationContactVerification{}, ErrUnavailable
	}
	defer clear(sealed.Nonce)
	defer clear(sealed.Ciphertext)
	change.Sealed = sealed
	// No recipient, password, code or encrypted bytes enter the Audit fact.
	digest, err := digestSanitized("notification-contact-start", struct{ VerificationID, RequestID string }{change.Binding.VerificationID, change.RequestID})
	if err != nil {
		return iamv1.NotificationContactVerification{}, err
	}
	change.AuditEvent, err = service.notificationContactEvent(change.Subject, auditv1.ActionIAMNotificationContactVerificationStarted, digest, change.RequestID, change.Binding.IssuedAt)
	if err != nil {
		return iamv1.NotificationContactVerification{}, err
	}
	return tx.StartNotificationVerification(ctx, change)
}

func (service *Authority) notificationContactEvent(subject NotificationContactSubject, action auditv1.Action, digest, requestID string, now time.Time) (auditv1.Event, error) {
	if action != auditv1.ActionIAMNotificationContactVerificationStarted && action != auditv1.ActionIAMNotificationContactVerified {
		return auditv1.Event{}, ErrInvalidArgument
	}
	id, err := service.config.NewID("event")
	if err != nil {
		return auditv1.Event{}, ErrUnavailable
	}
	return newAuditEvent(id, subject.AccountID, "", auditv1.ActorReference{Type: auditv1.ActorUser, ID: auditv1.ActorID(subject.UserID)},
		action, auditv1.TargetReference{Kind: auditv1.TargetUser, ID: string(subject.UserID)}, auditv1.ResultSucceeded, "", digest, requestID, requestID, now)
}

func (service *Authority) ConfirmNotificationContact(ctx context.Context, credential iamv1.Secret, id string, request iamv1.ConfirmNotificationContactVerificationRequest) (iamv1.NotificationContactVerification, error) {
	if iamv1.ValidateID("verificationId", id) != nil || iamv1.ValidateConfirmNotificationContactVerificationRequest(request) != nil {
		return iamv1.NotificationContactVerification{}, ErrInvalidArgument
	}
	return service.confirmNotificationContact(ctx, id, request.RequestID, request.Code, func(ctx context.Context, tx Transaction) (NotificationContactSubject, uint64, error) {
		subject, err := service.notificationSession(ctx, tx, credential)
		return notificationSubject(subject), subject.CredentialGeneration, err
	})
}

func (service *Authority) ConfirmChallengeNotificationContact(ctx context.Context, challengeID, id string, request iamv1.ConfirmChallengeNotificationContactVerificationRequest) (iamv1.NotificationContactVerification, error) {
	if iamv1.ValidateID("challengeId", challengeID) != nil || iamv1.ValidateID("verificationId", id) != nil || iamv1.ValidateConfirmChallengeNotificationContactVerificationRequest(request) != nil {
		return iamv1.NotificationContactVerification{}, ErrInvalidArgument
	}
	return service.confirmNotificationContact(ctx, id, request.RequestID, request.Code, func(ctx context.Context, tx Transaction) (NotificationContactSubject, uint64, error) {
		subject, inspection, err := service.enrollmentNotificationSubject(ctx, tx, challengeID, request.ChallengeCredential)
		return subject, inspection.CredentialGeneration, err
	})
}

// Only the two closed public methods above supply authentication. The shared
// reservation/comparison/finalization keeps their same persistent guess budget.
func (service *Authority) confirmNotificationContact(ctx context.Context, id, requestID string, code iamv1.Secret,
	authenticate func(context.Context, Transaction) (NotificationContactSubject, uint64, error)) (iamv1.NotificationContactVerification, error) {
	attemptID, err := service.config.NewID("email-attempt")
	if err != nil {
		return iamv1.NotificationContactVerification{}, ErrUnavailable
	}
	var attempt NotificationConfirmationAttempt
	var admitted bool
	err = service.withinTransaction(ctx, func(ctx context.Context, tx Transaction) error {
		subject, _, err := authenticate(ctx, tx)
		if err != nil {
			return err
		}
		attempt, admitted, err = tx.ReserveNotificationConfirmation(ctx, subject, id, attemptID)
		return err
	})
	if err != nil {
		return iamv1.NotificationContactVerification{}, err
	}
	if !admitted {
		return iamv1.NotificationContactVerification{}, ErrOverloaded
	}
	defer clear(attempt.Sealed.Nonce)
	defer clear(attempt.Sealed.Ciphertext)
	// The debit has committed before decryption/comparison. Unknown failures
	// keep it consumed; they cannot mint a new attempt or refund the window.
	expected, err := service.email.Open(attempt.Binding, attempt.Sealed)
	if err != nil {
		return iamv1.NotificationContactVerification{}, ErrUnavailable
	}
	matched, err := authority.CompareEmailVerificationCode(expected, code)
	if err != nil || !matched {
		if err := service.withinTransaction(ctx, func(ctx context.Context, tx Transaction) error {
			return tx.RejectNotificationConfirmation(ctx, attempt)
		}); err != nil {
			return iamv1.NotificationContactVerification{}, err
		}
		return iamv1.NotificationContactVerification{}, ErrVerificationRejected
	}
	notificationID, err := service.config.NewID("notification")
	if err != nil {
		return iamv1.NotificationContactVerification{}, ErrUnavailable
	}
	var result iamv1.NotificationContactVerification
	err = service.withinTransaction(ctx, func(ctx context.Context, tx Transaction) error {
		subject, generation, err := authenticate(ctx, tx)
		if err != nil {
			return err
		}
		if subject != attempt.Subject || generation != attempt.Binding.CredentialGeneration {
			return ErrUnauthenticated
		}
		now, err := transactionTime(ctx, tx)
		if err != nil {
			return err
		}
		digest, err := digestSanitized("notification-contact-confirm", struct{ VerificationID, RequestID string }{id, requestID})
		if err != nil {
			return err
		}
		event, err := service.notificationContactEvent(subject, auditv1.ActionIAMNotificationContactVerified, digest, requestID, now)
		if err != nil {
			return err
		}
		result, err = tx.ConfirmNotificationContact(ctx, NotificationConfirmation{Attempt: attempt, NotificationID: notificationID, AuditEvent: event})
		return err
	})
	if err != nil {
		return iamv1.NotificationContactVerification{}, err
	}
	if iamv1.ValidateNotificationContactVerification(result) != nil {
		return iamv1.NotificationContactVerification{}, ErrUnavailable
	}
	return result, nil
}
