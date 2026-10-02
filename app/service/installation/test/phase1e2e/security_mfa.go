package phase1e2e

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"net/http"
	"time"

	iamv1 "github.com/xiak/matrix/api/iam/v1"
	"github.com/xiak/matrix/test/totpauthenticator"
)

type startTOTPEnrollmentWire struct {
	RequestID              string `json:"requestId"`
	Password               string `json:"password"`
	ExpectedFactorRevision uint64 `json:"expectedFactorRevision"`
}

type confirmTOTPEnrollmentWire struct {
	RequestID string `json:"requestId"`
	Code      string `json:"code"`
}

type verifyAuthenticationChallengeWire struct {
	RequestID           string `json:"requestId"`
	ChallengeCredential string `json:"challengeCredential"`
	Code                string `json:"code"`
}

func (client *edgeClient) authenticatorState(ctx context.Context, bearer []byte) (iamv1.AuthenticatorState, error) {
	response, err := client.json(ctx, http.MethodGet, "/api/iam/v1/auth/authenticators", bearer, nil, nil, http.StatusOK)
	if err != nil {
		return iamv1.AuthenticatorState{}, err
	}
	defer clear(response.body)
	var result iamv1.AuthenticatorState
	if response.header.Get("Cache-Control") != "no-store" || decodeOne(response.body, &result) != nil ||
		iamv1.ValidateAuthenticatorState(result) != nil {
		return iamv1.AuthenticatorState{}, errors.New("IAM authenticator state response failed")
	}
	return result, nil
}

func (client *edgeClient) authenticatorBearerRejected(ctx context.Context, bearer []byte) error {
	response, err := client.json(
		ctx, http.MethodGet, "/api/iam/v1/auth/authenticators", bearer, nil, nil, http.StatusUnauthorized,
	)
	clear(response.body)
	return err
}

func (client *edgeClient) startTOTPEnrollment(
	ctx context.Context,
	bearer, password []byte,
	revision uint64,
) (iamv1.StartTOTPEnrollmentResponse, error) {
	response, err := client.json(
		ctx, http.MethodPost, "/api/iam/v1/auth/totp/enrollments", bearer,
		startTOTPEnrollmentWire{
			RequestID: "phase1-signed-mfa-enrollment", Password: string(password),
			ExpectedFactorRevision: revision,
		}, nil, http.StatusOK,
	)
	if err != nil {
		return iamv1.StartTOTPEnrollmentResponse{}, err
	}
	defer clear(response.body)
	var result iamv1.StartTOTPEnrollmentResponse
	if response.header.Get("Cache-Control") != "no-store" || decodeOne(response.body, &result) != nil ||
		iamv1.ValidateStartTOTPEnrollmentResponse(result) != nil || result.Outcome != "APPLIED" || result.Provisioning == nil {
		return iamv1.StartTOTPEnrollmentResponse{}, errors.New("IAM TOTP enrollment start response failed")
	}
	return result, nil
}

func (client *edgeClient) confirmTOTPEnrollment(
	ctx context.Context,
	bearer, code []byte,
	enrollmentID string,
) (iamv1.ConfirmTOTPEnrollmentResponse, error) {
	response, err := client.json(
		ctx, http.MethodPost, "/api/iam/v1/auth/totp/enrollments/"+enrollmentID+":confirm", bearer,
		confirmTOTPEnrollmentWire{RequestID: "phase1-signed-mfa-confirm", Code: string(code)},
		nil, http.StatusOK,
	)
	if err != nil {
		return iamv1.ConfirmTOTPEnrollmentResponse{}, err
	}
	defer clear(response.body)
	var result iamv1.ConfirmTOTPEnrollmentResponse
	if response.header.Get("Cache-Control") != "no-store" || decodeOne(response.body, &result) != nil ||
		iamv1.ValidateConfirmTOTPEnrollmentResponse(result) != nil || result.Enrollment.ID != enrollmentID ||
		result.Enrollment.State != "CONFIRMED" || result.NextStep != "REAUTHENTICATE" || len(result.RecoveryCodes) != 10 {
		return iamv1.ConfirmTOTPEnrollmentResponse{}, errors.New("IAM TOTP enrollment confirmation response failed")
	}
	return result, nil
}

func (client *edgeClient) loginWithTOTP(
	ctx context.Context,
	loginName string,
	password, seed []byte,
	accountID iamv1.AccountID,
	userID iamv1.PrincipalID,
	requestPrefix string,
	minimumStep int64,
) (iamv1.LoginResponse, int64, error) {
	step, code, err := nextTOTPCode(ctx, seed, minimumStep)
	if err != nil {
		return iamv1.LoginResponse{}, 0, err
	}
	defer clear(code)
	started, err := client.json(
		ctx, http.MethodPost, "/api/iam/v1/auth/login", nil,
		loginWire{LoginName: loginName, Password: string(password), RequestID: requestPrefix + "-password"},
		nil, http.StatusOK,
	)
	if err != nil {
		return iamv1.LoginResponse{}, 0, err
	}
	defer clear(started.body)
	var challenge iamv1.LoginResponse
	if started.header.Get("Cache-Control") != "no-store" || decodeOne(started.body, &challenge) != nil ||
		iamv1.ValidateLoginResponse(challenge) != nil || challenge.Outcome != iamv1.LoginChallengeRequired ||
		challenge.Challenge == nil || challenge.Challenge.Purpose != "LOGIN" || challenge.Challenge.NextStep != "TOTP" ||
		!challenge.ChallengeCredential.Present() || challenge.Credential.Present() {
		return iamv1.LoginResponse{}, 0, errors.New("IAM TOTP login challenge failed")
	}
	challengeCredential := challenge.ChallengeCredential.CopyBytes()
	defer clear(challengeCredential)
	completed, err := client.json(
		ctx, http.MethodPost, "/api/iam/v1/auth/challenges/"+challenge.Challenge.ID+":verify", nil,
		verifyAuthenticationChallengeWire{
			RequestID: requestPrefix + "-totp", ChallengeCredential: string(challengeCredential), Code: string(code),
		}, nil, http.StatusOK,
	)
	if err != nil {
		return iamv1.LoginResponse{}, 0, err
	}
	defer clear(completed.body)
	var result iamv1.LoginResponse
	if completed.header.Get("Cache-Control") != "no-store" || decodeOne(completed.body, &result) != nil ||
		iamv1.ValidateLoginResponse(result) != nil || result.Outcome != iamv1.LoginAuthenticated ||
		result.Session.AccountID != accountID || result.Session.PrincipalID != userID || !result.Credential.Present() ||
		result.MustChangePassword || result.Challenge != nil || result.ChallengeCredential.Present() {
		return iamv1.LoginResponse{}, 0, errors.New("IAM TOTP login completion failed")
	}
	return result, step, nil
}

func nextTOTPCode(ctx context.Context, seed []byte, minimumStep int64) (int64, []byte, error) {
	if len(seed) == 0 || minimumStep < -1 {
		return 0, nil, errors.New("TOTP fixture state is invalid")
	}
	deadline := time.Now().Add(35 * time.Second)
	for {
		instant := time.Now()
		step := instant.Unix() / 30
		if step > minimumStep {
			code, generatedStep, err := totpauthenticator.Code(seed, instant)
			if err != nil || generatedStep != step {
				return 0, nil, errors.New("TOTP fixture code generation failed")
			}
			return step, code, nil
		}
		if time.Now().After(deadline) {
			return 0, nil, errors.New("TOTP fixture did not reach a fresh time step")
		}
		select {
		case <-ctx.Done():
			return 0, nil, errors.New("TOTP fixture was cancelled")
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func (value *gate) verifySignedMFA(
	ctx context.Context,
	operator []byte,
	installationID string,
) (mfaRetention, error) {
	initialPassword, err := randomPassword(rand.Reader)
	if err != nil {
		return mfaRetention{}, fail("signed-mfa-initial-password")
	}
	defer clear(initialPassword)
	password, err := randomPassword(rand.Reader)
	if err != nil {
		return mfaRetention{}, fail("signed-mfa-password")
	}
	value.edge.addForbidden(bytes.Clone(initialPassword), bytes.Clone(password))
	var user iamv1.User
	if err := value.edge.mutateIAM(ctx, "/users", operator, map[string]any{
		"loginName": "signed.mfa", "displayName": "Signed MFA lifecycle",
		"initialPassword": string(initialPassword), "requestId": "phase1-signed-mfa-user",
	}, &user, http.StatusCreated); err != nil || iamv1.ValidateUser(user) != nil {
		clear(password)
		return mfaRetention{}, fail("signed-mfa-user")
	}
	loginName := "signed.mfa@" + string(user.AccountID)
	temporary, err := value.edge.loginNamed(
		ctx, loginName, initialPassword, user.AccountID, user.ID, "phase1-signed-mfa-initial-login",
	)
	if err != nil || !temporary.MustChangePassword {
		clear(password)
		return mfaRetention{}, fail("signed-mfa-initial-login")
	}
	temporaryCredential := temporary.Credential.CopyBytes()
	defer clear(temporaryCredential)
	value.edge.addForbidden(bytes.Clone(temporaryCredential))
	if err := value.edge.changePassword(ctx, temporaryCredential, initialPassword, password, false, nil); err != nil ||
		value.edge.logout(ctx, temporaryCredential) != nil {
		clear(password)
		return mfaRetention{}, fail("signed-mfa-password-change")
	}
	current, err := value.edge.loginNamed(
		ctx, loginName, password, user.AccountID, user.ID, "phase1-signed-mfa-current-login",
	)
	if err != nil || current.MustChangePassword {
		clear(password)
		return mfaRetention{}, fail("signed-mfa-current-login")
	}
	currentCredential := current.Credential.CopyBytes()
	defer clear(currentCredential)
	value.edge.addForbidden(bytes.Clone(currentCredential))
	fixture, err := startSecurityMailFixture(ctx, value.config, installationID)
	if err != nil {
		clear(password)
		return mfaRetention{}, err
	}
	var result mfaRetention
	verifyErr := func() error {
		contact, err := value.verifySecurityMailWithFixture(
			ctx, currentCredential, password, fixture, "phase1-signed-mfa-mail",
		)
		if err != nil {
			return err
		}
		state, err := value.edge.authenticatorState(ctx, currentCredential)
		if err != nil || state.EnrollmentState != "NEVER_BOUND" || state.FactorRevision != 1 || state.FactorID != "" {
			return fail("signed-mfa-initial-state")
		}
		started, err := value.edge.startTOTPEnrollment(ctx, currentCredential, password, state.FactorRevision)
		if err != nil || started.Enrollment.Purpose != "INITIAL" || started.Enrollment.FactorRevision != 1 {
			return fail("signed-mfa-enrollment-start")
		}
		seed := started.Provisioning.Seed.CopyBytes()
		uri := started.Provisioning.URI.CopyBytes()
		defer clear(uri)
		if len(seed) == 0 || len(uri) == 0 {
			clear(seed)
			return fail("signed-mfa-provisioning")
		}
		value.edge.addForbidden(seed, bytes.Clone(uri))
		step, code, err := nextTOTPCode(ctx, seed, -1)
		if err != nil {
			clear(seed)
			return fail("signed-mfa-enrollment-code")
		}
		value.edge.addForbidden(bytes.Clone(code))
		confirmed, err := value.edge.confirmTOTPEnrollment(ctx, currentCredential, code, started.Enrollment.ID)
		clear(code)
		if err != nil {
			clear(seed)
			return fail("signed-mfa-enrollment-confirm")
		}
		for _, secret := range confirmed.RecoveryCodes {
			code := secret.CopyBytes()
			value.edge.addForbidden(bytes.Clone(code))
			clear(code)
		}
		if err := value.edge.authenticatorBearerRejected(ctx, currentCredential); err != nil {
			clear(seed)
			return fail("signed-mfa-old-session")
		}
		authenticated, loginStep, err := value.edge.loginWithTOTP(
			ctx, loginName, password, seed, user.AccountID, user.ID, "phase1-signed-mfa-login", step,
		)
		if err != nil {
			clear(seed)
			return fail("signed-mfa-login")
		}
		credential := authenticated.Credential.CopyBytes()
		value.edge.addForbidden(credential)
		bound, err := value.edge.authenticatorState(ctx, credential)
		if err != nil || bound.EnrollmentState != "BOUND" || bound.FactorRevision != 2 ||
			bound.FactorID != started.Enrollment.ID {
			clear(seed)
			clear(credential)
			return fail("signed-mfa-bound-state")
		}
		notice, _, err := fixture.receive(ctx, "MATRIX authenticator bound", value.edge.forbidden)
		if err != nil || bytes.Contains(notice, seed) {
			clear(notice)
			clear(seed)
			clear(credential)
			return fail("signed-mfa-security-notice")
		}
		clear(notice)
		result = mfaRetention{
			User: user, Password: append([]byte(nil), password...), Seed: seed,
			Credential: credential, Contact: contact, State: bound, LastConsumedStep: loginStep,
		}
		return nil
	}()
	cleanupCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cleanupErr := fixture.close(cleanupCtx)
	clear(password)
	if verifyErr != nil {
		clear(result.Password)
		clear(result.Seed)
		clear(result.Credential)
		return mfaRetention{}, verifyErr
	}
	if cleanupErr != nil {
		clear(result.Password)
		clear(result.Seed)
		clear(result.Credential)
		return mfaRetention{}, fail("signed-mfa-fixture-cleanup")
	}
	return result, nil
}

func (value *gate) assertMFARetention(ctx context.Context, freshLogin bool) error {
	if value.retainedIAM == nil || !validMFARetention(value.retainedIAM.MFA) {
		return fail("signed-mfa-retention-fixture")
	}
	retained := &value.retainedIAM.MFA
	state, err := value.edge.authenticatorState(ctx, retained.Credential)
	if err != nil || !sameAuthenticatorState(state, retained.State) {
		return fail("signed-mfa-retained-session")
	}
	contact, err := value.edge.notificationContact(ctx, retained.Credential)
	if err != nil || !sameNotificationContact(contact, retained.Contact) {
		return fail("signed-mfa-retained-contact")
	}
	if !freshLogin {
		return nil
	}
	loginName := retained.User.LoginName + "@" + string(retained.User.AccountID)
	authenticated, step, err := value.edge.loginWithTOTP(
		ctx, loginName, retained.Password, retained.Seed, retained.User.AccountID, retained.User.ID,
		"phase1-signed-mfa-restart", retained.LastConsumedStep,
	)
	if err != nil {
		return fail("signed-mfa-restart-login")
	}
	credential := authenticated.Credential.CopyBytes()
	defer clear(credential)
	value.edge.addForbidden(bytes.Clone(credential))
	retained.LastConsumedStep = step
	state, err = value.edge.authenticatorState(ctx, credential)
	if err != nil || !sameAuthenticatorState(state, retained.State) {
		return fail("signed-mfa-restart-state")
	}
	if err := value.edge.logout(ctx, credential); err != nil {
		return fail("signed-mfa-restart-logout")
	}
	return nil
}

func validMFARetention(value mfaRetention) bool {
	return iamv1.ValidateUser(value.User) == nil && len(value.Password) != 0 && len(value.Seed) != 0 &&
		len(value.Credential) != 0 && value.LastConsumedStep >= 0 &&
		iamv1.ValidateNotificationContact(value.Contact) == nil && value.Contact.State == "VERIFIED" &&
		value.Contact.AccountID == value.User.AccountID && value.Contact.UserID == value.User.ID &&
		iamv1.ValidateAuthenticatorState(value.State) == nil && value.State.EnrollmentState == "BOUND"
}

func sameAuthenticatorState(left, right iamv1.AuthenticatorState) bool {
	return left == right
}
