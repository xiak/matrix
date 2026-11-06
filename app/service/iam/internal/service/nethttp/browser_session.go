package nethttp

import (
	"net/http"

	iamv1 "github.com/xiak/matrix/api/iam/v1"
	"github.com/xiak/matrix/app/service/iam/internal/usecase/identityaccess"
	"github.com/xiak/matrix/app/service/internal/processhttp"
)

func (value *handler) writeLoginResponse(w http.ResponseWriter, r *http.Request, result iamv1.LoginResponse) {
	encoded, err := iamv1.EncodeLoginResponse(result)
	if err != nil {
		value.writeError(w, r, identityaccess.ErrUnavailable)
		return
	}
	defer clear(encoded)
	if !processhttp.IsBrowserSessionRequest(r) || result.Outcome != iamv1.LoginAuthenticated {
		writeEncodedJSON(w, http.StatusOK, encoded)
		return
	}
	secret := result.Credential.CopyBytes()
	defer clear(secret)
	reference, err := processhttp.SetBrowserSession(w, r, value.config.BrowserOrigin, string(secret), result.Session.ExpiresAt, false)
	if err != nil {
		value.writeError(w, r, identityaccess.ErrUnavailable)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"outcome": result.Outcome, "session": result.Session,
		"mustChangePassword": result.MustChangePassword, "browserCredential": reference})
}

func (value *handler) currentBrowserSession(w http.ResponseWriter, r *http.Request) {
	if !value.requireMethod(w, r, http.MethodGet) || !rejectQueryAndBody(w, r) {
		return
	}
	if len(r.Header.Values("Authorization")) != 0 || len(r.Header.Values("Matrix-Subject-Credential")) != 0 {
		writeAuthenticationProblem(w, r)
		return
	}
	secret, ok := processhttp.BrowserSessionCredential(r, value.config.BrowserOrigin)
	if !ok {
		writeAuthenticationProblem(w, r)
		return
	}
	credential, err := iamv1.NewSecret(secret)
	if err != nil {
		writeAuthenticationProblem(w, r)
		return
	}
	current, err := value.workflow.CurrentSession(r.Context(), credential)
	if err != nil {
		// Never clear a cookie on a failed old request: another tab may already
		// have established a different session. Revocation is authoritative in IAM.
		value.writeError(w, r, err)
		return
	}
	if iamv1.ValidateSession(current.Session) != nil || current.Session.Status != iamv1.SessionActive || current.LoginName == "" {
		value.writeError(w, r, identityaccess.ErrUnavailable)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"session": current.Session, "loginName": current.LoginName,
		"mustChangePassword": current.MustChangePassword, "browserCredential": processhttp.BrowserCredentialReference(secret, false)})
}
