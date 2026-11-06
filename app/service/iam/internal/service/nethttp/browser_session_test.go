package nethttp

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	iamv1 "github.com/xiak/matrix/api/iam/v1"
	"github.com/xiak/matrix/app/service/iam/internal/usecase/identityaccess"
	"github.com/xiak/matrix/app/service/internal/processhttp"
)

type browserWorkflow struct {
	Workflow
	login        iamv1.LoginResponse
	current      identityaccess.CurrentSession
	currentError error
	currentCalls int
}

func (v *browserWorkflow) Login(context.Context, iamv1.LoginRequest) (iamv1.LoginResponse, error) {
	return v.login, nil
}
func (v *browserWorkflow) CurrentSession(_ context.Context, credential iamv1.Secret) (identityaccess.CurrentSession, error) {
	v.currentCalls++
	if !credential.Present() {
		return identityaccess.CurrentSession{}, identityaccess.ErrUnauthenticated
	}
	return v.current, v.currentError
}

func TestBrowserLoginAndRestorationNeverExposeReusableCredential(t *testing.T) {
	const origin = "https://console.example.test"
	secretText := "mx1." + strings.Repeat("a", 43)
	secret, err := iamv1.NewSecret(secretText)
	if err != nil {
		t.Fatal(err)
	}
	session := iamv1.Session{APIVersion: iamv1.APIVersion, Kind: "Session", ID: "session-browser", AccountID: "account-one", PrincipalID: "user-one", Status: iamv1.SessionActive, IssuedAt: time.Now().UTC().Truncate(time.Second), ExpiresAt: time.Now().Add(time.Hour).UTC().Truncate(time.Second)}
	workflow := &browserWorkflow{login: iamv1.LoginResponse{Outcome: iamv1.LoginAuthenticated, Session: session, Credential: secret, MustChangePassword: true},
		current: identityaccess.CurrentSession{Session: session, LoginName: "user-one", MustChangePassword: true}}
	handler, err := NewHandler(workflow, Config{BrowserOrigin: origin})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "/v1/auth/login", strings.NewReader(`{"loginName":"user-one","password":"synthetic-password","requestId":"login-one"}`))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", origin)
	r.Header.Set(processhttp.BrowserTransportHeader, "cookie")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("login status %d", w.Code)
	}
	if strings.Contains(w.Body.String(), secretText) || strings.Contains(w.Body.String(), `"credential"`) {
		t.Fatal("browser login exposed a bearer")
	}
	cookies := w.Result().Cookies()
	if len(cookies) != 1 || !cookies[0].HttpOnly || !cookies[0].Secure {
		t.Fatal("missing protected cookie")
	}
	var login map[string]any
	if json.Unmarshal(w.Body.Bytes(), &login) != nil || login["browserCredential"] != processhttp.BrowserCredentialReference(secretText, false) {
		t.Fatal("invalid reference")
	}
	for _, status := range []int{200, 401, 503} {
		workflow.currentError = nil
		if status == 401 {
			workflow.currentError = identityaccess.ErrUnauthenticated
		}
		if status == 503 {
			workflow.currentError = identityaccess.ErrUnavailable
		}
		r := httptest.NewRequest("GET", "/v1/auth/browser-session", nil)
		r.Header.Set(processhttp.BrowserTransportHeader, "cookie")
		r.AddCookie(cookies[0])
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != status || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("restoration status %d want %d", w.Code, status)
		}
		if strings.Contains(w.Body.String(), secretText) || w.Header().Get("Set-Cookie") != "" {
			t.Fatal("read exposed/rotated a credential or erased another tab's session")
		}
		if status == 200 {
			var restored map[string]any
			if json.Unmarshal(w.Body.Bytes(), &restored) != nil || restored["mustChangePassword"] != true || restored["loginName"] != "user-one" {
				t.Fatal("restoration lost restricted identity")
			}
		}
	}
	if workflow.currentCalls != 3 {
		t.Fatal("restoration skipped current authority")
	}
}
