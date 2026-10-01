package main

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestGeneratedOpenAPIIsCurrent(t *testing.T) {
	want, err := os.ReadFile("../../openapi.json")
	if err != nil {
		t.Fatalf("read committed OpenAPI: %v", err)
	}
	got, err := json.MarshalIndent(buildDocument(), "", "  ")
	if err != nil {
		t.Fatalf("generate OpenAPI: %v", err)
	}
	got = append(got, '\n')
	if !bytes.Equal(got, want) {
		t.Fatal("openapi.json is stale; run go generate ./api/iam/v1")
	}
}

func TestAuthorizationBatchPublishesOnlyTheCredentialBoundClosedRoute(t *testing.T) {
	path, ok := buildPaths()["/v1/authorize:batch"].(object)
	if !ok || len(path) != 1 || path["post"] == nil {
		t.Fatal("authorization batch route is missing or exposes another method")
	}
	operation := path["post"].(object)
	if operation["operationId"] != "authorizeBatch" || operation["parameters"] != nil {
		t.Fatal("authorization batch exposes a selector")
	}
	security, ok := operation["security"].([]any)
	if !ok || len(security) != 1 {
		t.Fatal("authorization batch lost its two credential carriers")
	}
	request := operation["requestBody"].(object)["content"].(object)["application/json"].(object)["schema"].(object)
	response := operation["responses"].(object)["200"].(object)["content"].(object)["application/json"].(object)["schema"].(object)
	if request["$ref"] != "#/components/schemas/AuthorizationBatchRequest" || response["$ref"] != "#/components/schemas/AuthorizationBatchDecision" {
		t.Fatal("authorization batch uses a broader request or response")
	}
}

func TestPasswordOverloadOnlyDocumentsTheBoundedAuthenticationEntrypoints(t *testing.T) {
	for _, operation := range []string{"login", "changePassword", "verifyStepUp", "createUser", "regenerateRecoveryCodes"} {
		value := mutationOperation(operation, "test", "LoginRequest", "LoginResponse", "200", nil, nil)
		responses := value["responses"].(object)
		_, present := responses["429"]
		if present != (operation == "login" || operation == "changePassword" || operation == "verifyStepUp") {
			t.Fatal("overload contract leaked to unrelated commands")
		}
	}
}

func TestPasswordRequirementsPublishOnlySelfAndOriginalChallenge(t *testing.T) {
	paths := buildPaths()
	own := paths["/v1/auth/password-requirements"].(object)
	if len(own) != 1 || own["get"] == nil {
		t.Fatal("self rules have another method")
	}
	get := own["get"].(object)
	if get["requestBody"] != nil || get["parameters"] != nil || get["security"] != nil || get["responses"].(object)["400"] == nil {
		t.Fatal("self requirements changed login-Session authority or accepted selectors")
	}
	challenge := paths["/v1/auth/challenges/{challengeId}/password-requirements"].(object)
	if len(challenge) != 1 || challenge["post"] == nil {
		t.Fatal("challenge secret became a GET parameter")
	}
	post := challenge["post"].(object)
	if security, ok := post["security"].([]any); !ok || len(security) != 0 {
		t.Fatal("challenge inherited bearer authentication")
	}
	parameters := post["parameters"].([]any)
	if len(parameters) != 1 || parameters[0].(object)["name"] != "challengeId" || parameters[0].(object)["in"] != "path" {
		t.Fatal("challenge rules accept an authority selector")
	}
	request := post["requestBody"].(object)["content"].(object)["application/json"].(object)["schema"].(object)
	if request["$ref"] != "#/components/schemas/ChallengePasswordRequirementsRequest" {
		t.Fatal("challenge rules use another secret carrier")
	}
}

func TestSecuritySettingsPublishesExactMutationAndOwnCompletion(t *testing.T) {
	document := buildDocument()
	found := 0
	for path, value := range document["paths"].(object) {
		if strings.HasPrefix(path, "/v1/account/security-settings") {
			methods := value.(object)
			if path == "/v1/account/security-settings" {
				if len(methods) != 2 || methods["get"] == nil || methods["put"] == nil {
					t.Fatal("settings methods differ")
				}
			} else if path != "/v1/account/security-settings/changes/{requestId}" || len(methods) != 1 || methods["get"] == nil {
				t.Fatal("settings exposes an extra selector or completion mutation")
			}
			found++
		}
	}
	if found != 2 {
		t.Fatal("settings command or completion is not documented")
	}
}

func TestSecurityReportPublishesOnlyCurrentAccountCreateReadAndCSV(t *testing.T) {
	paths := buildPaths()
	collection := paths["/v1/account/security-reports"].(object)
	if len(collection) != 1 || collection["post"] == nil {
		t.Fatal("security reports expose a directory or another collection method")
	}
	post := collection["post"].(object)
	if post["operationId"] != "createAccountSecurityReport" || post["parameters"] != nil {
		t.Fatal("security report creation exposes an authority selector")
	}
	request := post["requestBody"].(object)["content"].(object)["application/json"].(object)["schema"].(object)
	if request["$ref"] != "#/components/schemas/CreateAccountSecurityReportRequest" {
		t.Fatal("security report creation uses another request")
	}
	read := paths["/v1/account/security-reports/{reportId}"].(object)
	download := paths["/v1/account/security-reports/{reportId}/content"].(object)
	for name, route := range map[string]object{"read": read, "download": download} {
		if len(route) != 1 || route["get"] == nil {
			t.Fatal(name, " security report route exposes another method")
		}
		parameters := route["get"].(object)["parameters"].([]any)
		if len(parameters) != 1 || parameters[0].(object)["name"] != "reportId" || parameters[0].(object)["in"] != "path" {
			t.Fatal(name, " security report route accepts another selector")
		}
	}
	csvResponse := download["get"].(object)["responses"].(object)["200"].(object)
	if csvResponse["content"].(object)["text/csv"] == nil || csvResponse["headers"].(object)["Cache-Control"] == nil ||
		csvResponse["headers"].(object)["Content-Disposition"] == nil {
		t.Fatal("security report download is not a protected bounded CSV response")
	}
}

func TestInitialEnrollmentDocumentsItsOwnCredentialCarrier(t *testing.T) {
	paths := buildDocument()["paths"].(object)
	for _, sample := range []struct{ path, operation, request, response string }{
		{"/v1/auth/challenges/{challengeId}:enrollment-state", "inspectEnrollmentChallenge", "InspectEnrollmentChallengeRequest", "EnrollmentChallengeState"},
		{"/v1/auth/challenges/{challengeId}:enroll", "startChallengeTOTPEnrollment", "StartChallengeTOTPEnrollmentRequest", "StartTOTPEnrollmentResponse"},
		{"/v1/auth/challenges/{challengeId}:confirm-enrollment", "confirmChallengeTOTPEnrollment", "VerifyAuthenticationChallengeRequest", "ConfirmTOTPEnrollmentResponse"},
		{"/v1/auth/challenges/{challengeId}/notification-contact/verifications", "startChallengeNotificationVerification", "StartChallengeNotificationContactVerificationRequest", "NotificationContactVerification"},
		{"/v1/auth/challenges/{challengeId}/notification-contact/verifications/{verificationId}:confirm", "confirmChallengeNotificationContact", "ConfirmChallengeNotificationContactVerificationRequest", "NotificationContactVerification"},
	} {
		path, ok := paths[sample.path].(object)
		if !ok || len(path) != 1 {
			t.Fatal("restricted command route missing or exposes an extra method")
		}
		operation, ok := path["post"].(object)
		if !ok || operation["operationId"] != sample.operation {
			t.Fatal("wrong enrollment operation")
		}
		security, ok := operation["security"].([]any)
		if !ok || len(security) != 0 {
			t.Fatal("challenge command inherited normal Session bearer security")
		}
		request := operation["requestBody"].(object)["content"].(object)["application/json"].(object)["schema"].(object)
		response := operation["responses"].(object)["200"].(object)["content"].(object)["application/json"].(object)["schema"].(object)
		if request["$ref"] != "#/components/schemas/"+sample.request || response["$ref"] != "#/components/schemas/"+sample.response {
			t.Fatal("command reused a broader authentication body or response")
		}
	}
}
