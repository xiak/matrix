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
