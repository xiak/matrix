package authorityprocess

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	installationv1 "github.com/xiak/matrix/api/adapter/installation/v1"
	auditv1 "github.com/xiak/matrix/api/audit/v1"
	iamv1 "github.com/xiak/matrix/api/iam/v1"
	installationrelease "github.com/xiak/matrix/app/service/installation/release"
)

const userManagementCompletionPredecessor = "08e1dc4a6ce81386ea7223e62d03356f82aeee58"

// TestIAMAuthorizationProfileAdvanceProcess proves the current-schema release
// boundary for one source-built future authorization declaration. It is not a
// predecessor-binary or signed-release upgrade claim: the existing current
// process creates all policy, decision and Audit evidence before the tagged
// process advances the immutable profile head.
func TestIAMAuthorizationProfileAdvanceProcess(t *testing.T) {
	const variable = "MATRIX_IAM_PROFILE_ADVANCE_POSTGRES_TEST_DSN"
	dsn := os.Getenv(variable)
	if dsn == "" {
		t.Skipf("set %s to a clean disposable PostgreSQL 18 database", variable)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Minute)
	defer cancel()
	config, err := pgx.ParseConfig(dsn)
	if err != nil || !strings.HasPrefix(config.Database, "matrix_iam_profile_advance_") {
		t.Fatal("profile advance process gate requires its own disposable database")
	}
	config.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	admin, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal("connect profile advance process database", err)
	}
	defer admin.Close(context.Background())
	assertPostgres18(t, ctx, admin)
	assertCleanSchemas(t, ctx, admin)

	root, temporary := repositoryRoot(t), t.TempDir()
	currentBinary := buildAuthorityBinary(t, ctx, root, temporary, "iam-profile-current", "./app/service/iam/cmd/matrix-iam")
	currentMigrator := buildAuthorityBinary(t, ctx, root, temporary, "iam-profile-current-migrate", "./app/service/iam/cmd/matrix-iam-migrate")
	bootstrap := processBootstrap(t)
	bootstrap.InstallationID = "mxi-66778899001122334455667788990011"
	const apiLogin = "matrix_iam_api_login"
	var migrationEnvironment []string
	for _, value := range []struct{ environment, login string }{
		{"MATRIX_MIGRATION_DATABASE_DSN_FILE", ""},
		{"MATRIX_MIGRATION_IAM_ACCESS_ANALYSIS_DSN_FILE", "matrix_iam_access_analysis_worker_login"},
		{"MATRIX_MIGRATION_IAM_API_DSN_FILE", apiLogin},
		{installationv1.AuthenticationRecoveryMigrationDSNFileEnvironment, "matrix_iam_authentication_recovery_login"},
		{"MATRIX_MIGRATION_IAM_WORKER_DSN_FILE", "matrix_iam_worker_login"},
		{"MATRIX_MIGRATION_IAM_RECOVERY_DSN_FILE", localRecoveryProcessLogin},
		{installationv1.TOTPBackupCustodyMigrationDSNFileEnvironment, "matrix_iam_backup_custody_login"},
		{"MATRIX_MIGRATION_IAM_NOTIFICATION_DSN_FILE", "matrix_iam_notification_worker_login"},
	} {
		valueDSN := dsn
		if value.login != "" {
			valueDSN = localRecoveryMigrationDSN(t, runtimeDSN(t, config, value.login, processDBPassword))
		}
		migrationEnvironment = append(migrationEnvironment,
			value.environment+"="+writeProtectedFile(t, temporary, value.environment, []byte(valueDSN)))
	}
	productAuthorization, err := iamv1.EncodeProductAuthorizationReleaseCatalog(iamv1.ProductAuthorizationReleaseCatalog{
		APIVersion: iamv1.APIVersion, Kind: iamv1.ProductAuthorizationReleaseCatalogKind,
		Profiles: []iamv1.AuthorizationProfile{}, ProfileHistory: []iamv1.AuthorizationProfile{},
		ServiceRolePolicies: []iamv1.ProductServiceRolePolicy{}, ServiceRoleTemplates: []iamv1.ServiceRoleTemplate{},
	})
	if err != nil {
		t.Fatal(err)
	}
	migrationEnvironment = append(migrationEnvironment,
		installationv1.IAMProductAuthorizationMigrationFileEnvironment+"="+
			writeProtectedFile(t, temporary, "iam-profile-product-authorization.json", productAuthorization),
		"MATRIX_MIGRATION_INSTALLATION_ID="+bootstrap.InstallationID,
		"MATRIX_MIGRATION_PLATFORM_IAM_CREDENTIAL_FILE="+
			writeProtectedFile(t, temporary, "iam-profile-platform-credential", []byte(platformServiceCredential)))
	clear(productAuthorization)
	for _, action := range []string{"apply", "apply", "verify"} {
		child := startChild(t, root, currentMigrator, migrationEnvironment, action)
		if err := child.wait(30 * time.Second); err != nil {
			t.Fatalf("current profile migration %s failed: %v output=%q", action, err, child.output())
		}
		assertProcessOutputsSanitized(t, []*childProcess{child}, config.Password, processDBPassword)
	}

	encodedBootstrap, err := iamv1.EncodeBootstrapDocument(bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	bootstrapPath := writeProtectedFile(t, temporary, "iam-profile-bootstrap", encodedBootstrap)
	clear(encodedBootstrap)
	digest, err := iamv1.BootstrapDigest(bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	mail := iamv1.EmailVerificationKeyring{APIVersion: iamv1.APIVersion, Kind: "EmailVerificationKeyring",
		Purpose:        iamv1.EmailVerificationWrappingPurpose,
		Scope:          iamv1.SecurityMailInstallationScope{InstallationID: bootstrap.InstallationID, BootstrapDigest: digest},
		KeysetRevision: 1, ActiveKeyID: "profile-mail", Keys: []iamv1.EmailVerificationWrappingKey{{
			KeyID: "profile-mail", FormatVersion: 1,
			KeyMaterial: processSecret(t, base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x64}, 32))),
		}}}
	encodedMail, err := iamv1.EncodeEmailVerificationKeyring(mail)
	if err != nil {
		t.Fatal(err)
	}
	address := freeAddress(t)
	endpoint := "http://" + address
	environment := []string{
		"MATRIX_IAM_DATABASE_DSN_FILE=" + writeProtectedFile(t, temporary, "iam-profile-api-dsn", []byte(runtimeDSN(t, config, apiLogin, processDBPassword))),
		"MATRIX_IAM_BOOTSTRAP_FILE=" + bootstrapPath,
		"MATRIX_IAM_LISTEN_ADDRESS=" + address,
		"MATRIX_IAM_CURSOR_KEY_FILE=" + writeProtectedFile(t, temporary, "iam-profile-cursor", []byte(strings.Repeat("42", 32))),
		"MATRIX_IAM_ACCESS_KEY_WRAPPING_KEYRING_FILE=" + writeProcessAccessKeyWrapping(t, temporary, bootstrap),
		"MATRIX_IAM_TOTP_KEYRING_FILE=" + writeProcessTOTPKeyring(t, temporary, bootstrap),
		"MATRIX_IAM_EMAIL_VERIFICATION_KEYRING_FILE=" + writeProtectedFile(t, temporary, "iam-profile-mail.json", encodedMail),
	}
	clear(encodedMail)
	var children []*childProcess
	sensitive := []string{initialAdminPassword, changedAdminPassword, initialReaderPassword, changedReaderPassword, processDBPassword}
	defer func() {
		for _, child := range children {
			child.stop()
		}
		assertProcessOutputsSanitized(t, children, sensitive...)
	}()
	start := func(binary string) *childProcess {
		t.Helper()
		child := startChild(t, root, binary, environment)
		children = append(children, child)
		waitHTTPStatus(t, ctx, child, endpoint+"/ready", http.StatusOK)
		assertRuntimeProcessLogins(t, ctx, admin, apiLogin)
		response := performJSON(t, http.MethodGet, endpoint+"/ready", "", nil)
		var readiness iamv1.Readiness
		wantSchema := installationrelease.CurrentDatabaseProfile().Authorities.IAM
		if response.Status != http.StatusOK || json.Unmarshal(response.Body, &readiness) != nil || readiness.SchemaVersion != wantSchema {
			t.Fatalf("profile process readiness schema=%d status=%d want=%d", readiness.SchemaVersion, response.Status, wantSchema)
		}
		return child
	}
	current := start(currentBinary)
	primary := loginIAM(t, endpoint, "admin", initialAdminPassword, "profile-root-login")
	changePasswordIAM(t, endpoint, primary.Credential, initialAdminPassword, changedAdminPassword, "profile-root-password")
	member := createIAMUser(t, endpoint, primary.Credential, "profile.member", "Profile member", initialReaderPassword, "profile-member-create")
	memberLogin := loginIAM(t, endpoint, member.LoginName+"@"+string(member.AccountID), initialReaderPassword, "profile-member-login")
	changePasswordIAM(t, endpoint, memberLogin.Credential, initialReaderPassword, changedReaderPassword, "profile-member-password")
	sensitive = append(sensitive, primary.Credential, memberLogin.Credential)
	proveFrozenFamilyProfileAdvance(t, ctx, admin, root, temporary, endpoint, primary.Credential, memberLogin.Credential,
		migrationEnvironment, start, current)
}

func proveFrozenFamilyProfileAdvance(t *testing.T, ctx context.Context, admin *pgx.Conn, root, temporary, endpoint, primary, member string,
	migrationEnvironment []string, start func(string) *childProcess, current *childProcess) {
	t.Helper()
	const addedAction iamv1.Action = "paas.application.inspect"
	profile, found := iamv1.LookupAuthorizationProfile(iamv1.ProductPaaS)
	if !found {
		t.Fatal("future-source fixture requires its explicit original PaaS revision")
	}
	originalRevision := profile.Revision
	originalProfile, _, err := iamv1.CanonicalizeAuthorizationProfile(profile)
	if err != nil {
		t.Fatal(err)
	}
	var added iamv1.AuthorizationProfileAction
	for index, action := range profile.Actions {
		if action.Action == iamv1.ActionPaaSApplicationRead {
			added = action
			profile.Actions[index].Conditions = nil
			for _, condition := range action.Conditions {
				if condition.Key != iamv1.ConditionIAMPrincipalID {
					profile.Actions[index].Conditions = append(profile.Actions[index].Conditions, condition)
				}
			}
		}
	}
	added.Action = addedAction
	profile.Revision++
	profile.Actions = append(profile.Actions, added)
	_, futureDigest, err := iamv1.CanonicalizeAuthorizationProfile(profile)
	if err != nil {
		t.Fatal(err)
	}
	futureReference := iamv1.AuthorizationProfileReference{Product: profile.Product, Revision: profile.Revision, ContentDigest: futureDigest}
	author := iamv1.PolicyDocument{LanguageVersion: iamv1.PolicyLanguageVersion, Scope: iamv1.AuthorityScopeTenant,
		Statements: []iamv1.PolicyStatement{{SID: "family", Effect: iamv1.PolicyAllow, Actions: []iamv1.Action{"paas.application.*"},
			Resources: []iamv1.PolicyResourceSelector{{Kind: iamv1.ResourceApplication, Match: iamv1.PolicyResourceExact, ID: "family-retained"}}}}}
	response := performJSON(t, http.MethodPost, endpoint+"/v1/policies", primary,
		iamv1.CreatePolicyRequest{DisplayName: "Frozen family", Document: author, RequestID: "family-profile-create"})
	var original iamv1.PolicyDetail
	if response.Status != http.StatusCreated || json.Unmarshal(response.Body, &original) != nil || iamv1.ValidatePolicyDetail(original) != nil {
		t.Fatal("original executable did not publish the real family version")
	}
	identityResponse := performJSON(t, http.MethodGet, endpoint+"/v1/auth/me", member, nil)
	var identity iamv1.CurrentIdentity
	if identityResponse.Status != http.StatusOK || json.Unmarshal(identityResponse.Body, &identity) != nil || iamv1.ValidateCurrentIdentity(identity) != nil {
		t.Fatal("retained family member identity unavailable")
	}
	attachment := createIAMPolicyAttachment(t, endpoint, primary, identity.User.ID, original.Policy.ID, "family-profile-attach")
	denyAuthor := iamv1.PolicyDocument{LanguageVersion: iamv1.PolicyLanguageVersion, Scope: iamv1.AuthorityScopeTenant,
		Statements: []iamv1.PolicyStatement{{SID: "nonmatching-deny", Effect: iamv1.PolicyDeny, Actions: []iamv1.Action{"paas.application.*"},
			Resources:  []iamv1.PolicyResourceSelector{{Kind: iamv1.ResourceApplication, Match: iamv1.PolicyResourceExact, ID: "different-family-resource"}},
			Conditions: []iamv1.PolicyCondition{{Key: iamv1.ConditionIAMPrincipalID, Operator: iamv1.PolicyStringEquals, Values: []string{string(identity.User.ID)}}}}}}
	response = performJSON(t, http.MethodPost, endpoint+"/v1/policies", primary,
		iamv1.CreatePolicyRequest{DisplayName: "Frozen nonmatching Deny", Document: denyAuthor, RequestID: "family-deny-create"})
	var frozenDeny iamv1.PolicyDetail
	if response.Status != http.StatusCreated || json.Unmarshal(response.Body, &frozenDeny) != nil || iamv1.ValidatePolicyDetail(frozenDeny) != nil {
		t.Fatal("original executable did not publish frozen nonmatching Deny")
	}
	originalVersionBytes, err := iamv1.CanonicalizePolicyVersion(original.Version)
	if err != nil {
		t.Fatal(err)
	}
	request, err := iamv1.NewAuthorizationRequest(iamv1.ActionPaaSApplicationRead,
		iamv1.ResourceReference{Kind: iamv1.ResourceApplication, ID: "family-retained"}, iamv1.AuthorizationResourceInstance, "", "family-before", "family-before")
	if err != nil {
		t.Fatal(err)
	}
	decide := func(profile iamv1.AuthorizationProfile, request iamv1.AuthorizationRequest, allowed bool) iamv1.AuthorizationDecision {
		t.Helper()
		response := performJSONWithHeaders(t, http.MethodPost, endpoint+"/v1/authorize", paasServiceCredential, "", request,
			map[string]string{"Matrix-Subject-Credential": member})
		var decision iamv1.AuthorizationDecision
		if response.Status != http.StatusOK || json.Unmarshal(response.Body, &decision) != nil ||
			iamv1.ValidateAuthorizationDecisionForProfile(decision, profile) != nil || decision.Profile == nil || *decision.Profile != request.Profile ||
			decision.Action != request.Action || decision.Resource != request.Resource || decision.ResourceMode != request.ResourceMode ||
			decision.RequestID != request.RequestID || decision.CorrelationID != request.CorrelationID || decision.Allowed != allowed {
			t.Fatalf("family source transition request %s: status=%d allowed=%v want=%v", request.RequestID, response.Status, decision.Allowed, allowed)
		}
		return decision
	}
	originalDeclaration, _ := iamv1.LookupAuthorizationProfile(iamv1.ProductPaaS)
	before := decide(originalDeclaration, request, true)
	proofRequest, err := iamv1.NewAuthorizationRequestForProfile(originalDeclaration, iamv1.ActionPaaSApplicationCreate,
		iamv1.ResourceReference{Kind: iamv1.ResourceApplication, ID: "collection"}, iamv1.AuthorizationResourceCollection,
		iamv1.AuthorizationCollectionCreate, "family-proof-before", "family-proof-before")
	if err != nil {
		t.Fatal(err)
	}
	proofResponse := performJSONWithHeaders(t, http.MethodPost, endpoint+"/v1/authorize", paasServiceCredential, "", proofRequest,
		map[string]string{"Matrix-Subject-Credential": primary})
	var profileDecision iamv1.AuthorizationDecision
	if proofResponse.Status != http.StatusOK || json.Unmarshal(proofResponse.Body, &profileDecision) != nil ||
		iamv1.ValidateAuthorizationDecisionForProfile(profileDecision, originalDeclaration) != nil ||
		profileDecision.Profile == nil || *profileDecision.Profile != proofRequest.Profile || !profileDecision.Allowed || profileDecision.Subject == nil {
		t.Fatalf("family source transition proof decision invalid: status=%d", proofResponse.Status)
	}
	originalFact := auditv1.Event{APIVersion: auditv1.APIVersion, Kind: "AuditEvent", EventID: "family-profile-business-event",
		TenantID: auditv1.TenantID(profileDecision.TenantID), Actor: auditv1.ActorReference{Type: auditv1.ActorUser, ID: auditv1.ActorID(profileDecision.Subject.ID)},
		IAMDecisionID: auditv1.DecisionID(profileDecision.ID), Action: auditv1.ActionPaaSApplicationCreated,
		Target: auditv1.TargetReference{Kind: auditv1.TargetApplication, ID: "family-retained"}, Result: auditv1.ResultSucceeded,
		RequestDigest: "sha256:" + strings.Repeat("1", 64), RequestID: profileDecision.RequestID,
		CorrelationID: profileDecision.CorrelationID, OperationID: "family-profile-operation", OccurredAt: profileDecision.DecidedAt.Add(time.Microsecond)}
	var retainedDecision []byte
	if err := admin.QueryRow(ctx, "SELECT document FROM iam.authorization_decisions WHERE id=$1", before.ID).Scan(&retainedDecision); err != nil {
		t.Fatal(err)
	}
	// The explicitly tagged build changes only this fixture's declaration.
	// Ordinary and release builds use the production catalog transform; no
	// runtime selector exists and archived declarations remain unchanged.
	build := func(name, packagePath string) string {
		t.Helper()
		if runtime.GOOS == "windows" {
			name += ".exe"
		}
		path := filepath.Join(temporary, name)
		command := exec.CommandContext(ctx, "go", "build", "-p", "2", "-tags", "matrix_authority_future_profile_fixture", "-o", path, packagePath)
		command.Dir = root
		command.Env = append(os.Environ(), "GOMAXPROCS=2", "GOMEMLIMIT=512MiB")
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("build future declaration consumer: %v\n%s", err, output)
		}
		return path
	}
	futureBinary := build("matrix-iam-future-profile", "./app/service/iam/cmd/matrix-iam")
	futureMigrator := build("matrix-iam-future-profile-migrate", "./app/service/iam/cmd/matrix-iam-migrate")
	current.stop()
	for _, action := range []string{"apply", "apply", "verify"} {
		child := startChild(t, root, futureMigrator, migrationEnvironment, action)
		err := child.wait(30 * time.Second)
		child.stop()
		assertProcessOutputsSanitized(t, []*childProcess{child}, processDBPassword)
		if err != nil {
			t.Fatalf("future-source migrator %s failed: %v", action, err)
		}
	}
	future := start(futureBinary)
	defer future.stop()
	assertOriginal := func() {
		t.Helper()
		var canonical, archive string
		var document []byte
		if err := admin.QueryRow(ctx, "SELECT canonical_document FROM iam.policy_versions WHERE policy_id=$1 AND id=$2", original.Policy.ID, original.Version.ID).Scan(&canonical); err != nil || canonical != originalVersionBytes {
			t.Fatal("future registration rewrote frozen policy bytes")
		}
		if err := admin.QueryRow(ctx, "SELECT canonical_document FROM iam.authorization_profiles WHERE product='paas' AND revision=$1", originalRevision).Scan(&archive); err != nil || archive != originalProfile {
			t.Fatal("future registration replaced original profile archive")
		}
		if err := admin.QueryRow(ctx, "SELECT document FROM iam.authorization_decisions WHERE id=$1", before.ID).Scan(&document); err != nil || !bytes.Equal(document, retainedDecision) {
			t.Fatal("future registration changed historical decision evidence")
		}
		proofResponse := performJSON(t, http.MethodPost, endpoint+"/v1/audit-producer:resolve", paasServiceCredential, iamv1.ResolveAuditProducerRequest{Event: originalFact})
		var proof iamv1.AuditProducerAuthorization
		_, expectedDigest, err := auditv1.CanonicalizeEvent(auditv1.SourcePaaS, originalFact)
		if err != nil || proofResponse.Status != http.StatusOK || json.Unmarshal(proofResponse.Body, &proof) != nil ||
			iamv1.ValidateAuditProducerAuthorization(proof) != nil || proof.ContentDigest != expectedDigest || string(proof.TenantID) != string(originalFact.TenantID) {
			t.Fatal("new head lost exact archived business proof")
		}
	}
	assertOriginal()
	request.RequestID = "family-old-online-protocol"
	response = performJSONWithHeaders(t, http.MethodPost, endpoint+"/v1/authorize", paasServiceCredential, "", request,
		map[string]string{"Matrix-Subject-Credential": member})
	var mismatchDecisions int
	if response.Status != http.StatusUnprocessableEntity {
		t.Fatalf("old online request was not a protocol mismatch: status=%d", response.Status)
	}
	if err := admin.QueryRow(ctx, "SELECT count(*) FROM iam.authorization_decisions WHERE request_id=$1", request.RequestID).Scan(&mismatchDecisions); err != nil || mismatchDecisions != 0 {
		t.Fatal("protocol mismatch became an ordinary policy DENY")
	}
	request.Profile, request.Action, request.RequestID, request.CorrelationID = futureReference, addedAction, "family-new-before-publication", "family-new-before-publication"
	decide(profile, request, false)
	request.Action, request.RequestID = iamv1.ActionPaaSApplicationRead, "family-old-after-registration"
	decide(profile, request, true)
	response = performJSON(t, http.MethodPost, endpoint+"/v1/policies/"+string(original.Policy.ID)+"/versions", primary,
		iamv1.CreatePolicyVersionRequest{Document: author, ResourceVersion: original.Policy.ResourceVersion, RequestID: "family-new-publish"})
	var published iamv1.PolicyVersionDetail
	if response.Status != http.StatusCreated || json.Unmarshal(response.Body, &published) != nil || iamv1.ValidatePolicyVersionDetail(published) != nil ||
		published.Policy.DefaultVersionID != original.Version.ID || published.Version.ContentDigest == original.Version.ContentDigest ||
		published.Version.Compilation == nil || len(published.Version.Compilation.Profiles) != 1 || published.Version.Compilation.Profiles[0] != futureReference {
		t.Fatalf("explicit future publication lost frozen/default contract: status=%d", response.Status)
	}
	if _, _, err := iamv1.CanonicalizePolicyCompilation(author, *published.Version.Compilation, []iamv1.AuthorizationProfile{profile}); err != nil {
		t.Fatal("future binary returned an incomplete expanded version", err)
	}
	request.Action, request.RequestID = addedAction, "family-new-published-not-selected"
	decide(profile, request, false)
	response = performJSON(t, http.MethodPost, endpoint+"/v1/policies/"+string(original.Policy.ID)+":set-default-version", primary,
		iamv1.SetDefaultPolicyVersionRequest{VersionID: published.Version.ID, ResourceVersion: published.Policy.ResourceVersion, RequestID: "family-new-select"})
	if response.Status != http.StatusOK {
		t.Fatal("explicit future default selection failed")
	}
	request.RequestID = "family-new-selected"
	decide(profile, request, true)
	future.stop()
	future = start(futureBinary)
	defer future.stop()
	request.RequestID = "family-new-after-restart"
	decide(profile, request, true)
	denyAttachment := createIAMPolicyAttachment(t, endpoint, primary, identity.User.ID, frozenDeny.Policy.ID, "family-deny-attach")
	request.Action, request.RequestID = iamv1.ActionPaaSApplicationRead, "family-incompatible-nonmatching-deny"
	response = performJSONWithHeaders(t, http.MethodPost, endpoint+"/v1/authorize", paasServiceCredential, "", request,
		map[string]string{"Matrix-Subject-Credential": member})
	if response.Status != http.StatusServiceUnavailable {
		t.Fatalf("incompatible nonmatching frozen Deny was skipped: status=%d", response.Status)
	}
	if err := admin.QueryRow(ctx, "SELECT count(*) FROM iam.authorization_decisions WHERE request_id=$1", request.RequestID).Scan(&mismatchDecisions); err != nil || mismatchDecisions != 0 {
		t.Fatal("incompatible frozen policy produced an ordinary decision")
	}
	revokeIAMPolicyAttachment(t, endpoint, primary, denyAttachment.ID, denyAttachment.ResourceVersion, "family-deny-revoke")
	request.RequestID = "family-after-incompatible-deny-revoke"
	decide(profile, request, true)
	revokeIAMPolicyAttachment(t, endpoint, primary, attachment.ID, attachment.ResourceVersion, "family-new-revoke")
	request.Action = addedAction
	request.RequestID = "family-new-after-revoke"
	decide(profile, request, false)
	assertOriginal()
	t.Logf("source-built Profile r%d: old family frozen; new publication does not select; explicit selection grants; restart/revocation hold; not a production PaaS inspect endpoint or release-upgrade gate", profile.Revision)
}

// TestIAMUserManagementCompletionPredecessorProcess is the rolling single
// predecessor gate for the IAM87 User-command completion shape. The fixed
// accepted IAM86 executable creates real User/Audit state; only the current
// migrator and executable may create or read the new immutable completions.
func TestIAMUserManagementCompletionPredecessorProcess(t *testing.T) {
	const variable = "MATRIX_IAM_USER_MANAGEMENT_UPGRADE_POSTGRES_TEST_DSN"
	dsn := os.Getenv(variable)
	if dsn == "" {
		t.Skipf("set %s to a clean disposable PostgreSQL 18 database", variable)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 6*time.Minute)
	defer cancel()
	config, err := pgx.ParseConfig(dsn)
	if err != nil || !strings.HasPrefix(config.Database, "matrix_iam_user_management_upgrade_") {
		t.Fatal("user management predecessor gate requires its own disposable database")
	}
	config.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	admin, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal("connect user management predecessor database", err)
	}
	defer admin.Close(context.Background())
	assertPostgres18(t, ctx, admin)
	assertCleanSchemas(t, ctx, admin)

	root, temporary := repositoryRoot(t), t.TempDir()
	predecessorRoot := extractFixedIAMSource(t, ctx, root, temporary, userManagementCompletionPredecessor)
	predecessorMigrator := buildAuthorityBinary(t, ctx, predecessorRoot, temporary, "iam-user-management-predecessor-migrate", "./app/service/iam/cmd/matrix-iam-migrate")
	predecessorBinary := buildAuthorityBinary(t, ctx, predecessorRoot, temporary, "iam-user-management-predecessor", "./app/service/iam/cmd/matrix-iam")
	currentMigrator := buildAuthorityBinary(t, ctx, root, temporary, "iam-user-management-current-migrate", "./app/service/iam/cmd/matrix-iam-migrate")
	currentBinary := buildAuthorityBinary(t, ctx, root, temporary, "iam-user-management-current", "./app/service/iam/cmd/matrix-iam")
	bootstrap := processBootstrap(t)

	const apiLogin = "matrix_iam_api_login"
	var migrationEnvironment []string
	for _, value := range []struct{ environment, login string }{
		{"MATRIX_MIGRATION_DATABASE_DSN_FILE", ""},
		{"MATRIX_MIGRATION_IAM_ACCESS_ANALYSIS_DSN_FILE", "matrix_iam_access_analysis_worker_login"},
		{"MATRIX_MIGRATION_IAM_API_DSN_FILE", apiLogin},
		{installationv1.AuthenticationRecoveryMigrationDSNFileEnvironment, "matrix_iam_authentication_recovery_login"},
		{"MATRIX_MIGRATION_IAM_WORKER_DSN_FILE", "matrix_iam_worker_login"},
		{"MATRIX_MIGRATION_IAM_RECOVERY_DSN_FILE", localRecoveryProcessLogin},
		{installationv1.TOTPBackupCustodyMigrationDSNFileEnvironment, "matrix_iam_backup_custody_login"},
		{"MATRIX_MIGRATION_IAM_NOTIFICATION_DSN_FILE", "matrix_iam_notification_worker_login"},
	} {
		valueDSN := dsn
		if value.login != "" {
			valueDSN = localRecoveryMigrationDSN(t, runtimeDSN(t, config, value.login, processDBPassword))
		}
		migrationEnvironment = append(migrationEnvironment,
			value.environment+"="+writeProtectedFile(t, temporary, value.environment, []byte(valueDSN)))
	}
	productAuthorization, err := iamv1.EncodeProductAuthorizationReleaseCatalog(iamv1.ProductAuthorizationReleaseCatalog{
		APIVersion: iamv1.APIVersion, Kind: iamv1.ProductAuthorizationReleaseCatalogKind,
		Profiles: []iamv1.AuthorizationProfile{}, ProfileHistory: []iamv1.AuthorizationProfile{},
		ServiceRolePolicies: []iamv1.ProductServiceRolePolicy{}, ServiceRoleTemplates: []iamv1.ServiceRoleTemplate{},
	})
	if err != nil {
		t.Fatal(err)
	}
	migrationEnvironment = append(migrationEnvironment,
		installationv1.IAMProductAuthorizationMigrationFileEnvironment+"="+
			writeProtectedFile(t, temporary, "iam-user-management-product-authorization.json", productAuthorization),
		"MATRIX_MIGRATION_INSTALLATION_ID="+bootstrap.InstallationID,
		"MATRIX_MIGRATION_PLATFORM_IAM_CREDENTIAL_FILE="+
			writeProtectedFile(t, temporary, "iam-user-management-platform-credential", []byte(platformServiceCredential)))
	clear(productAuthorization)

	var children []*childProcess
	sensitive := []string{initialAdminPassword, changedAdminPassword, initialReaderPassword, changedReaderPassword, processDBPassword, platformServiceCredential}
	defer func() {
		for _, child := range children {
			child.stop()
		}
		assertProcessOutputsSanitized(t, children, sensitive...)
	}()
	runMigration := func(workdir, binary, generation string) {
		t.Helper()
		for _, action := range []string{"apply", "apply", "verify"} {
			child := startChild(t, workdir, binary, migrationEnvironment, action)
			children = append(children, child)
			if err := child.wait(45 * time.Second); err != nil {
				t.Fatalf("%s migration %s failed: %v output=%q", generation, action, err, child.output())
			}
		}
	}
	runMigration(predecessorRoot, predecessorMigrator, "IAM86 predecessor")

	legacyServices := make([]iamv1.BootstrapServiceCredential, 0, len(bootstrap.Services)-1)
	for _, service := range bootstrap.Services {
		if service.Purpose != iamv1.ServicePlatform {
			legacyServices = append(legacyServices, service)
		}
	}
	bootstrap.Services = legacyServices
	encodedBootstrap, err := iamv1.EncodeBootstrapReplayDocument(bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	bootstrapPath := writeProtectedFile(t, temporary, "iam-user-management-bootstrap", encodedBootstrap)
	clear(encodedBootstrap)
	digest, err := iamv1.BootstrapDigest(bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	mail := iamv1.EmailVerificationKeyring{APIVersion: iamv1.APIVersion, Kind: "EmailVerificationKeyring",
		Purpose:        iamv1.EmailVerificationWrappingPurpose,
		Scope:          iamv1.SecurityMailInstallationScope{InstallationID: bootstrap.InstallationID, BootstrapDigest: digest},
		KeysetRevision: 1, ActiveKeyID: "user-management-mail", Keys: []iamv1.EmailVerificationWrappingKey{{
			KeyID: "user-management-mail", FormatVersion: 1,
			KeyMaterial: processSecret(t, base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x65}, 32))),
		}}}
	encodedMail, err := iamv1.EncodeEmailVerificationKeyring(mail)
	if err != nil {
		t.Fatal(err)
	}
	address := freeAddress(t)
	endpoint := "http://" + address
	environment := []string{
		"MATRIX_IAM_DATABASE_DSN_FILE=" + writeProtectedFile(t, temporary, "iam-user-management-api-dsn", []byte(runtimeDSN(t, config, apiLogin, processDBPassword))),
		"MATRIX_IAM_BOOTSTRAP_FILE=" + bootstrapPath,
		"MATRIX_IAM_LISTEN_ADDRESS=" + address,
		"MATRIX_IAM_CURSOR_KEY_FILE=" + writeProtectedFile(t, temporary, "iam-user-management-cursor", []byte(strings.Repeat("43", 32))),
		"MATRIX_IAM_ACCESS_KEY_WRAPPING_KEYRING_FILE=" + writeProcessAccessKeyWrapping(t, temporary, bootstrap),
		"MATRIX_IAM_TOTP_KEYRING_FILE=" + writeProcessTOTPKeyring(t, temporary, bootstrap),
		"MATRIX_IAM_EMAIL_VERIFICATION_KEYRING_FILE=" + writeProtectedFile(t, temporary, "iam-user-management-mail.json", encodedMail),
	}
	clear(encodedMail)
	start := func(workdir, binary string, schema uint64) *childProcess {
		t.Helper()
		child := startChild(t, workdir, binary, environment)
		children = append(children, child)
		waitHTTPStatus(t, ctx, child, endpoint+"/ready", http.StatusOK)
		assertRuntimeProcessLogins(t, ctx, admin, apiLogin)
		response := performJSON(t, http.MethodGet, endpoint+"/ready", "", nil)
		var readiness iamv1.Readiness
		if response.Status != http.StatusOK || json.Unmarshal(response.Body, &readiness) != nil || readiness.SchemaVersion != schema {
			t.Fatalf("user management process readiness schema=%d status=%d want=%d", readiness.SchemaVersion, response.Status, schema)
		}
		return child
	}

	predecessor := start(predecessorRoot, predecessorBinary, 86)
	operator := loginIAM(t, endpoint, "admin", initialAdminPassword, "user-management-operator-login")
	changePasswordIAM(t, endpoint, operator.Credential, initialAdminPassword, changedAdminPassword, "user-management-operator-password")
	sensitive = append(sensitive, operator.Credential)
	retained := createIAMUser(t, endpoint, operator.Credential, "history.member", "History member", initialReaderPassword, "user-management-member-create")
	const predecessorUpdateRequest = "user-management-predecessor-update"
	updatedResponse := performJSON(t, http.MethodPost, endpoint+"/v1/users/"+string(retained.ID)+":update", operator.Credential,
		iamv1.UpdateUserRequest{DisplayName: "Predecessor updated member", ResourceVersion: retained.ResourceVersion, RequestID: predecessorUpdateRequest})
	if updatedResponse.Status != http.StatusOK || json.Unmarshal(updatedResponse.Body, &retained) != nil ||
		iamv1.ValidateUser(retained) != nil || retained.ResourceVersion != 2 || retained.DisplayName != "Predecessor updated member" {
		t.Fatalf("IAM86 did not update retained User: status=%d", updatedResponse.Status)
	}
	const predecessorStatusRequest = "user-management-predecessor-disable"
	disabledResponse := performJSON(t, http.MethodPost, endpoint+"/v1/users/"+string(retained.ID)+":set-status", operator.Credential,
		iamv1.SetUserStatusRequest{Status: iamv1.PrincipalDisabled, ResourceVersion: retained.ResourceVersion, RequestID: predecessorStatusRequest})
	if disabledResponse.Status != http.StatusOK || json.Unmarshal(disabledResponse.Body, &retained) != nil ||
		iamv1.ValidateUser(retained) != nil || retained.ResourceVersion != 3 || retained.Status != iamv1.PrincipalDisabled {
		t.Fatalf("IAM86 did not disable retained User: status=%d", disabledResponse.Status)
	}

	type canonicalAuditFact struct {
		canonical string
		event     auditv1.Event
	}
	canonicalOutbox := func() map[string]canonicalAuditFact {
		t.Helper()
		rows, err := admin.Query(ctx, "SELECT event_document FROM iam.audit_outbox ORDER BY event_id")
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		result := make(map[string]canonicalAuditFact)
		for rows.Next() {
			var encoded []byte
			var event auditv1.Event
			if rows.Scan(&encoded) != nil || json.Unmarshal(encoded, &event) != nil {
				t.Fatal("decode retained IAM outbox fact")
			}
			document, contentDigest, err := auditv1.CanonicalizeEvent(auditv1.SourceIAM, event)
			eventID := string(event.EventID)
			if _, duplicate := result[eventID]; err != nil || duplicate {
				t.Fatal("canonicalize retained IAM outbox fact", err)
			}
			result[eventID] = canonicalAuditFact{canonical: document + "\x00" + contentDigest, event: event}
		}
		if rows.Err() != nil || len(result) == 0 {
			t.Fatal("retained IAM outbox facts are unavailable", rows.Err())
		}
		return result
	}
	predecessorFacts := canonicalOutbox()
	predecessor.stop()
	runMigration(root, currentMigrator, "IAM87 current")

	var schema uint64
	var ready, contractReady bool
	var completionCount int
	if err := admin.QueryRow(ctx, "SELECT schema_version, ready, iam.user_management_completion_contract_ready() FROM iam.readiness()").Scan(&schema, &ready, &contractReady); err != nil || schema != 88 || !ready || !contractReady {
		t.Fatal("IAM87 user management completion schema is not ready", err)
	}
	if err := admin.QueryRow(ctx, "SELECT count(*) FROM iam.user_management_completions").Scan(&completionCount); err != nil || completionCount != 0 {
		t.Fatal("IAM87 migration invented predecessor user completions", err)
	}
	current := start(root, currentBinary, installationrelease.CurrentDatabaseProfile().Authorities.IAM)
	currentFacts := canonicalOutbox()
	if len(currentFacts) != len(predecessorFacts)+1 {
		t.Fatal("IAM87 migration did not add exactly one PLATFORM enrollment fact")
	}
	for eventID, before := range predecessorFacts {
		if currentFacts[eventID].canonical != before.canonical {
			t.Fatal("IAM87 migration or equal bootstrap rewrote retained Audit canonical bytes")
		}
	}
	added := 0
	for eventID, after := range currentFacts {
		if _, retained := predecessorFacts[eventID]; retained {
			continue
		}
		event := after.event
		if event.Action != auditv1.ActionIAMBootstrapApplied || event.Actor.Type != auditv1.ActorSystem ||
			event.Actor.ID != "iam-migration" || event.Target.Kind != auditv1.TargetInstallation ||
			event.Target.ID != bootstrap.InstallationID || event.TenantID != auditv1.TenantID(bootstrap.Organization.ID) ||
			event.InstallationID != "" || event.Result != auditv1.ResultSucceeded ||
			!strings.HasPrefix(event.RequestID, "migration-platform-") || event.CorrelationID != event.RequestID {
			t.Fatalf("IAM87 migration added an unexpected Audit fact: %#v", event)
		}
		added++
	}
	if added != 1 {
		t.Fatal("IAM87 migration PLATFORM enrollment fact is unavailable")
	}

	readUser := func() iamv1.User {
		t.Helper()
		response := performJSON(t, http.MethodGet, endpoint+"/v1/users/"+string(retained.ID), operator.Credential, nil)
		var access iamv1.UserAccess
		if response.Status != http.StatusOK || json.Unmarshal(response.Body, &access) != nil ||
			iamv1.ValidateUserAccess(access) != nil || access.User.ID != retained.ID {
			t.Fatalf("read retained User after IAM87 migration: status=%d", response.Status)
		}
		return access.User
	}
	readCompletion := func(request string, operation iamv1.UserManagementOperation, expectedVersion uint64, status int) iamv1.UserManagementCompletion {
		t.Helper()
		path := endpoint + "/v1/users/" + string(retained.ID) + "/management-completions/" + request +
			"?operation=" + string(operation) + "&expectedResourceVersion=" + fmt.Sprint(expectedVersion)
		response := performJSON(t, http.MethodGet, path, operator.Credential, nil)
		if response.Status != status {
			t.Fatalf("read user completion %s: status=%d want=%d", request, response.Status, status)
		}
		if status != http.StatusOK {
			return iamv1.UserManagementCompletion{}
		}
		var completion iamv1.UserManagementCompletion
		if json.Unmarshal(response.Body, &completion) != nil || iamv1.ValidateUserManagementCompletion(completion) != nil {
			t.Fatal("decode current user management completion")
		}
		return completion
	}
	readCompletion(predecessorUpdateRequest, iamv1.UserManagementUpdate, 1, http.StatusNotFound)
	readCompletion(predecessorStatusRequest, iamv1.UserManagementSetStatus, 2, http.StatusNotFound)
	if retained = readUser(); retained.Status != iamv1.PrincipalDisabled || retained.ResourceVersion != 3 || retained.DisplayName != "Predecessor updated member" {
		t.Fatal("IAM87 migration changed retained User identity or state")
	}

	reused := performJSON(t, http.MethodPost, endpoint+"/v1/users/"+string(retained.ID)+":update", operator.Credential,
		iamv1.UpdateUserRequest{DisplayName: "Forbidden reused intent", ResourceVersion: retained.ResourceVersion, RequestID: predecessorStatusRequest})
	unchanged := readUser()
	if reused.Status != http.StatusConflict || unchanged != retained {
		t.Fatal("IAM87 reused a predecessor request across User operations or changed retained state")
	}
	const currentUpdateRequest = "user-management-current-update"
	completedResponse := performJSON(t, http.MethodPost, endpoint+"/v1/users/"+string(retained.ID)+":update", operator.Credential,
		iamv1.UpdateUserRequest{DisplayName: "Current updated member", ResourceVersion: retained.ResourceVersion, RequestID: currentUpdateRequest})
	var updated iamv1.User
	if completedResponse.Status != http.StatusOK || json.Unmarshal(completedResponse.Body, &updated) != nil ||
		iamv1.ValidateUser(updated) != nil || updated.ResourceVersion != 4 || updated.Status != iamv1.PrincipalDisabled ||
		updated.DisplayName != "Current updated member" {
		t.Fatalf("IAM87 did not update retained User: status=%d", completedResponse.Status)
	}
	updateCompletion := readCompletion(currentUpdateRequest, iamv1.UserManagementUpdate, 3, http.StatusOK)
	if updateCompletion.Result != updated {
		t.Fatal("IAM87 update completion did not preserve the original result")
	}
	const currentStatusRequest = "user-management-current-enable"
	statusResponse := performJSON(t, http.MethodPost, endpoint+"/v1/users/"+string(retained.ID)+":set-status", operator.Credential,
		iamv1.SetUserStatusRequest{Status: iamv1.PrincipalActive, ResourceVersion: updated.ResourceVersion, RequestID: currentStatusRequest})
	var enabled iamv1.User
	if statusResponse.Status != http.StatusOK || json.Unmarshal(statusResponse.Body, &enabled) != nil ||
		iamv1.ValidateUser(enabled) != nil || enabled.ResourceVersion != 5 || enabled.Status != iamv1.PrincipalActive {
		t.Fatalf("IAM87 did not enable retained User: status=%d", statusResponse.Status)
	}
	statusCompletion := readCompletion(currentStatusRequest, iamv1.UserManagementSetStatus, 4, http.StatusOK)
	if statusCompletion.Result != enabled || readCompletion(currentUpdateRequest, iamv1.UserManagementUpdate, 3, http.StatusOK) != updateCompletion {
		t.Fatal("later User state rewrote an original completion")
	}
	current.stop()
	current = start(root, currentBinary, installationrelease.CurrentDatabaseProfile().Authorities.IAM)
	defer current.stop()
	if replay := readCompletion(currentUpdateRequest, iamv1.UserManagementUpdate, 3, http.StatusOK); replay != updateCompletion {
		t.Fatal("IAM87 restart changed the immutable update completion")
	}
	if replay := readCompletion(currentStatusRequest, iamv1.UserManagementSetStatus, 4, http.StatusOK); replay != statusCompletion {
		t.Fatal("IAM87 restart changed the immutable status completion")
	}
	if restarted := readUser(); restarted != enabled {
		t.Fatal("IAM87 restart changed retained User state")
	}
	t.Log("fixed IAM86 process -> IAM87: old completions absent, old request IDs consumed, canonical facts retained, exact profile/status snapshots survive later mutation and restart")
}

// Fixed predecessor source is extracted into a bounded temporary directory;
// it is test input only and never a build or runtime dependency.
func extractFixedIAMSource(t *testing.T, ctx context.Context, root, temporary, fixedCommit string) string {
	t.Helper()
	command := exec.CommandContext(ctx, "git", "archive", "--format=zip", fixedCommit,
		"go.mod", "go.sum", "api", "app/service/iam", "app/service/paas", "app/service/internal")
	command.Dir = root
	archive, err := command.Output()
	if err != nil || len(archive) > 32<<20 {
		t.Fatal("cannot read bounded fixed IAM source archive")
	}
	reader, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
	if err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(temporary, "iam-predecessor-"+fixedCommit[:12])
	var extracted uint64
	for _, entry := range reader.File {
		path := filepath.FromSlash(entry.Name)
		extracted += entry.UncompressedSize64
		if !filepath.IsLocal(path) || entry.UncompressedSize64 > 8<<20 || extracted > 64<<20 || entry.Mode()&os.ModeSymlink != 0 {
			t.Fatal("unsafe fixed IAM source entry")
		}
		target := filepath.Join(destination, path)
		if entry.FileInfo().IsDir() {
			if err := os.MkdirAll(target, 0o700); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			t.Fatal(err)
		}
		source, err := entry.Open()
		if err != nil {
			t.Fatal(err)
		}
		content, readErr := io.ReadAll(io.LimitReader(source, 8<<20))
		closeErr := source.Close()
		if readErr != nil || closeErr != nil {
			t.Fatal("cannot extract fixed IAM source entry")
		}
		if err := os.WriteFile(target, content, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return destination
}
