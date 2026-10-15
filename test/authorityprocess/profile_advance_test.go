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

const accountLifecycleCompletionPredecessor = "5effc802fa8116d14420188d9075d6fe3ab1ceaa"

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
			writeProtectedFile(t, temporary, "iam-profile-product-authorization.json", productAuthorization))
	clear(productAuthorization)
	for _, action := range []string{"apply", "apply", "verify"} {
		child := startChild(t, root, currentMigrator, migrationEnvironment, action)
		if err := child.wait(30 * time.Second); err != nil {
			t.Fatalf("current profile migration %s failed: %v output=%q", action, err, child.output())
		}
		assertProcessOutputsSanitized(t, []*childProcess{child}, config.Password, processDBPassword)
	}

	bootstrap := processBootstrap(t)
	bootstrap.InstallationID = "mxi-66778899001122334455667788990011"
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

// TestIAMAccountLifecycleCompletionPredecessorProcess is the rolling, single
// predecessor gate for the IAM86 account-command completion shape. The fixed
// IAM85 executable creates real Account/Audit state; only the current
// migrator and executable may create or read the new completion rows.
func TestIAMAccountLifecycleCompletionPredecessorProcess(t *testing.T) {
	const variable = "MATRIX_IAM_ACCOUNT_COMPLETION_UPGRADE_POSTGRES_TEST_DSN"
	dsn := os.Getenv(variable)
	if dsn == "" {
		t.Skipf("set %s to a clean disposable PostgreSQL 18 database", variable)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 6*time.Minute)
	defer cancel()
	config, err := pgx.ParseConfig(dsn)
	if err != nil || !strings.HasPrefix(config.Database, "matrix_iam_account_completion_upgrade_") {
		t.Fatal("account completion predecessor gate requires its own disposable database")
	}
	config.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	admin, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal("connect account completion predecessor database", err)
	}
	defer admin.Close(context.Background())
	assertPostgres18(t, ctx, admin)
	assertCleanSchemas(t, ctx, admin)

	root, temporary := repositoryRoot(t), t.TempDir()
	predecessorRoot := extractFixedIAMSource(t, ctx, root, temporary, accountLifecycleCompletionPredecessor)
	predecessorMigrator := buildAuthorityBinary(t, ctx, predecessorRoot, temporary, "iam-account-completion-predecessor-migrate", "./app/service/iam/cmd/matrix-iam-migrate")
	predecessorBinary := buildAuthorityBinary(t, ctx, predecessorRoot, temporary, "iam-account-completion-predecessor", "./app/service/iam/cmd/matrix-iam")
	currentMigrator := buildAuthorityBinary(t, ctx, root, temporary, "iam-account-completion-current-migrate", "./app/service/iam/cmd/matrix-iam-migrate")
	currentBinary := buildAuthorityBinary(t, ctx, root, temporary, "iam-account-completion-current", "./app/service/iam/cmd/matrix-iam")

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
			writeProtectedFile(t, temporary, "iam-account-completion-product-authorization.json", productAuthorization))
	clear(productAuthorization)

	var children []*childProcess
	sensitive := []string{initialAdminPassword, changedAdminPassword, initialReaderPassword, changedReaderPassword, processDBPassword}
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
	runMigration(predecessorRoot, predecessorMigrator, "IAM85 predecessor")

	bootstrap := processBootstrap(t)
	encodedBootstrap, err := iamv1.EncodeBootstrapDocument(bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	bootstrapPath := writeProtectedFile(t, temporary, "iam-account-completion-bootstrap", encodedBootstrap)
	clear(encodedBootstrap)
	digest, err := iamv1.BootstrapDigest(bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	mail := iamv1.EmailVerificationKeyring{APIVersion: iamv1.APIVersion, Kind: "EmailVerificationKeyring",
		Purpose:        iamv1.EmailVerificationWrappingPurpose,
		Scope:          iamv1.SecurityMailInstallationScope{InstallationID: bootstrap.InstallationID, BootstrapDigest: digest},
		KeysetRevision: 1, ActiveKeyID: "account-completion-mail", Keys: []iamv1.EmailVerificationWrappingKey{{
			KeyID: "account-completion-mail", FormatVersion: 1,
			KeyMaterial: processSecret(t, base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x65}, 32))),
		}}}
	encodedMail, err := iamv1.EncodeEmailVerificationKeyring(mail)
	if err != nil {
		t.Fatal(err)
	}
	address := freeAddress(t)
	endpoint := "http://" + address
	environment := []string{
		"MATRIX_IAM_DATABASE_DSN_FILE=" + writeProtectedFile(t, temporary, "iam-account-completion-api-dsn", []byte(runtimeDSN(t, config, apiLogin, processDBPassword))),
		"MATRIX_IAM_BOOTSTRAP_FILE=" + bootstrapPath,
		"MATRIX_IAM_LISTEN_ADDRESS=" + address,
		"MATRIX_IAM_CURSOR_KEY_FILE=" + writeProtectedFile(t, temporary, "iam-account-completion-cursor", []byte(strings.Repeat("43", 32))),
		"MATRIX_IAM_ACCESS_KEY_WRAPPING_KEYRING_FILE=" + writeProcessAccessKeyWrapping(t, temporary, bootstrap),
		"MATRIX_IAM_TOTP_KEYRING_FILE=" + writeProcessTOTPKeyring(t, temporary, bootstrap),
		"MATRIX_IAM_EMAIL_VERIFICATION_KEYRING_FILE=" + writeProtectedFile(t, temporary, "iam-account-completion-mail.json", encodedMail),
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
			t.Fatalf("account completion process readiness schema=%d status=%d want=%d", readiness.SchemaVersion, response.Status, schema)
		}
		return child
	}

	predecessor := start(predecessorRoot, predecessorBinary, 85)
	operator := loginIAM(t, endpoint, "admin", initialAdminPassword, "account-completion-operator-login")
	changePasswordIAM(t, endpoint, operator.Credential, initialAdminPassword, changedAdminPassword, "account-completion-operator-password")
	sensitive = append(sensitive, operator.Credential)
	const accountID = "account-completion-retained"
	const createRequest = "account-completion-predecessor-create"
	createdResponse := performJSON(t, http.MethodPost, endpoint+"/v1/accounts", operator.Credential, map[string]any{
		"id": accountID, "displayName": "Retained completion account", "rootLoginName": "completion.retained.root",
		"rootDisplayName": "Retained completion root", "initialPassword": initialReaderPassword, "requestId": createRequest,
	})
	var retained iamv1.Account
	if createdResponse.Status != http.StatusCreated || json.Unmarshal(createdResponse.Body, &retained) != nil ||
		iamv1.ValidateAccount(retained) != nil || retained.ResourceVersion != 1 || retained.Status != iamv1.AccountActive {
		t.Fatalf("IAM85 did not create retained Account: status=%d", createdResponse.Status)
	}
	rootID := retained.RootIdentity.PrincipalID
	const disableRequest = "account-completion-predecessor-disable"
	disabledResponse := performJSON(t, http.MethodPost, endpoint+"/v1/accounts/"+accountID+":set-status", operator.Credential,
		iamv1.SetAccountStatusRequest{Status: iamv1.AccountDisabled, ResourceVersion: retained.ResourceVersion, RequestID: disableRequest})
	if disabledResponse.Status != http.StatusOK || json.Unmarshal(disabledResponse.Body, &retained) != nil ||
		iamv1.ValidateAccount(retained) != nil || retained.ResourceVersion != 2 || retained.Status != iamv1.AccountDisabled || retained.RootIdentity.PrincipalID != rootID {
		t.Fatalf("IAM85 did not pause retained Account: status=%d", disabledResponse.Status)
	}
	const predecessorRecoveryPassword = "Retained-Predecessor-Recovery-Password-76!"
	const recoveryRequest = "account-completion-predecessor-recovery"
	sensitive = append(sensitive, predecessorRecoveryPassword)
	recoveryResponse := performJSON(t, http.MethodPost, endpoint+"/v1/accounts/"+accountID+":recover-root-credentials", operator.Credential,
		map[string]any{"initialPassword": predecessorRecoveryPassword, "resourceVersion": retained.ResourceVersion, "requestId": recoveryRequest})
	if recoveryResponse.Status != http.StatusOK || json.Unmarshal(recoveryResponse.Body, &retained) != nil ||
		iamv1.ValidateAccount(retained) != nil || retained.ResourceVersion != 3 || retained.Status != iamv1.AccountDisabled || retained.RootIdentity.PrincipalID != rootID {
		t.Fatalf("IAM85 did not recover the retained disabled Account: status=%d", recoveryResponse.Status)
	}

	canonicalOutbox := func() map[string]string {
		t.Helper()
		rows, err := admin.Query(ctx, "SELECT event_document FROM iam.audit_outbox ORDER BY event_id")
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		result := make(map[string]string)
		for rows.Next() {
			var encoded []byte
			var event auditv1.Event
			if rows.Scan(&encoded) != nil || json.Unmarshal(encoded, &event) != nil {
				t.Fatal("decode retained IAM outbox fact")
			}
			document, contentDigest, err := auditv1.CanonicalizeEvent(auditv1.SourceIAM, event)
			eventID := string(event.EventID)
			if err != nil || result[eventID] != "" {
				t.Fatal("canonicalize retained IAM outbox fact", err)
			}
			result[eventID] = document + "\x00" + contentDigest
		}
		if rows.Err() != nil || len(result) == 0 {
			t.Fatal("retained IAM outbox facts are unavailable", rows.Err())
		}
		return result
	}
	predecessorFacts := canonicalOutbox()
	predecessor.stop()
	runMigration(root, currentMigrator, "IAM86 current")

	var schema uint64
	var ready, contractReady bool
	var completionCount int
	if err := admin.QueryRow(ctx, "SELECT schema_version, ready, iam.account_lifecycle_completion_contract_ready() FROM iam.readiness()").Scan(&schema, &ready, &contractReady); err != nil || schema != 86 || !ready || !contractReady {
		t.Fatal("IAM86 completion schema is not ready", err)
	}
	if err := admin.QueryRow(ctx, "SELECT count(*) FROM iam.account_lifecycle_completions").Scan(&completionCount); err != nil || completionCount != 0 {
		t.Fatal("IAM86 migration invented predecessor completion facts", err)
	}
	current := start(root, currentBinary, installationrelease.CurrentDatabaseProfile().Authorities.IAM)
	currentFacts := canonicalOutbox()
	if len(currentFacts) != len(predecessorFacts) {
		t.Fatal("IAM86 migration or equal bootstrap changed retained Audit fact count")
	}
	for eventID, before := range predecessorFacts {
		if currentFacts[eventID] != before {
			t.Fatal("IAM86 migration or equal bootstrap rewrote retained Audit canonical bytes")
		}
	}

	readAccount := func() iamv1.Account {
		t.Helper()
		response := performJSON(t, http.MethodGet, endpoint+"/v1/accounts/"+accountID, operator.Credential, nil)
		var access iamv1.AccountAccess
		if response.Status != http.StatusOK || json.Unmarshal(response.Body, &access) != nil ||
			iamv1.ValidateAccountAccess(access) != nil || access.Account.ID != accountID {
			t.Fatalf("read retained Account after IAM86 migration: status=%d", response.Status)
		}
		return access.Account
	}
	readCompletion := func(request string, operation iamv1.AccountLifecycleOperation, expectedVersion uint64, status int) iamv1.AccountLifecycleCompletion {
		t.Helper()
		path := endpoint + "/v1/accounts/" + accountID + "/lifecycle-completions/" + request +
			"?operation=" + string(operation) + "&expectedResourceVersion=" + fmt.Sprint(expectedVersion)
		response := performJSON(t, http.MethodGet, path, operator.Credential, nil)
		if response.Status != status {
			t.Fatalf("read account completion %s: status=%d want=%d", request, response.Status, status)
		}
		if status != http.StatusOK {
			return iamv1.AccountLifecycleCompletion{}
		}
		var completion iamv1.AccountLifecycleCompletion
		if json.Unmarshal(response.Body, &completion) != nil || iamv1.ValidateAccountLifecycleCompletion(completion) != nil {
			t.Fatal("decode current account completion")
		}
		return completion
	}
	readCompletion(createRequest, iamv1.AccountLifecycleCreate, 0, http.StatusNotFound)
	readCompletion(disableRequest, iamv1.AccountLifecycleSetStatus, 1, http.StatusNotFound)
	readCompletion(recoveryRequest, iamv1.AccountLifecycleRecoverRootCredentials, 2, http.StatusNotFound)
	if retained = readAccount(); retained.Status != iamv1.AccountDisabled || retained.ResourceVersion != 3 || retained.RootIdentity.PrincipalID != rootID {
		t.Fatal("IAM86 migration changed retained Account identity or state")
	}

	const currentRecoveryPassword = "Retained-Current-Recovery-Password-87!"
	sensitive = append(sensitive, currentRecoveryPassword)
	var beforeCredentialVersion uint64
	var beforePasswordHash string
	if err := admin.QueryRow(ctx, "SELECT credential_version,password_hash FROM iam.user_credentials WHERE tenant_id=$1 AND principal_id=$2", accountID, rootID).Scan(&beforeCredentialVersion, &beforePasswordHash); err != nil {
		t.Fatal("read retained root credential state", err)
	}
	reused := performJSON(t, http.MethodPost, endpoint+"/v1/accounts/"+accountID+":recover-root-credentials", operator.Credential,
		map[string]any{"initialPassword": currentRecoveryPassword, "resourceVersion": retained.ResourceVersion, "requestId": recoveryRequest})
	var afterCredentialVersion uint64
	var afterPasswordHash string
	if err := admin.QueryRow(ctx, "SELECT credential_version,password_hash FROM iam.user_credentials WHERE tenant_id=$1 AND principal_id=$2", accountID, rootID).Scan(&afterCredentialVersion, &afterPasswordHash); err != nil {
		t.Fatal("read rejected retained root credential state", err)
	}
	unchanged := readAccount()
	if reused.Status != http.StatusConflict || unchanged.Status != retained.Status || unchanged.ResourceVersion != retained.ResourceVersion ||
		unchanged.RootIdentity.PrincipalID != retained.RootIdentity.PrincipalID || afterCredentialVersion != beforeCredentialVersion || afterPasswordHash != beforePasswordHash {
		t.Fatal("IAM86 reused a consumed predecessor request or changed retained state")
	}
	const currentRecoveryRequest = "account-completion-current-recovery"
	completedResponse := performJSON(t, http.MethodPost, endpoint+"/v1/accounts/"+accountID+":recover-root-credentials", operator.Credential,
		map[string]any{"initialPassword": currentRecoveryPassword, "resourceVersion": retained.ResourceVersion, "requestId": currentRecoveryRequest})
	var completedAccount iamv1.Account
	if completedResponse.Status != http.StatusOK || json.Unmarshal(completedResponse.Body, &completedAccount) != nil ||
		iamv1.ValidateAccount(completedAccount) != nil || completedAccount.ResourceVersion != 4 ||
		completedAccount.Status != iamv1.AccountDisabled || completedAccount.RootIdentity.PrincipalID != rootID {
		t.Fatalf("IAM86 did not recover retained disabled Account: status=%d", completedResponse.Status)
	}
	completion := readCompletion(currentRecoveryRequest, iamv1.AccountLifecycleRecoverRootCredentials, 3, http.StatusOK)
	if completion.ResultingResourceVersion != 4 || completion.Status != iamv1.AccountDisabled || completion.RootPrincipalID != rootID {
		t.Fatal("IAM86 retained-data completion implied enable or changed the root identity")
	}
	current.stop()
	current = start(root, currentBinary, installationrelease.CurrentDatabaseProfile().Authorities.IAM)
	defer current.stop()
	if replay := readCompletion(currentRecoveryRequest, iamv1.AccountLifecycleRecoverRootCredentials, 3, http.StatusOK); replay != completion {
		t.Fatal("IAM86 restart changed the immutable account completion")
	}
	restartedAccount := readAccount()
	if restartedAccount.Status != completedAccount.Status || restartedAccount.ResourceVersion != completedAccount.ResourceVersion ||
		restartedAccount.RootIdentity.PrincipalID != completedAccount.RootIdentity.PrincipalID {
		t.Fatal("IAM86 restart changed retained Account state")
	}
	t.Log("fixed IAM85 process -> IAM86: old completions absent, old request consumed, canonical facts retained, new disabled-root completion survives restart")
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
