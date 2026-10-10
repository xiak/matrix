package migrations

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"

	iamv1 "github.com/xiak/matrix/api/iam/v1"
)

func productProfileFixture(revision uint64) iamv1.AuthorizationProfile {
	return iamv1.AuthorizationProfile{APIVersion: iamv1.APIVersion, Kind: "AuthorizationProfile", Product: "catalog", Revision: revision, CallingService: iamv1.ServicePaaS,
		Actions: []iamv1.AuthorizationProfileAction{
			{Action: "catalog.item.read", ResourceKind: "CATALOG_ITEM", Scope: iamv1.AuthorityScopeTenant,
				ResourceShapes: []iamv1.AuthorizationResourceShape{{Mode: iamv1.AuthorizationResourceInstance}},
				SubjectTypes:   []iamv1.SubjectType{iamv1.SubjectUser, iamv1.SubjectRole}, UserAuthenticationMethods: []iamv1.UserAuthenticationMethod{iamv1.UserAuthenticationLoginSession}},
			{Action: "catalog.item.role-bind", ResourceKind: "CATALOG_ITEM", Scope: iamv1.AuthorityScopeTenant,
				ResourceShapes: []iamv1.AuthorizationResourceShape{{Mode: iamv1.AuthorizationResourceInstance}},
				SubjectTypes:   []iamv1.SubjectType{iamv1.SubjectUser}, UserAuthenticationMethods: []iamv1.UserAuthenticationMethod{iamv1.UserAuthenticationLoginSession}},
			{Action: "catalog.item.role-unbind", ResourceKind: "CATALOG_ITEM", Scope: iamv1.AuthorityScopeTenant,
				ResourceShapes: []iamv1.AuthorizationResourceShape{{Mode: iamv1.AuthorizationResourceInstance}},
				SubjectTypes:   []iamv1.SubjectType{iamv1.SubjectUser}, UserAuthenticationMethods: []iamv1.UserAuthenticationMethod{iamv1.UserAuthenticationLoginSession}},
		}}
}

func productServiceRoleFixture(t *testing.T, profile iamv1.AuthorizationProfile) (iamv1.ProductServiceRolePolicy, iamv1.ServiceRoleTemplate) {
	t.Helper()
	document := iamv1.PolicyDocument{LanguageVersion: iamv1.PolicyLanguageVersion, Scope: iamv1.AuthorityScopeTenant,
		Statements: []iamv1.PolicyStatement{{SID: "catalog-read", Effect: iamv1.PolicyAllow,
			Actions:   []iamv1.Action{"catalog.item.read"},
			Resources: []iamv1.PolicyResourceSelector{{Kind: "CATALOG_ITEM", Match: iamv1.PolicyResourceAnyInAuthority}}}}}
	compilation, err := iamv1.CompilePolicyDocument(document, []iamv1.AuthorizationProfile{profile})
	if err != nil {
		t.Fatal(err)
	}
	_, digest, err := iamv1.CanonicalizePolicyCompilation(document, compilation, []iamv1.AuthorizationProfile{profile})
	if err != nil {
		t.Fatal(err)
	}
	policy := iamv1.ProductServiceRolePolicy{Product: profile.Product, DisplayName: "CatalogItemReader",
		Version: iamv1.PolicyVersion{PolicyID: "system.service-role.catalog.item-reader",
			ID: iamv1.PolicyVersionID("version-" + strings.TrimPrefix(digest, "sha256:")), Document: document,
			ContentDigest: digest, ContractVersion: iamv1.PolicyVersionCompiledContract, Compilation: &compilation}}
	spec := iamv1.ServiceRoleTemplateSpec{Product: profile.Product, ServicePurpose: iamv1.ServicePaaS,
		RoleName: "CatalogItemReader", RoleDescription: "Reads one explicitly bound catalog item.",
		PolicyVersion: iamv1.PolicyVersionReference{PolicyID: policy.Version.PolicyID, VersionID: policy.Version.ID,
			ContentDigest: policy.Version.ContentDigest},
		Workloads: []iamv1.ServiceRoleWorkloadSpec{{ResourceKind: "CATALOG_ITEM", BindAction: "catalog.item.role-bind",
			UnbindAction: "catalog.item.role-unbind"}}, MaxSessionDurationSeconds: 900}
	_, templateDigest, err := iamv1.CanonicalizeServiceRoleTemplateSpec(spec)
	if err != nil {
		t.Fatal(err)
	}
	return policy, iamv1.ServiceRoleTemplate{APIVersion: iamv1.APIVersion, Kind: "ServiceRoleTemplate",
		ID: "catalog.item-reader", Version: 1, Spec: spec, ContentDigest: templateDigest, Status: iamv1.ServiceRoleTemplateActive}
}

func productReleaseCatalog(current, history []iamv1.AuthorizationProfile) iamv1.ProductAuthorizationReleaseCatalog {
	if current == nil {
		current = []iamv1.AuthorizationProfile{}
	}
	if history == nil {
		history = []iamv1.AuthorizationProfile{}
	}
	return iamv1.ProductAuthorizationReleaseCatalog{
		APIVersion: iamv1.APIVersion, Kind: iamv1.ProductAuthorizationReleaseCatalogKind,
		Profiles: current, ProfileHistory: history,
		ServiceRolePolicies: []iamv1.ProductServiceRolePolicy{}, ServiceRoleTemplates: []iamv1.ServiceRoleTemplate{},
	}
}

func TestSourceWithProductAuthorizationAddsOnlyValidatedReleaseOwnedHeads(t *testing.T) {
	current, historical := productProfileFixture(2), productProfileFixture(1)
	profiles, archive, err := authorizationProfilesForSource([]iamv1.AuthorizationProfile{current}, []iamv1.AuthorizationProfile{historical})
	if err != nil || len(profiles) != len(iamv1.AllAuthorizationProfiles())+1 ||
		!slices.ContainsFunc(profiles, func(profile iamv1.AuthorizationProfile) bool {
			return profile.Product == current.Product && profile.Revision == current.Revision
		}) ||
		!slices.ContainsFunc(archive, func(profile iamv1.AuthorizationProfile) bool {
			return profile.Product == historical.Product && profile.Revision == historical.Revision
		}) {
		t.Fatalf("additional Profile assembly failed: profiles=%d archive=%d err=%v", len(profiles), len(archive), err)
	}
	current.Actions[0].ResourceKind = "MUTATED"
	if slices.ContainsFunc(profiles, func(profile iamv1.AuthorizationProfile) bool {
		return profile.Product == "catalog" && profile.Actions[0].ResourceKind == "MUTATED"
	}) {
		t.Fatal("migration source retained caller-owned declaration slices")
	}
	canonical, digest, err := iamv1.CanonicalizeAuthorizationProfile(productProfileFixture(2))
	if err != nil {
		t.Fatal(err)
	}
	encodedCanonical, err := json.Marshal(canonical)
	if err != nil {
		t.Fatal(err)
	}
	releaseCatalog := productReleaseCatalog([]iamv1.AuthorizationProfile{productProfileFixture(2)}, []iamv1.AuthorizationProfile{historical})
	serviceRolePolicy, serviceRoleTemplate := productServiceRoleFixture(t, productProfileFixture(2))
	releaseCatalog.ServiceRolePolicies = []iamv1.ProductServiceRolePolicy{serviceRolePolicy}
	releaseCatalog.ServiceRoleTemplates = []iamv1.ServiceRoleTemplate{serviceRoleTemplate}
	source := SourceWithProductAuthorization(releaseCatalog)
	if source.Context != "iam" || source.UpSQL == "" || source.VerifySQL == "" ||
		!strings.Contains(source.UpSQL, string(encodedCanonical[1:len(encodedCanonical)-1])) || !strings.Contains(source.UpSQL, digest) ||
		!strings.Contains(source.UpSQL, string(serviceRolePolicy.Version.PolicyID)) ||
		!strings.Contains(source.UpSQL, string(serviceRolePolicy.Version.ID)) ||
		!strings.Contains(source.UpSQL, string(serviceRoleTemplate.ID)) ||
		!strings.Contains(source.VerifySQL, serviceRoleTemplate.ContentDigest) {
		t.Fatal("valid product authorization release was not committed to migration bytes")
	}
}

func TestSourceWithProductAuthorizationFillsOneBoundedTemplateDirectory(t *testing.T) {
	profile := productProfileFixture(1)
	policy, template := productServiceRoleFixture(t, profile)
	templates := make([]iamv1.ServiceRoleTemplate, 0, iamv1.MaxProductServiceRoleTemplates)
	for index := 0; index < iamv1.MaxProductServiceRoleTemplates; index++ {
		candidate := template
		candidate.ID = iamv1.ServiceRoleTemplateID(fmt.Sprintf("catalog.item-reader-%02d", index))
		templates = append(templates, candidate)
	}
	catalog := productReleaseCatalog([]iamv1.AuthorizationProfile{profile}, nil)
	catalog.ServiceRolePolicies = []iamv1.ProductServiceRolePolicy{policy}
	catalog.ServiceRoleTemplates = templates
	if source := SourceWithProductAuthorization(catalog); source.UpSQL == "" || source.VerifySQL == "" {
		t.Fatal("ninety-nine product templates plus the built-in template did not fill the bounded directory")
	}
	catalog.ServiceRoleTemplates = append(catalog.ServiceRoleTemplates, template)
	if source := SourceWithProductAuthorization(catalog); source.UpSQL != "" || source.VerifySQL != "" {
		t.Fatal("one hundred product templates exceeded the release-owned directory allocation")
	}
}

func TestSourceWithProductAuthorizationRejectsAmbiguousOrInventedHistory(t *testing.T) {
	builtin := iamv1.AllAuthorizationProfiles()[0]
	unenrolledService := productProfileFixture(1)
	unenrolledService.CallingService = "CATALOG"
	changedHistoricalService := productProfileFixture(1)
	changedHistoricalService.CallingService = iamv1.ServiceIAM
	platformScope := productProfileFixture(1)
	platformScope.Actions[0].Scope = iamv1.AuthorityScopeInstallation
	for name, test := range map[string]struct {
		current []iamv1.AuthorizationProfile
		history []iamv1.AuthorizationProfile
	}{
		"built-in product collision":    {current: []iamv1.AuthorizationProfile{builtin}},
		"unenrolled calling service":    {current: []iamv1.AuthorizationProfile{unenrolledService}},
		"unsupported platform scope":    {current: []iamv1.AuthorizationProfile{platformScope}},
		"history without current head":  {history: []iamv1.AuthorizationProfile{productProfileFixture(1)}},
		"history equal to current":      {current: []iamv1.AuthorizationProfile{productProfileFixture(1)}, history: []iamv1.AuthorizationProfile{productProfileFixture(1)}},
		"history newer than current":    {current: []iamv1.AuthorizationProfile{productProfileFixture(1)}, history: []iamv1.AuthorizationProfile{productProfileFixture(2)}},
		"history changes service owner": {current: []iamv1.AuthorizationProfile{productProfileFixture(2)}, history: []iamv1.AuthorizationProfile{changedHistoricalService}},
		"duplicate history":             {current: []iamv1.AuthorizationProfile{productProfileFixture(2)}, history: []iamv1.AuthorizationProfile{productProfileFixture(1), productProfileFixture(1)}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := authorizationProfilesForSource(test.current, test.history); err == nil {
				t.Fatal("invalid release Profile set was accepted")
			}
			if source := SourceWithProductAuthorization(productReleaseCatalog(test.current, test.history)); source.UpSQL != "" || source.VerifySQL != "" {
				t.Fatal("invalid release Profile set produced executable migration SQL")
			}
		})
	}
}

func TestAuthorizationProfileSeedsRejectOversizedEmbeddedReleaseInput(t *testing.T) {
	profiles := make([]iamv1.AuthorizationProfile, 0, iamv1.MaxAuthorizationProfileRegistryItems)
	for productIndex := 0; productIndex < iamv1.MaxAuthorizationProfileRegistryItems; productIndex++ {
		product := iamv1.ProductID(fmt.Sprintf("catalog%03d", productIndex))
		profile := iamv1.AuthorizationProfile{APIVersion: iamv1.APIVersion, Kind: "AuthorizationProfile", Product: product,
			Revision: 1, CallingService: iamv1.ServicePaaS, Actions: make([]iamv1.AuthorizationProfileAction, 0, iamv1.MaxAuthorizationProfileActions)}
		for actionIndex := 0; actionIndex < iamv1.MaxAuthorizationProfileActions; actionIndex++ {
			profile.Actions = append(profile.Actions, iamv1.AuthorizationProfileAction{
				Action:       iamv1.Action(fmt.Sprintf("%s.item%03d.read", product, actionIndex)),
				ResourceKind: "CATALOG_ITEM", Scope: iamv1.AuthorityScopeTenant,
				ResourceShapes:            []iamv1.AuthorizationResourceShape{{Mode: iamv1.AuthorizationResourceInstance}},
				SubjectTypes:              []iamv1.SubjectType{iamv1.SubjectUser},
				UserAuthenticationMethods: []iamv1.UserAuthenticationMethod{iamv1.UserAuthenticationLoginSession},
			})
		}
		if iamv1.CheckTenantProductAuthorizationProfile(profile) != nil {
			t.Fatal("oversized fixture must remain individually valid")
		}
		profiles = append(profiles, profile)
	}
	if _, err := authorizationProfileSeeds(profiles, nil); err == nil {
		t.Fatal("embedded Profile seed exceeded its release budget")
	}
}
