package iamv1

import (
	"bytes"
	"cmp"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"strings"

	"github.com/xiak/matrix/api/contractjson"
)

const (
	ProductAuthorizationReleaseCatalogKind = "ProductAuthorizationReleaseCatalog"
	// MaxProductAuthorizationReleaseCatalogBytes is deliberately smaller than
	// the shared migration executor budget because the registry seed is embedded
	// in both apply and verification SQL. Larger catalogs need another protocol.
	MaxProductAuthorizationReleaseCatalogBytes int64 = 1024 * 1024
	MaxProductServiceRolePolicies                    = 100
	// The public directory is deliberately bounded to one page. Keep one slot
	// for the executable-owned template while this release contract admits at
	// most ninety-nine additional product-owned templates.
	MaxProductServiceRoleTemplates = 99
)

// ProductServiceRolePolicy is an immutable, product-owned permission ceiling.
// It is admitted only when a template in the same signed catalog references
// the exact version. Product is provenance, not an evaluator selector.
type ProductServiceRolePolicy struct {
	Product     ProductID     `json:"product"`
	DisplayName string        `json:"displayName"`
	Version     PolicyVersion `json:"version"`
}

// ProductAuthorizationReleaseCatalog is the one signed-release input for
// products not already owned by the Matrix executable. Publication registers
// declarations only: it creates no service principal, account consent, policy
// attachment, workload binding or authorization permit.
type ProductAuthorizationReleaseCatalog struct {
	APIVersion           string                     `json:"apiVersion"`
	Kind                 string                     `json:"kind"`
	Profiles             []AuthorizationProfile     `json:"profiles"`
	ProfileHistory       []AuthorizationProfile     `json:"profileHistory"`
	ServiceRolePolicies  []ProductServiceRolePolicy `json:"serviceRolePolicies"`
	ServiceRoleTemplates []ServiceRoleTemplate      `json:"serviceRoleTemplates"`
}

var ErrInvalidProductAuthorizationReleaseCatalog = errors.New("invalid IAM product authorization release catalog")

func EncodeProductAuthorizationReleaseCatalog(value ProductAuthorizationReleaseCatalog) ([]byte, error) {
	normalized, err := normalizeProductAuthorizationReleaseCatalog(value)
	if err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(normalized)
	if err != nil || int64(len(encoded)) > MaxProductAuthorizationReleaseCatalogBytes {
		return nil, ErrInvalidProductAuthorizationReleaseCatalog
	}
	return encoded, nil
}

// DecodeProductAuthorizationReleaseCatalog accepts canonical bytes only. The
// release signature establishes provenance; this decoder proves the closed
// object graph, immutable commitments and evolution rules.
func DecodeProductAuthorizationReleaseCatalog(reader io.Reader) (ProductAuthorizationReleaseCatalog, error) {
	if reader == nil {
		return ProductAuthorizationReleaseCatalog{}, ErrInvalidProductAuthorizationReleaseCatalog
	}
	encoded, err := io.ReadAll(io.LimitReader(reader, MaxProductAuthorizationReleaseCatalogBytes+1))
	if err != nil || int64(len(encoded)) > MaxProductAuthorizationReleaseCatalogBytes {
		return ProductAuthorizationReleaseCatalog{}, ErrInvalidProductAuthorizationReleaseCatalog
	}
	var value ProductAuthorizationReleaseCatalog
	if contractjson.DecodeObject(bytes.NewReader(encoded), MaxProductAuthorizationReleaseCatalogBytes, &value) != nil {
		return ProductAuthorizationReleaseCatalog{}, ErrInvalidProductAuthorizationReleaseCatalog
	}
	normalized, err := normalizeProductAuthorizationReleaseCatalog(value)
	if err != nil {
		return ProductAuthorizationReleaseCatalog{}, ErrInvalidProductAuthorizationReleaseCatalog
	}
	canonical, err := json.Marshal(normalized)
	if err != nil || !bytes.Equal(encoded, canonical) {
		return ProductAuthorizationReleaseCatalog{}, ErrInvalidProductAuthorizationReleaseCatalog
	}
	return normalized, nil
}

type authorizationProfileRevisionKey struct {
	product  ProductID
	revision uint64
}

type productServiceRolePolicyKey struct {
	policyID PolicyID
	version  PolicyVersionID
	digest   string
}

func normalizeProductAuthorizationReleaseCatalog(value ProductAuthorizationReleaseCatalog) (ProductAuthorizationReleaseCatalog, error) {
	if value.APIVersion != APIVersion || value.Kind != ProductAuthorizationReleaseCatalogKind ||
		value.Profiles == nil || value.ProfileHistory == nil || value.ServiceRolePolicies == nil || value.ServiceRoleTemplates == nil ||
		len(value.Profiles)+len(AllAuthorizationProfiles()) > MaxAuthorizationProfileRegistryItems ||
		len(value.Profiles)+len(value.ProfileHistory)+len(AllAuthorizationProfiles())+len(HistoricalAuthorizationProfiles()) > MaxAuthorizationProfileArchiveItems ||
		len(value.ServiceRolePolicies) > MaxProductServiceRolePolicies || len(value.ServiceRoleTemplates) > MaxProductServiceRoleTemplates {
		return ProductAuthorizationReleaseCatalog{}, ErrInvalidProductAuthorizationReleaseCatalog
	}
	normalized := ProductAuthorizationReleaseCatalog{
		APIVersion: value.APIVersion, Kind: value.Kind,
		Profiles:             make([]AuthorizationProfile, 0, len(value.Profiles)),
		ProfileHistory:       make([]AuthorizationProfile, 0, len(value.ProfileHistory)),
		ServiceRolePolicies:  make([]ProductServiceRolePolicy, 0, len(value.ServiceRolePolicies)),
		ServiceRoleTemplates: make([]ServiceRoleTemplate, 0, len(value.ServiceRoleTemplates)),
	}
	builtIn := make(map[ProductID]struct{}, len(AllAuthorizationProfiles()))
	for _, profile := range AllAuthorizationProfiles() {
		builtIn[profile.Product] = struct{}{}
	}
	heads := make(map[ProductID]AuthorizationProfile, len(value.Profiles))
	archive := make(map[authorizationProfileRevisionKey]AuthorizationProfile, len(value.Profiles)+len(value.ProfileHistory))
	for _, profile := range value.Profiles {
		if _, collision := builtIn[profile.Product]; collision || CheckTenantProductAuthorizationProfile(profile) != nil {
			return ProductAuthorizationReleaseCatalog{}, ErrInvalidProductAuthorizationReleaseCatalog
		}
		if _, duplicate := heads[profile.Product]; duplicate {
			return ProductAuthorizationReleaseCatalog{}, ErrInvalidProductAuthorizationReleaseCatalog
		}
		current, err := normalizeReleaseAuthorizationProfile(profile)
		if err != nil {
			return ProductAuthorizationReleaseCatalog{}, err
		}
		heads[current.Product] = current
		archive[authorizationProfileRevisionKey{current.Product, current.Revision}] = current
		normalized.Profiles = append(normalized.Profiles, current)
	}
	for _, profile := range value.ProfileHistory {
		head, found := heads[profile.Product]
		key := authorizationProfileRevisionKey{profile.Product, profile.Revision}
		if !found || CheckTenantProductAuthorizationProfile(profile) != nil || profile.Revision >= head.Revision || profile.CallingService != head.CallingService {
			return ProductAuthorizationReleaseCatalog{}, ErrInvalidProductAuthorizationReleaseCatalog
		}
		if _, duplicate := archive[key]; duplicate {
			return ProductAuthorizationReleaseCatalog{}, ErrInvalidProductAuthorizationReleaseCatalog
		}
		historical, err := normalizeReleaseAuthorizationProfile(profile)
		if err != nil {
			return ProductAuthorizationReleaseCatalog{}, err
		}
		archive[key] = historical
		normalized.ProfileHistory = append(normalized.ProfileHistory, historical)
	}

	policies := make(map[productServiceRolePolicyKey]ProductServiceRolePolicy, len(value.ServiceRolePolicies))
	policyIDs := make(map[PolicyID]struct{}, len(value.ServiceRolePolicies))
	for _, candidate := range value.ServiceRolePolicies {
		policy, key, err := normalizeProductServiceRolePolicy(candidate, heads, archive)
		if err != nil {
			return ProductAuthorizationReleaseCatalog{}, err
		}
		if _, duplicate := policies[key]; duplicate {
			return ProductAuthorizationReleaseCatalog{}, ErrInvalidProductAuthorizationReleaseCatalog
		}
		if _, duplicate := policyIDs[policy.Version.PolicyID]; duplicate {
			// One immutable version per ceiling Policy ID prevents a release
			// from expanding existing grants through a moved default pointer.
			return ProductAuthorizationReleaseCatalog{}, ErrInvalidProductAuthorizationReleaseCatalog
		}
		policies[key], policyIDs[policy.Version.PolicyID] = policy, struct{}{}
		normalized.ServiceRolePolicies = append(normalized.ServiceRolePolicies, policy)
	}

	usedPolicies := make(map[productServiceRolePolicyKey]bool, len(policies))
	templateVersions := make(map[ServiceRoleTemplateID]map[uint64]struct{}, len(value.ServiceRoleTemplates))
	activeTemplates := make(map[ServiceRoleTemplateID]bool, len(value.ServiceRoleTemplates))
	for _, candidate := range value.ServiceRoleTemplates {
		template, err := normalizeProductServiceRoleTemplate(candidate, heads, archive, policies)
		if err != nil {
			return ProductAuthorizationReleaseCatalog{}, err
		}
		versions := templateVersions[template.ID]
		if versions == nil {
			versions = make(map[uint64]struct{})
			templateVersions[template.ID] = versions
		}
		if _, duplicate := versions[template.Version]; duplicate || template.Status == ServiceRoleTemplateActive && activeTemplates[template.ID] {
			return ProductAuthorizationReleaseCatalog{}, ErrInvalidProductAuthorizationReleaseCatalog
		}
		versions[template.Version] = struct{}{}
		activeTemplates[template.ID] = activeTemplates[template.ID] || template.Status == ServiceRoleTemplateActive
		key := productServiceRolePolicyKey{template.Spec.PolicyVersion.PolicyID,
			template.Spec.PolicyVersion.VersionID, template.Spec.PolicyVersion.ContentDigest}
		usedPolicies[key] = true
		normalized.ServiceRoleTemplates = append(normalized.ServiceRoleTemplates, template)
	}
	for key := range policies {
		if !usedPolicies[key] {
			return ProductAuthorizationReleaseCatalog{}, ErrInvalidProductAuthorizationReleaseCatalog
		}
	}

	slices.SortFunc(normalized.Profiles, func(left, right AuthorizationProfile) int { return cmp.Compare(left.Product, right.Product) })
	slices.SortFunc(normalized.ProfileHistory, func(left, right AuthorizationProfile) int {
		if order := cmp.Compare(left.Product, right.Product); order != 0 {
			return order
		}
		return cmp.Compare(left.Revision, right.Revision)
	})
	slices.SortFunc(normalized.ServiceRolePolicies, func(left, right ProductServiceRolePolicy) int {
		if order := cmp.Compare(left.Product, right.Product); order != 0 {
			return order
		}
		return cmp.Compare(left.Version.PolicyID, right.Version.PolicyID)
	})
	slices.SortFunc(normalized.ServiceRoleTemplates, func(left, right ServiceRoleTemplate) int {
		if order := cmp.Compare(left.ID, right.ID); order != 0 {
			return order
		}
		return cmp.Compare(left.Version, right.Version)
	})
	return normalized, nil
}

func normalizeReleaseAuthorizationProfile(profile AuthorizationProfile) (AuthorizationProfile, error) {
	canonical, _, err := CanonicalizeAuthorizationProfile(profile)
	var normalized AuthorizationProfile
	if err != nil || json.Unmarshal([]byte(canonical), &normalized) != nil {
		return AuthorizationProfile{}, ErrInvalidProductAuthorizationReleaseCatalog
	}
	return normalized, nil
}

func normalizeProductServiceRolePolicy(value ProductServiceRolePolicy, heads map[ProductID]AuthorizationProfile,
	archive map[authorizationProfileRevisionKey]AuthorizationProfile,
) (ProductServiceRolePolicy, productServiceRolePolicyKey, error) {
	invalid := func() (ProductServiceRolePolicy, productServiceRolePolicyKey, error) {
		return ProductServiceRolePolicy{}, productServiceRolePolicyKey{}, ErrInvalidProductAuthorizationReleaseCatalog
	}
	if !profileIdentifier(string(value.Product), false) || validateText("displayName", value.DisplayName, 1, 128) != nil ||
		value.Version.ContractVersion != PolicyVersionCompiledContract || value.Version.Compilation == nil ||
		value.Version.Document.Scope != AuthorityScopeTenant || value.Version.PolicyID == "" ||
		!strings.HasPrefix(string(value.Version.PolicyID), "system.service-role."+string(value.Product)+".") ||
		len(value.Version.Compilation.Profiles) != 1 {
		return invalid()
	}
	reference := value.Version.Compilation.Profiles[0]
	profile, found := archive[authorizationProfileRevisionKey{reference.Product, reference.Revision}]
	if !found || value.Product != reference.Product || CheckAuthorizationProfileReference(profile, reference) != nil {
		return invalid()
	}
	compiled, err := CompilePolicyDocument(value.Version.Document, []AuthorizationProfile{profile})
	if err != nil {
		return invalid()
	}
	canonical, digest, err := CanonicalizePolicyCompilation(value.Version.Document, compiled, []AuthorizationProfile{profile})
	providedCanonical, providedDigest, providedErr := CanonicalizePolicyCompilation(
		value.Version.Document, *value.Version.Compilation, []AuthorizationProfile{profile})
	if err != nil || providedErr != nil || canonical != providedCanonical || digest != providedDigest ||
		value.Version.ContentDigest != digest || value.Version.ID != PolicyVersionID("version-"+strings.TrimPrefix(digest, "sha256:")) {
		return invalid()
	}
	var envelope struct {
		Document PolicyDocument `json:"document"`
	}
	if json.Unmarshal([]byte(canonical), &envelope) != nil {
		return invalid()
	}
	normalized := ProductServiceRolePolicy{Product: value.Product, DisplayName: value.DisplayName,
		Version: PolicyVersion{PolicyID: value.Version.PolicyID, ID: value.Version.ID, Document: envelope.Document,
			ContentDigest: digest, ContractVersion: PolicyVersionCompiledContract, Compilation: &compiled}}
	if head, known := heads[value.Product]; !known || head.CallingService != profile.CallingService || ValidatePolicyVersion(normalized.Version) != nil {
		return invalid()
	}
	return normalized, productServiceRolePolicyKey{normalized.Version.PolicyID, normalized.Version.ID, normalized.Version.ContentDigest}, nil
}

func normalizeProductServiceRoleTemplate(value ServiceRoleTemplate, heads map[ProductID]AuthorizationProfile,
	archive map[authorizationProfileRevisionKey]AuthorizationProfile, policies map[productServiceRolePolicyKey]ProductServiceRolePolicy,
) (ServiceRoleTemplate, error) {
	canonical, digest, err := CanonicalizeServiceRoleTemplateSpec(value.Spec)
	if err != nil || digest != value.ContentDigest || value.APIVersion != APIVersion || value.Kind != "ServiceRoleTemplate" ||
		(value.Status != ServiceRoleTemplateActive && value.Status != ServiceRoleTemplateRetired) ||
		ValidateID("serviceRoleTemplate.id", string(value.ID)) != nil || validatePositiveVersion(value.Version) != nil ||
		!strings.HasPrefix(string(value.ID), string(value.Spec.Product)+".") {
		return ServiceRoleTemplate{}, ErrInvalidProductAuthorizationReleaseCatalog
	}
	key := productServiceRolePolicyKey{value.Spec.PolicyVersion.PolicyID, value.Spec.PolicyVersion.VersionID,
		value.Spec.PolicyVersion.ContentDigest}
	policy, found := policies[key]
	if !found || policy.Product != value.Spec.Product || policy.Version.Compilation == nil || len(policy.Version.Compilation.Profiles) != 1 {
		return ServiceRoleTemplate{}, ErrInvalidProductAuthorizationReleaseCatalog
	}
	reference := policy.Version.Compilation.Profiles[0]
	profile, found := archive[authorizationProfileRevisionKey{reference.Product, reference.Revision}]
	if !found || CheckAuthorizationProfileReference(profile, reference) != nil {
		return ServiceRoleTemplate{}, ErrInvalidProductAuthorizationReleaseCatalog
	}
	for _, statement := range policy.Version.Compilation.ResolvedStatements {
		for _, action := range statement.Actions {
			if CheckAuthorizationProfileSubject(profile, reference, action, SubjectRole) != nil {
				return ServiceRoleTemplate{}, ErrInvalidProductAuthorizationReleaseCatalog
			}
		}
	}
	var spec ServiceRoleTemplateSpec
	if json.Unmarshal([]byte(canonical), &spec) != nil {
		return ServiceRoleTemplate{}, ErrInvalidProductAuthorizationReleaseCatalog
	}
	normalized := ServiceRoleTemplate{APIVersion: APIVersion, Kind: "ServiceRoleTemplate", ID: value.ID,
		Version: value.Version, Spec: spec, ContentDigest: digest, Status: value.Status}
	if CheckServiceRoleTemplate(normalized, []AuthorizationProfile{profile}) != nil {
		return ServiceRoleTemplate{}, ErrInvalidProductAuthorizationReleaseCatalog
	}
	head, known := heads[value.Spec.Product]
	// Retiring a template closes new consent but cannot strand an existing
	// workload binding. Its bind/unbind vocabulary must remain meaningful in
	// the current product declaration until the immutable template disappears
	// from the supported release history.
	if !known || CheckServiceRoleTemplateSpec(normalized.Spec, []AuthorizationProfile{head}) != nil {
		return ServiceRoleTemplate{}, ErrInvalidProductAuthorizationReleaseCatalog
	}
	if value.Status == ServiceRoleTemplateActive {
		if CheckAuthorizationProfileReference(head, reference) != nil {
			return ServiceRoleTemplate{}, ErrInvalidProductAuthorizationReleaseCatalog
		}
	}
	return normalized, nil
}
