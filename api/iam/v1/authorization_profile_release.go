package iamv1

import (
	"bytes"
	"cmp"
	"encoding/json"
	"errors"
	"io"
	"slices"

	"github.com/xiak/matrix/api/contractjson"
)

const (
	AuthorizationProfileReleaseCatalogKind = "AuthorizationProfileReleaseCatalog"
	// MaxAuthorizationProfileReleaseCatalogBytes is deliberately smaller than
	// the shared migration executor budget because the seed is embedded in both
	// apply and verification SQL. Larger catalogs need a different protocol.
	MaxAuthorizationProfileReleaseCatalogBytes int64 = 1024 * 1024
)

// AuthorizationProfileReleaseCatalog is a signed-release input containing
// only products not already owned by the Matrix executable. It is neither a
// tenant registration API nor permission to call the declared products.
type AuthorizationProfileReleaseCatalog struct {
	APIVersion string                 `json:"apiVersion"`
	Kind       string                 `json:"kind"`
	Current    []AuthorizationProfile `json:"current"`
	Historical []AuthorizationProfile `json:"historical"`
}

var ErrInvalidAuthorizationProfileReleaseCatalog = errors.New("invalid IAM authorization profile release catalog")

// EncodeAuthorizationProfileReleaseCatalog returns the one canonical document
// admitted to a signed release. Inputs are cloned and normalized.
func EncodeAuthorizationProfileReleaseCatalog(value AuthorizationProfileReleaseCatalog) ([]byte, error) {
	normalized, err := normalizeAuthorizationProfileReleaseCatalog(value)
	if err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(normalized)
	if err != nil || int64(len(encoded)) > MaxAuthorizationProfileReleaseCatalogBytes {
		return nil, ErrInvalidAuthorizationProfileReleaseCatalog
	}
	return encoded, nil
}

// DecodeAuthorizationProfileReleaseCatalog accepts only canonical bytes. The
// surrounding release signature establishes provenance; this decoder proves
// the closed catalog shape and evolution rules only.
func DecodeAuthorizationProfileReleaseCatalog(reader io.Reader) (AuthorizationProfileReleaseCatalog, error) {
	if reader == nil {
		return AuthorizationProfileReleaseCatalog{}, ErrInvalidAuthorizationProfileReleaseCatalog
	}
	encoded, err := io.ReadAll(io.LimitReader(reader, MaxAuthorizationProfileReleaseCatalogBytes+1))
	if err != nil || int64(len(encoded)) > MaxAuthorizationProfileReleaseCatalogBytes {
		return AuthorizationProfileReleaseCatalog{}, ErrInvalidAuthorizationProfileReleaseCatalog
	}
	var value AuthorizationProfileReleaseCatalog
	if contractjson.DecodeObject(bytes.NewReader(encoded), MaxAuthorizationProfileReleaseCatalogBytes, &value) != nil {
		return AuthorizationProfileReleaseCatalog{}, ErrInvalidAuthorizationProfileReleaseCatalog
	}
	canonical, err := EncodeAuthorizationProfileReleaseCatalog(value)
	if err != nil || !bytes.Equal(encoded, canonical) {
		return AuthorizationProfileReleaseCatalog{}, ErrInvalidAuthorizationProfileReleaseCatalog
	}
	return cloneAuthorizationProfileReleaseCatalog(value), nil
}

func normalizeAuthorizationProfileReleaseCatalog(value AuthorizationProfileReleaseCatalog) (AuthorizationProfileReleaseCatalog, error) {
	if value.APIVersion != APIVersion || value.Kind != AuthorizationProfileReleaseCatalogKind ||
		value.Current == nil || value.Historical == nil ||
		len(value.Current)+len(AllAuthorizationProfiles()) > MaxAuthorizationProfileRegistryItems ||
		len(value.Current)+len(value.Historical)+len(AllAuthorizationProfiles())+len(HistoricalAuthorizationProfiles()) > MaxAuthorizationProfileArchiveItems {
		return AuthorizationProfileReleaseCatalog{}, ErrInvalidAuthorizationProfileReleaseCatalog
	}
	builtIn := make(map[ProductID]struct{}, len(AllAuthorizationProfiles()))
	for _, profile := range AllAuthorizationProfiles() {
		builtIn[profile.Product] = struct{}{}
	}
	normalized := AuthorizationProfileReleaseCatalog{
		APIVersion: value.APIVersion,
		Kind:       value.Kind,
		Current:    make([]AuthorizationProfile, 0, len(value.Current)),
		Historical: make([]AuthorizationProfile, 0, len(value.Historical)),
	}
	heads := make(map[ProductID]AuthorizationProfile, len(value.Current))
	for _, profile := range value.Current {
		if _, collision := builtIn[profile.Product]; collision || CheckTenantProductAuthorizationProfile(profile) != nil {
			return AuthorizationProfileReleaseCatalog{}, ErrInvalidAuthorizationProfileReleaseCatalog
		}
		if _, duplicate := heads[profile.Product]; duplicate {
			return AuthorizationProfileReleaseCatalog{}, ErrInvalidAuthorizationProfileReleaseCatalog
		}
		canonical, _, err := CanonicalizeAuthorizationProfile(profile)
		var current AuthorizationProfile
		if err != nil || json.Unmarshal([]byte(canonical), &current) != nil {
			return AuthorizationProfileReleaseCatalog{}, ErrInvalidAuthorizationProfileReleaseCatalog
		}
		heads[current.Product] = current
		normalized.Current = append(normalized.Current, current)
	}
	type revisionKey struct {
		product  ProductID
		revision uint64
	}
	revisions := make(map[revisionKey]struct{}, len(value.Historical))
	for _, profile := range value.Historical {
		head, found := heads[profile.Product]
		key := revisionKey{product: profile.Product, revision: profile.Revision}
		if !found || CheckTenantProductAuthorizationProfile(profile) != nil ||
			profile.Revision >= head.Revision || profile.CallingService != head.CallingService {
			return AuthorizationProfileReleaseCatalog{}, ErrInvalidAuthorizationProfileReleaseCatalog
		}
		if _, duplicate := revisions[key]; duplicate {
			return AuthorizationProfileReleaseCatalog{}, ErrInvalidAuthorizationProfileReleaseCatalog
		}
		revisions[key] = struct{}{}
		canonical, _, err := CanonicalizeAuthorizationProfile(profile)
		var historical AuthorizationProfile
		if err != nil || json.Unmarshal([]byte(canonical), &historical) != nil {
			return AuthorizationProfileReleaseCatalog{}, ErrInvalidAuthorizationProfileReleaseCatalog
		}
		normalized.Historical = append(normalized.Historical, historical)
	}
	slices.SortFunc(normalized.Current, func(left, right AuthorizationProfile) int {
		return cmp.Compare(left.Product, right.Product)
	})
	slices.SortFunc(normalized.Historical, func(left, right AuthorizationProfile) int {
		if order := cmp.Compare(left.Product, right.Product); order != 0 {
			return order
		}
		return cmp.Compare(left.Revision, right.Revision)
	})
	return normalized, nil
}

func cloneAuthorizationProfileReleaseCatalog(value AuthorizationProfileReleaseCatalog) AuthorizationProfileReleaseCatalog {
	value.Current = slices.Clone(value.Current)
	for index := range value.Current {
		value.Current[index] = CloneAuthorizationProfile(value.Current[index])
	}
	value.Historical = slices.Clone(value.Historical)
	for index := range value.Historical {
		value.Historical[index] = CloneAuthorizationProfile(value.Historical[index])
	}
	return value
}
