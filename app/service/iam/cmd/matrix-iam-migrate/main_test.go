package main

import (
	"os"
	"path/filepath"
	"testing"

	installationv1 "github.com/xiak/matrix/api/adapter/installation/v1"
	iamv1 "github.com/xiak/matrix/api/iam/v1"
)

func TestReadProductAuthorizationReleaseCatalogRequiresCanonicalFile(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "product-authorization.json")
	catalog := iamv1.ProductAuthorizationReleaseCatalog{
		APIVersion: iamv1.APIVersion, Kind: iamv1.ProductAuthorizationReleaseCatalogKind,
		Profiles: []iamv1.AuthorizationProfile{}, ProfileHistory: []iamv1.AuthorizationProfile{},
		ServiceRolePolicies: []iamv1.ProductServiceRolePolicy{}, ServiceRoleTemplates: []iamv1.ServiceRoleTemplate{},
	}
	encoded, err := iamv1.EncodeProductAuthorizationReleaseCatalog(catalog)
	if err != nil || os.WriteFile(path, encoded, 0o600) != nil {
		t.Fatal("write canonical release catalog", err)
	}
	t.Setenv(installationv1.IAMProductAuthorizationMigrationFileEnvironment, path)
	decoded, err := readProductAuthorizationReleaseCatalog()
	if err != nil || decoded.Profiles == nil || decoded.ProfileHistory == nil ||
		decoded.ServiceRolePolicies == nil || decoded.ServiceRoleTemplates == nil {
		t.Fatalf("read canonical release catalog: %#v / %v", decoded, err)
	}
	if err := os.WriteFile(path, append(encoded, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readProductAuthorizationReleaseCatalog(); err == nil {
		t.Fatal("non-canonical release catalog was accepted")
	}
}
