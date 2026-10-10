package main

import (
	"os"
	"path/filepath"
	"testing"

	installationv1 "github.com/xiak/matrix/api/adapter/installation/v1"
	iamv1 "github.com/xiak/matrix/api/iam/v1"
)

func TestReadAuthorizationProfileReleaseCatalogRequiresCanonicalFile(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "authorization-profiles.json")
	catalog := iamv1.AuthorizationProfileReleaseCatalog{
		APIVersion: iamv1.APIVersion, Kind: iamv1.AuthorizationProfileReleaseCatalogKind,
		Current: []iamv1.AuthorizationProfile{}, Historical: []iamv1.AuthorizationProfile{},
	}
	encoded, err := iamv1.EncodeAuthorizationProfileReleaseCatalog(catalog)
	if err != nil || os.WriteFile(path, encoded, 0o600) != nil {
		t.Fatal("write canonical release catalog", err)
	}
	t.Setenv(installationv1.IAMAuthorizationProfilesMigrationFileEnvironment, path)
	decoded, err := readAuthorizationProfileReleaseCatalog()
	if err != nil || decoded.Current == nil || decoded.Historical == nil {
		t.Fatalf("read canonical release catalog: %#v / %v", decoded, err)
	}
	if err := os.WriteFile(path, append(encoded, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readAuthorizationProfileReleaseCatalog(); err == nil {
		t.Fatal("non-canonical release catalog was accepted")
	}
}
