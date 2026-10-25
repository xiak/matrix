package localcontainer

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func TestRecoveryInventoryTracksProviderInstallationIdentitiesOnly(t *testing.T) {
	first, second := recoveryInventoryRoot(t), recoveryInventoryRoot(t)
	empty, err := InspectRecoveryInventory(first)
	if err != nil {
		t.Fatal(err)
	}
	providers := []string{"postgres", "mysql"}
	projects := []string{ProjectName("tenant-a", "database-a"), ProjectName("tenant-b", "database-b")}
	for rootIndex, root := range []string{first, second} {
		order := []int{0, 1}
		if rootIndex == 1 {
			order = []int{1, 0}
		}
		for _, providerIndex := range order {
			providerName, err := ProviderDirectoryName(providers[providerIndex])
			if err != nil || os.Mkdir(filepath.Join(root, providerName), 0o700) != nil {
				t.Fatal("create provider inventory")
			}
			project := projects[providerIndex]
			if err := os.Mkdir(filepath.Join(root, providerName, project), 0o700); err != nil {
				t.Fatal(err)
			}
		}
	}
	before, err := InspectRecoveryInventory(first)
	if err != nil || before == empty {
		t.Fatalf("prepared installations did not change inventory: %v", err)
	}
	relocated, err := InspectRecoveryInventory(second)
	if err != nil || relocated != before {
		t.Fatalf("inventory depends on absolute root or enumeration order: %v", err)
	}
	providerName, _ := ProviderDirectoryName("postgres")
	projectPath := filepath.Join(first, providerName, projects[0])
	if err := os.WriteFile(filepath.Join(projectPath, "database-value"), []byte("post-backup-data"), 0o600); err != nil {
		t.Fatal(err)
	}
	afterWrite, err := InspectRecoveryInventory(first)
	if err != nil || afterWrite != before {
		t.Fatalf("service contents changed identity inventory: %v", err)
	}
	if err := os.Mkdir(filepath.Join(first, providerName, ProjectName("tenant-a", "database-after-backup")), 0o700); err != nil {
		t.Fatal(err)
	}
	afterCreate, err := InspectRecoveryInventory(first)
	if err != nil || afterCreate == before {
		t.Fatalf("new service was absent from identity inventory: %v", err)
	}
}

func TestRecoveryInventoryRejectsUnprovedAndUnboundedManagedRoots(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing")
	if _, err := InspectRecoveryInventory(missing); err == nil {
		t.Fatal("missing root was accepted")
	}
	root := recoveryInventoryRoot(t)
	if err := os.WriteFile(filepath.Join(root, "managed-foreign"), []byte("foreign"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := InspectRecoveryInventory(root); err == nil {
		t.Fatal("unproved provider entry was accepted")
	}
	bounded := recoveryInventoryRoot(t)
	providerName, _ := ProviderDirectoryName("postgres")
	provider := filepath.Join(bounded, providerName)
	if err := os.Mkdir(provider, 0o700); err != nil {
		t.Fatal(err)
	}
	for index := 0; index <= maximumRecoveryProjects; index++ {
		name := ProjectName("tenant", "database-"+strconv.Itoa(index))
		if err := os.Mkdir(filepath.Join(provider, name), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := InspectRecoveryInventory(bounded); err == nil {
		t.Fatal("unbounded project inventory was accepted")
	}
}

func TestRecoveryInventoryRejectsSymlinkProjects(t *testing.T) {
	root := recoveryInventoryRoot(t)
	providerName, _ := ProviderDirectoryName("postgres")
	provider := filepath.Join(root, providerName)
	if err := os.Mkdir(provider, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(t.TempDir(), filepath.Join(provider, ProjectName("tenant", "linked"))); err != nil {
		t.Skip("symlinks are unavailable on this test host")
	}
	if _, err := InspectRecoveryInventory(root); err == nil {
		t.Fatal("symlink project crossed the recovery inventory boundary")
	}
}

func recoveryInventoryRoot(t *testing.T) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "executor")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	return root
}
