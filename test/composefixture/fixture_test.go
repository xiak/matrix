package composefixture

import (
	"context"
	"path/filepath"
	"testing"
)

func TestImportBinariesRejectsImplicitOrNonRegularAuthority(t *testing.T) {
	for _, target := range []string{"", "relative-fixture", t.TempDir()} {
		if _, err := ImportBinaries(context.Background(), target, target); err == nil {
			t.Fatalf("unsafe prebuilt fixture path admitted: %q", target)
		}
	}
	missing := filepath.Join(t.TempDir(), "missing-fixture")
	if _, err := ImportBinaries(context.Background(), missing, missing); err == nil {
		t.Fatal("missing prebuilt fixture admitted")
	}
}
