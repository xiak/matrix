package delivery_test

import (
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestDeliveryKeepsProductAndAdapterBoundaries(t *testing.T) {
	files := token.NewFileSet()
	err := filepath.WalkDir(".", func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		parsed, err := parser.ParseFile(files, path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		cleanPath := filepath.ToSlash(path)
		policyPackage := strings.HasPrefix(cleanPath, "domain/") ||
			strings.HasPrefix(cleanPath, "port/") || strings.HasPrefix(cleanPath, "usecase/")
		for _, imported := range parsed.Imports {
			importPath, err := strconv.Unquote(imported.Path.Value)
			if err != nil {
				return err
			}
			if strings.Contains(importPath, "/app/service/paas/") ||
				strings.Contains(importPath, "k8s.io/test-infra/prow") {
				t.Errorf("delivery imports another product or donor at %s: %s", files.Position(imported.Pos()), importPath)
			}
			if policyPackage &&
				strings.Contains(importPath, "/internal/delivery/data/") {
				t.Errorf("delivery policy imports a persistence adapter at %s", files.Position(imported.Pos()))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("inspect delivery architecture: %v", err)
	}
}
