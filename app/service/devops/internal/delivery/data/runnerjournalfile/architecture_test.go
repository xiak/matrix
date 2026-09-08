package runnerjournalfile

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestRunnerJournalKeepsTransportAndExecutionAuthorityOut(t *testing.T) {
	allowedMatrix := map[string]bool{
		"github.com/xiak/matrix/api/adapter/devopsbuild/v1":                         true,
		"github.com/xiak/matrix/api/devops/v1":                                      true,
		"github.com/xiak/matrix/app/service/devops/internal/delivery/runnerlog":     true,
		"github.com/xiak/matrix/app/service/devops/internal/delivery/sourcearchive": true,
	}
	forbiddenStandard := map[string]bool{
		"database/sql": true,
		"net":          true,
		"net/http":     true,
		"os/exec":      true,
		"plugin":       true,
	}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	files := token.NewFileSet()
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") ||
			strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		path := filepath.Clean(entry.Name())
		parsed, err := parser.ParseFile(files, path, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		for _, imported := range parsed.Imports {
			importPath, err := strconv.Unquote(imported.Path.Value)
			if err != nil {
				t.Fatalf("decode import in %s: %v", path, err)
			}
			if forbiddenStandard[importPath] {
				t.Errorf("runner journal imports forbidden authority %q at %s", importPath, files.Position(imported.Pos()))
				continue
			}
			if strings.HasPrefix(importPath, "github.com/xiak/matrix/") &&
				!allowedMatrix[importPath] {
				t.Errorf("runner journal crosses Matrix boundary through %q at %s", importPath, files.Position(imported.Pos()))
				continue
			}
			if strings.Contains(importPath, ".") &&
				importPath != "golang.org/x/sys/windows" &&
				!strings.HasPrefix(importPath, "github.com/xiak/matrix/") {
				t.Errorf("runner journal imports unapproved external package %q at %s", importPath, files.Position(imported.Pos()))
			}
		}
	}
}
