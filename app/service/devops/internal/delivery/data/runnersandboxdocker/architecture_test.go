package runnersandboxdocker

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestRunnerSandboxOwnsOnlyClosedLocalDockerAuthority(t *testing.T) {
	allowedMatrix := map[string]bool{
		"github.com/xiak/matrix/api/devops/v1": true,
	}
	forbiddenStandard := map[string]bool{
		"database/sql": true,
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
				t.Errorf("runner sandbox imports forbidden authority %q at %s", importPath, files.Position(imported.Pos()))
				continue
			}
			if strings.HasPrefix(importPath, "github.com/xiak/matrix/") &&
				!allowedMatrix[importPath] {
				t.Errorf("runner sandbox crosses Matrix boundary through %q at %s", importPath, files.Position(imported.Pos()))
				continue
			}
			if strings.Contains(importPath, ".") && importPath != "golang.org/x/sys/unix" &&
				!strings.HasPrefix(importPath, "github.com/xiak/matrix/") {
				t.Errorf("runner sandbox imports unapproved external package %q at %s", importPath, files.Position(imported.Pos()))
			}
		}
	}
}
