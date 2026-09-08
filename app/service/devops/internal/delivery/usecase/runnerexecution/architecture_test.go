package runnerexecution

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestRunnerExecutionKeepsSideEffectAuthorityBehindPorts(t *testing.T) {
	allowed := map[string]bool{
		"context": true,
		"errors":  true,
		"sync":    true,
		"time":    true,
		"github.com/xiak/matrix/api/adapter/devopsbuild/v1":                     true,
		"github.com/xiak/matrix/api/devops/v1":                                  true,
		"github.com/xiak/matrix/app/service/devops/internal/delivery/port":      true,
		"github.com/xiak/matrix/app/service/devops/internal/delivery/runnerlog": true,
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
			if !allowed[importPath] {
				t.Errorf(
					"runner execution imports side-effect or unapproved boundary %q at %s",
					importPath,
					files.Position(imported.Pos()),
				)
			}
		}
	}
}
