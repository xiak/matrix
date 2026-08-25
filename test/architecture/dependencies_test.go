package architecture

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

const modulePath = "github.com/xiak/matrix/"

func TestSourceDependenciesFollowRepositoryBoundaries(t *testing.T) {
	root := repositoryRoot(t)
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			switch entry.Name() {
			case ".git", "node_modules", "vendor":
				return filepath.SkipDir
			default:
				return nil
			}
		}
		if filepath.Ext(path) != ".go" {
			return nil
		}

		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			t.Errorf("parse %s: %v", relative, err)
			return nil
		}
		for _, declaration := range file.Imports {
			imported, err := strconv.Unquote(declaration.Path.Value)
			if err != nil {
				t.Errorf("decode import %s in %s: %v", declaration.Path.Value, relative, err)
				continue
			}
			assertAllowedDependency(t, relative, imported, declaration)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk repository: %v", err)
	}
}

func TestPlacementCoreKeepsItsPureDependencyBoundary(t *testing.T) {
	root := repositoryRoot(t)
	placementRoot := filepath.Join(
		root,
		"app",
		"service",
		"paas",
		"internal",
		"apphosting",
		"domain",
		"placement",
	)
	allowed := map[string]struct{}{
		"crypto/sha256":                      {},
		"encoding/binary":                    {},
		"encoding/hex":                       {},
		"errors":                             {},
		"fmt":                                {},
		"hash":                               {},
		"math":                               {},
		"math/big":                           {},
		"github.com/xiak/matrix/api/paas/v1": {},
		"sort":                               {},
		"time":                               {},
	}
	err := filepath.WalkDir(placementRoot, func(
		path string,
		entry fs.DirEntry,
		walkErr error,
	) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || filepath.Ext(path) != ".go" || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		for _, declaration := range file.Imports {
			imported, err := strconv.Unquote(declaration.Path.Value)
			if err != nil {
				return err
			}
			if _, found := allowed[imported]; !found {
				relative, relativeErr := filepath.Rel(root, path)
				if relativeErr != nil {
					return relativeErr
				}
				t.Errorf(
					"%s: pure placement core cannot import %q",
					filepath.ToSlash(relative),
					imported,
				)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("inspect placement dependencies: %v", err)
	}
}

func TestPaaSApphostingUsesPragmaticDDDDependencies(t *testing.T) {
	root := repositoryRoot(t)
	apphostingRoot := filepath.Join(root, "app", "service", "paas", "internal", "apphosting")
	err := filepath.WalkDir(apphostingRoot, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || filepath.Ext(path) != ".go" {
			return nil
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		for _, declaration := range file.Imports {
			imported, err := strconv.Unquote(declaration.Path.Value)
			if err != nil {
				return err
			}
			assertApphostingDDDDependency(t, relative, imported)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("inspect PaaS apphosting DDD dependencies: %v", err)
	}
}

func TestPaaSApphostingBusinessTypesAvoidAmbiguousNames(t *testing.T) {
	root := repositoryRoot(t)
	apphostingRoot := filepath.Join(root, "app", "service", "paas", "internal", "apphosting")
	forbiddenSuffixes := []string{"Manager", "Helper", "Logic", "DAO", "Model", "DTO"}
	err := filepath.WalkDir(apphostingRoot, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || filepath.Ext(path) != ".go" || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			return err
		}
		for _, declaration := range file.Decls {
			general, ok := declaration.(*ast.GenDecl)
			if !ok || general.Tok != token.TYPE {
				continue
			}
			for _, specification := range general.Specs {
				typeSpec, ok := specification.(*ast.TypeSpec)
				if !ok || !ast.IsExported(typeSpec.Name.Name) {
					continue
				}
				for _, suffix := range forbiddenSuffixes {
					if strings.HasSuffix(typeSpec.Name.Name, suffix) {
						t.Errorf(
							"%s: exported business type %q has ambiguous DDD suffix %q",
							filepath.ToSlash(relative),
							typeSpec.Name.Name,
							suffix,
						)
					}
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("inspect PaaS apphosting business names: %v", err)
	}
}

func assertApphostingDDDDependency(t *testing.T, source, imported string) {
	t.Helper()
	const contextPrefix = modulePath + "app/service/paas/internal/apphosting/"

	if strings.HasPrefix(source, "app/service/paas/internal/apphosting/domain/") &&
		(strings.HasPrefix(imported, contextPrefix+"usecase/") ||
			strings.HasPrefix(imported, contextPrefix+"data/") ||
			strings.HasPrefix(imported, contextPrefix+"port/") ||
			strings.HasPrefix(imported, modulePath+"app/adapter/")) {
		t.Errorf("%s: domain cannot import %q", source, imported)
	}

	if strings.HasPrefix(source, "app/service/paas/internal/apphosting/usecase/") &&
		(strings.HasPrefix(imported, contextPrefix+"data/") ||
			strings.HasPrefix(imported, modulePath+"app/adapter/")) {
		t.Errorf("%s: use case cannot import concrete adapter %q", source, imported)
	}
}

func assertAllowedDependency(
	t *testing.T,
	source string,
	imported string,
	declaration *ast.ImportSpec,
) {
	t.Helper()
	_ = declaration

	if strings.HasPrefix(source, "api/") &&
		(strings.HasPrefix(imported, modulePath+"app/") ||
			strings.HasPrefix(imported, modulePath+"deploy/")) {
		t.Errorf("%s: public API cannot import implementation package %q", source, imported)
	}

	if (strings.HasPrefix(source, "api/") || strings.HasPrefix(source, "app/")) &&
		strings.HasPrefix(imported, modulePath+"deploy/") {
		t.Errorf("%s: application code cannot import deployment package %q", source, imported)
	}

	const servicePrefix = modulePath + "app/service/"
	if strings.HasPrefix(imported, servicePrefix) {
		remainder := strings.TrimPrefix(imported, servicePrefix)
		parts := strings.Split(remainder, "/")
		if len(parts) >= 2 && parts[1] == "internal" {
			ownerPrefix := "app/service/" + parts[0] + "/"
			if !strings.HasPrefix(source, ownerPrefix) {
				t.Errorf(
					"%s: service internal package %q is owned by %s",
					source,
					imported,
					ownerPrefix,
				)
			}
		}
	}

	if strings.HasPrefix(source, "app/service/") &&
		strings.HasPrefix(imported, modulePath+"app/adapter/") &&
		!isServiceCompositionRoot(source) {
		t.Errorf(
			"%s: concrete adapter %q may only be imported by an owning service cmd package",
			source,
			imported,
		)
	}
}

func isServiceCompositionRoot(source string) bool {
	parts := strings.Split(source, "/")
	return len(parts) >= 5 &&
		parts[0] == "app" &&
		parts[1] == "service" &&
		parts[3] == "cmd"
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot resolve architecture test source path")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(currentFile), "..", ".."))
}
