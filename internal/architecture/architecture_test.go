package architecture

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// These are dependency directions, not a fixed package/file inventory. New
// production files are checked automatically, including other platform tags.
func TestApplicationBoundaries(t *testing.T) {
	root := filepath.Join("..", "..")
	rules := map[string]func(string) bool{
		"internal/dashboard": func(path string) bool {
			const sandbox = "github.com/ejpir/gantry/internal/sandbox"
			return (path == sandbox || strings.HasPrefix(path, sandbox+"/")) &&
				path != sandbox+"/config" && path != sandbox+"/lifecycle"
		},
		"internal/sandbox/lifecycle": func(path string) bool {
			return path == "flag" || path == "os/exec" || strings.Contains(path, "/internal/dashboard") || strings.Contains(path, "/sandbox/manager")
		},
		"internal/sandbox/inspection": func(path string) bool {
			return strings.Contains(path, "/internal/dashboard") || strings.Contains(path, "/sandbox/manager") ||
				path == "github.com/ejpir/gantry/internal/sandbox"
		},
		"internal/sandbox/worker": func(path string) bool {
			return strings.Contains(path, "/internal/dashboard") || strings.Contains(path, "/sandbox/manager") ||
				strings.HasPrefix(path, "github.com/ejpir/gantry/internal/vmm")
		},
	}
	for dir, forbidden := range rules {
		t.Run(dir, func(t *testing.T) {
			err := filepath.WalkDir(filepath.Join(root, dir), func(path string, entry fs.DirEntry, err error) error {
				if err != nil {
					return err
				}
				if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
					return nil
				}
				file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
				if err != nil {
					return err
				}
				for _, spec := range file.Imports {
					imported, err := strconv.Unquote(spec.Path.Value)
					if err != nil {
						return err
					}
					if forbidden(imported) {
						t.Errorf("%s imports %s across the application boundary", path, imported)
					}
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
		})
	}
	// The manager's CLI command may parse flags, but HTTP lifecycle code must
	// never reconstruct a CLI RunFlags input.
	files, err := filepath.Glob(filepath.Join(root, "internal/sandbox/manager/*.go"))
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(file, func(node ast.Node) bool {
			selector, ok := node.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if selector.Sel.Name == "RunFlags" || selector.Sel.Name == "RegisterRunFlags" {
				t.Errorf("%s depends on CLI launch flags", path)
			}
			return true
		})
	}
}
