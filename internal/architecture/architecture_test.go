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
	const sandboxRoot = "github.com/ejpir/gantry/internal/sandbox"
	noSandboxParent := func(path string) bool { return path == sandboxRoot }
	const dashboardRoot = "github.com/ejpir/gantry/internal/dashboard"
	noDashboardParent := func(path string) bool { return path == dashboardRoot }
	const sharefsRoot = "github.com/ejpir/gantry/internal/sharefs"
	noShareFSParent := func(path string) bool { return path == sharefsRoot }
	const vmmRoot = "github.com/ejpir/gantry/internal/vmm"
	noVMMParent := func(path string) bool { return path == vmmRoot }
	const managerRoot = "github.com/ejpir/gantry/internal/sandbox/manager"
	noManagerParent := func(path string) bool { return path == managerRoot }
	rules := map[string]func(string) bool{
		"internal/dashboard": func(path string) bool {
			const sandbox = "github.com/ejpir/gantry/internal/sandbox"
			return (path == sandbox || strings.HasPrefix(path, sandbox+"/")) &&
				path != sandbox+"/config" && path != sandbox+"/lifecycle"
		},
		"internal/sandbox/supervisor":             noSandboxParent,
		"internal/sandbox/guestplane":             noSandboxParent,
		"internal/sandbox/hostplane":              noSandboxParent,
		"internal/sandbox/controlplane":           noSandboxParent,
		"internal/sandbox/sshgw":                  noSandboxParent,
		"internal/sandbox/mcpgw":                  noSandboxParent,
		"internal/vmm/boot":                       noVMMParent,
		"internal/vmm/devices":                    noVMMParent,
		"internal/sandbox/manager/operationstate": noManagerParent,
		"internal/sandbox/manager/runtimeowner":   noManagerParent,
		"internal/dashboard/operationstate":       noDashboardParent,
		"internal/dashboard/refreshstate":         noDashboardParent,
		"internal/dashboard/pagestate":            noDashboardParent,
		"internal/dashboard/notificationstate":    noDashboardParent,
		"internal/dashboard/selectionstate":       noDashboardParent,
		"internal/sharefs/lifecycle":              noShareFSParent,
		"internal/sharefs/exportstate":            noShareFSParent,
		"internal/sharefs/coherencestate":         noShareFSParent,
		"internal/sharefs/preparedstate":          noShareFSParent,
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

// Export and coherence phases have dedicated state owners. Resource code may
// request transitions through their adapters but cannot replace those owners.
func TestShareFSStateOwnership(t *testing.T) {
	root := filepath.Join("..", "..", "internal", "sharefs")
	owned := map[string]string{
		"exportState":    "export.go",
		"coherenceState": "coherence.go",
		"preparedState":  "export.go",
		"directoryCache": "dir_cache_unix.go",
		"cacheMu":        "dir_cache_unix.go",
	}
	if err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		parsed, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			return err
		}
		base := filepath.Base(path)
		ast.Inspect(parsed, func(node ast.Node) bool {
			var field string
			switch value := node.(type) {
			case *ast.SelectorExpr:
				field = value.Sel.Name
			case *ast.KeyValueExpr:
				if ident, ok := value.Key.(*ast.Ident); ok {
					field = ident.Name
				}
			}
			owner, exists := owned[field]
			if exists && base != owner {
				t.Errorf("%s accesses sharefs-owned state %s outside %s", path, field, owner)
			}
			return true
		})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestDashboardOperationOwnership(t *testing.T) {
	root := filepath.Join("..", "..", "internal", "dashboard")
	owned := map[string]bool{
		"busyAction": true, "busyName": true, "busyProgress": true, "selectNext": true,
	}
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") || filepath.Base(path) == "operation_state.go" {
			return nil
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			return err
		}
		ast.Inspect(file, func(node ast.Node) bool {
			assignment, ok := node.(*ast.AssignStmt)
			if !ok {
				return true
			}
			for _, expression := range assignment.Lhs {
				ast.Inspect(expression, func(node ast.Node) bool {
					selector, ok := node.(*ast.SelectorExpr)
					if ok && owned[selector.Sel.Name] {
						t.Errorf("%s writes operation-owned field %s", path, selector.Sel.Name)
					}
					return true
				})
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// Dashboard modal transitions and refresh publication have dedicated owners.
// Rendering and input handlers may inspect these fields but cannot bypass the
// generation and transition checks.
func TestDashboardViewStateOwnership(t *testing.T) {
	root := filepath.Join("..", "..", "internal", "dashboard")
	owned := map[string]bool{
		"dialog": true, "refreshing": true, "refreshVisible": true,
		"page": true, "toast": true, "toastGen": true,
		"cursor": true, "scrollRow": true,
		"trafficCursor": true, "trafficScroll": true, "rulesCursor": true, "rulesScroll": true,
		"mountCursor": true, "mountScroll": true, "portCursor": true, "portScroll": true,
		"secretCursor": true, "secretScroll": true, "mcpCursor": true, "mcpScroll": true,
		"auditCursor": true, "auditScroll": true, "remoteCursor": true, "remoteScroll": true,
		"imageCursor": true, "imageScroll": true, "registryCursor": true, "registryScroll": true,
		"packetCursor": true, "packetScroll": true,
	}
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		base := filepath.Base(path)
		if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") ||
			strings.Contains(filepath.ToSlash(path), "/dashboard/refreshstate/") ||
			strings.Contains(filepath.ToSlash(path), "/dashboard/selectionstate/") ||
			base == "dialog_state.go" || base == "refresh_state.go" ||
			base == "page_state.go" || base == "notification_state.go" ||
			base == "selection_state.go" || base == "sandbox_picker.go" {
			return nil
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			return err
		}
		ast.Inspect(file, func(node ast.Node) bool {
			assignment, ok := node.(*ast.AssignStmt)
			if !ok {
				return true
			}
			for _, expression := range assignment.Lhs {
				ast.Inspect(expression, func(node ast.Node) bool {
					selector, ok := node.(*ast.SelectorExpr)
					if ok && owned[selector.Sel.Name] {
						t.Errorf("%s writes dashboard-owned field %s", path, selector.Sel.Name)
					}
					return true
				})
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// Manager operation records are mutated only by operationstate.Store after it
// validates the private completion owner and typed transition.
func TestManagerOperationOwnership(t *testing.T) {
	root := filepath.Join("..", "..", "internal", "sandbox", "manager")
	owned := map[string]bool{
		"State": true, "Error": true, "Warnings": true, "Configure": true,
		"Run": true, "Progress": true, "Updated": true,
	}
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") ||
			strings.Contains(filepath.ToSlash(path), "/manager/operationstate/") {
			return nil
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			return err
		}
		ast.Inspect(file, func(node ast.Node) bool {
			assignment, ok := node.(*ast.AssignStmt)
			if !ok {
				return true
			}
			for _, expression := range assignment.Lhs {
				ast.Inspect(expression, func(node ast.Node) bool {
					selector, ok := node.(*ast.SelectorExpr)
					if ok && owned[selector.Sel.Name] {
						t.Errorf("%s writes manager operation-owned field %s", path, selector.Sel.Name)
					}
					return true
				})
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
