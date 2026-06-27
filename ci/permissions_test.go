package ci

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// permissionSetterArgIndex maps os package calls to the argument index holding file mode.
var permissionSetterArgIndex = map[string]int{
	"Chmod":     1,
	"WriteFile": 2,
	"OpenFile":  2,
	"Mkdir":     1,
	"MkdirAll":  1,
}

func TestNoDecimalFilePermissionsInCodebase(t *testing.T) {
	root := repoRoot(t)
	fset := token.NewFileSet()

	var violations []string

	err := filepath.Walk(root, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if info.IsDir() {
			switch filepath.Base(path) {
			case ".git", "vendor", "node_modules":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}

		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return fmt.Errorf("parse %s: %w", path, err)
		}

		rel, err := filepath.Rel(root, path)
		if err != nil {
			rel = path
		}

		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}

			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok || pkg.Name != "os" {
				return true
			}

			argIdx, ok := permissionSetterArgIndex[sel.Sel.Name]
			if !ok || len(call.Args) <= argIdx {
				return true
			}

			if msg := decimalPermissionViolation(call.Args[argIdx]); msg != "" {
				violations = append(violations, fmt.Sprintf("%s: os.%s uses %s", rel, sel.Sel.Name, msg))
			}
			return true
		})

		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	if len(violations) > 0 {
		t.Fatalf("found %d permission bug(s):\n  %s", len(violations), strings.Join(violations, "\n  "))
	}
}

func decimalPermissionViolation(expr ast.Expr) string {
	lit, ok := expr.(*ast.BasicLit)
	if !ok || lit.Kind != token.INT {
		return ""
	}

	val := lit.Value
	if isOctalLiteral(val) {
		return ""
	}

	n, err := strconv.ParseInt(val, 10, 64)
	if err != nil {
		return ""
	}

	// Decimal literals in the 400-777 range are almost always mistaken shell-style
	// permission modes (e.g. 644 instead of 0644). The L1002 bug used 644 decimal.
	if n >= 400 && n <= 777 {
		return fmt.Sprintf("decimal literal %s (use octal, e.g. 0%s)", val, val)
	}

	return ""
}

func isOctalLiteral(val string) bool {
	return strings.HasPrefix(val, "0o") ||
		strings.HasPrefix(val, "0O") ||
		(strings.HasPrefix(val, "0") && len(val) > 1)
}
