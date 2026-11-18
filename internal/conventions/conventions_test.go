package conventions_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// TestSharedHelpersLiveInHelpersTest enforces the CODING_STANDARDS.md rule
// "Shared helpers sit in helpers_test.go": an unexported function declared in a
// _test.go file that another _test.go file of the same package calls must live
// in that package's helpers_test.go.
//
// It parses every _test.go file in the module with go/parser, groups files by
// directory and package clause (so x and x_test count as separate packages),
// and matches calls by identifier, which is enough within one package.
func TestSharedHelpersLiveInHelpersTest(t *testing.T) {
	root := moduleRoot(t)

	// pkgKey identifies one package: its directory and package clause.
	type pkgKey struct {
		dir  string
		name string
	}
	type fileAST struct {
		path string // path relative to the module root
		base string // file name only
		file *ast.File
	}
	fset := token.NewFileSet()
	pkgs := map[pkgKey][]fileAST{}

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == "testdata" || d.Name() == "vendor" || strings.HasPrefix(d.Name(), ".") && d.Name() != "." {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			return perr
		}
		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			return rerr
		}
		key := pkgKey{dir: filepath.Dir(path), name: f.Name.Name}
		pkgs[key] = append(pkgs[key], fileAST{path: rel, base: filepath.Base(path), file: f})
		return nil
	})
	if err != nil {
		t.Fatalf("walk module: %v", err)
	}

	// A violation is one shared helper: its name, the file it sits in, and the
	// files that call it from outside that file.
	type violation struct {
		helper  string
		decl    string
		callers []string
	}
	var violations []violation

	for _, files := range pkgs {
		// Unexported funcs declared outside helpers_test.go, with their file.
		declFile := map[string]string{}
		for _, fa := range files {
			if fa.base == "helpers_test.go" {
				continue
			}
			for _, d := range fa.file.Decls {
				fn, ok := d.(*ast.FuncDecl)
				if !ok || fn.Recv != nil {
					continue // skip methods: a call by identifier cannot reach them
				}
				name := fn.Name.Name
				if name == "" || ast.IsExported(name) {
					continue
				}
				if strings.HasPrefix(name, "Test") || strings.HasPrefix(name, "Benchmark") ||
					strings.HasPrefix(name, "Fuzz") || strings.HasPrefix(name, "Example") {
					continue
				}
				declFile[name] = fa.base
			}
		}
		if len(declFile) == 0 {
			continue
		}

		// Files, other than the declaring one, that call each helper by identifier.
		callers := map[string]map[string]bool{}
		for _, fa := range files {
			ast.Inspect(fa.file, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				id, ok := call.Fun.(*ast.Ident)
				if !ok {
					return true
				}
				name := id.Name
				decl, isHelper := declFile[name]
				if !isHelper || decl == fa.base {
					return true
				}
				if callers[name] == nil {
					callers[name] = map[string]bool{}
				}
				callers[name][fa.path] = true
				return true
			})
		}

		for name, callerSet := range callers {
			paths := make([]string, 0, len(callerSet))
			for p := range callerSet {
				paths = append(paths, p)
			}
			sort.Strings(paths)
			// Find the declaring file's relative path.
			decl := declFile[name]
			var declPath string
			for _, fa := range files {
				if fa.base == decl {
					declPath = fa.path
					break
				}
			}
			violations = append(violations, violation{helper: name, decl: declPath, callers: paths})
		}
	}

	if len(violations) == 0 {
		return
	}

	sort.Slice(violations, func(i, j int) bool {
		if violations[i].decl != violations[j].decl {
			return violations[i].decl < violations[j].decl
		}
		return violations[i].helper < violations[j].helper
	})

	var b strings.Builder
	b.WriteString("shared test helpers must live in their package's helpers_test.go ")
	b.WriteString("(see CODING_STANDARDS.md > Tests > Shared helpers):\n")
	for _, v := range violations {
		b.WriteString("\t")
		b.WriteString(v.helper)
		b.WriteString(" in ")
		b.WriteString(v.decl)
		b.WriteString(" is called from ")
		b.WriteString(strings.Join(v.callers, ", "))
		b.WriteString("\n")
	}
	t.Fatal(b.String())
}

// moduleRoot returns the directory holding go.mod, walking up from the cwd.
func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := filepath.Abs(".")
	if err != nil {
		t.Fatalf("abs cwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found walking up from test directory")
		}
		dir = parent
	}
}
