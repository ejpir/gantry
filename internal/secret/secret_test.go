package secret

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func getenvFrom(m map[string]string) func(string) (string, bool) {
	return func(k string) (string, bool) { v, ok := m[k]; return v, ok }
}

func TestValueRedaction(t *testing.T) {
	v := Value("sk-canary-123")
	for _, format := range []string{"%v", "%s", "%q", "%#v"} {
		if got := fmt.Sprintf(format, v); strings.Contains(got, "canary") {
			t.Errorf("Sprintf(%q, Value) = %s — leaked", format, got)
		}
	}
	// fmt honours Stringer on struct fields: the whole point of the type
	s := struct {
		Name  string
		Token Value
	}{"x", v}
	if got := fmt.Sprintf("%v", s); strings.Contains(got, "canary") {
		t.Errorf("struct %%v leaked: %s", got)
	}
	if v.Raw() != "sk-canary-123" {
		t.Errorf("Raw() = %q", v.Raw())
	}
}

func TestParseForms(t *testing.T) {
	env := map[string]string{"GITHUB_TOKEN": "ghp_x"}
	name, v, err := Parse("GITHUB_TOKEN", getenvFrom(env))
	if err != nil || name != "GITHUB_TOKEN" || v.Raw() != "ghp_x" {
		t.Errorf("env form: %q %q %v", name, v.Raw(), err)
	}

	if _, _, err := Parse("MISSING", getenvFrom(env)); err == nil ||
		!strings.Contains(err.Error(), "not set") {
		t.Errorf("unset env: %v", err)
	}

	// literal values are refused — argv is world-readable
	_, _, err = Parse("TOKEN=sk-literal", getenvFrom(env))
	if err == nil || !strings.Contains(err.Error(), "refusing") {
		t.Errorf("literal form must be refused, got %v", err)
	}

	f := filepath.Join(canonicalTempDir(t), "tok")
	_ = os.WriteFile(f, []byte("file-value\n"), 0o600)
	name, v, err = Parse("MY_TOKEN=@"+f, getenvFrom(env))
	if err != nil || name != "MY_TOKEN" || v.Raw() != "file-value" {
		t.Errorf("file form: %q %q %v", name, v.Raw(), err) // trailing \n trimmed
	}

	for _, bad := range []string{"1BAD", "HAS-DASH", "", "SP ACE"} {
		if _, _, err := Parse(bad, getenvFrom(env)); err == nil {
			t.Errorf("bad name %q accepted", bad)
		}
	}
}

func TestParseFile(t *testing.T) {
	f := filepath.Join(canonicalTempDir(t), "env")
	_ = os.WriteFile(f, []byte(`# comment
GITHUB_TOKEN=ghp_x
QUOTED="va lue"
SINGLE='oth er'

EMPTY=
`), 0o600)
	m, err := ParseFile(f)
	if err != nil {
		t.Fatal(err)
	}
	if m["GITHUB_TOKEN"].Raw() != "ghp_x" || m["QUOTED"].Raw() != "va lue" ||
		m["SINGLE"].Raw() != "oth er" || m["EMPTY"].Raw() != "" {
		t.Errorf("parsed: %+v", m)
	}

	_ = os.WriteFile(f, []byte("not-an-assignment\n"), 0o600)
	if _, err := ParseFile(f); err == nil {
		t.Error("malformed line must error")
	}
}

func TestResolveAllOrderAndNames(t *testing.T) {
	f := filepath.Join(canonicalTempDir(t), "env")
	_ = os.WriteFile(f, []byte("A=from-file\nB=from-file\n"), 0o600)
	values, names, err := ResolveAll(
		[]string{"B", "C"}, []string{f},
		getenvFrom(map[string]string{"B": "from-env", "C": "see"}))
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 3 {
		t.Fatalf("names = %v", names)
	}
	// -secret specs come after -secret-file, so B's env value wins
	if values["B"].Raw() != "from-env" {
		t.Errorf("B = %q, want from-env (specs override files)", values["B"].Raw())
	}
	env := Env(values)
	if strings.Join(env, "|") != "A=from-file|B=from-env|C=see" {
		t.Errorf("Env = %v", env)
	}
}

func TestParseSpecBindings(t *testing.T) {
	env := func(k string) (string, bool) {
		if k == "GH" {
			return "tok", true
		}
		return "", false
	}
	s, err := ParseSpec("GH@github.com", env)
	if err != nil {
		t.Fatalf("ParseSpec bound env: %v", err)
	}
	if s.Name != "GH" || s.Binding != "github.com" || s.Value.Raw() != "tok" {
		t.Fatalf("spec = %+v", s)
	}
	if s.DisplayName() != "GH@github.com" {
		t.Fatalf("DisplayName = %q", s.DisplayName())
	}

	// Bound + file form.
	f := filepath.Join(canonicalTempDir(t), "tok")
	if err := os.WriteFile(f, []byte("filetok\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err = ParseSpec("GH@*.githubusercontent.com=@"+f, env)
	if err != nil {
		t.Fatalf("ParseSpec bound file: %v", err)
	}
	if s.Binding != "*.githubusercontent.com" || s.Value.Raw() != "filetok" {
		t.Fatalf("spec = %+v", s)
	}

	// Ambient still works.
	s, err = ParseSpec("GH", env)
	if err != nil || s.Binding != "" || s.DisplayName() != "GH" {
		t.Fatalf("ambient spec = %+v, err = %v", s, err)
	}

	for _, bad := range []string{"GH@", "GH@UPPER.com", "GH@bad_host", "GH@-lead.com", "GH@a..b"} {
		if _, err := ParseSpec(bad, env); err == nil {
			t.Fatalf("ParseSpec(%q) succeeded, want binding rejection", bad)
		}
	}
	// Parse (import path) refuses bindings.
	if _, _, err := Parse("GH@github.com", env); err == nil {
		t.Fatal("Parse accepted a bound spec")
	}
}

func TestResolveAllBindingPersistence(t *testing.T) {
	env := func(string) (string, bool) { return "v", true }
	values, names, err := ResolveAll([]string{"A@api.anthropic.com", "B"}, nil, env)
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 2 || names[0] != "A@api.anthropic.com" || names[1] != "B" {
		t.Fatalf("names = %v", names)
	}
	if _, ok := values["A"]; !ok {
		t.Fatalf("values = %v", values)
	}
	// Re-occurrence with a different binding updates the display name.
	_, names, err = ResolveAll([]string{"A", "A@github.com"}, nil, env)
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 1 || names[0] != "A@github.com" {
		t.Fatalf("names after rebind = %v", names)
	}
	// Round-trip through BindingsFromNames.
	bindings, err := BindingsFromNames(names)
	if err != nil {
		t.Fatal(err)
	}
	if bindings["A"] != "github.com" {
		t.Fatalf("bindings = %v", bindings)
	}
	if _, err := BindingsFromNames([]string{"X@bad_host"}); err == nil {
		t.Fatal("BindingsFromNames accepted a malformed entry")
	}
}
