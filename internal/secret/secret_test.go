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

	f := filepath.Join(t.TempDir(), "tok")
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
	f := filepath.Join(t.TempDir(), "env")
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
	f := filepath.Join(t.TempDir(), "env")
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
