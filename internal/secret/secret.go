// Package secret holds workload secrets: values injected INTO the guest
// for the agent to use. This is the opposite direction from registry
// credentials (internal/image/auth), which must never reach the guest —
// docs/secrets.md defines the boundary. The two share one redacted type
// so a reviewer never has to work out which a variable holds: both
// redact; only this package's values are ever injected.
//
// Rules enforced here (the rest are structural — see the doc):
//   - a value never comes from argv (NAME=literal is refused)
//   - formatting a Value always redacts (fmt honours Stringer on struct
//     fields, so %v of anything containing a Value is safe by construction)
package secret

import (
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
)

// Value is a secret value that redacts itself under every verb.
type Value string

func (v Value) String() string   { return "<redacted>" }
func (v Value) GoString() string { return "<redacted>" }

// Raw exposes the value. The ONLY legitimate callers are the two
// injection points: the CLI→daemon stdin handshake and the guest process
// spec's Env. Never log it.
func (v Value) Raw() string { return string(v) }

var nameRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// Parse one -secret spec:
//
//	NAME            value from gantry's own environment (getenv)
//	NAME=@/path     value read from a file (trailing newline trimmed)
//
// NAME=literal is REFUSED — argv is world-readable via ps and lands in
// shell history, the same reason `gantry image login` has no --password.
func Parse(spec string, getenv func(string) (string, bool)) (name string, v Value, err error) {
	if i := strings.Index(spec, "=@"); i > 0 {
		name = spec[:i]
		if !nameRE.MatchString(name) {
			return "", "", fmt.Errorf("bad secret name %q (want [A-Za-z_][A-Za-z0-9_]*)", name)
		}
		b, err := os.ReadFile(spec[i+2:])
		if err != nil {
			return "", "", fmt.Errorf("secret %s: %w", name, err)
		}
		return name, Value(strings.TrimRight(string(b), "\r\n")), nil
	}
	if strings.Contains(spec, "=") {
		return "", "", fmt.Errorf("refusing a secret value on the command line (visible in ps + shell history); use -secret %s (environment) or -secret %[1]s=@/path", strings.SplitN(spec, "=", 2)[0])
	}
	if !nameRE.MatchString(spec) {
		return "", "", fmt.Errorf("bad secret name %q (want [A-Za-z_][A-Za-z0-9_]*)", spec)
	}
	val, ok := getenv(spec)
	if !ok {
		return "", "", fmt.Errorf("secret %s: not set in gantry's environment (export it first, or use -secret %[1]s=@/path)", spec)
	}
	return spec, Value(val), nil
}

// ParseFile reads a dotenv-style file: NAME=VALUE per line, '#' comments
// and blank lines ignored, one optional pair of surrounding quotes
// stripped, CR tolerated. Every name must still be a valid env name.
func ParseFile(path string) (map[string]Value, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	out := map[string]Value{}
	for ln, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, val, ok := strings.Cut(line, "=")
		if !ok || !nameRE.MatchString(strings.TrimSpace(name)) {
			return nil, fmt.Errorf("%s:%d: want NAME=VALUE, got %q", path, ln+1, line)
		}
		val = strings.TrimSpace(val)
		if len(val) >= 2 {
			if q := val[0]; (q == '"' || q == '\'') && val[len(val)-1] == q {
				val = val[1 : len(val)-1]
			}
		}
		out[strings.TrimSpace(name)] = Value(val)
	}
	return out, nil
}

// ResolveAll merges -secret specs and -secret-file files into the final
// set. Later occurrences win. Returns the values (CLI memory only — never
// serialized) and the ordered unique names (safe to persist).
func ResolveAll(specs, files []string, getenv func(string) (string, bool)) (map[string]Value, []string, error) {
	values := map[string]Value{}
	var names []string
	add := func(name string, v Value) {
		if _, seen := values[name]; !seen {
			names = append(names, name)
		}
		values[name] = v
	}
	for _, f := range files {
		m, err := ParseFile(f)
		if err != nil {
			return nil, nil, fmt.Errorf("-secret-file: %w", err)
		}
		for _, name := range sortedKeys(m) {
			add(name, m[name])
		}
	}
	for _, spec := range specs {
		name, v, err := Parse(spec, getenv)
		if err != nil {
			return nil, nil, fmt.Errorf("-secret: %w", err)
		}
		add(name, v)
	}
	return values, names, nil
}

// Env renders the set as NAME=raw pairs, sorted for determinism. This is
// the injection point: the result goes into the guest process spec and
// nowhere else.
func Env(secrets map[string]Value) []string {
	out := make([]string, 0, len(secrets))
	for _, name := range sortedKeys(secrets) {
		out = append(out, name+"="+secrets[name].Raw())
	}
	return out
}

func sortedKeys(m map[string]Value) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
