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

// ValidateName validates a secret's environment-variable name without
// resolving or handling its value.
func ValidateName(name string) error {
	if !nameRE.MatchString(name) {
		return fmt.Errorf("bad secret name %q (want [A-Za-z_][A-Za-z0-9_]*)", name)
	}
	return nil
}

// bindingRE validates a host binding: a lowercase DNS hostname, optionally
// wildcard-led ("*.example.com"). Lowercase-only by design so bindings
// compare canonically; DNS names are case-insensitive anyway.
var bindingRE = regexp.MustCompile(`^(\*\.)?[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$`)

// ValidateBinding validates a secret's host binding without resolving or
// handling its value.
func ValidateBinding(host string) error {
	if host == "" || len(host) > 253 || !bindingRE.MatchString(host) {
		return fmt.Errorf("bad binding host %q (want a lowercase DNS name like github.com or *.githubusercontent.com)", host)
	}
	return nil
}

// SplitBinding divides a NAME@host pair. A bare NAME yields an empty
// binding (ambient secret). The binding is everything after the first '@'.
func SplitBinding(s string) (name, binding string, err error) {
	name, binding, found := strings.Cut(s, "@")
	if !found {
		return s, "", nil
	}
	if err := ValidateBinding(binding); err != nil {
		return "", "", fmt.Errorf("secret %q: %w", s, err)
	}
	return name, binding, nil
}

// Spec is one parsed -secret argument: a name, an optional host binding,
// and the resolved value. A bound secret (Binding != "") is delivered only
// through the credential broker for requests to that host; it is NOT
// injected into session environments.
type Spec struct {
	Name    string
	Binding string
	Value   Value
}

// DisplayName renders the spec the way it is persisted in SecretNames:
// "NAME" when ambient, "NAME@host" when bound. Safe to persist and show.
func (s Spec) DisplayName() string {
	if s.Binding == "" {
		return s.Name
	}
	return s.Name + "@" + s.Binding
}

// BindingsFromNames maps persisted display names (see Spec.DisplayName) to
// their host bindings. Ambient entries are omitted.
func BindingsFromNames(names []string) (map[string]string, error) {
	out := map[string]string{}
	for _, n := range names {
		name, binding, err := SplitBinding(n)
		if err != nil {
			return nil, err
		}
		if binding != "" {
			out[name] = binding
		}
	}
	return out, nil
}

// ParseSpec parses one -secret spec, including an optional host binding:
//
//	NAME                    value from gantry's own environment (getenv)
//	NAME=@/path             value read from a file (trailing newline trimmed)
//	NAME@host               bound to host: broker-only delivery, no env injection
//	NAME@host=@/path        file value, bound to host
//
// NAME=literal is REFUSED — argv is world-readable via ps and lands in
// shell history, the same reason `gantry image login` has no --password.
func ParseSpec(spec string, getenv func(string) (string, bool)) (Spec, error) {
	rest := spec
	fileRef := ""
	if i := strings.Index(rest, "=@"); i > 0 {
		fileRef = rest[i+2:]
		rest = rest[:i]
	} else if strings.Contains(rest, "=") {
		return Spec{}, fmt.Errorf("refusing a secret value on the command line (visible in ps + shell history); use -secret %s (environment) or -secret %[1]s=@/path", strings.SplitN(spec, "=", 2)[0])
	}
	name, binding, err := SplitBinding(rest)
	if err != nil {
		return Spec{}, err
	}
	if err := ValidateName(name); err != nil {
		return Spec{}, err
	}
	if fileRef != "" {
		b, err := os.ReadFile(fileRef)
		if err != nil {
			return Spec{}, fmt.Errorf("secret %s: %w", name, err)
		}
		return Spec{Name: name, Binding: binding, Value: Value(strings.TrimRight(string(b), "\r\n"))}, nil
	}
	val, ok := getenv(name)
	if !ok {
		return Spec{}, fmt.Errorf("secret %s: not set in gantry's environment (export it first, or use -secret %[1]s=@/path)", name)
	}
	return Spec{Name: name, Binding: binding, Value: Value(val)}, nil
}

// Parse one -secret spec without a host binding (see ParseSpec). Bound
// specs are rejected here: bindings change delivery semantics (broker-only,
// no ambient env), which only the sandbox-start paths honour.
func Parse(spec string, getenv func(string) (string, bool)) (name string, v Value, err error) {
	s, err := ParseSpec(spec, getenv)
	if err != nil {
		return "", "", err
	}
	if s.Binding != "" {
		return "", "", fmt.Errorf("secret %s: host bindings (@%s) are only supported via -secret at sandbox start", s.Name, s.Binding)
	}
	return s.Name, s.Value, nil
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
// serialized) and the ordered unique display names (safe to persist;
// bound secrets persist as "NAME@host").
func ResolveAll(specs, files []string, getenv func(string) (string, bool)) (map[string]Value, []string, error) {
	values := map[string]Value{}
	display := map[string]string{}
	var names []string
	add := func(s Spec) {
		if _, seen := values[s.Name]; !seen {
			names = append(names, s.DisplayName())
			values[s.Name] = s.Value
			display[s.Name] = s.DisplayName()
			return
		}
		values[s.Name] = s.Value
		if d := s.DisplayName(); d != display[s.Name] {
			// Re-occurrence with a different binding updates the persisted
			// display name in place; order is stable.
			for i, n := range names {
				if n == display[s.Name] {
					names[i] = d
					break
				}
			}
			display[s.Name] = d
		}
	}
	for _, f := range files {
		m, err := ParseFile(f)
		if err != nil {
			return nil, nil, fmt.Errorf("-secret-file: %w", err)
		}
		for _, name := range sortedKeys(m) {
			add(Spec{Name: name, Value: m[name]})
		}
	}
	for _, spec := range specs {
		s, err := ParseSpec(spec, getenv)
		if err != nil {
			return nil, nil, fmt.Errorf("-secret: %w", err)
		}
		add(s)
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
