package secret

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"
)

// Source-backed secrets (internal/secret v2): instead of resolving a value
// eagerly at spawn, the daemon keeps a Store of Sources and resolves at
// USE time with TTL caching, so rotation of a file- or command-backed
// secret is picked up without a sandbox restart. The shape mirrors
// Docker's sandboxd pkg/secrets.Store (fetchFromSource +
// sourceCacheExpired), adapted to gantry's no-MITM model:
//
//   - Refresh == 0 means always re-resolve ("on-demand"); a positive
//     duration is a TTL against the cached resolution time. An
//     unparseable ttl in a spec is a hard error at parse time, never a
//     silent cache.
//   - env and file keep v1's resolution rules; NAME=literal is refused in
//     ParseSource exactly as in ParseSpec.
//   - exec is opt-in: run an argv (never a shell string) on the host,
//     capture stdout as the value. Covers `op read`, `pass`, `gh auth
//     token`-style sources without per-vendor code.
//   - Failed re-resolution of a previously good value fails CLOSED: the
//     cached value is dropped, the error is returned (and logged by
//     name), and nothing stale is served. Serving stale secrets silently
//     is how rotated-out credentials keep working.
//
// Spec grammar (ParseSource):
//
//	NAME                        env source: value from the daemon's environment
//	NAME=@/abs/path             file source (trailing newline trimmed)
//	NAME=!argv0 argv1 ...       exec source (fields-split argv, no shell)
//	NAME@host=<any of the above>  host binding: broker-only delivery
//	<any>,ttl=60s               refresh override (ttl=0 = on-demand)
//
// Defaults: env resolves on demand (cheap; the daemon's environment is
// static), file caches for fileDefaultTTL, exec caches for execDefaultTTL.

// SourceKind identifies how a secret value is obtained at resolve time.
type SourceKind string

const (
	SourceEnv  SourceKind = "env"
	SourceFile SourceKind = "file"
	SourceExec SourceKind = "exec"
)

const (
	fileDefaultTTL = time.Minute
	execDefaultTTL = 5 * time.Minute
	// execTimeout bounds a source command; a hung credential helper must
	// not wedge the broker's resolution path.
	execTimeout = 10 * time.Second
)

// Source describes where a secret's value comes from. It contains no
// value material itself — Ref is an env name, a file path, or (with Argv)
// a command — so Sources are safe to log, persist, and display.
type Source struct {
	Kind    SourceKind
	Ref     string        // env var name or file path
	Argv    []string      // exec only
	Binding string        // optional host binding ("github.com", "*.example.com")
	Refresh time.Duration // 0 = on-demand
}

// DisplaySpec renders the persisted form of a source spec (name prepended
// by the caller). It never contains value material.
func (s Source) DisplaySpec() string {
	var b strings.Builder
	switch s.Kind {
	case SourceFile:
		b.WriteString("=@")
		b.WriteString(s.Ref)
	case SourceExec:
		b.WriteString("=!")
		b.WriteString(strings.Join(s.Argv, " "))
	}
	if s.Refresh != 0 {
		fmt.Fprintf(&b, ",ttl=%s", s.Refresh)
	}
	return b.String()
}

// ParseSource parses one -secret spec into a name and Source WITHOUT
// resolving any value. Values are resolved later, daemon-side, at use
// time. The grammar is ParseSpec's plus exec sources and the ttl suffix;
// NAME=literal remains refused.
func ParseSource(spec string) (string, Source, error) {
	rest := spec
	var refresh time.Duration
	var refreshSet bool
	if i := strings.LastIndex(rest, ",ttl="); i >= 0 {
		d, err := time.ParseDuration(rest[i+5:])
		if err != nil {
			return "", Source{}, fmt.Errorf("secret %q: invalid ttl %q: %w", spec, rest[i+5:], err)
		}
		if d < 0 {
			return "", Source{}, fmt.Errorf("secret %q: ttl must be >= 0 (0 = on-demand)", spec)
		}
		refresh, refreshSet = d, true
		rest = rest[:i]
	}

	var src Source
	if i := strings.Index(rest, "=@"); i > 0 {
		src = Source{Kind: SourceFile, Ref: rest[i+2:], Refresh: fileDefaultTTL}
		if src.Ref == "" {
			return "", Source{}, fmt.Errorf("secret %q: empty file path after =@", spec)
		}
		rest = rest[:i]
	} else if i := strings.Index(rest, "=!"); i > 0 {
		argv := strings.Fields(rest[i+2:])
		if len(argv) == 0 {
			return "", Source{}, fmt.Errorf("secret %q: empty command after =!", spec)
		}
		src = Source{Kind: SourceExec, Argv: argv, Refresh: execDefaultTTL}
		rest = rest[:i]
	} else if strings.Contains(rest, "=") {
		return "", Source{}, fmt.Errorf("refusing a secret value on the command line (visible in ps + shell history); use -secret %s (environment), -secret %[1]s=@/path, or -secret %[1]s='!cmd args'", strings.SplitN(spec, "=", 2)[0])
	} else {
		src = Source{Kind: SourceEnv}
	}

	name, binding, err := SplitBinding(rest)
	if err != nil {
		return "", Source{}, err
	}
	if err := ValidateName(name); err != nil {
		return "", Source{}, err
	}
	src.Binding = binding
	if src.Kind == SourceEnv {
		src.Ref = name
	}
	if refreshSet {
		src.Refresh = refresh
	}
	return name, src, nil
}

// NamedSource pairs a secret name with its Source: the unit the CLI
// hands to the daemon in the secrets handshake and the RunConfig persists
// for restart/resume. It carries no value material.
type NamedSource struct {
	Name   string `json:"name"`
	Source Source `json:"source"`
}

// ParseNamedSource parses one -secret spec into a NamedSource.
func ParseNamedSource(spec string) (NamedSource, error) {
	name, src, err := ParseSource(spec)
	if err != nil {
		return NamedSource{}, err
	}
	return NamedSource{Name: name, Source: src}, nil
}

// Spec renders the full re-parseable spec form: NAME[@host][=@path|
// =!argv][,ttl=...]. Safe to persist and display — it contains no value.
func (ns NamedSource) Spec() string {
	name := ns.Name
	if ns.Source.Binding != "" {
		name += "@" + ns.Source.Binding
	}
	return name + ns.Source.DisplaySpec()
}

// Store resolves source-backed secrets at use time with TTL caching. It
// also holds literal values (from -secret-file dotenv files, which carry
// values rather than sources) so callers have one resolution point.
// Values never leave the Store except through Resolve, which returns the
// redacting Value type.
type Store struct {
	env  func(string) (string, bool)
	now  func() time.Time
	logf func(string, ...any)

	mu    sync.Mutex
	srcs  map[string]Source
	vals  map[string]Value
	cache map[string]cachedValue
}

type cachedValue struct {
	v  Value
	at time.Time
}

// NewStore builds a Store resolving env sources through getenv. logf
// receives one line per failed re-resolution (named, never valued); it
// may be nil.
func NewStore(getenv func(string) (string, bool), logf func(string, ...any)) *Store {
	return &Store{
		env:   getenv,
		now:   time.Now,
		logf:  logf,
		srcs:  map[string]Source{},
		vals:  map[string]Value{},
		cache: map[string]cachedValue{},
	}
}

// Put registers or replaces a source-backed secret.
func (s *Store) Put(name string, src Source) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.srcs[name] = src
	delete(s.vals, name)
	delete(s.cache, name)
}

// PutValue registers a literal value (dotenv-file entries, control-socket
// sets). Literal values are served from memory and never re-resolved.
func (s *Store) PutValue(name string, v Value) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.srcs, name)
	delete(s.cache, name)
	s.vals[name] = v
}

// Remove drops a secret entirely.
func (s *Store) Remove(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.srcs, name)
	delete(s.vals, name)
	delete(s.cache, name)
}

// Has reports whether the store holds the name.
func (s *Store) Has(name string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, v := s.vals[name]
	_, src := s.srcs[name]
	return v || src
}

// Sources returns a copy of the source map (name → Source), for binding
// checks and display. Literal entries are omitted.
func (s *Store) Sources() map[string]Source {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]Source, len(s.srcs))
	for k, v := range s.srcs {
		out[k] = v
	}
	return out
}

// LiteralNames returns the names held as literal values.
func (s *Store) LiteralNames() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.vals))
	for k := range s.vals {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Resolve returns the current value for name. Source-backed entries are
// re-resolved when uncached, on-demand (Refresh == 0), or once Refresh
// has elapsed. A failed re-resolution of a previously good value fails
// closed: the cache is dropped and the error returned.
func (s *Store) Resolve(name string) (Value, error) {
	s.mu.Lock()
	if v, ok := s.vals[name]; ok {
		s.mu.Unlock()
		return v, nil
	}
	src, ok := s.srcs[name]
	if !ok {
		s.mu.Unlock()
		return "", fmt.Errorf("secret %s: not configured", name)
	}
	if c, ok := s.cache[name]; ok && (src.Refresh > 0 && s.now().Sub(c.at) < src.Refresh) {
		s.mu.Unlock()
		return c.v, nil
	}
	s.mu.Unlock()

	// Fetch outside the lock so a slow exec source doesn't stall other
	// resolutions; the store is map-guarded, not fetch-serialized.
	v, err := s.fetch(src)

	s.mu.Lock()
	defer s.mu.Unlock()
	if err != nil {
		delete(s.cache, name) // fail closed: never serve stale
		if s.logf != nil {
			s.logf("secret %s: source resolution failed: %v", name, err)
		}
		return "", fmt.Errorf("secret %s: %w", name, err)
	}
	s.cache[name] = cachedValue{v: v, at: s.now()}
	return v, nil
}

func (s *Store) fetch(src Source) (Value, error) {
	switch src.Kind {
	case SourceEnv:
		v, ok := s.env(src.Ref)
		if !ok {
			return "", fmt.Errorf("%s not set in the daemon's environment", src.Ref)
		}
		return Value(v), nil
	case SourceFile:
		b, err := os.ReadFile(src.Ref)
		if err != nil {
			return "", err
		}
		return Value(strings.TrimRight(string(b), "\r\n")), nil
	case SourceExec:
		ctx, cancel := context.WithTimeout(context.Background(), execTimeout)
		defer cancel()
		out, err := exec.CommandContext(ctx, src.Argv[0], src.Argv[1:]...).Output()
		if ctx.Err() == context.DeadlineExceeded {
			return "", fmt.Errorf("%s: timed out after %s", src.Argv[0], execTimeout)
		}
		if err != nil {
			return "", fmt.Errorf("%s: %w", src.Argv[0], err)
		}
		return Value(strings.TrimRight(string(out), "\r\n")), nil
	}
	return "", fmt.Errorf("unknown source kind %q", src.Kind)
}
