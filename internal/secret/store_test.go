package secret

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestParseSourceGrammar(t *testing.T) {
	tests := []struct {
		spec        string
		wantName    string
		wantKind    SourceKind
		wantBinding string
		wantRefresh time.Duration
	}{
		{"TOKEN", "TOKEN", SourceEnv, "", 0},
		{"TOKEN@git.test", "TOKEN", SourceEnv, "git.test", 0},
		{"TOKEN=@/run/secrets/tok", "TOKEN", SourceFile, "", fileDefaultTTL},
		{"TOKEN@git.test=@/run/secrets/tok", "TOKEN", SourceFile, "git.test", fileDefaultTTL},
		{"TOKEN=!op read vault/item", "TOKEN", SourceExec, "", execDefaultTTL},
		{"TOKEN=@/run/secrets/tok,ttl=2s", "TOKEN", SourceFile, "", 2 * time.Second},
		{"TOKEN=@/run/secrets/tok,ttl=0s", "TOKEN", SourceFile, "", 0},
	}
	for _, tc := range tests {
		name, src, err := ParseSource(tc.spec)
		if err != nil {
			t.Fatalf("ParseSource(%q): %v", tc.spec, err)
		}
		if name != tc.wantName || src.Kind != tc.wantKind || src.Binding != tc.wantBinding || src.Refresh != tc.wantRefresh {
			t.Errorf("ParseSource(%q) = (%q, %+v), want (%q, kind=%s binding=%s refresh=%s)",
				tc.spec, name, src, tc.wantName, tc.wantKind, tc.wantBinding, tc.wantRefresh)
		}
	}
}

func TestParseSourceRefuses(t *testing.T) {
	for _, spec := range []string{
		"TOKEN=literal-value",  // argv-visible literal
		"TOKEN=@",              // empty file path
		"TOKEN=!",              // empty exec argv
		"TOKEN=@/x,ttl=banana", // unparseable ttl: hard error, never silent cache
		"TOKEN=@/x,ttl=-5s",    // negative ttl
		"bad name",             // invalid name
		"TOKEN@Bad_Host",       // invalid binding
	} {
		if _, _, err := ParseSource(spec); err == nil {
			t.Errorf("ParseSource(%q) unexpectedly succeeded", spec)
		}
	}
}

func TestStoreEnvOnDemand(t *testing.T) {
	env := map[string]string{"TOK": "v1"}
	st := NewStore(func(k string) (string, bool) { v, ok := env[k]; return v, ok }, nil)
	name, src, err := ParseSource("TOK")
	if err != nil {
		t.Fatal(err)
	}
	st.Put(name, src)
	v, err := st.Resolve("TOK")
	if err != nil || v.Raw() != "v1" {
		t.Fatalf("Resolve = %q, %v", v, err)
	}
	env["TOK"] = "v2" // env sources are on-demand: no TTL, always re-read
	v, err = st.Resolve("TOK")
	if err != nil || v.Raw() != "v2" {
		t.Fatalf("Resolve after env change = %q, %v; want v2", v, err)
	}
}

func TestStoreFileTTLAndRotation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tok")
	if err := os.WriteFile(path, []byte("v1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	st := NewStore(os.LookupEnv, nil)
	st.now = func() time.Time { return now }
	name, src, err := ParseSource("TOK=@" + path + ",ttl=60s")
	if err != nil {
		t.Fatal(err)
	}
	st.Put(name, src)

	v, _ := st.Resolve("TOK")
	if v.Raw() != "v1" {
		t.Fatalf("first Resolve = %q, want v1", v)
	}
	// Rotate the file inside the TTL window: cached value is served.
	if err := os.WriteFile(path, []byte("v2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	now = now.Add(30 * time.Second)
	v, _ = st.Resolve("TOK")
	if v.Raw() != "v1" {
		t.Fatalf("within TTL Resolve = %q, want cached v1", v)
	}
	// Past the TTL the rotation is picked up without a restart.
	now = now.Add(31 * time.Second)
	v, err = st.Resolve("TOK")
	if err != nil || v.Raw() != "v2" {
		t.Fatalf("post-TTL Resolve = %q, %v; want rotated v2", v, err)
	}
}

func TestStoreFailClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tok")
	if err := os.WriteFile(path, []byte("v1"), 0o600); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	var logs []string
	st := NewStore(os.LookupEnv, func(f string, a ...any) { logs = append(logs, fmt.Sprintf(f, a...)) })
	st.now = func() time.Time { return now }
	name, src, _ := ParseSource("TOK=@" + path + ",ttl=1s")
	st.Put(name, src)
	if _, err := st.Resolve("TOK"); err != nil {
		t.Fatal(err)
	}
	// Source breaks after a good resolve: fail closed — error, cache
	// dropped, error logged by name (never the value).
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Second)
	if _, err := st.Resolve("TOK"); err == nil {
		t.Fatal("Resolve with a broken source succeeded")
	}
	if len(logs) != 1 || !strings.Contains(logs[0], "TOK") {
		t.Fatalf("expected one named resolution-error log, got %v", logs)
	}
	if strings.Contains(logs[0], "v1") {
		t.Fatalf("log line leaked a value: %q", logs[0])
	}
	// The cache was dropped: a later resolve does not serve the stale value.
	if v, err := st.Resolve("TOK"); err == nil || v.Raw() == "v1" {
		t.Fatalf("stale value served after source failure: %q, %v", v, err)
	}
}

func TestStoreExecSource(t *testing.T) {
	const helperEnv = "GANTRY_SECRET_EXEC_TEST_HELPER"
	if os.Getenv(helperEnv) == "1" {
		fmt.Print("hello-exec")
		os.Exit(0)
	}

	st := NewStore(os.LookupEnv, nil)
	name, src, err := ParseSource("TOK=!placeholder")
	if err != nil {
		t.Fatal(err)
	}
	// Use the test executable as the source command so this exercises the
	// argv-based exec path without assuming Unix printf or a Windows shell.
	src.Argv = []string{os.Args[0], "-test.run=^TestStoreExecSource$"}
	t.Setenv(helperEnv, "1")
	st.Put(name, src)
	v, err := st.Resolve("TOK")
	if err != nil || v.Raw() != "hello-exec" {
		t.Fatalf("exec Resolve = %q, %v", v, err)
	}
}

func TestStoreLiteralAndRemove(t *testing.T) {
	st := NewStore(os.LookupEnv, nil)
	st.PutValue("TOK", "literal")
	if v, err := st.Resolve("TOK"); err != nil || v.Raw() != "literal" {
		t.Fatalf("literal Resolve = %q, %v", v, err)
	}
	if got := st.LiteralNames(); len(got) != 1 || got[0] != "TOK" {
		t.Fatalf("LiteralNames = %v", got)
	}
	st.Remove("TOK")
	if _, err := st.Resolve("TOK"); err == nil {
		t.Fatal("Resolve after Remove succeeded")
	}
	if st.Has("TOK") {
		t.Fatal("Has after Remove = true")
	}
}

func TestStoreRemoveDuringResolutionCannotResurrectValue(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	st := NewStore(func(string) (string, bool) {
		close(started)
		<-release
		return "revoked-value", true
	}, nil)
	st.Put("TOK", Source{Kind: SourceEnv, Ref: "TOK"})
	type outcome struct {
		value Value
		err   error
	}
	result := make(chan outcome, 1)
	go func() {
		value, err := st.Resolve("TOK")
		result <- outcome{value: value, err: err}
	}()
	<-started
	st.Remove("TOK")
	close(release)
	got := <-result
	if got.err == nil || got.value.Raw() != "" {
		t.Fatalf("revoked resolve = %q, %v", got.value.Raw(), got.err)
	}
	if st.Has("TOK") {
		t.Fatal("source was resurrected after Remove")
	}
}

func TestStoreConcurrentResolvesShareOneFetch(t *testing.T) {
	var fetches atomic.Int32
	started := make(chan struct{})
	release := make(chan struct{})
	st := NewStore(func(string) (string, bool) {
		if fetches.Add(1) == 1 {
			close(started)
		}
		<-release
		return "value", true
	}, nil)
	st.Put("TOK", Source{Kind: SourceEnv, Ref: "TOK"})
	results := make(chan error, 2)
	go func() { _, err := st.Resolve("TOK"); results <- err }()
	<-started
	go func() { _, err := st.Resolve("TOK"); results <- err }()
	// Wait until the second resolver has joined the registered call before
	// allowing the source fetch to complete.
	deadline := time.Now().Add(time.Second)
	for {
		st.mu.Lock()
		call := st.inflight["TOK"]
		joined := call != nil && call.waiters == 1
		st.mu.Unlock()
		if joined {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("second resolver did not join the in-flight call")
		}
		time.Sleep(time.Millisecond)
	}
	close(release)
	for i := 0; i < 2; i++ {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	if got := fetches.Load(); got != 1 {
		t.Fatalf("source fetches = %d, want one", got)
	}
}

func TestStoreRejectsOversizedSourceValues(t *testing.T) {
	path := filepath.Join(t.TempDir(), "huge")
	if err := os.WriteFile(path, []byte(strings.Repeat("x", maxResolvedValueBytes+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	st := NewStore(os.LookupEnv, nil)
	st.Put("TOK", Source{Kind: SourceFile, Ref: path})
	if _, err := st.Resolve("TOK"); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized file resolution error = %v", err)
	}
	var out limitedValueBuffer
	_, _ = out.Write([]byte(strings.Repeat("x", maxResolvedValueBytes+1)))
	if !out.overflow || out.Len() > maxResolvedValueBytes+1 {
		t.Fatalf("limited exec buffer overflow=%v len=%d", out.overflow, out.Len())
	}
}

func TestStoreValueStillRedacts(t *testing.T) {
	st := NewStore(func(string) (string, bool) { return "supersecret", true }, nil)
	name, src, _ := ParseSource("TOK")
	st.Put(name, src)
	v, err := st.Resolve("TOK")
	if err != nil {
		t.Fatal(err)
	}
	if s := v.String(); strings.Contains(s, "supersecret") {
		t.Fatalf("Value.String() leaked: %q", s)
	}
}
