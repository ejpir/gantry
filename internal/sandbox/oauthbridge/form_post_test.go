package oauthbridge

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

func formPost(uri, body string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, uri, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return r
}

func TestFormPostPreservesBodyAndDoesNotMergeQuery(t *testing.T) {
	for _, body := range []string{
		"code=a%2Bb%2Fc%3D&state=opaque+state&session_state=msal-session",
		"state=opaque&error=access_denied&error_description=MFA+cancelled",
		"code=x&state=s&extra=" + strings.Repeat("x", maxRequestBodyBytes-len("code=x&state=s&extra=")),
	} {
		var got replayRequest
		b := testBridge(t, func(_ int, request replayRequest) (replayResult, error) {
			got = request
			return replayResult{status: http.StatusOK}, nil
		})
		r := formPost("/callback?client_hint=keep%2Fme", body)
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
		rec := httptest.NewRecorder()
		b.handleCallback(&listener{port: 1455})(rec, r)
		if rec.Code != http.StatusOK || got.method != http.MethodPost || got.body != body || got.uri != r.URL.RequestURI() {
			t.Fatalf("callback was rejected or changed: status=%d", rec.Code)
		}
		if len(b.replaySlots) != 0 {
			t.Fatal("completed callback retained a replay slot")
		}
		assertSafeBrowserHeaders(t, rec.Header())
	}
}

func TestFormPostRejectsInvalidRequests(t *testing.T) {
	tests := []struct {
		name   string
		uri    string
		body   string
		mutate func(*http.Request)
		status int
	}{
		{name: "empty", status: http.StatusNotFound},
		{name: "state only", body: "state=s", status: http.StatusNotFound},
		{name: "code only", body: "code=x", status: http.StatusNotFound},
		{name: "error only", body: "error=access_denied", status: http.StatusNotFound},
		{name: "empty state", body: "code=x&state=", status: http.StatusNotFound},
		{name: "empty code", body: "code=&state=s", status: http.StatusNotFound},
		{name: "duplicate state", body: "code=x&state=s&state=other", status: http.StatusNotFound},
		{name: "duplicate code", body: "code=x&code=y&state=s", status: http.StatusNotFound},
		{name: "duplicate error", body: "error=x&error=y&state=s", status: http.StatusNotFound},
		{name: "code and error", body: "code=x&error=denied&state=s", status: http.StatusNotFound},
		{name: "empty error with code", body: "code=x&error=&state=s", status: http.StatusNotFound},
		{name: "query only", uri: "/?code=x&state=s", status: http.StatusBadRequest},
		{name: "query state", uri: "/?state=other", body: "code=x&state=s", status: http.StatusBadRequest},
		{name: "query code", uri: "/?code=other", body: "code=x&state=s", status: http.StatusBadRequest},
		{name: "query error", uri: "/?error=denied", body: "code=x&state=s", status: http.StatusBadRequest},
		{name: "malformed query", uri: "/?unused=%zz", body: "code=x&state=s", status: http.StatusBadRequest},
		{name: "malformed form", body: "code=x&state=s&unused=%zz", status: http.StatusBadRequest},
		{name: "semicolon", body: "code=x&state=s&other=a;b", status: http.StatusBadRequest},
		{name: "missing content type", body: "code=x&state=s", mutate: func(r *http.Request) { r.Header.Del("Content-Type") }, status: http.StatusUnsupportedMediaType},
		{name: "json", body: `{"code":"x","state":"s"}`, mutate: func(r *http.Request) { r.Header.Set("Content-Type", "application/json") }, status: http.StatusUnsupportedMediaType},
		{name: "multipart", body: "code=x&state=s", mutate: func(r *http.Request) { r.Header.Set("Content-Type", "multipart/form-data; boundary=test") }, status: http.StatusUnsupportedMediaType},
		{name: "duplicate content type", body: "code=x&state=s", mutate: func(r *http.Request) { r.Header.Add("Content-Type", "application/json") }, status: http.StatusUnsupportedMediaType},
		{name: "charset", body: "code=x&state=s", mutate: func(r *http.Request) {
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-16")
		}, status: http.StatusUnsupportedMediaType},
		{name: "compressed", body: "code=x&state=s", mutate: func(r *http.Request) { r.Header.Set("Content-Encoding", "gzip") }, status: http.StatusUnsupportedMediaType},
		{name: "oversized URL", uri: "/?x=" + strings.Repeat("x", maxRequestURIBytes), body: "code=x&state=s", status: http.StatusRequestURITooLong},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			b := testBridge(t, func(int, replayRequest) (replayResult, error) {
				t.Error("invalid callback was replayed")
				return replayResult{}, nil
			})
			uri := tc.uri
			if uri == "" {
				uri = "/"
			}
			r := formPost(uri, tc.body)
			if tc.mutate != nil {
				tc.mutate(r)
			}
			rec := httptest.NewRecorder()
			b.handleCallback(&listener{port: 1455})(rec, r)
			if rec.Code != tc.status {
				t.Fatalf("status = %d, want %d", rec.Code, tc.status)
			}
			if len(b.replaySlots) != 0 {
				t.Fatal("invalid callback retained a replay slot")
			}
			assertSafeBrowserHeaders(t, rec.Header())
		})
	}
}

type observedBody struct {
	reader io.Reader
	read   int
}

func (b *observedBody) Read(p []byte) (int, error) {
	n, err := b.reader.Read(p)
	b.read += n
	return n, err
}
func (*observedBody) Close() error { return nil }

func TestFormPostBoundsKnownAndUnknownLengths(t *testing.T) {
	for _, knownLength := range []bool{true, false} {
		t.Run(fmt.Sprintf("known=%v", knownLength), func(t *testing.T) {
			b := testBridge(t, func(int, replayRequest) (replayResult, error) {
				t.Error("oversized callback was replayed")
				return replayResult{}, nil
			})
			body := "code=x&state=s&extra=" + strings.Repeat("x", maxRequestBodyBytes*2)
			r := formPost("/", body)
			observed := &observedBody{reader: r.Body}
			r.Body = observed
			if !knownLength {
				r.ContentLength = -1 // e.g. a chunked browser request
			}
			rec := httptest.NewRecorder()
			b.handleCallback(&listener{port: 1455})(rec, r)
			if rec.Code != http.StatusRequestEntityTooLarge || observed.read > maxRequestBodyBytes+1 {
				t.Fatalf("status/read = %d/%d", rec.Code, observed.read)
			}
			if knownLength && observed.read != 0 {
				t.Fatal("known oversized body was read")
			}
		})
	}
}

func TestFormPostEarlyRefusalsDoNotReadBody(t *testing.T) {
	for _, reason := range []string{"custody", "saturated", "media type", "method"} {
		t.Run(reason, func(t *testing.T) {
			b := testBridge(t, func(int, replayRequest) (replayResult, error) {
				t.Error("refused callback was replayed")
				return replayResult{}, nil
			})
			b.SetCustodyConsumer(func(int, *url.URL) bool {
				t.Error("POST entered GET-only custody consumer")
				return true
			})
			l := &listener{port: 1455}
			r := formPost("/", "code=x&state=owned-state")
			observed := &observedBody{reader: r.Body}
			r.Body = observed
			want := http.StatusMethodNotAllowed
			switch reason {
			case "custody":
				l.custody = true
			case "saturated":
				for b.acquireReplay() {
				}
				want = http.StatusTooManyRequests
			case "media type":
				r.Header.Set("Content-Type", "text/plain")
				want = http.StatusUnsupportedMediaType
			case "method":
				r.Method = http.MethodPut
			}
			rec := httptest.NewRecorder()
			b.handleCallback(l)(rec, r)
			if rec.Code != want || observed.read != 0 {
				t.Fatalf("status/read = %d/%d, want %d/0", rec.Code, observed.read, want)
			}
		})
	}
}

// Use the production bash /dev/tcp replay and a POST-only, MSAL-shaped listener,
// not a replay stub. This validates transport/framing, not real Entra MFA or a VM.
func TestFormPostViaDevTCPToMSALStyleListener(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("guest bash /dev/tcp requires a Unix host for this no-VM fixture")
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash is required for the guest replay fixture")
	}
	body := "code=opaque%2Bcode%2F%3D&state=opaque-state&session_state=msal-session&extra=$(:)%3B'`%0D%0A+%25&unicode=é"
	observed := make(chan error, 1)
	guest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		check := func() error {
			if r.Method != http.MethodPost || r.URL.RequestURI() != "/?client_hint=keep%2Fme" || r.Proto != "HTTP/1.0" {
				return fmt.Errorf("method/URI/protocol changed: %s %s %s", r.Method, r.URL.RequestURI(), r.Proto)
			}
			if r.ContentLength != int64(len(body)) || r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
				return errors.New("incorrect form framing")
			}
			for _, key := range []string{"Cookie", "Authorization", "Origin", "Referer", "X-Browser-Only", "Transfer-Encoding"} {
				if r.Header.Get(key) != "" {
					return fmt.Errorf("browser header %s reached the guest", key)
				}
			}
			raw, err := io.ReadAll(r.Body)
			if err != nil || string(raw) != body {
				return errors.New("raw form bytes changed")
			}
			r.Body = io.NopCloser(strings.NewReader(string(raw)))
			if err := r.ParseForm(); err != nil {
				return err
			}
			if r.PostFormValue("state") != "opaque-state" || r.PostFormValue("code") != "opaque+code/=" {
				return errors.New("POST-only callback could not validate state/code")
			}
			return nil
		}
		observed <- check()
		w.Header().Set("Location", "https://attacker.invalid/")
		w.Header().Set("Set-Cookie", "guest-cookie=must-not-escape")
		w.WriteHeader(http.StatusFound)
		_, _ = io.WriteString(w, "<script>guest-controlled</script>")
	}))
	defer guest.Close()
	_, rawPort, err := net.SplitHostPort(guest.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(rawPort)
	if err != nil {
		t.Fatal(err)
	}
	b := testBridge(t, nil)
	b.exec = func(stdin io.Reader, args []string, timeout time.Duration) ([]byte, int, error) {
		if len(args) != 5 || args[4] != rawPort {
			return nil, 0, errors.New("callback data entered exec argv")
		}
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		cmd := exec.CommandContext(ctx, args[0], args[1:]...)
		cmd.Stdin = stdin
		cmd.WaitDelay = time.Second
		output, err := cmd.CombinedOutput()
		if err != nil {
			return output, 0, err
		}
		return output, 0, nil
	}
	bridge := httptest.NewServer(http.HandlerFunc(b.handleCallback(&listener{port: port})))
	defer bridge.Close()
	r, err := http.NewRequest(http.MethodPost, bridge.URL+"/?client_hint=keep%2Fme", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, key := range []string{"Cookie", "Authorization", "Origin", "Referer", "X-Browser-Only"} {
		r.Header.Set(key, "browser-only-canary")
	}
	response, err := bridge.Client().Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = response.Body.Close() }()
	page, _ := io.ReadAll(response.Body)
	if response.StatusCode != http.StatusOK || string(page) != completionPage || response.Header.Get("Location") != "" || response.Header.Get("Set-Cookie") != "" {
		t.Fatalf("unsafe/failed browser response: status=%d", response.StatusCode)
	}
	assertSafeBrowserHeaders(t, response.Header)
	select {
	case err := <-observed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("guest callback listener was not reached")
	}
}

func TestReplayRequestUsesStdinAndSyntheticHeaders(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		t.Run(method, func(t *testing.T) {
			request := replayRequest{method: method, uri: "/?code=argv-canary%2B&state=opaque"}
			if method == http.MethodPost {
				request.uri = "/callback"
				request.body = "code=argv-canary%2B&state=opaque"
			}
			b := &Bridge{exec: func(stdin io.Reader, args []string, timeout time.Duration) ([]byte, int, error) {
				if len(args) != 5 || args[4] != "53692" || timeout != ReplayTimeout || strings.Contains(strings.Join(args, " "), "argv-canary") {
					t.Error("callback data entered argv or replay bounds changed")
				}
				r, err := http.ReadRequest(bufio.NewReader(stdin))
				if err != nil {
					return nil, 0, err
				}
				body, err := io.ReadAll(r.Body)
				_ = r.Body.Close()
				if err != nil || r.Method != method || r.RequestURI != request.uri || string(body) != request.body || r.Host != "localhost:53692" {
					t.Error("callback framing or data changed")
				}
				return []byte("HTTP/1.0 200 OK\r\n\r\n"), 0, nil
			}}
			if _, err := b.replayViaDevTCP(53692, request); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestFormPostCancellationKeepsSlotCharged(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	defer close(release)
	b := testBridge(t, func(int, replayRequest) (replayResult, error) {
		close(started)
		<-release
		return replayResult{status: http.StatusOK}, nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		b.handleCallback(&listener{port: 1455})(httptest.NewRecorder(), formPost("/", "code=x&state=s").WithContext(ctx))
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("replay did not start")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("canceled browser request did not return")
	}
	if len(b.replaySlots) != 1 {
		t.Fatal("cancellation released the slot before the underlying replay unwound")
	}
}

func TestGetCallbackRejectsAmbiguityAndRequestLineInjection(t *testing.T) {
	for _, query := range []string{
		"code=x&state=s&state=other", "code=x&error=denied&state=s",
		"code=x&state=s&unused=%zz", "code=x&state=s\r\nInjected: header",
		"code=x&state=s\x00", "code=x&state=s HTTP/1.0",
	} {
		b := testBridge(t, func(int, replayRequest) (replayResult, error) {
			t.Error("invalid GET callback replayed")
			return replayResult{}, nil
		})
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.URL.RawQuery = query
		rec := httptest.NewRecorder()
		b.handleCallback(&listener{port: 1455})(rec, r)
		if rec.Code != http.StatusBadRequest && rec.Code != http.StatusNotFound {
			t.Fatalf("unexpected rejection status %d", rec.Code)
		}
	}
}

func TestReplayFailuresDoNotLogCallbackData(t *testing.T) {
	const secret = "authorization-code-canary"
	for _, mode := range []string{"exec error", "exit status", "no HTTP", "status line", "status code", "panic"} {
		t.Run(mode, func(t *testing.T) {
			b := testBridge(t, nil)
			b.exec = func(io.Reader, []string, time.Duration) ([]byte, int, error) {
				switch mode {
				case "exec error":
					return nil, 0, errors.New(secret)
				case "exit status":
					return []byte(secret), 1, nil
				case "no HTTP":
					return []byte(secret), 0, nil
				case "status line":
					return []byte(secret + "\r\n\r\n"), 0, nil
				case "status code":
					return []byte("HTTP/1.0 " + secret + "\r\n\r\n"), 0, nil
				default:
					panic(secret)
				}
			}
			var log strings.Builder
			b.logf = func(f string, args ...any) { fmt.Fprintf(&log, f, args...) }
			rec := httptest.NewRecorder()
			b.handleCallback(&listener{port: 1455})(rec, formPost("/", "code="+secret+"&state=s"))
			if rec.Code != http.StatusBadGateway || strings.Contains(rec.Body.String()+log.String(), secret) {
				t.Fatalf("unsafe/incorrect failure: status=%d", rec.Code)
			}
		})
	}
}
