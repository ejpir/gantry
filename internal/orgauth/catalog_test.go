package orgauth_test

import (
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ejpir/gantry/internal/orgauth"
	"github.com/ejpir/gantry/internal/orgauth/testidp"
	"github.com/ejpir/gantry/internal/remoteprofile"
)

func catalogConfig(t *testing.T, path string, server *httptest.Server) *orgauth.ProviderConfig {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var config orgauth.Config
	if err := json.Unmarshal(data, &config); err != nil {
		t.Fatal(err)
	}
	config.RemoteCatalog = &orgauth.CatalogConfig{URL: server.URL + "/remotes", Resource: server.URL, Scope: "gantry.catalog.read", CAFile: "catalog-ca.pem"}
	data, err = json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(filepath.Dir(path), "catalog-ca.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	trusted, err := orgauth.LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	return trusted
}

func TestDynamicCatalogUsesScopedAccessAndTokenFreeReceipts(t *testing.T) {
	idp, path := fixture(t)
	var requests atomic.Int32
	var server *httptest.Server
	profile := remoteprofile.Profile{Name: "team", URL: "https://manager.example.com"}
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Method != "GET" || r.URL.Path != "/remotes" || !idp.ValidAccessToken(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "), server.URL, "gantry.catalog.read") {
			http.Error(w, "not a resource-scoped access token", http.StatusForbidden)
			return
		}
		_ = json.NewEncoder(w).Encode(orgauth.RemoteCatalog{Version: 1, Organization: testidp.Organization, Subject: "synthetic-user", ExpiresAt: time.Now().Add(time.Hour), Remotes: []remoteprofile.Profile{profile}})
	}))
	defer server.Close()
	trusted := catalogConfig(t, path, server)
	idp.Set(testidp.Scenario{Resource: server.URL, Scope: "gantry.catalog.read"})
	s, err := orgauth.Login(t.Context(), trusted, "", func(url string) error {
		// Pin catalog URL and CA before opening the browser, like IdP trust.
		if err := os.WriteFile(path, []byte("changed"), 0o600); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(filepath.Dir(path), "catalog-ca.pem"), []byte("changed"), 0o600); err != nil {
			return err
		}
		return idp.Visit(url)
	})
	if err != nil {
		t.Fatal(err)
	}
	if s.Catalog == nil || s.CatalogError != "" || requests.Load() != 1 {
		t.Fatalf("discovery unavailable: %s, requests=%d", s.CatalogError, requests.Load())
	}
	if !s.Catalog.ExpiresAt.Equal(s.ExpiresAt) {
		t.Fatal("catalog lifetime must be capped by login")
	}
	dir := filepath.Join(t.TempDir(), "sessions")
	if err := orgauth.SaveSession(dir, s); err != nil {
		t.Fatal(err)
	}
	available, err := orgauth.AvailableRemotes(dir)
	if err != nil || len(available) != 1 || available[0].Profile != profile {
		t.Fatalf("available: %v %v", available, err)
	}
	renamed := profile
	renamed.Name = "local-alias"
	if snapshot, err := orgauth.PolicyForRemote(dir, s.Organization, renamed); err != nil || snapshot.Profile != "developer" {
		t.Fatalf("renamed endpoint policy: %v", err)
	}
	renamed.URL = "https://unrelated.example.com"
	if _, err := orgauth.PolicyForRemote(dir, s.Organization, renamed); err == nil {
		t.Fatal("unrelated endpoint accepted")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		for _, secret := range idp.Secrets() {
			if strings.Contains(string(data), secret) {
				t.Fatal("credential persisted in receipt")
			}
		}
	}
	if err := orgauth.Logout(dir, s.Organization); err != nil {
		t.Fatal(err)
	}
	available, err = orgauth.AvailableRemotes(dir)
	if err != nil || len(available) != 0 {
		t.Fatalf("logout kept suggestions: %v %v", available, err)
	}
	if requests.Load() != 1 {
		t.Fatal("receipt reads must not perform hidden token refreshes or network calls")
	}
}

func TestCatalogFailuresAreFailSoftButNeverTrusted(t *testing.T) {
	idp, path := fixture(t)
	profile := remoteprofile.Profile{Name: "team", URL: "https://manager.example.com"}
	valid := orgauth.RemoteCatalog{Version: 1, Organization: testidp.Organization, Subject: "synthetic-user", ExpiresAt: time.Now().Add(time.Minute), Remotes: []remoteprofile.Profile{profile}}
	var body []byte
	var status int
	var calls atomic.Int32
	leak := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("catalog followed redirect") }))
	defer leak.Close()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if status == 302 {
			w.Header().Set("Location", leak.URL)
		}
		w.WriteHeader(status)
		_, _ = w.Write(body)
	}))
	defer server.Close()
	trusted := catalogConfig(t, path, server)
	for _, tc := range []struct {
		name   string
		change func(*orgauth.RemoteCatalog)
		raw    string
		status int
	}{
		{name: "wrong identity", change: func(c *orgauth.RemoteCatalog) { c.Subject = "someone-else" }},
		{name: "wrong org", change: func(c *orgauth.RemoteCatalog) { c.Organization = "other" }},
		{name: "expired", change: func(c *orgauth.RemoteCatalog) { c.ExpiresAt = time.Now().Add(-time.Minute) }},
		{name: "HTTP manager", change: func(c *orgauth.RemoteCatalog) {
			c.Remotes = []remoteprofile.Profile{{Name: "bad", URL: "http://example.com"}}
		}},
		{name: "duplicate names", change: func(c *orgauth.RemoteCatalog) { c.Remotes = []remoteprofile.Profile{profile, profile} }},
		{name: "too many", change: func(c *orgauth.RemoteCatalog) { c.Remotes = make([]remoteprofile.Profile, 129) }},
		{name: "trailing JSON", raw: `{} {}`},
		{name: "unknown credential field", raw: `{"version":1,"token":"UPSTREAM-SECRET-CANARY"}`},
		{name: "oversized", raw: strings.Repeat("x", (384<<10)+1)},
		{name: "unauthorized", raw: "UPSTREAM-SECRET-CANARY", status: 403},
		{name: "redirect", raw: "UPSTREAM-SECRET-CANARY", status: 302},
	} {
		t.Run(tc.name, func(t *testing.T) {
			catalog := valid
			if tc.change != nil {
				tc.change(&catalog)
			}
			body, _ = json.Marshal(catalog)
			if tc.raw != "" {
				body = []byte(tc.raw)
			}
			status = tc.status
			if status == 0 {
				status = 200
			}
			session, err := orgauth.Login(t.Context(), trusted, "", idp.Visit)
			if err != nil {
				t.Fatalf("optional discovery broke valid login: %v", err)
			}
			if session.Catalog != nil || session.CatalogError == "" {
				t.Fatal("invalid catalog trusted")
			}
			if strings.Contains(session.CatalogError, "UPSTREAM-SECRET-CANARY") {
				t.Fatal("upstream diagnostic leaked")
			}
			for _, secret := range idp.Secrets() {
				if strings.Contains(session.CatalogError, secret) {
					t.Fatal("credential leaked")
				}
			}
		})
	}
	before := calls.Load()
	idp.Set(testidp.Scenario{Groups: []string{}})
	if _, err := orgauth.Login(t.Context(), trusted, "", idp.Visit); err == nil {
		t.Fatal("non-member signed in")
	}
	if calls.Load() != before {
		t.Fatal("catalog called before membership verification")
	}
}

func TestCatalogConfigurationRejectsUntrustedAudience(t *testing.T) {
	_, path := fixture(t)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, catalog := range []orgauth.CatalogConfig{
		{URL: "http://catalog.example.com", Resource: "https://catalog.example.com", Scope: "read"},
		{URL: "https://catalog.example.com", Resource: "https://another.example.com", Scope: "read"},
		{URL: "https://catalog.example.com", Scope: "read"},
		{URL: "https://user:secret@catalog.example.com", Resource: "https://catalog.example.com", Scope: "read"},
		{URL: "https://catalog.example.com?token=secret", Resource: "https://catalog.example.com", Scope: "read"},
		{URL: "https://catalog.example.com", Resource: "https://catalog.example.com", Scope: "offline_access"},
		{URL: "https://catalog.example.com", Resource: "https://catalog.example.com", Scope: "openid"},
	} {
		var c orgauth.Config
		if err := json.Unmarshal(raw, &c); err != nil {
			t.Fatal(err)
		}
		c.RemoteCatalog = &catalog
		changed, _ := json.Marshal(c)
		if err := os.WriteFile(path, changed, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := orgauth.LoadConfig(path); err == nil {
			t.Fatalf("catalog config accepted: %+v", catalog)
		}
	}
}
