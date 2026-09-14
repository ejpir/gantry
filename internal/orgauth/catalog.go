package orgauth

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ejpir/gantry/internal/policy"
	"github.com/ejpir/gantry/internal/remoteprofile"
	"github.com/ejpir/gantry/internal/sandbox/layout"
	"golang.org/x/oauth2"
)

// CatalogConfig pins the organization-owned inventory service, not the IdP.
// Resource is an RFC 8707 audience on the SAME origin as URL. The IdP must
// support resource indicators and the service must verify audience/scope and
// user membership itself; a supplied client profile is not authorization.
type CatalogConfig struct {
	URL      string `json:"url"`
	Resource string `json:"resource"`
	Scope    string `json:"scope"`
	CAFile   string `json:"ca_file,omitempty"`
}

// RemoteCatalog is the organization's public, time-bounded discovery response.
// It has no credentials and confers no authority to a manager.
type RemoteCatalog struct {
	Version      int                     `json:"version"`
	Organization string                  `json:"organization"`
	Subject      string                  `json:"subject"`
	ExpiresAt    time.Time               `json:"expires_at"`
	Remotes      []remoteprofile.Profile `json:"remotes"`
}

func validateCatalogConfig(c *CatalogConfig) error {
	if c == nil {
		return nil
	}
	endpoint, e1 := httpsURL(c.URL)
	resource, e2 := httpsURL(c.Resource)
	if e1 != nil || e2 != nil || endpoint.RawQuery != "" || endpoint.ForceQuery || resource.RawQuery != "" || resource.ForceQuery ||
		!strings.EqualFold(endpoint.Host, resource.Host) || !text(c.Scope, 128) || strings.ContainsAny(c.Scope, " \"\\") || c.Scope == "offline_access" || c.Scope == "openid" {
		return fmt.Errorf("remote_catalog requires HTTPS url and same-origin resource, plus a dedicated scope (no query, credentials or fragment)")
	}
	return nil
}

func (catalog *RemoteCatalog) validate(organization, subject string) error {
	if catalog == nil || catalog.Version != 1 || catalog.Organization != organization || catalog.Subject != subject || catalog.ExpiresAt.IsZero() || len(catalog.Remotes) > 128 {
		return fmt.Errorf("invalid remote catalog identity, version, lifetime or size")
	}
	names := make(map[string]bool)
	for _, profile := range catalog.Remotes {
		if remoteprofile.Validate(profile) != nil || names[profile.Name] {
			return fmt.Errorf("remote catalog has invalid or duplicate profiles")
		}
		names[profile.Name] = true
	}
	return nil
}

// fetchCatalog runs only AFTER OIDC verification and membership selection.
// It sends the resource-scoped access token to exactly the host-pinned URL,
// never an ID token and never to the managers returned by the catalog.
func fetchCatalog(ctx context.Context, trusted *ProviderConfig, tokens *oauth2.Token, session *Session) (*RemoteCatalog, error) {
	if tokens == nil || tokens.AccessToken == "" || len(tokens.AccessToken) > 64<<10 || !strings.EqualFold(tokens.Type(), "Bearer") || !tokens.Valid() {
		return nil, fmt.Errorf("remote catalog requires a live resource-scoped bearer access token")
	}
	client, closeClient, err := oidcClient(trusted.catalogCA)
	if err != nil {
		return nil, fmt.Errorf("remote catalog TLS configuration is invalid")
	}
	defer closeClient()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, trusted.config.RemoteCatalog.URL, nil)
	if err != nil {
		return nil, fmt.Errorf("invalid remote catalog endpoint")
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
	response, err := client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("remote catalog request failed (check connectivity and TLS; redirects are refused)")
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("remote catalog returned HTTP %d (check resource, scope and organization access)", response.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, (384<<10)+1))
	if err != nil || len(data) > 384<<10 {
		return nil, fmt.Errorf("remote catalog response failed or exceeds 384 KiB")
	}
	var catalog RemoteCatalog
	// Never include decoder errors, response bytes or credential-bearing HTTP
	// errors in diagnostics. Unknown fields (including tokens) are rejected.
	if strictJSON(data, &catalog) != nil || catalog.validate(session.Organization, session.Subject) != nil || !time.Now().Before(catalog.ExpiresAt) {
		return nil, fmt.Errorf("remote catalog response is invalid, expired or belongs to another identity")
	}
	if catalog.ExpiresAt.After(session.ExpiresAt) {
		catalog.ExpiresAt = session.ExpiresAt
	}
	return &catalog, nil
}

// SessionDir is shared with CLI/TUI readers; receipts are local-only.
func SessionDir() string {
	if os.Getenv("GANTRY_HOME") != "" {
		return layout.Root() + "-orgs"
	}
	return filepath.Join(filepath.Dir(layout.Root()), "orgs")
}

type AvailableRemote struct {
	Organization string                `json:"organization"`
	ExpiresAt    time.Time             `json:"expires_at"`
	Profile      remoteprofile.Profile `json:"remote"`
}

// AvailableRemotes reads only live receipts. It never contacts an IdP or a
// manager, caches a token, merges profile stores or changes the default target.
func AvailableRemotes(dir string) ([]AvailableRemote, error) {
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if err := secureStore(dir, false); err != nil {
		return nil, err
	}
	var available []AvailableRemote
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		data, err := readRegular(filepath.Join(dir, entry.Name()), 1<<20)
		if err != nil {
			continue
		}
		var s Session
		if strictJSON(data, &s) != nil {
			continue
		}
		path, err := sessionPath(dir, s.Organization)
		if err != nil || filepath.Base(path) != entry.Name() {
			continue
		}
		// LoadSession repeats ownership, expiry and signature checks; an
		// arbitrary receipt file cannot bypass those by naming another org.
		session, err := LoadSession(dir, s.Organization)
		if err != nil || session.Catalog == nil || !time.Now().Before(session.Catalog.ExpiresAt) {
			continue
		}
		for _, profile := range session.Catalog.Remotes {
			available = append(available, AvailableRemote{Organization: session.Organization, ExpiresAt: session.Catalog.ExpiresAt, Profile: profile})
		}
	}
	sort.Slice(available, func(i, j int) bool {
		return available[i].Organization+"/"+available[i].Profile.Name < available[j].Organization+"/"+available[j].Profile.Name
	})
	return available, nil
}

// PolicyForRemote revalidates the live receipt, signed snapshot and catalog
// binding before an organization create. A local alias may differ from the
// catalog's name, but its endpoint and TLS trust must match exactly.
func PolicyForRemote(dir, organization string, profile remoteprofile.Profile) (*policy.Config, error) {
	session, err := LoadSession(dir, organization)
	if err != nil {
		return nil, fmt.Errorf("organization sign-in is unavailable or expired; sign in again")
	}
	if session.Catalog == nil || !time.Now().Before(session.Catalog.ExpiresAt) {
		return nil, fmt.Errorf("organization remote catalog is unavailable or expired; sign in again")
	}
	for _, candidate := range session.Catalog.Remotes {
		candidate.Name = profile.Name
		if candidate == profile {
			return policy.CloneConfig(session.Policy), nil
		}
	}
	return nil, fmt.Errorf("selected remote is no longer in this organization's catalog; discover and select a remote again")
}

func catalogResource(config *CatalogConfig) oauth2.AuthCodeOption {
	return oauth2.SetAuthURLParam("resource", config.Resource)
}
