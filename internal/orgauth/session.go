package orgauth

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/ejpir/gantry/internal/atomicfile"
	"github.com/ejpir/gantry/internal/policy"
	"github.com/ejpir/gantry/internal/sandbox/localsec"
)

// Session is a host-local receipt, not a transferable proof or credential. Raw
// ID/access/refresh tokens, authorization codes, and groups are never stored.
// Expiry gates subsequent apply operations; already-pinned sandboxes retain
// their independent signed-policy lifetime until explicitly changed/stopped.
type Session struct {
	Version      int            `json:"version"`
	Organization string         `json:"organization"`
	Issuer       string         `json:"issuer"`
	ClientID     string         `json:"client_id"`
	Subject      string         `json:"subject"`
	Profile      string         `json:"profile"`
	ExpiresAt    time.Time      `json:"expires_at"`
	Policy       *policy.Config `json:"policy"`
	Catalog      *RemoteCatalog `json:"remote_catalog,omitempty"`
	CatalogError string         `json:"-"` // transient discovery warning; never an upstream body
}

func (s *Session) Validate() error {
	if s == nil || s.Version != 1 || !identifier(s.Organization) || !identifier(s.Profile) || !text(s.ClientID, 256) || !text(s.Subject, 255) || s.Policy == nil || s.Policy.Profile != s.Profile {
		return fmt.Errorf("invalid organization session")
	}
	if _, err := httpsURL(s.Issuer); err != nil {
		return fmt.Errorf("invalid organization session issuer")
	}
	if !time.Now().Before(s.ExpiresAt) {
		return fmt.Errorf("organization login expired; log in again")
	}
	engine, err := policy.New(s.Policy, nil)
	if err != nil {
		return fmt.Errorf("saved organization policy is invalid or expired")
	}
	if engine.Info().Organization != s.Organization || s.ExpiresAt.After(engine.ExpiresAt()) {
		return fmt.Errorf("organization session does not match signed policy")
	}
	if s.Catalog != nil {
		if err := s.Catalog.validate(s.Organization, s.Subject); err != nil || s.Catalog.ExpiresAt.After(s.ExpiresAt) {
			return fmt.Errorf("invalid saved remote catalog")
		}
	}
	return nil
}

func sessionPath(dir, organization string) (string, error) {
	if !identifier(organization) {
		return "", fmt.Errorf("invalid organization identifier")
	}
	hash := sha256.Sum256([]byte(organization))
	return filepath.Join(dir, hex.EncodeToString(hash[:])+".json"), nil
}

func secureStore(dir string, create bool) error {
	if _, err := os.Lstat(dir); err != nil {
		if os.IsNotExist(err) && create {
			return localsec.CreateManagerDir(dir)
		}
		return err
	}
	return localsec.ValidateManagerDir(dir)
}

func SaveSession(dir string, s *Session) error {
	if err := s.Validate(); err != nil {
		return err
	}
	path, err := sessionPath(dir, s.Organization)
	if err != nil {
		return err
	}
	if err := secureStore(dir, true); err != nil {
		return err
	}
	if info, err := os.Lstat(path); err == nil && !info.Mode().IsRegular() {
		return fmt.Errorf("organization session must be a regular file")
	} else if err != nil && !os.IsNotExist(err) {
		return err
	}
	raw, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return atomicfile.WriteFileDurable(path, raw, 0o600)
}

func LoadSession(dir, organization string) (*Session, error) {
	path, err := sessionPath(dir, organization)
	if err != nil {
		return nil, err
	}
	if err := secureStore(dir, false); err != nil {
		return nil, fmt.Errorf("organization session unavailable; log in first")
	}
	if err := localsec.SecureRegularFile(path); err != nil {
		return nil, fmt.Errorf("organization session must be an owned regular file")
	}
	if err := localsec.SecureEndpoint(path); err != nil {
		return nil, err
	}
	raw, err := readRegular(path, 1<<20)
	if err != nil {
		return nil, fmt.Errorf("organization session unavailable; log in first")
	}
	var s Session
	if strictJSON(raw, &s) != nil || s.Organization != organization {
		return nil, fmt.Errorf("invalid organization session")
	}
	if err := s.Validate(); err != nil {
		return nil, err
	}
	return &s, nil
}

// Logout removes only this host's receipt. It neither calls the provider's
// logout/revocation endpoints nor clears policies already pinned to sandboxes.
func Logout(dir, organization string) error {
	path, err := sessionPath(dir, organization)
	if err != nil {
		return err
	}
	if err := secureStore(dir, false); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}
