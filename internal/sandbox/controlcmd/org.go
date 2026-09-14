package controlcmd

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"time"

	"github.com/ejpir/gantry/internal/orgauth"
	"github.com/ejpir/gantry/internal/policy"
	"github.com/ejpir/gantry/internal/sandbox/config"
	"github.com/ejpir/gantry/internal/sandbox/layout"
)

// CmdOrg manages host-only OIDC receipts and explicit stopped-sandbox adoption.
func CmdOrg(args []string) int {
	usage := func() {
		fmt.Fprintln(os.Stderr, `usage:
  gantry org login -config organization.json [-profile NAME] [-no-browser] [-timeout 5m]
  gantry org status ORGANIZATION
  gantry org remotes ORGANIZATION
  gantry org logout ORGANIZATION
  gantry org apply ORGANIZATION SANDBOX

The host-owned config pins an HTTPS issuer, public OIDC client, group-to-profile
mapping, signed policy bundle and verification key. Login uses code + PKCE;
no tokens are saved or delivered to guests. apply requires a stopped sandbox.
Login expiry/logout do not revoke policies already pinned to sandboxes.`)
	}
	fail := func(err error) int { fmt.Fprintln(os.Stderr, "gantry org:", err); return 1 }
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" {
		usage()
		return 0
	}
	if args[0] == "login" {
		return cmdOrgLogin(args[1:])
	}
	if args[0] == "apply" && len(args) != 3 || args[0] != "apply" && len(args) != 2 {
		usage()
		return 2
	}
	organization := args[1]
	switch args[0] {
	case "logout":
		if err := orgauth.Logout(orgSessionDir(), organization); err != nil {
			return fail(err)
		}
		fmt.Println("Local organization login removed. Provider SSO and pinned sandbox policies are unchanged.")
		return 0
	case "status", "apply", "remotes":
		session, err := orgauth.LoadSession(orgSessionDir(), organization)
		if err != nil {
			return fail(err)
		}
		if args[0] == "remotes" {
			if session.Catalog == nil || !time.Now().Before(session.Catalog.ExpiresAt) {
				return fail(fmt.Errorf("no live remote catalog; log in again with remote_catalog configured"))
			}
			if err := json.NewEncoder(os.Stdout).Encode(session.Catalog); err != nil {
				return fail(err)
			}
			return 0
		}
		if args[0] == "status" {
			if err := printOrgSession(session); err != nil {
				return fail(err)
			}
			return 0
		}
		if len(args) != 3 {
			usage()
			return 2
		}
		if err := applyOrgSession(args[2], session); err != nil {
			return fail(err)
		}
		fmt.Println("Organization policy pinned for next start. Login expiry/logout will not revoke this snapshot.")
		return 0
	default:
		usage()
		return 2
	}
}

func cmdOrgLogin(args []string) int {
	fs := flag.NewFlagSet("org login", flag.ContinueOnError)
	path := fs.String("config", "", "trusted host-owned organization configuration JSON")
	profile := fs.String("profile", "", "select among profiles authorized by verified membership")
	noBrowser := fs.Bool("no-browser", false, "print authorization URL without opening a browser")
	timeout := fs.Duration("timeout", 5*time.Minute, "overall login deadline (1s..15m)")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() != 0 || *path == "" || *timeout < time.Second || *timeout > 15*time.Minute {
		fmt.Fprintln(os.Stderr, "gantry org: login requires -config and a timeout of 1s..15m; no positional arguments")
		return 2
	}
	fail := func(err error) int { fmt.Fprintln(os.Stderr, "gantry org:", err); return 1 }
	trusted, err := orgauth.LoadConfig(*path)
	if err != nil {
		return fail(err)
	}
	parent, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	ctx, cancel := context.WithTimeout(parent, *timeout)
	defer cancel()
	session, err := orgauth.Login(ctx, trusted, *profile, func(url string) error {
		if _, err := fmt.Fprintln(os.Stderr, "Open this URL in your browser:\n"+url); err != nil {
			return err
		}
		if !*noBrowser {
			if err := openOrgBrowser(url); err != nil {
				fmt.Fprintln(os.Stderr, "Browser could not be opened; use the URL above on this host.")
			}
		}
		return nil
	})
	if err != nil {
		return fail(err)
	}
	if ctx.Err() != nil {
		return fail(fmt.Errorf("organization login canceled or timed out"))
	}
	if err := layout.EnsureRoot(); err != nil {
		return fail(err)
	}
	if err := orgauth.SaveSession(orgSessionDir(), session); err != nil {
		return fail(err)
	}
	if err := printOrgSession(session); err != nil {
		return fail(err)
	}
	if session.CatalogError != "" {
		fmt.Fprintln(os.Stderr, "Organization login succeeded; remote discovery unavailable:", session.CatalogError)
	} else if session.Catalog != nil {
		fmt.Fprintf(os.Stderr, "%d remote(s) available from your organization; view with gantry org remotes %s or the TUI Remotes page. Manager credentials are separate.\n", len(session.Catalog.Remotes), session.Organization)
	}
	return 0
}

// Keep receipts beside sandbox state, inside the existing protected application
// tree. An override gets a unique sibling rather than a shared global store.
func orgSessionDir() string { return orgauth.SessionDir() }

func openOrgBrowser(url string) error { return orgauth.OpenBrowser(url) }

func printOrgSession(s *orgauth.Session) error {
	engine, err := policy.New(s.Policy, nil)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(struct {
		Organization string    `json:"organization"`
		Issuer       string    `json:"issuer"`
		ClientID     string    `json:"client_id"`
		Subject      string    `json:"subject"`
		Profile      string    `json:"profile"`
		Revision     string    `json:"revision"`
		ExpiresAt    time.Time `json:"expires_at"`
	}{s.Organization, s.Issuer, s.ClientID, s.Subject, s.Profile, engine.Info().Revision, s.ExpiresAt})
}

func applyOrgSession(name string, session *orgauth.Session) error {
	if err := layout.ValidateName(name); err != nil {
		return err
	}
	return mutateRunningOrStopped(name, func() error {
		return fmt.Errorf("stop %s before changing its organization policy", name)
	}, func() error {
		store, err := config.LoadConfigStore(layout.Dir(name))
		if err != nil {
			return err
		}
		return store.Mutate(func(cfg *config.RunConfig) error {
			if err := session.Validate(); err != nil {
				return err
			}
			if cfg.OAuthCustodyEnabled() {
				return fmt.Errorf("organization policy v1 does not support OAuth custody")
			}
			cfg.OrgPolicy = policy.CloneConfig(session.Policy)
			return nil
		})
	})
}
