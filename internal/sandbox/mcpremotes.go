// SPDX-License-Identifier: Apache-2.0

// mcpremotes.go — parsing and resolution of -mcp-remote specs into
// gateway server entries (docs/mcp-gateway.md milestone 2).
//
// Spec grammar (comma-separated k=v; repeat allow/deny/redact):
//
//	name=github,url=https://api.githubcopilot.com/mcp/,auth=bearer:GITHUB_TOKEN,allow=read*
//	name=corp,url=https://mcp.corp.example/sse,auth=header:X-Api-Key:CORP_MCP_KEY,deny=admin*
//	name=ai,url=https://api.example/mcp,auth=custody:claude,redact=OTHER_TOKEN
//
// Security rules (normative in the design doc):
//   - URLs are validated by mcpgw.ValidateRemoteURL: HTTPS-only with
//     verified TLS, plain HTTP only to loopback literals, no
//     userinfo, non-public literal IPs refused at parse time.
//   - Secret references resolve through the broker's secret Store
//     (env/file/exec sources, fail-closed) — never from the guest.
//   - custody: providers read the LIVE custody registry per session, so
//     refreshed access tokens reach new sessions.
//   - A spec that fails to parse or resolve refuses the whole `gantry
//     start` loudly. Custody must never silently degrade.

package sandbox

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/ejpir/gantry/internal/sandbox/mcpgw"
)

var mcpRemoteNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,30}$`)

var mcpHeaderNameRe = regexp.MustCompile(`^[!#$%&'*+\-.^_` + "`" + `|~0-9A-Za-z]{1,64}$`)

type mcpRemoteSpec struct {
	Name        string
	URL         string
	AuthKind    string // "", "bearer", "header", "custody"
	AuthHeader  string // header name for AuthKind == "header"
	AuthRef     string // secret name (bearer/header) or custody provider
	Allow, Deny []string
	RedactNames []string
}

// parseMCPRemote parses one -mcp-remote spec. Everything structural is
// validated here (name, URL, auth shape, header name); secret VALUES are
// resolved later by the daemon against the live Store.
func parseMCPRemote(spec string) (mcpRemoteSpec, error) {
	var out mcpRemoteSpec
	for _, kv := range strings.Split(spec, ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(kv), "=")
		if !ok || k == "" || v == "" {
			return out, fmt.Errorf("bad field %q (want k=v)", kv)
		}
		switch k {
		case "name":
			out.Name = v
		case "url":
			out.URL = v
		case "auth":
			kind, rest, _ := strings.Cut(v, ":")
			switch kind {
			case "bearer", "custody":
				if rest == "" || strings.Contains(rest, ":") {
					return out, fmt.Errorf("auth=%s: want %s:<name>", kind, kind)
				}
				out.AuthKind, out.AuthRef = kind, rest
			case "header":
				hdr, ref, ok := strings.Cut(rest, ":")
				if !ok || hdr == "" || ref == "" {
					return out, fmt.Errorf("auth=header: want header:<Header-Name>:<secret-name>")
				}
				if !mcpHeaderNameRe.MatchString(hdr) {
					return out, fmt.Errorf("auth=header: invalid header name %q", hdr)
				}
				out.AuthKind, out.AuthHeader, out.AuthRef = kind, hdr, ref
			default:
				return out, fmt.Errorf("auth: unknown kind %q (want bearer:, header:, or custody:)", kind)
			}
		case "allow":
			out.Allow = append(out.Allow, v)
		case "deny":
			out.Deny = append(out.Deny, v)
		case "redact":
			out.RedactNames = append(out.RedactNames, v)
		default:
			return out, fmt.Errorf("unknown field %q (want name/url/auth/allow/deny/redact)", k)
		}
	}
	if !mcpRemoteNameRe.MatchString(out.Name) || strings.Contains(out.Name, "__") {
		return out, fmt.Errorf("name %q must match %s without '__'", out.Name, mcpRemoteNameRe)
	}
	if out.Name == "fs" {
		return out, fmt.Errorf("name %q is reserved for the built-in filesystem server", out.Name)
	}
	if out.URL == "" {
		return out, fmt.Errorf("missing url=")
	}
	if _, err := mcpgw.ValidateRemoteURL(out.URL); err != nil {
		return out, fmt.Errorf("url: %w", err)
	}
	return out, nil
}

// resolveMCPServers turns the built-in fs server plus any -mcp-remote
// specs into gateway server entries, resolving secret and custody
// references against the broker's live stores. Failures are loud: a bad
// spec refuses the whole start.
func (d *daemonRuntime) resolveMCPServers() ([]mcpgw.Server, error) {
	root, usr := d.cfg.MCPFSRoot, d.cfg.MCPFSUser
	if root == "" {
		root = "/"
	}
	if usr == "" {
		usr = "nobody"
	}
	servers := []mcpgw.Server{{
		Name: "fs",
		Argv: []string{
			filepath.Join(guestToolsDirGuest, "gantry-guest"), "mcp-serve", "filesystem",
			"--root", root, "--user", usr,
		},
		Tools: mcpgw.ToolPolicy{Allow: []string{"read_file", "list_directory"}},
	}}
	for _, raw := range d.cfg.MCPRemotes {
		spec, err := parseMCPRemote(raw)
		if err != nil {
			return nil, fmt.Errorf("-mcp-remote %q: %w", raw, err)
		}
		srv := mcpgw.Server{
			Name:  spec.Name,
			URL:   spec.URL,
			Tools: mcpgw.ToolPolicy{Allow: spec.Allow, Deny: spec.Deny},
		}
		authDesc := "none"
		switch spec.AuthKind {
		case "bearer", "header":
			v, err := d.broker.secretStore.Resolve(spec.AuthRef)
			if err != nil {
				return nil, fmt.Errorf("-mcp-remote %s: secret %s: %w", spec.Name, spec.AuthRef, err)
			}
			hdr := "Authorization"
			val := "Bearer " + v.Raw()
			if spec.AuthKind == "header" {
				hdr, val = spec.AuthHeader, v.Raw()
			}
			srv.Headers = map[string]string{hdr: val}
			authDesc = spec.AuthKind + " (secret " + spec.AuthRef + ")"
		case "custody":
			if d.broker.custodyRegistry == nil {
				return nil, fmt.Errorf("-mcp-remote %s: auth=custody: needs -oauth-custody", spec.Name)
			}
			provider := spec.AuthRef
			registry := d.broker.custodyRegistry
			srv.TokenFunc = func() (string, error) {
				set, ok := registry.Get(provider)
				if !ok || set.AccessToken == "" {
					return "", fmt.Errorf("no custody login for %s", provider)
				}
				return set.AccessToken, nil
			}
			authDesc = "custody:" + provider
		}
		for _, name := range spec.RedactNames {
			v, err := d.broker.secretStore.Resolve(name)
			if err != nil {
				return nil, fmt.Errorf("-mcp-remote %s: redact secret %s: %w", spec.Name, name, err)
			}
			srv.Redact = append(srv.Redact, []byte(v.Raw()))
		}
		d.broker.auditf("mcp: remote %s configured (%s, auth %s)", spec.Name, mcpgw.AuditRemoteOrigin(spec.URL), authDesc)
		servers = append(servers, srv)
	}
	return servers, nil
}
