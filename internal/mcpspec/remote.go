// Package mcpspec owns the persisted grammar for remote MCP servers.
// It contains no credential values: auth and redaction fields are references
// to supervisor-owned secret or OAuth custody stores.
package mcpspec

import (
	"fmt"
	"path"
	"regexp"
	"strings"

	"github.com/ejpir/gantry/internal/sandbox/mcpgw"
	"github.com/ejpir/gantry/internal/secret"
)

// MaxRemotes leaves one slot for the built-in filesystem server in the MCP
// worker's bounded 64-server capability table.
const (
	MaxRemotes      = 63
	MaxSpecBytes    = 32 << 10
	MaxToolPatterns = 256
	MaxRedactNames  = 64
)

var remoteNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,30}$`)
var headerNameRE = regexp.MustCompile(`^[!#$%&'*+\-.^_` + "`" + `|~0-9A-Za-z]{1,64}$`)

// Remote is one validated, authority-free remote MCP server definition.
type Remote struct {
	Name        string
	URL         string
	AuthKind    string // "", "bearer", "header", or "custody"
	AuthHeader  string // header name when AuthKind == "header"
	AuthRef     string // secret name or custody provider
	Allow       []string
	Deny        []string
	RedactNames []string
}

// Parse validates one comma-separated -mcp-remote specification. Credential
// references are intentionally not resolved here.
func Parse(raw string) (Remote, error) {
	var out Remote
	if len(raw) > MaxSpecBytes {
		return out, fmt.Errorf("MCP remote spec exceeds %d bytes", MaxSpecBytes)
	}
	for _, field := range strings.Split(raw, ",") {
		key, value, ok := strings.Cut(strings.TrimSpace(field), "=")
		if !ok || key == "" || value == "" {
			return out, fmt.Errorf("bad field %q (want k=v)", field)
		}
		switch key {
		case "name":
			out.Name = value
		case "url":
			out.URL = value
		case "auth":
			kind, rest, _ := strings.Cut(value, ":")
			switch kind {
			case "bearer", "custody":
				if rest == "" || strings.Contains(rest, ":") {
					return out, fmt.Errorf("auth=%s: want %s:<name>", kind, kind)
				}
				out.AuthKind, out.AuthRef = kind, rest
			case "header":
				header, ref, found := strings.Cut(rest, ":")
				if !found || header == "" || ref == "" {
					return out, fmt.Errorf("auth=header: want header:<Header-Name>:<secret-name>")
				}
				if !headerNameRE.MatchString(header) {
					return out, fmt.Errorf("auth=header: invalid header name %q", header)
				}
				out.AuthKind, out.AuthHeader, out.AuthRef = kind, header, ref
			default:
				return out, fmt.Errorf("auth: unknown kind %q (want bearer:, header:, or custody:)", kind)
			}
		case "allow":
			out.Allow = append(out.Allow, value)
		case "deny":
			out.Deny = append(out.Deny, value)
		case "redact":
			out.RedactNames = append(out.RedactNames, value)
		default:
			return out, fmt.Errorf("unknown field %q (want name/url/auth/allow/deny/redact)", key)
		}
	}
	if len(out.Allow)+len(out.Deny) > MaxToolPatterns {
		return out, fmt.Errorf("too many allow/deny tool patterns (max %d)", MaxToolPatterns)
	}
	if len(out.RedactNames) > MaxRedactNames {
		return out, fmt.Errorf("too many redact secret names (max %d)", MaxRedactNames)
	}
	if !remoteNameRE.MatchString(out.Name) || strings.Contains(out.Name, "__") {
		return out, fmt.Errorf("name %q must match %s without '__'", out.Name, remoteNameRE)
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
	if out.AuthKind == "bearer" || out.AuthKind == "header" {
		if err := secret.ValidateName(out.AuthRef); err != nil {
			return out, fmt.Errorf("auth: invalid secret reference: %w", err)
		}
	}
	for _, name := range out.RedactNames {
		if err := secret.ValidateName(name); err != nil {
			return out, fmt.Errorf("redact: invalid secret reference: %w", err)
		}
	}
	for _, policy := range []struct {
		name     string
		patterns []string
	}{{"allow", out.Allow}, {"deny", out.Deny}} {
		for _, pattern := range policy.patterns {
			if _, err := path.Match(pattern, ""); err != nil {
				return out, fmt.Errorf("%s: bad tool pattern %q: %w", policy.name, pattern, err)
			}
		}
	}
	return out, nil
}

// String returns the canonical persisted -mcp-remote spelling.
func (remote Remote) String() string {
	fields := []string{"name=" + remote.Name, "url=" + remote.URL}
	switch remote.AuthKind {
	case "bearer", "custody":
		fields = append(fields, "auth="+remote.AuthKind+":"+remote.AuthRef)
	case "header":
		fields = append(fields, "auth=header:"+remote.AuthHeader+":"+remote.AuthRef)
	}
	for _, pattern := range remote.Allow {
		fields = append(fields, "allow="+pattern)
	}
	for _, pattern := range remote.Deny {
		fields = append(fields, "deny="+pattern)
	}
	for _, name := range remote.RedactNames {
		fields = append(fields, "redact="+name)
	}
	return strings.Join(fields, ",")
}
