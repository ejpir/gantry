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
	seen := make(map[string]bool)
	for _, field := range strings.Split(raw, ",") {
		key, value, ok := strings.Cut(strings.TrimSpace(field), "=")
		if !ok || key == "" || value == "" {
			return out, fmt.Errorf("bad field %q (want k=v)", field)
		}
		if (key == "name" || key == "url" || key == "auth") && seen[key] {
			return out, fmt.Errorf("duplicate field %q", key)
		}
		seen[key] = true
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
	if err := Validate(out); err != nil {
		return Remote{}, err
	}
	return out, nil
}

// Validate checks a typed remote without passing its values through the
// comma-separated command-line grammar. Values containing commas are rejected
// because they cannot be represented without becoming new grammar fields.
func Validate(remote Remote) error {
	if len(remote.Allow)+len(remote.Deny) > MaxToolPatterns {
		return fmt.Errorf("too many allow/deny tool patterns (max %d)", MaxToolPatterns)
	}
	if len(remote.RedactNames) > MaxRedactNames {
		return fmt.Errorf("too many redact secret names (max %d)", MaxRedactNames)
	}
	if !remoteNameRE.MatchString(remote.Name) || strings.Contains(remote.Name, "__") {
		return fmt.Errorf("name %q must match %s without '__'", remote.Name, remoteNameRE)
	}
	if remote.Name == "fs" {
		return fmt.Errorf("name %q is reserved for the built-in filesystem server", remote.Name)
	}
	if remote.URL == "" {
		return fmt.Errorf("missing url=")
	}
	if strings.Contains(remote.URL, ",") {
		return fmt.Errorf("url: comma is not allowed")
	}
	if _, err := mcpgw.ValidateRemoteURL(remote.URL); err != nil {
		return fmt.Errorf("url: %w", err)
	}
	switch remote.AuthKind {
	case "":
		if remote.AuthHeader != "" || remote.AuthRef != "" {
			return fmt.Errorf("auth: credential fields require an authentication kind")
		}
	case "bearer", "custody":
		if remote.AuthHeader != "" {
			return fmt.Errorf("auth=%s: header name is not allowed", remote.AuthKind)
		}
		if remote.AuthRef == "" || strings.ContainsAny(remote.AuthRef, ":,") {
			return fmt.Errorf("auth=%s: want %s:<name>", remote.AuthKind, remote.AuthKind)
		}
	case "header":
		if !headerNameRE.MatchString(remote.AuthHeader) {
			return fmt.Errorf("auth=header: invalid header name %q", remote.AuthHeader)
		}
		if remote.AuthRef == "" || strings.Contains(remote.AuthRef, ",") {
			return fmt.Errorf("auth=header: want header:<Header-Name>:<secret-name>")
		}
	default:
		return fmt.Errorf("auth: unknown kind %q (want bearer:, header:, or custody:)", remote.AuthKind)
	}
	if remote.AuthKind == "bearer" || remote.AuthKind == "header" {
		if err := secret.ValidateName(remote.AuthRef); err != nil {
			return fmt.Errorf("auth: invalid secret reference: %w", err)
		}
	}
	for _, name := range remote.RedactNames {
		if strings.Contains(name, ",") {
			return fmt.Errorf("redact: comma is not allowed")
		}
		if err := secret.ValidateName(name); err != nil {
			return fmt.Errorf("redact: invalid secret reference: %w", err)
		}
	}
	for _, policy := range []struct {
		name     string
		patterns []string
	}{{"allow", remote.Allow}, {"deny", remote.Deny}} {
		for _, pattern := range policy.patterns {
			if pattern == "" {
				return fmt.Errorf("%s: empty tool pattern", policy.name)
			}
			if strings.Contains(pattern, ",") {
				return fmt.Errorf("%s: comma is not allowed", policy.name)
			}
			if _, err := path.Match(pattern, ""); err != nil {
				return fmt.Errorf("%s: bad tool pattern %q: %w", policy.name, pattern, err)
			}
		}
	}
	if len(encode(remote)) > MaxSpecBytes {
		return fmt.Errorf("MCP remote spec exceeds %d bytes", MaxSpecBytes)
	}
	return nil
}

// Encode validates a typed remote and returns its canonical persisted spelling.
func Encode(remote Remote) (string, error) {
	if err := Validate(remote); err != nil {
		return "", err
	}
	return encode(remote), nil
}

func encode(remote Remote) string {
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
