package mcpgw

import (
	"fmt"
	"strings"
	"unicode"
)

// Event is the bounded audit vocabulary emitted by the untrusted MCP engine.
// It deliberately cannot carry arguments, results, headers, URLs with paths,
// or credential values. A supervisor validates the event before persisting it.
type Event struct {
	Type   string `json:"type"`
	Server string `json:"server,omitempty"`
	Tool   string `json:"tool,omitempty"`
	Name   string `json:"name,omitempty"`
	Method string `json:"method,omitempty"`
	Origin string `json:"origin,omitempty"`
	Count  int64  `json:"count,omitempty"`
	Count2 int64  `json:"count2,omitempty"`
	Count3 int64  `json:"count3,omitempty"`
}

const (
	EventSessionRejected  = "session-rejected"
	EventSessionOpen      = "session-open"
	EventSessionClosed    = "session-closed"
	EventUpstreamFailed   = "upstream-failed"
	EventUpstreamRemote   = "upstream-remote"
	EventUpstreamStdio    = "upstream-stdio"
	EventUpstreamStopped  = "upstream-stopped"
	EventToolsListFailed  = "tools-list-failed"
	EventToolsMalformed   = "tools-malformed"
	EventToolsServed      = "tools-served"
	EventCallDenied       = "call-denied"
	EventCall             = "call"
	EventCallError        = "call-error"
	EventUpstreamBadFrame = "upstream-bad-frame"
	EventUpstreamBadID    = "upstream-bad-id"
	EventNotificationFail = "notification-failed"
)

// ValidateEvent rejects fields outside the fixed audit schema. allowedServers
// is the immutable supervisor-owned namespace; nil permits constructor tests
// that validate only syntax.
func ValidateEvent(event Event, allowedServers map[string]bool) error {
	serverEvent := false
	switch event.Type {
	case EventSessionRejected, EventSessionOpen, EventSessionClosed, EventToolsServed, EventCallDenied:
	case EventUpstreamFailed, EventUpstreamRemote, EventUpstreamStdio, EventUpstreamStopped,
		EventToolsListFailed, EventToolsMalformed, EventCall, EventCallError,
		EventUpstreamBadFrame, EventUpstreamBadID, EventNotificationFail:
		serverEvent = true
	default:
		return fmt.Errorf("unknown MCP audit event %q", event.Type)
	}
	if serverEvent {
		if !validAuditAtom(event.Server, 31) || strings.Contains(event.Server, "__") {
			return fmt.Errorf("invalid MCP audit server")
		}
		if allowedServers != nil && !allowedServers[event.Server] {
			return fmt.Errorf("unknown MCP audit server %q", event.Server)
		}
	} else if event.Server != "" {
		return fmt.Errorf("MCP audit event %q has an unexpected server", event.Type)
	}
	if event.Tool != "" && !validAuditText(event.Tool, maxToolNameBytes) {
		return fmt.Errorf("invalid MCP audit tool")
	}
	if event.Name != "" && !validAuditText(event.Name, maxToolNameBytes) {
		return fmt.Errorf("invalid MCP audit name")
	}
	if event.Method != "" && !validAuditText(event.Method, maxToolNameBytes) {
		return fmt.Errorf("invalid MCP audit method")
	}
	if event.Origin != "" {
		if len(event.Origin) > 512 || !validAuditText(event.Origin, 512) ||
			(!strings.HasPrefix(event.Origin, "https://") && !strings.HasPrefix(event.Origin, "http://")) ||
			strings.ContainsAny(strings.TrimPrefix(strings.TrimPrefix(event.Origin, "https://"), "http://"), "/?#@") {
			return fmt.Errorf("invalid MCP audit origin")
		}
	}
	for _, count := range []int64{event.Count, event.Count2, event.Count3} {
		if count < 0 || count > 1<<30 {
			return fmt.Errorf("invalid MCP audit count")
		}
	}
	return nil
}

func validAuditAtom(value string, max int) bool {
	if value == "" || len(value) > max {
		return false
	}
	for _, r := range value {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && !strings.ContainsRune("._-*", r) {
			return false
		}
	}
	return true
}

func validAuditText(value string, max int) bool {
	if value == "" || len(value) > max {
		return false
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

// String preserves the existing user-facing audit lines while deriving them
// only from the bounded event fields above.
func (event Event) String() string {
	switch event.Type {
	case EventSessionRejected:
		return fmt.Sprintf("mcp: session rejected (gateway session limit %d)", event.Count)
	case EventSessionOpen:
		return "mcp: session open"
	case EventSessionClosed:
		return fmt.Sprintf("mcp: session closed (%d calls, %d denied)", event.Count, event.Count2)
	case EventUpstreamFailed:
		return fmt.Sprintf("mcp: upstream %s start failed", event.Server)
	case EventUpstreamRemote:
		return fmt.Sprintf("mcp: upstream %s started (remote %s, %d injected headers)", event.Server, event.Origin, event.Count)
	case EventUpstreamStdio:
		return fmt.Sprintf("mcp: upstream %s started (stdio)", event.Server)
	case EventUpstreamStopped:
		return fmt.Sprintf("mcp: upstream %s stopped", event.Server)
	case EventToolsListFailed:
		return fmt.Sprintf("mcp: tools/list on %s failed", event.Server)
	case EventToolsMalformed:
		return fmt.Sprintf("mcp: tools/list on %s: malformed result; skipping server", event.Server)
	case EventToolsServed:
		return fmt.Sprintf("mcp: tools/list served %d tools across %d servers (%d policy-hidden)", event.Count, event.Count2, event.Count3)
	case EventCallDenied:
		return fmt.Sprintf("mcp: denied call %q (policy)", event.Name)
	case EventCall:
		return fmt.Sprintf("mcp: call %s__%s", event.Server, event.Tool)
	case EventCallError:
		return fmt.Sprintf("mcp: call %s__%s upstream error", event.Server, event.Tool)
	case EventUpstreamBadFrame:
		return fmt.Sprintf("mcp: upstream %s sent a non-JSON-RPC frame (%d bytes); killed", event.Server, event.Count)
	case EventUpstreamBadID:
		return fmt.Sprintf("mcp: upstream %s echoed a non-numeric id; killed", event.Server)
	case EventNotificationFail:
		return fmt.Sprintf("mcp: upstream %s notification %s failed", event.Server, event.Method)
	default:
		return "mcp: invalid audit event"
	}
}
