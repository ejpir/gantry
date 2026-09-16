package dashboardsvc

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	dashboardapi "github.com/ejpir/gantry/internal/dashboard/api"
	"github.com/ejpir/gantry/internal/sandbox/config"
	"github.com/ejpir/gantry/internal/sandbox/controlproto"
	"github.com/ejpir/gantry/internal/sandbox/layout"
)

const auditTestDecision = `policy: {"effect":"deny","action":"mcp.tools.call","reason":"no_match","organization":"org","revision":"rev-1","profile":"dev","rules":["blocked-tool"]}`

func TestDashboardAuditRows(t *testing.T) {
	lines := []string{"credential withheld: TOKEN", auditTestDecision, auditTestDecision, "policy: {truncated", " ", `policy: {"effect":"unknown","action":"mount.read"}`}
	rows := dashboardAuditRows("dev", lines)
	if len(rows) != 5 || rows[0].Line != lines[5] || rows[1].Line != lines[3] || rows[4].Line != lines[0] {
		t.Fatalf("newest-first rows = %+v", rows)
	}
	if rows[0].Decision != nil || rows[1].Decision != nil || rows[4].Decision != nil {
		t.Fatal("unrecognized/truncated event was assigned a policy effect")
	}
	if rows[2].Occurrence != 0 || rows[3].Occurrence != 1 {
		t.Fatal("duplicate events were collapsed")
	}
	d := rows[2].Decision
	if d == nil || d.Effect != "deny" || d.Action != "mcp.tools.call" || d.Reason != "no_match" || d.Organization != "org" || d.Revision != "rev-1" || d.Profile != "dev" || len(d.Rules) != 1 || d.Rules[0] != "blocked-tool" {
		t.Fatalf("decision provenance = %+v", d)
	}
	allowed := dashboardAuditRows("dev", []string{strings.Replace(auditTestDecision, `"deny"`, `"allow"`, 1)})
	if allowed[0].Decision == nil || allowed[0].Decision.Effect != "allow" {
		t.Fatal("allow decision was not recognized")
	}
	for _, row := range rows {
		if row.Sandbox != "dev" || row.Error != "" {
			t.Fatalf("event attribution = %+v", row)
		}
	}
}

func TestDashboardAuditBounds(t *testing.T) {
	var lines []string
	for i := range 300 {
		lines = append(lines, fmt.Sprintf("event %d", i))
	}
	rows := dashboardAuditRows("dev", lines)
	if len(rows) != 256 || rows[0].Line != "event 299" || rows[255].Line != "event 44" {
		t.Fatal("tail count/order not bounded")
	}
	rows = dashboardAuditRows("dev", []string{"policy: " + strings.Repeat("x", 1<<20)})
	if len(rows[0].Line) > 4200 || !strings.HasSuffix(rows[0].Line, "[audit line truncated]") || rows[0].Decision != nil {
		t.Fatal("oversized line not bounded or assigned a policy effect")
	}
}

func TestDashboardSnapshotLoadsStoppedAudit(t *testing.T) {
	t.Setenv("GANTRY_HOME", t.TempDir())
	t.Setenv("GANTRY_IMAGES", t.TempDir())
	for _, name := range []string{"alpha", "broken", "empty"} {
		if err := os.MkdirAll(layout.Dir(name), 0o700); err != nil {
			t.Fatal(err)
		}
		writeDashboardTestConfig(t, name, config.RunConfig{})
	}
	// Audit stays available even if the sandbox configuration is broken.
	if err := os.WriteFile(filepath.Join(layout.Dir("broken"), "sandbox.json"), []byte("invalid"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"alpha", "broken"} {
		if err := os.WriteFile(filepath.Join(layout.Dir(name), "audit.log"), []byte("credential withheld: TOKEN\n"+auditTestDecision+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	data, err := loadDashboardSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if len(data.Audit) != 4 || data.Audit[0].Sandbox != "alpha" || data.Audit[2].Sandbox != "broken" {
		t.Fatalf("stopped audit = %+v", data.Audit)
	}
	if data.Audit[0].Decision == nil || data.Audit[0].Error != "" || data.Audit[2].Decision == nil {
		t.Fatal("stopped policy decisions lost")
	}
	for _, row := range data.Audit {
		if row.Sandbox == "empty" {
			t.Fatal("missing audit.log should be empty, not an error")
		}
	}
	if err := os.Mkdir(filepath.Join(layout.Dir("empty"), "audit.log"), 0o700); err != nil {
		t.Fatal(err)
	}
	rows := loadDashboardAudit(dashboardapi.Sandbox{Name: "empty", State: dashboardapi.Stopped})
	if len(rows) != 1 || rows[0].Error == "" || rows[0].Sandbox != "empty" {
		t.Fatal("unreadable/invalid audit log should produce an attributed error row")
	}
}

func TestDashboardAuditLive(t *testing.T) {
	// Keep Unix-domain socket paths short, including on Windows.
	root, err := os.MkdirTemp("", "gda-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	t.Setenv("GANTRY_HOME", root)
	if err := os.MkdirAll(layout.Dir("dev"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(layout.Dir("dev"), "audit.log"), []byte("disk-only event\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, reply := range []controlproto.AuditResponse{{Lines: []string{auditTestDecision}}, {Error: "audit temporarily unavailable"}} {
		listener, err := net.Listen("unix", filepath.Join(layout.Dir("dev"), "ctl.sock"))
		if err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() {
			conn, err := listener.Accept()
			if err != nil {
				done <- err
				return
			}
			defer func() { _ = conn.Close() }()
			if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
				done <- err
				return
			}
			var request controlproto.Request
			if err := json.NewDecoder(conn).Decode(&request); err != nil {
				done <- err
				return
			}
			if request.Op != "audit.tail" {
				done <- fmt.Errorf("unexpected operation %q", request.Op)
				return
			}
			done <- json.NewEncoder(conn).Encode(reply)
		}()
		rows := loadDashboardAudit(dashboardapi.Sandbox{Name: "dev", State: dashboardapi.Running})
		_ = listener.Close()
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		if len(rows) != 1 {
			t.Fatalf("live audit rows = %+v", rows)
		}
		if reply.Error == "" && (rows[0].Decision == nil || rows[0].Line == "disk-only event") {
			t.Fatal("live trail did not take precedence over disk")
		}
		if reply.Error != "" && !strings.Contains(rows[0].Error, reply.Error) {
			t.Fatalf("broker error not surfaced: %+v", rows[0])
		}
	}
}
