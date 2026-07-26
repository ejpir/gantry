//go:build linux

package main

import (
	"strings"
	"testing"
)

func TestInsertFlags(t *testing.T) {
	in := []string{"/sbin/crun", "--root", "/run/runc", "--debug", "--log", "/run/bundles/sb/log.json", "--log-format", "json", "create", "--bundle", "/run/bundles/sb", "--pid-file", "/run/bundles/sb/init.pid", "--console-socket", "/tmp/pty/pty.sock", "sb"}
	out := insertFlags(append([]string(nil), in...), true)
	t.Logf("debug=true : %v", out)
	out2 := insertFlags(append([]string(nil), in...), false)
	t.Logf("debug=false: %v", out2)
	if !strings.Contains(strings.Join(out, " "), "--log /dev/console") {
		t.Errorf("debug=true: --log not rewritten: %v", out)
	}
	if !strings.Contains(strings.Join(out2, " "), "--log /run/bundles/sb/log.json") {
		t.Errorf("debug=false: --log must stay: %v", out2)
	}
}
