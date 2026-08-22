package mcpworker

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestConfigRejectsUnknownBootstrapFields(t *testing.T) {
	for _, raw := range []string{
		`{"version":1,"confinement":"off","servers":[],"hostPath":"/"}`,
		`{"version":1,"confinement":"off","servers":[{"name":"fs","local":true,"argv":["sh"]}]}`,
	} {
		var config Config
		if err := json.Unmarshal([]byte(raw), &config); err == nil || !strings.Contains(err.Error(), "unknown field") {
			t.Fatalf("config accepted unknown field: %s (%v)", raw, err)
		}
	}
}

func TestOpenRequestHasNoAuthorityFields(t *testing.T) {
	typeShape, _ := json.Marshal(OpenRequest{Kind: StreamRemote, Server: "remote", Session: strings.Repeat("0", 32)})
	for _, forbidden := range []string{"url", "address", "host", "port", "argv", "path", "credential", "sandbox"} {
		if strings.Contains(string(typeShape), forbidden) {
			t.Fatalf("open request carries %q authority: %s", forbidden, typeShape)
		}
	}
}
