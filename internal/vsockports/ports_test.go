package vsockports

import "testing"

func TestHostSocketNameAllowlist(t *testing.T) {
	for port, want := range map[uint32]string{
		RPCPort:        "1025.sock",
		CredentialPort: "1027.sock",
		MCPPort:        "1029.sock",
	} {
		if got, ok := HostSocketName(port); !ok || got != want {
			t.Errorf("HostSocketName(%d) = (%q, %v), want (%q, true)", port, got, ok, want)
		}
	}
	for _, port := range []uint32{0, 1024, 1026, 1028, 42424, ^uint32(0)} {
		if got, ok := HostSocketName(port); ok || got != "" {
			t.Errorf("HostSocketName(%d) = (%q, %v), want (empty, false)", port, got, ok)
		}
	}
}
