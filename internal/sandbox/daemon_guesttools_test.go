package sandbox

import (
	"testing"
	"time"

	"github.com/ejpir/gantry/internal/sandbox/config"
)

func TestMCPReadyTimeoutCoversBothGuestToolDeliveryAttempts(t *testing.T) {
	if got := sandboxDaemonReadyTimeout(config.RunConfig{}); got != defaultSandboxDaemonReadyTimeout {
		t.Fatalf("ordinary ready timeout = %s, want %s", got, defaultSandboxDaemonReadyTimeout)
	}
	got := sandboxDaemonReadyTimeout(config.RunConfig{MCP: true})
	if wantMin := 2*guestToolsTimeout + time.Second; got < wantMin {
		t.Fatalf("MCP ready timeout = %s, want at least %s", got, wantMin)
	}
}

func TestParseGuestToolsVerificationIgnoresSessionDiagnostics(t *testing.T) {
	const wantSum = "e6a4c87f683ab0c07fd85517986f5a488c5359b19b1314546ec2d12a2e76bb23"
	transcript := []byte("client: task started — shell is live\n" +
		"client: bytes sha256 task\n" +
		"GANTRY_GUEST_TOOLS_VERIFY 2556066 " + wantSum + "\n" +
		"client: task exited, status 0\n")
	size, sum := parseGuestToolsVerification(transcript)
	if size != "2556066" || sum != wantSum {
		t.Fatalf("verification = (%q, %q), want (%q, %q)", size, sum, "2556066", wantSum)
	}
}

func TestParseGuestToolsVerificationRequiresTaggedValidDigest(t *testing.T) {
	transcript := []byte("2556066\n" +
		"e6a4c87f683ab0c07fd85517986f5a488c5359b19b1314546ec2d12a2e76bb23  /run/gantry/bin/gantry-guest\n" +
		"GANTRY_GUEST_TOOLS_VERIFY 2556066 not-a-digest\n")
	size, sum := parseGuestToolsVerification(transcript)
	if size != "" || sum != "" {
		t.Fatalf("verification = (%q, %q), want invalid record rejected", size, sum)
	}
}
