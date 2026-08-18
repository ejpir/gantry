package sandbox

import (
	"strings"
	"testing"

	"github.com/ejpir/gantry/internal/sandbox/oauthbridge"
)

// oauthCapture drains everything the guest writes but must retain only the
// bounded prefix the callback parser needs, reporting the truncation.
func TestOAuthCaptureRetainsBoundedPrefix(t *testing.T) {
	var capture oauthCapture
	payload := []byte(strings.Repeat("y", oauthbridge.MaxReplayResponseSize+4096))
	if n, err := capture.Write(payload); err != nil || n != len(payload) {
		t.Fatalf("bounded capture write = %d, %v", n, err)
	}
	if !capture.overflow || capture.buf.Len() != oauthbridge.MaxReplayResponseSize {
		t.Fatalf("bounded capture: overflow=%v retained=%d", capture.overflow, capture.buf.Len())
	}
}
