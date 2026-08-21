package controlcmd

import (
	"fmt"

	"github.com/ejpir/gantry/internal/sandbox/controlproto"
)

// AuditTail reads the sandbox daemon's bounded in-memory trail of
// security-relevant events (credential deliveries and withholds, secret
// source errors, OAuth custody events) over ctl.sock. The trail names
// secrets but never quotes their values.
func AuditTail(name string) ([]string, error) {
	resp, err := controlproto.Call[controlproto.AuditResponse](name, controlproto.Request{
		Op: "audit.tail",
		ID: controlproto.NewRequestID("audit"),
	})
	if err != nil {
		return nil, err
	}
	if resp.Error != "" {
		return nil, fmt.Errorf("audit.tail: %s", resp.Error)
	}
	return resp.Lines, nil
}
