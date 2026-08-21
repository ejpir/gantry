//go:build !linux

package main

import (
	"fmt"

	"github.com/ejpir/gantry/internal/sandbox/credhelper/credproto"
)

// askBroker is unreachable outside the guest VM; the stub keeps host
// builds (and `go build ./...` on developer machines) clean.
func askBroker(string, string) (credproto.Response, error) {
	return credproto.Response{}, fmt.Errorf("credential broker is only reachable from inside a gantry guest")
}
