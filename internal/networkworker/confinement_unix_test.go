//go:build linux || darwin

package networkworker

import (
	"testing"

	"github.com/ejpir/gantry/internal/workerconf"
)

func TestRequiredConfinementPropertiesArePlatformSpecific(t *testing.T) {
	has := func(items []string, want string) bool {
		for _, item := range items {
			if item == want {
				return true
			}
		}
		return false
	}
	linux := RequiredConfinementProperties("linux")
	if !has(linux, workerconf.PropFDTable) || !has(linux, workerconf.PropSyscall) || !has(linux, workerconf.PropLandlock) || !has(linux, workerconf.PropProcEnum) || !has(linux, workerconf.PropTaskLimit) || has(linux, workerconf.PropProcSignal) {
		t.Fatalf("Linux required properties = %v", linux)
	}
	darwin := RequiredConfinementProperties("darwin")
	if !has(darwin, workerconf.PropProcSignal) || !has(darwin, workerconf.PropProcEnum) || has(darwin, workerconf.PropLandlock) || has(darwin, workerconf.PropTaskLimit) {
		t.Fatalf("Darwin required properties = %v", darwin)
	}
}
