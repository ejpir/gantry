package controlcmd

import (
	"fmt"

	"github.com/ejpir/gantry/internal/sandbox/config"
	"github.com/ejpir/gantry/internal/sandbox/controlproto"
	"github.com/ejpir/gantry/internal/sandbox/layout"
)

// SetResources safely updates both stopped and running sandboxes. A
// live daemon owns sandbox.json through ConfigStore, so running updates must
// cross its control socket instead of opening a competing store in this
// process. The allocation is consumed on the next boot.
func SetResources(name string, memMB uint, vcpus int, processIsolation string) error {
	if err := layout.ValidateName(name); err != nil {
		return err
	}
	if err := config.ValidateSandboxResources(memMB, vcpus); err != nil {
		return err
	}
	if err := config.ValidateProcessIsolation(processIsolation); err != nil {
		return err
	}
	if _, alive := layout.PID(name); alive {
		req := controlproto.Request{
			Op: "resources.set", ID: controlproto.NewRequestID("resources"),
			Resources: &controlproto.ResourceRequest{MemMB: memMB, VCPUs: vcpus, ProcessIsolation: config.NormalizeProcessIsolation(processIsolation)},
		}
		resp, err := controlproto.Call[controlproto.ResourceResponse](name, req)
		if err != nil {
			return err
		}
		if !resp.OK {
			if resp.Error == "" {
				resp.Error = "resource update failed"
			}
			return fmt.Errorf("%s", resp.Error)
		}
		return nil
	}

	store, err := config.LoadConfigStore(layout.Dir(name))
	if err != nil {
		return err
	}
	return store.SetResources(memMB, vcpus, processIsolation)
}
