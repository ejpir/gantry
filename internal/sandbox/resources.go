package sandbox

import (
	"encoding/json"
	"fmt"
	"time"
)

// setSandboxResources safely updates both stopped and running sandboxes. A
// live daemon owns sandbox.json through ConfigStore, so running updates must
// cross its control socket instead of opening a competing store in this
// process. The allocation is consumed on the next boot.
func setSandboxResources(name string, memMB uint, vcpus int) error {
	if err := ValidateSandboxName(name); err != nil {
		return err
	}
	if err := validateSandboxResources(memMB, vcpus); err != nil {
		return err
	}
	if _, alive := sandboxPID(name); alive {
		conn, err := dialShareControl(name)
		if err != nil {
			return fmt.Errorf("connect to running sandbox: %w", err)
		}
		defer conn.Close()
		// Same deadline every other ctl.sock client sets: a wedged broker
		// must not hang the CLI forever.
		_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
		req := brokerRequest{
			Op: "resources.set", ID: "resources",
			Resources: &brokerResourceRequest{MemMB: memMB, VCPUs: vcpus},
		}
		if err := json.NewEncoder(conn).Encode(&req); err != nil {
			return err
		}
		var resp brokerResourceResponse
		if err := json.NewDecoder(conn).Decode(&resp); err != nil {
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

	store, err := LoadConfigStore(sandboxDir(name))
	if err != nil {
		return err
	}
	return store.SetResources(memMB, vcpus)
}
