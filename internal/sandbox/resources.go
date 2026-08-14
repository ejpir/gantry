package sandbox

import "fmt"

// setSandboxResources safely updates both stopped and running sandboxes. A
// live daemon owns sandbox.json through ConfigStore, so running updates must
// cross its control socket instead of opening a competing store in this
// process. The allocation is consumed on the next boot.
func setSandboxResources(name string, memMB uint, vcpus int, processIsolation string) error {
	if err := ValidateSandboxName(name); err != nil {
		return err
	}
	if err := validateSandboxResources(memMB, vcpus); err != nil {
		return err
	}
	if err := validateProcessIsolation(processIsolation); err != nil {
		return err
	}
	if _, alive := sandboxPID(name); alive {
		req := brokerRequest{
			Op: "resources.set", ID: newControlRequestID("resources"),
			Resources: &brokerResourceRequest{MemMB: memMB, VCPUs: vcpus, ProcessIsolation: normalizedProcessIsolation(processIsolation)},
		}
		resp, err := callControl[brokerResourceResponse](name, req)
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

	store, err := LoadConfigStore(sandboxDir(name))
	if err != nil {
		return err
	}
	return store.SetResources(memMB, vcpus, processIsolation)
}
