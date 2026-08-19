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
		return setResourcesLive(name, memMB, vcpus, processIsolation)
	}

	// A daemon may be mid-boot between our liveness check and the store
	// write: it reads sandbox.json while its launcher holds the launch lock,
	// and it would never observe an allocation persisted in that window (the
	// user is told the new resources saved while the machine boots with the
	// old ones). Same serialization as SetNetworkPolicy's stopped path.
	lock, err := layout.HoldLaunchLock(name)
	if err != nil {
		if _, alive := layout.PID(name); alive {
			return setResourcesLive(name, memMB, vcpus, processIsolation)
		}
		return fmt.Errorf("sandbox %q is launching; retry the resource update when it is up or fully stopped", name)
	}
	defer func() { _ = lock.Close() }()
	if _, alive := layout.PID(name); alive {
		return setResourcesLive(name, memMB, vcpus, processIsolation)
	}

	store, err := config.LoadConfigStore(layout.Dir(name))
	if err != nil {
		return err
	}
	return store.SetResources(memMB, vcpus, processIsolation)
}

// setResourcesLive routes the update through the daemon's control socket. It
// passes the mode through unchanged: ConfigStore.SetResources already
// normalizes and treats "" as "preserve the stored value", exactly like the
// stopped-sandbox path. Normalizing here would turn "keep" into "auto" for
// running sandboxes only.
func setResourcesLive(name string, memMB uint, vcpus int, processIsolation string) error {
	req := controlproto.Request{
		Op: "resources.set", ID: controlproto.NewRequestID("resources"),
		Resources: &controlproto.ResourceRequest{MemMB: memMB, VCPUs: vcpus, ProcessIsolation: processIsolation},
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
