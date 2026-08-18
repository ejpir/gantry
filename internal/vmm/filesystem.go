//go:build linux || darwin || windows

package vmm

import (
	"fmt"
	"io"

	"github.com/ejpir/gantry/internal/fusewire"
	"github.com/ejpir/gantry/internal/virtio"
	"github.com/ejpir/gantry/internal/vmm/boot"
)

// Filesystem is a fully prepared virtio-fs endpoint. The composition layer
// resolves host paths and constructs the request handler; vmm only attaches
// the resulting protocol endpoint to the guest.
//
// Owner is optional. Prepare consumes a non-nil Owner on entry, and the
// resulting Machine closes it with the device. A nil Owner keeps lifecycle
// control with the caller, which is appropriate for supervisor-owned hubs and
// broker clients whose connection is managed by the worker runtime.
type Filesystem struct {
	Tag     string
	Handler fusewire.Handler
	Owner   io.Closer
	// Vhost replaces Handler with a shared-memory virtqueue endpoint. It is
	// mutually exclusive with Handler/Owner and is consumed by Prepare.
	Vhost       *virtio.VhostEndpoint
	Description string
}

func (m *Machine) attachFilesystems(o Opts, inputs *prepareInputs) error {
	for index, filesystem := range o.Filesystems {
		var device virtio.Device
		var err error
		if filesystem.Vhost != nil {
			if filesystem.Handler != nil || filesystem.Owner != nil {
				return fmt.Errorf("virtio-fs %s: vhost endpoint conflicts with handler/owner", filesystem.Tag)
			}
			if m.arch == "amd64" && uint64(len(m.ram)) > boot.LowRAMEnd {
				return fmt.Errorf("virtio-fs %s: vhost shared RAM does not yet support the x86 high-memory hole", filesystem.Tag)
			}
			guestBase := uint64(boot.RAMBase)
			if m.arch == "amd64" {
				guestBase = 0
			}
			device, err = filesystem.Vhost.NewDevice(filesystem.Tag, o.SharedRAM, guestBase, uint64(len(m.ram)))
			if err == nil {
				inputs.takeFile(o.SharedRAM)
			}
		} else {
			device, err = virtio.NewFS(filesystem.Tag, filesystem.Handler, filesystem.Owner)
		}
		if err != nil {
			return err
		}
		// The device owns Owner/Vhost from this point. If addVirtio rejects it,
		// the device is closed there; after attachment Machine.Close owns it.
		inputs.takeFilesystem(index)
		core, err := m.addVirtio(device, "fs")
		if err != nil {
			return err
		}
		description := ""
		if filesystem.Description != "" {
			description = ", " + filesystem.Description
		}
		fmt.Printf("virtio-fs: tag %s @ %#x irq %d%s\n",
			filesystem.Tag, core.Base(), core.IRQ(), description)
	}
	return nil
}
