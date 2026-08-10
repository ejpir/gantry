//go:build linux || darwin || windows

package vmm

import (
	"fmt"
	"io"

	"github.com/ejpir/gantry/internal/fusewire"
	"github.com/ejpir/gantry/internal/virtio"
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
	Tag         string
	Handler     fusewire.Handler
	Owner       io.Closer
	Description string
}

func (m *Machine) attachFilesystems(filesystems []Filesystem, inputs *prepareInputs) error {
	for index, filesystem := range filesystems {
		device, err := virtio.NewFS(filesystem.Tag, filesystem.Handler, filesystem.Owner)
		if err != nil {
			return err
		}
		// The device owns Owner from this point. If addVirtio rejects it, the
		// device is closed there; after attachment Machine.Close owns it.
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
