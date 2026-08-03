//go:build linux || darwin

package vmm

import (
	"fmt"

	"gantry/internal/virtio"
)

// addShare attaches one host directory as a virtio-fs device (legacy
// one-shot/raw-run mode).
func (m *Machine) addShare(share Share) error {
	fsdev, err := virtio.NewFS(share.Tag, share.Path, share.RO)
	if err != nil {
		return fmt.Errorf("virtio-fs %s: %w", share.Tag, err)
	}
	core, err := m.addVirtio(fsdev, "fs")
	if err != nil {
		return err
	}
	ro := ""
	if share.RO {
		ro = " (read-only, host-enforced)"
	}
	fmt.Printf("virtio-fs: tag %s host %s @ %#x irq %d%s\n",
		share.Tag, fsdev.Root(), core.Base(), core.IRQ(), ro)
	return nil
}

// addShareHub attaches the persistent sandbox's one multiplexed share device.
func (m *Machine) addShareHub(hub *virtio.ShareHub) error {
	core, err := m.addVirtio(hub, "fs")
	if err != nil {
		return err
	}
	fmt.Printf("virtio-fs: tag %s share hub @ %#x irq %d (%d exports, hot-add enabled)\n",
		hub.Tag(), core.Base(), core.IRQ(), len(hub.Exports()))
	return nil
}
