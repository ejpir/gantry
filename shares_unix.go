//go:build linux || darwin

package main

import "fmt"

// addShare attaches one host directory as a virtio-fs device.
func (m *machine) addShare(share hostShare) error {
	fsdev, err := newVirtioFS(share.tag, share.path, share.ro)
	if err != nil {
		return fmt.Errorf("virtio-fs %s: %w", share.tag, err)
	}
	core, err := m.addVirtio(fsdev, "fs")
	if err != nil {
		return err
	}
	fsdev.core = core
	ro := ""
	if share.ro {
		ro = " (read-only, host-enforced)"
	}
	fmt.Printf("virtio-fs: tag %s host %s @ %#x irq %d%s\n",
		share.tag, fsdev.root, core.base, core.irq, ro)
	return nil
}
