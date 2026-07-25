//go:build linux || darwin

package main

import "fmt"

// addShare attaches one host directory as a virtio-fs device.
func (m *machine) addShare(share hostShare) error {
	fsdev, err := newVirtioFS(share.tag, share.path)
	if err != nil {
		return fmt.Errorf("virtio-fs %s: %w", share.tag, err)
	}
	core := m.addVirtio(fsdev, "fs")
	fsdev.core = core
	ro := ""
	if share.ro {
		ro = " (guest mounts read-only)"
	}
	fmt.Printf("virtio-fs: tag %s host %s @ %#x irq %d%s\n",
		share.tag, fsdev.root, core.base, core.irq, ro)
	return nil
}
