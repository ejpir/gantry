//go:build windows

package devices

// setDeliver connects the userspace PIC to WHPX after the backend is ready.
// Linux uses the kernel's PIC and therefore has no delivery callback to set.
func (p *PIC8259) SetDeliver(deliver func(vector uint32)) {
	p.mu.Lock()
	p.deliver = deliver
	vector, fire := p.dispatchLocked()
	p.mu.Unlock()
	if fire && deliver != nil {
		deliver(vector)
	}
}
