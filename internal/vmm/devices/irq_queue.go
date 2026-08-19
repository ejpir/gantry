package devices

import (
	"fmt"
	"sync"
)

// IRQChange is one interrupt line transition.
type IRQChange struct {
	IRQ   int
	Level bool
}

// SerializedIRQDelivery applies VM-global interrupt line changes synchronously
// and in order. A deferred queue coupled to hv_vcpus_exit has a lost-wakeup
// window: an exit request made while a vCPU is between hv_vcpu_run calls does
// not affect its next entry. Direct GIC injection is the wakeup mechanism for
// SPIs; serialization only prevents concurrent producers from reordering line
// transitions or entering Hypervisor.framework together.
type SerializedIRQDelivery struct {
	mu sync.Mutex
}

func (d *SerializedIRQDelivery) Inject(change IRQChange, set func(irq int, level bool) error) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := set(change.IRQ, change.Level); err != nil {
		return fmt.Errorf("inject IRQ %d level %t: %w", change.IRQ, change.Level, err)
	}
	return nil
}
