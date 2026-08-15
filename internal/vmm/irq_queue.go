package vmm

import (
	"fmt"
	"sync"
)

type irqChange struct {
	irq   int
	level bool
}

// serializedIRQQueue preserves line-change order across concurrent vCPU run
// loops without blocking producers while a Hypervisor.framework call is in
// progress. applyMu prevents a newer batch from being injected before an older
// one, while pendingMu remains available to the completion goroutine so it can
// enqueue the next line change and kick vCPUs out of hv_vcpu_run.
type serializedIRQQueue struct {
	applyMu   sync.Mutex
	pendingMu sync.Mutex
	pending   []irqChange
}

func (q *serializedIRQQueue) push(change irqChange) {
	q.pendingMu.Lock()
	q.pending = append(q.pending, change)
	q.pendingMu.Unlock()
}

func (q *serializedIRQQueue) apply(set func(irq int, level bool) error) error {
	q.applyMu.Lock()
	defer q.applyMu.Unlock()

	for {
		q.pendingMu.Lock()
		pending := q.pending
		q.pending = nil
		q.pendingMu.Unlock()
		if len(pending) == 0 {
			return nil
		}
		for index, change := range pending {
			if err := set(change.irq, change.level); err != nil {
				return fmt.Errorf("apply IRQ change %d/%d: %w", index+1, len(pending), err)
			}
		}
	}
}
