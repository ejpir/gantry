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
// loops. The setter remains under mu deliberately: taking a batch and then
// applying it after unlocking lets another vCPU apply a newer batch first,
// which can turn assert/deassert into deassert/assert and lose a level IRQ.
type serializedIRQQueue struct {
	mu      sync.Mutex
	pending []irqChange
}

func (q *serializedIRQQueue) push(change irqChange) {
	q.mu.Lock()
	q.pending = append(q.pending, change)
	q.mu.Unlock()
}

func (q *serializedIRQQueue) apply(set func(irq int, level bool) error) error {
	q.mu.Lock()
	defer q.mu.Unlock()

	pending := q.pending
	q.pending = nil
	for index, change := range pending {
		if err := set(change.irq, change.level); err != nil {
			return fmt.Errorf("apply IRQ change %d/%d: %w", index+1, len(pending), err)
		}
	}
	return nil
}
