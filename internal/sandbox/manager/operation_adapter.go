package manager

import (
	"crypto/sha256"
	"sync"

	"github.com/ejpir/gantry/api/managerapi"
	"github.com/ejpir/gantry/internal/sandbox/manager/operationstate"
)

func (m *managerService) sandboxLock(name string) *sync.RWMutex {
	digest := sha256.Sum256([]byte(name))
	return &m.sandboxLocks[int(digest[0])%len(m.sandboxLocks)]
}

func (m *managerService) beginOperation(kind, name, key, fingerprint string) (operationstate.Start, error) {
	if m.runtime.Context().Err() != nil {
		return operationstate.Start{}, errManagerStopping
	}
	return m.operationState.Begin(kind, name, key, fingerprint)
}

func (m *managerService) finishOperation(owner operationstate.Owner, operationErr error) *managerapi.Operation {
	operation, err := m.operationState.Finish(owner, operationErr)
	if err == nil {
		return operation
	}
	if current, ok := m.operationState.Operation(owner.ID()); ok {
		return current
	}
	return &managerapi.Operation{ID: owner.ID(), Kind: owner.Kind(), Sandbox: owner.Sandbox(), State: operationstate.Failed.String(), Error: err.Error()}
}

func (m *managerService) operation(id string) (*managerapi.Operation, bool) {
	return m.operationState.Operation(id)
}

func (m *managerService) subscribe() (uint64, <-chan managerapi.Event, func(), bool) {
	return m.operationState.Subscribe()
}
