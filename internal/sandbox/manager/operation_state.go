package manager

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/ejpir/gantry/api/managerapi"
)

type operationPhase uint8

const (
	operationRunning operationPhase = iota
	operationSucceeded
	operationFailed
)

func (phase operationPhase) String() string {
	switch phase {
	case operationRunning:
		return "running"
	case operationSucceeded:
		return "succeeded"
	case operationFailed:
		return "failed"
	default:
		return fmt.Sprintf("operationPhase(%d)", uint8(phase))
	}
}

func (phase operationPhase) terminal() bool {
	return phase == operationSucceeded || phase == operationFailed
}

// operationOwner is the unforgeable completion capability for one admitted
// operation. The wire ID remains stable for polling, while generation rejects
// stale internal updates even if a record is removed or an ID is reused.
type operationOwner struct {
	id         string
	generation uint64
	kind       string
	sandbox    string
}

func (owner operationOwner) ID() string { return owner.id }

// operationRecord is the manager's private state for one wire operation.
// phase is authoritative; Operation.State mirrors it for wire compatibility.
type operationRecord struct {
	managerapi.Operation

	phase          operationPhase
	owner          operationOwner
	idempotencyKey string
	fingerprint    string
}

func (record *operationRecord) transition(next operationPhase) error {
	if record.phase != operationRunning || !next.terminal() {
		return fmt.Errorf("invalid operation transition %s -> %s", record.phase, next)
	}
	record.phase = next
	record.State = next.String()
	return nil
}

type managerIdempotency struct {
	operationID string
	fingerprint string
}

type operationStart struct {
	Operation *managerapi.Operation
	Owner     operationOwner
	Phase     operationPhase
	Replay    bool
}

// operationStore is the sole owner of operation records, idempotency routing,
// and event subscriptions. No caller receives mutable record state.
type operationStore struct {
	mu sync.Mutex

	records        map[string]*operationRecord
	order          []string
	idempotency    map[string]managerIdempotency
	nextGeneration uint64

	subscribers    map[uint64]chan managerapi.Event
	nextSubscriber uint64
	nextEvent      uint64
}

func newOperationStore() operationStore {
	return operationStore{
		records:     make(map[string]*operationRecord),
		idempotency: make(map[string]managerIdempotency),
		subscribers: make(map[uint64]chan managerapi.Event),
	}
}

func (store *operationStore) begin(kind, name, key, fingerprint string) (operationStart, error) {
	if err := validateIdempotencyKey(key); err != nil {
		return operationStart{}, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if key != "" {
		if existing, ok := store.idempotency[key]; ok {
			if existing.fingerprint != fingerprint {
				return operationStart{}, fmt.Errorf("idempotency key was already used for a different request")
			}
			record, ok := store.records[existing.operationID]
			if !ok {
				return operationStart{}, fmt.Errorf("idempotency record expired; use a new key")
			}
			return operationStart{Operation: cloneManagerOperation(record), Phase: record.phase, Replay: true}, nil
		}
	}
	if len(store.records) >= managerMaxOperations && !store.removeOldestCompletedLocked() {
		return operationStart{}, fmt.Errorf("operation capacity is full")
	}
	store.nextGeneration++
	now := time.Now().UTC()
	owner := operationOwner{id: newManagerOperationID(), generation: store.nextGeneration, kind: kind, sandbox: name}
	record := &operationRecord{
		Operation: managerapi.Operation{
			ID: owner.id, Kind: kind, Sandbox: name,
			State: operationRunning.String(), Created: now, Updated: now,
		},
		phase: operationRunning, owner: owner,
		idempotencyKey: key, fingerprint: fingerprint,
	}
	store.records[record.ID] = record
	store.order = append(store.order, record.ID)
	if key != "" {
		store.idempotency[key] = managerIdempotency{operationID: record.ID, fingerprint: fingerprint}
	}
	store.pruneLocked()
	store.publishLocked("operation", record)
	return operationStart{Operation: cloneManagerOperation(record), Owner: owner, Phase: record.phase}, nil
}

func (store *operationStore) ownsIdempotency(owner operationOwner, key string) bool {
	if key == "" {
		return true
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	current, ok := store.idempotency[key]
	return ok && current.operationID == owner.id && store.ownedRunningLocked(owner) != nil
}

func (store *operationStore) mutate(owner operationOwner, update func(*operationRecord)) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	record := store.ownedRunningLocked(owner)
	if record == nil {
		return fmt.Errorf("%w: operation %q is no longer owned by this completion", errOperationCompletionRejected, owner.id)
	}
	update(record)
	record.Updated = time.Now().UTC()
	return nil
}

func (store *operationStore) setWarnings(owner operationOwner, warnings []string) error {
	return store.mutate(owner, func(record *operationRecord) {
		record.Warnings = append([]string(nil), warnings...)
	})
}

func (store *operationStore) setProgress(owner operationOwner, progress string) error {
	if len(progress) > 4096 {
		progress = progress[:4096]
	}
	return store.mutate(owner, func(record *operationRecord) { record.Progress = progress })
}

func (store *operationStore) setConfigure(owner operationOwner, result managerapi.ConfigureSandboxResult) error {
	return store.mutate(owner, func(record *operationRecord) {
		copy := result
		record.Configure = &copy
	})
}

func (store *operationStore) setRun(owner operationOwner, result managerapi.ExecResult) error {
	return store.mutate(owner, func(record *operationRecord) {
		copy := result
		record.Run = &copy
	})
}

func (store *operationStore) finish(owner operationOwner, operationErr error) (*managerapi.Operation, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	record := store.ownedRunningLocked(owner)
	if record == nil {
		return nil, fmt.Errorf("%w: operation %q is stale or already complete", errOperationCompletionRejected, owner.id)
	}
	next := operationSucceeded
	if operationErr != nil {
		next = operationFailed
		record.Error = operationErr.Error()
	}
	if err := record.transition(next); err != nil {
		return nil, err
	}
	record.Updated = time.Now().UTC()
	store.publishLocked("operation", record)
	return cloneManagerOperation(record), nil
}

func (store *operationStore) ownedRunningLocked(owner operationOwner) *operationRecord {
	if owner.id == "" || owner.generation == 0 {
		return nil
	}
	record := store.records[owner.id]
	if record == nil || record.phase != operationRunning || record.owner != owner {
		return nil
	}
	return record
}

func (store *operationStore) operation(id string) (*managerapi.Operation, bool) {
	store.mu.Lock()
	defer store.mu.Unlock()
	record, ok := store.records[id]
	return cloneManagerOperation(record), ok
}

func cloneManagerOperation(record *operationRecord) *managerapi.Operation {
	if record == nil {
		return nil
	}
	clone := record.Operation
	clone.Warnings = append([]string(nil), record.Warnings...)
	if record.Configure != nil {
		result := *record.Configure
		clone.Configure = &result
	}
	if record.Run != nil {
		result := *record.Run
		clone.Run = &result
	}
	return &clone
}

func (store *operationStore) pruneLocked() {
	for len(store.records) > managerMaxOperations {
		if !store.removeOldestCompletedLocked() {
			return
		}
	}
}

func (store *operationStore) removeOldestCompletedLocked() bool {
	for index, id := range store.order {
		record := store.records[id]
		if record != nil && !record.phase.terminal() {
			continue
		}
		store.order = append(store.order[:index], store.order[index+1:]...)
		delete(store.records, id)
		if record != nil && record.idempotencyKey != "" {
			delete(store.idempotency, record.idempotencyKey)
		}
		return true
	}
	return false
}

func (store *operationStore) publishLocked(eventType string, record *operationRecord) {
	store.nextEvent++
	event := managerapi.Event{
		ID: store.nextEvent, Type: eventType, OperationID: record.ID,
		Sandbox: record.Sandbox, State: record.phase.String(), Time: time.Now().UTC(),
	}
	for id, subscriber := range store.subscribers {
		select {
		case subscriber <- event:
		default:
			close(subscriber)
			delete(store.subscribers, id)
		}
	}
}

func (store *operationStore) subscribe() (uint64, <-chan managerapi.Event, func(), bool) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if len(store.subscribers) >= managerMaxSubscribers {
		return 0, nil, nil, false
	}
	store.nextSubscriber++
	id := store.nextSubscriber
	channel := make(chan managerapi.Event, managerEventBuffer)
	store.subscribers[id] = channel
	cancel := func() {
		store.mu.Lock()
		if current, ok := store.subscribers[id]; ok && current == channel {
			delete(store.subscribers, id)
			close(channel)
		}
		store.mu.Unlock()
	}
	return id, channel, cancel, true
}

func (store *operationStore) counts() (records, order, subscribers int) {
	store.mu.Lock()
	defer store.mu.Unlock()
	return len(store.records), len(store.order), len(store.subscribers)
}

func (store *operationStore) runningCount() int {
	store.mu.Lock()
	defer store.mu.Unlock()
	count := 0
	for _, record := range store.records {
		if record.phase == operationRunning {
			count++
		}
	}
	return count
}

func newManagerOperationID() string {
	var entropy [16]byte
	if _, err := rand.Read(entropy[:]); err == nil {
		return hex.EncodeToString(entropy[:])
	}
	return fmt.Sprintf("op-%d", time.Now().UnixNano())
}

var errOperationCompletionRejected = errors.New("operation completion rejected")
