package operationstate

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/ejpir/gantry/api/managerapi"
)

type Phase uint8

const (
	Running Phase = iota
	Succeeded
	Failed
)

func (phase Phase) String() string {
	switch phase {
	case Running:
		return "running"
	case Succeeded:
		return "succeeded"
	case Failed:
		return "failed"
	default:
		return fmt.Sprintf("Phase(%d)", uint8(phase))
	}
}

func (phase Phase) terminal() bool {
	return phase == Succeeded || phase == Failed
}

// Owner is the unforgeable completion capability for one admitted
// operation. The wire ID remains stable for polling, while generation rejects
// stale internal updates even if a record is removed or an ID is reused.
type Owner struct {
	id         string
	generation uint64
	kind       string
	sandbox    string
}

func (owner Owner) ID() string      { return owner.id }
func (owner Owner) Kind() string    { return owner.kind }
func (owner Owner) Sandbox() string { return owner.sandbox }

// record is the manager's private state for one wire operation.
// phase is authoritative; Operation.State mirrors it for wire compatibility.
type record struct {
	managerapi.Operation

	phase          Phase
	owner          Owner
	idempotencyKey string
	fingerprint    string
}

func (record *record) transition(next Phase) error {
	if record.phase != Running || !next.terminal() {
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

type Start struct {
	Operation *managerapi.Operation
	Owner     Owner
	Phase     Phase
	Replay    bool
}

// Store is the sole owner of operation records, idempotency routing,
// and event subscriptions. No caller receives mutable record state.
type Store struct {
	mu sync.Mutex

	records        map[string]*record
	order          []string
	idempotency    map[string]managerIdempotency
	nextGeneration uint64

	subscribers    map[uint64]chan managerapi.Event
	nextSubscriber uint64
	nextEvent      uint64

	maxOperations  int
	maxSubscribers int
	eventBuffer    int
}

func New(maxOperations, maxSubscribers, eventBuffer int) *Store {
	if maxOperations < 1 || maxSubscribers < 1 || eventBuffer < 1 {
		panic("operationstate: limits must be positive")
	}
	return &Store{
		records: make(map[string]*record), idempotency: make(map[string]managerIdempotency),
		subscribers:   make(map[uint64]chan managerapi.Event),
		maxOperations: maxOperations, maxSubscribers: maxSubscribers, eventBuffer: eventBuffer,
	}
}

func (store *Store) Begin(kind, name, key, fingerprint string) (Start, error) {
	if err := validateIdempotencyKey(key); err != nil {
		return Start{}, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if key != "" {
		if existing, ok := store.idempotency[key]; ok {
			if existing.fingerprint != fingerprint {
				return Start{}, fmt.Errorf("idempotency key was already used for a different request")
			}
			record, ok := store.records[existing.operationID]
			if !ok {
				return Start{}, fmt.Errorf("idempotency record expired; use a new key")
			}
			return Start{Operation: cloneOperation(record), Phase: record.phase, Replay: true}, nil
		}
	}
	if len(store.records) >= store.maxOperations && !store.removeOldestCompletedLocked() {
		return Start{}, fmt.Errorf("operation capacity is full")
	}
	store.nextGeneration++
	now := time.Now().UTC()
	owner := Owner{id: newOperationID(), generation: store.nextGeneration, kind: kind, sandbox: name}
	record := &record{
		Operation: managerapi.Operation{
			ID: owner.id, Kind: kind, Sandbox: name,
			State: Running.String(), Created: now, Updated: now,
		},
		phase: Running, owner: owner,
		idempotencyKey: key, fingerprint: fingerprint,
	}
	store.records[record.ID] = record
	store.order = append(store.order, record.ID)
	if key != "" {
		store.idempotency[key] = managerIdempotency{operationID: record.ID, fingerprint: fingerprint}
	}
	store.pruneLocked()
	store.publishLocked("operation", record)
	return Start{Operation: cloneOperation(record), Owner: owner, Phase: record.phase}, nil
}

func (store *Store) OwnsIdempotency(owner Owner, key string) bool {
	if key == "" {
		return true
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	current, ok := store.idempotency[key]
	return ok && current.operationID == owner.id && store.ownedRunningLocked(owner) != nil
}

func (store *Store) mutate(owner Owner, update func(*record)) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	record := store.ownedRunningLocked(owner)
	if record == nil {
		return fmt.Errorf("%w: operation %q is no longer owned by this completion", ErrCompletionRejected, owner.id)
	}
	update(record)
	record.Updated = time.Now().UTC()
	return nil
}

func (store *Store) SetWarnings(owner Owner, warnings []string) error {
	return store.mutate(owner, func(record *record) {
		record.Warnings = append([]string(nil), warnings...)
	})
}

func (store *Store) SetProgress(owner Owner, progress string) error {
	if len(progress) > 4096 {
		progress = progress[:4096]
	}
	return store.mutate(owner, func(record *record) { record.Progress = progress })
}

func (store *Store) SetConfigure(owner Owner, result managerapi.ConfigureSandboxResult) error {
	return store.mutate(owner, func(record *record) {
		copy := result
		record.Configure = &copy
	})
}

func (store *Store) SetRun(owner Owner, result managerapi.ExecResult) error {
	return store.mutate(owner, func(record *record) {
		copy := result
		record.Run = &copy
	})
}

func (store *Store) Finish(owner Owner, operationErr error) (*managerapi.Operation, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	record := store.ownedRunningLocked(owner)
	if record == nil {
		return nil, fmt.Errorf("%w: operation %q is stale or already complete", ErrCompletionRejected, owner.id)
	}
	next := Succeeded
	if operationErr != nil {
		next = Failed
		record.Error = operationErr.Error()
	}
	if err := record.transition(next); err != nil {
		return nil, err
	}
	record.Updated = time.Now().UTC()
	store.publishLocked("operation", record)
	return cloneOperation(record), nil
}

func (store *Store) ownedRunningLocked(owner Owner) *record {
	if owner.id == "" || owner.generation == 0 {
		return nil
	}
	record := store.records[owner.id]
	if record == nil || record.phase != Running || record.owner != owner {
		return nil
	}
	return record
}

func (store *Store) Operation(id string) (*managerapi.Operation, bool) {
	store.mu.Lock()
	defer store.mu.Unlock()
	record, ok := store.records[id]
	return cloneOperation(record), ok
}

func cloneOperation(record *record) *managerapi.Operation {
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

func (store *Store) pruneLocked() {
	for len(store.records) > store.maxOperations {
		if !store.removeOldestCompletedLocked() {
			return
		}
	}
}

func (store *Store) removeOldestCompletedLocked() bool {
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

func (store *Store) publishLocked(eventType string, record *record) {
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

func (store *Store) Subscribe() (uint64, <-chan managerapi.Event, func(), bool) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if len(store.subscribers) >= store.maxSubscribers {
		return 0, nil, nil, false
	}
	store.nextSubscriber++
	id := store.nextSubscriber
	channel := make(chan managerapi.Event, store.eventBuffer)
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

type Stats struct {
	Records     int
	Order       int
	Subscribers int
	Running     int
}

func (store *Store) Stats() Stats {
	store.mu.Lock()
	defer store.mu.Unlock()
	stats := Stats{Records: len(store.records), Order: len(store.order), Subscribers: len(store.subscribers)}
	for _, record := range store.records {
		if record.phase == Running {
			stats.Running++
		}
	}
	return stats
}

func validateIdempotencyKey(key string) error {
	if key == "" {
		return nil
	}
	if len(key) > 128 {
		return fmt.Errorf("idempotency key exceeds 128 bytes")
	}
	for _, character := range key {
		if character < 0x21 || character > 0x7e {
			return fmt.Errorf("idempotency key must contain printable non-space ASCII")
		}
	}
	return nil
}

func newOperationID() string {
	var entropy [16]byte
	if _, err := rand.Read(entropy[:]); err == nil {
		return hex.EncodeToString(entropy[:])
	}
	return fmt.Sprintf("op-%d", time.Now().UnixNano())
}

var ErrCompletionRejected = errors.New("operation completion rejected")
