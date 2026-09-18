package netpol

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/ejpir/gantry/internal/atomicfile"
)

type trafficWriteFunc func(path string, data []byte) error

// trafficPersistence serializes publication attempts. It borrows the aggregate
// and never closes it; a failed write restores the dirty marker so the next
// periodic or final flush retries the newest complete snapshot.
type trafficPersistence struct {
	mu    sync.Mutex
	path  string
	store *trafficStore
	write trafficWriteFunc
}

func newTrafficPersistence(path string, store *trafficStore, write trafficWriteFunc) *trafficPersistence {
	if path == "" {
		return nil
	}
	return &trafficPersistence{path: path, store: store, write: write}
}

func (p *trafficPersistence) flush() {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	snapshot, dirty := p.store.takeDirtySnapshot(time.Now())
	if !dirty {
		return
	}
	data, err := json.Marshal(snapshot)
	if err == nil {
		err = p.write(p.path, append(data, '\n'))
	}
	if err != nil {
		p.store.markDirty()
	}
}

// ReadTrafficSnapshot loads a snapshot without starting a recorder. A missing
// file is an empty snapshot, which keeps stopped and never-networked sandboxes
// inexpensive to render.
func ReadTrafficSnapshot(path string) (TrafficSnapshot, error) {
	var snapshot TrafficSnapshot
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return TrafficSnapshot{Version: trafficSnapshotVersion}, nil
	}
	if err != nil {
		return snapshot, err
	}
	if err := json.Unmarshal(data, &snapshot); err != nil {
		return TrafficSnapshot{}, err
	}
	if snapshot.Version != trafficSnapshotVersion {
		return TrafficSnapshot{}, nil
	}
	return snapshot, nil
}

func loadTrafficSnapshot(path string) TrafficSnapshot {
	initial := TrafficSnapshot{Version: trafficSnapshotVersion}
	if path == "" {
		return initial
	}
	snapshot, err := ReadTrafficSnapshot(path)
	if err == nil && snapshot.Version == trafficSnapshotVersion {
		return snapshot
	}
	return initial
}

func writeTrafficSnapshot(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return atomicfile.WriteFile(path, data, 0o600)
}
