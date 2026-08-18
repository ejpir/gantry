package control

import (
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"sync"

	"github.com/ejpir/gantry/internal/atomicfile"
	"github.com/ejpir/gantry/internal/sandbox/config"
	"github.com/ejpir/gantry/internal/vnet"
)

// PortManager owns host→guest port publishing for one running sandbox:
// live listeners in the network backend plus the desired set persisted
// in sandbox.json (replayed at every boot as static forwards). Mutations
// go live first, persist second, and roll the live side back if the write
// fails — a crashed publish never leaves a phantom listener behind.
//
// The backend is the embedded netstack in-process (monolithic mode) or
// the split network worker over RPC; the transaction shape is identical.
//
// Persistence goes through the broker-owned ConfigStore, so a port publish
// can never clobber a concurrent (or earlier) share mutation: both managers
// always mutate the latest configuration, under one lock.
type PortManager struct {
	store   *config.ConfigStore
	backend NetworkBackend // nil: ports unavailable (gvproxy backend or -net=false)

	mu sync.Mutex
}

// PortEntry is one mapping as reported to the CLI/TUI: bound (listener
// active in the netstack) or saved (desired, applies at next boot).
type PortEntry struct {
	Mapping config.PortMapping `json:"mapping"`
	State   string             `json:"state"` // "bound" | "saved"
}

// NewPortManager binds the manager to the sandbox's network backend;
// backend may be nil (ports then report unavailable, listing still shows
// the saved set).
func NewPortManager(store *config.ConfigStore, backend NetworkBackend) *PortManager {
	return &PortManager{store: store, backend: backend}
}

var errPortsUnavailable = fmt.Errorf("port publishing requires the embedded netstack and networking enabled")

// Publish opens the listener now; persistent also records the mapping in
// sandbox.json so stop/start cycles re-apply it.
func (m *PortManager) Publish(spec string, persistent bool) (PortEntry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.backend == nil {
		return PortEntry{}, errPortsUnavailable
	}
	normalized, err := config.NormalizePortSpec(spec)
	if err != nil {
		return PortEntry{}, err
	}
	mapping, _ := config.ParsePortSpec(normalized)
	live, err := m.backend.Forwards()
	if err != nil {
		return PortEntry{}, err
	}
	for _, f := range live {
		if forwardMapping(f).Key() == mapping.Key() {
			return PortEntry{}, fmt.Errorf("%s is already published", mapping.Short())
		}
	}
	if err := m.backend.Publish(mapping.Proto, mapping.Local(), mapping.Remote()); err != nil {
		return PortEntry{}, err
	}
	if persistent {
		if err := m.store.Mutate(func(cfg *config.RunConfig) error {
			cfg.Ports = append(cfg.Ports, normalized)
			return nil
		}); err != nil {
			if atomicfile.Committed(err) {
				return PortEntry{Mapping: mapping, State: "bound"},
					fmt.Errorf("published port configuration committed but durability is uncertain: %w", err)
			}
			rollbackErr := m.backend.Unpublish(mapping.Proto, mapping.Local())
			if rollbackErr != nil {
				rollbackErr = fmt.Errorf("rollback published listener: %w", rollbackErr)
			}
			return PortEntry{}, errors.Join(err, rollbackErr)
		}
	}
	return PortEntry{Mapping: mapping, State: "bound"}, nil
}

// Unpublish tears a mapping down by its host-side identity; persistent
// also drops it from the saved set. A saved-but-unbound mapping
// (persistence drift) is still removed without touching the netstack.
func (m *PortManager) Unpublish(spec string, persistent bool) (PortEntry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.backend == nil {
		return PortEntry{}, errPortsUnavailable
	}
	mapping, err := config.ParsePortSpec(spec)
	if err != nil {
		return PortEntry{}, err
	}
	if mapping.HostPort == 0 {
		return PortEntry{}, fmt.Errorf("unpublish needs the concrete host port (see: gantry ports ls)")
	}
	bound := false
	live, err := m.backend.Forwards()
	if err != nil {
		return PortEntry{}, err
	}
	for _, f := range live {
		if forwardMapping(f).Key() == mapping.Key() {
			bound = true
		}
	}
	if bound {
		if err := m.backend.Unpublish(mapping.Proto, mapping.Local()); err != nil {
			return PortEntry{}, err
		}
	}
	if persistent {
		if err := m.store.Mutate(func(cfg *config.RunConfig) error {
			filtered := make([]string, 0, len(cfg.Ports))
			for _, raw := range cfg.Ports {
				if saved, parseErr := config.ParsePortSpec(raw); parseErr != nil || saved.Key() != mapping.Key() {
					filtered = append(filtered, raw)
				}
			}
			cfg.Ports = filtered
			return nil
		}); err != nil {
			if atomicfile.Committed(err) {
				return PortEntry{Mapping: mapping, State: "unpublished"},
					fmt.Errorf("unpublished port configuration committed but durability is uncertain: %w", err)
			}
			var rollbackErr error
			if bound { // restore the listener we just dropped
				rollbackErr = m.backend.Publish(mapping.Proto, mapping.Local(), mapping.Remote())
				if rollbackErr != nil {
					rollbackErr = fmt.Errorf("restore unpublished listener: %w", rollbackErr)
				}
			}
			return PortEntry{}, errors.Join(err, rollbackErr)
		}
	}
	if !bound && !persistent {
		return PortEntry{}, fmt.Errorf("%s is not published", mapping.Short())
	}
	return PortEntry{Mapping: mapping, State: "unpublished"}, nil
}

// List merges the netstack's active listeners with the saved desired set.
func (m *PortManager) List() ([]PortEntry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	bound := map[string]PortEntry{}
	if m.backend != nil {
		live, err := m.backend.Forwards()
		if err != nil {
			return nil, err
		}
		for _, f := range live {
			mapping := forwardMapping(f)
			bound[mapping.Key()] = PortEntry{Mapping: mapping, State: "bound"}
		}
	}
	for _, raw := range m.store.Snapshot().Ports {
		mapping, err := config.ParsePortSpec(raw)
		if err != nil {
			continue
		}
		if _, ok := bound[mapping.Key()]; !ok {
			bound[mapping.Key()] = PortEntry{Mapping: mapping, State: "saved"}
		}
	}
	out := make([]PortEntry, 0, len(bound))
	for _, e := range bound {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Mapping.Key() < out[j].Mapping.Key() })
	return out, nil
}

// forwardMapping converts the netstack's wire shape back to a PortMapping
// (the remote always carries the pinned guest IP; only its port matters).
func forwardMapping(f vnet.Forward) config.PortMapping {
	m := config.PortMapping{Proto: f.Protocol}
	if m.Proto == "" {
		m.Proto = "tcp"
	}
	host, port, err := net.SplitHostPort(f.Local)
	if err == nil {
		m.HostIP = host
		if n, err := strconv.ParseUint(port, 10, 16); err == nil {
			m.HostPort = uint16(n)
		}
	}
	_, port, err = net.SplitHostPort(f.Remote)
	if err == nil {
		if n, err := strconv.ParseUint(port, 10, 16); err == nil {
			m.GuestPort = uint16(n)
		}
	}
	return m
}
