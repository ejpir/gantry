package sandbox

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"sync"

	"gantry/internal/vnet"
)

// PortManager owns host→guest port publishing for one running sandbox:
// live listeners in the embedded netstack plus the desired set persisted
// in sandbox.json (replayed at every boot as static forwards). Mutations
// go live first, persist second, and roll the live side back if the write
// fails — a crashed publish never leaves a phantom listener behind.
//
// Persistence goes through the broker-owned ConfigStore, so a port publish
// can never clobber a concurrent (or earlier) share mutation: both managers
// always mutate the latest configuration, under one lock.
type PortManager struct {
	store *ConfigStore
	stack *vnet.Stack // nil: ports unavailable (gvproxy backend or -net=false)

	mu sync.Mutex
}

// PortEntry is one mapping as reported to the CLI/TUI: bound (listener
// active in the netstack) or saved (desired, applies at next boot).
type PortEntry struct {
	Mapping PortMapping `json:"mapping"`
	State   string      `json:"state"` // "bound" | "saved"
}

// NewPortManager binds the manager to the sandbox's netstack; stack may be
// nil (ports then report unavailable, listing still shows the saved set).
func NewPortManager(store *ConfigStore, stack *vnet.Stack) *PortManager {
	return &PortManager{store: store, stack: stack}
}

var errPortsUnavailable = fmt.Errorf("port publishing requires the embedded netstack and networking enabled")

// Publish opens the listener now; persistent also records the mapping in
// sandbox.json so stop/start cycles re-apply it.
func (m *PortManager) Publish(spec string, persistent bool) (PortEntry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.stack == nil {
		return PortEntry{}, errPortsUnavailable
	}
	normalized, err := NormalizePortSpec(spec)
	if err != nil {
		return PortEntry{}, err
	}
	mapping, _ := ParsePortSpec(normalized)
	live, err := m.stack.Forwards()
	if err != nil {
		return PortEntry{}, err
	}
	for _, f := range live {
		if forwardMapping(f).Key() == mapping.Key() {
			return PortEntry{}, fmt.Errorf("%s is already published", mapping.Short())
		}
	}
	if err := m.stack.Publish(mapping.Proto, mapping.Local(), mapping.Remote()); err != nil {
		return PortEntry{}, err
	}
	if persistent {
		ports := append(append([]string(nil), m.store.Snapshot().Ports...), normalized)
		if err := m.persistLocked(ports); err != nil {
			_ = m.stack.Unpublish(mapping.Proto, mapping.Local())
			return PortEntry{}, err
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
	if m.stack == nil {
		return PortEntry{}, errPortsUnavailable
	}
	mapping, err := ParsePortSpec(spec)
	if err != nil {
		return PortEntry{}, err
	}
	if mapping.HostPort == 0 {
		return PortEntry{}, fmt.Errorf("unpublish needs the concrete host port (see: gantry ports ls)")
	}
	bound := false
	live, err := m.stack.Forwards()
	if err != nil {
		return PortEntry{}, err
	}
	for _, f := range live {
		if forwardMapping(f).Key() == mapping.Key() {
			bound = true
		}
	}
	if bound {
		if err := m.stack.Unpublish(mapping.Proto, mapping.Local()); err != nil {
			return PortEntry{}, err
		}
	}
	if persistent {
		filtered := make([]string, 0)
		for _, raw := range m.store.Snapshot().Ports {
			if saved, err := ParsePortSpec(raw); err != nil || saved.Key() != mapping.Key() {
				filtered = append(filtered, raw)
			}
		}
		if err := m.persistLocked(filtered); err != nil {
			if bound { // restore the listener we just dropped
				_ = m.stack.Publish(mapping.Proto, mapping.Local(), mapping.Remote())
			}
			return PortEntry{}, err
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
	if m.stack != nil {
		live, err := m.stack.Forwards()
		if err != nil {
			return nil, err
		}
		for _, f := range live {
			mapping := forwardMapping(f)
			bound[mapping.Key()] = PortEntry{Mapping: mapping, State: "bound"}
		}
	}
	for _, raw := range m.store.Snapshot().Ports {
		mapping, err := ParsePortSpec(raw)
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

func (m *PortManager) persistLocked(ports []string) error {
	return m.store.Mutate(func(cfg *RunConfig) error {
		cfg.Ports = ports
		return nil
	})
}

// forwardMapping converts the netstack's wire shape back to a PortMapping
// (the remote always carries the pinned guest IP; only its port matters).
func forwardMapping(f vnet.Forward) PortMapping {
	m := PortMapping{Proto: f.Protocol}
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
