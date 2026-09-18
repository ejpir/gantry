package hostplane

import (
	"errors"
	"sync"
)

// Plane owns host resources while exposing only the non-closing capability
// types selected by its parent package. Close callbacks capture concrete
// owners without placing Close on borrowed interfaces.
type Plane[Config, Audit, Network, Shares, Ports, Transactions, Console any] struct {
	closeOnce          sync.Once
	closeErr           error
	networkBackendOnce sync.Once
	networkBackendErr  error

	config       Config
	audit        Audit
	network      Network
	shares       Shares
	ports        Ports
	transactions Transactions
	console      Console

	closeLock           func() error
	closeConsole        func() error
	closeConsoleLog     func() error
	closeNetworkBackend func() error
	closeNetwork        func()
	closeShares         func() error
}

func (p *Plane[C, A, N, S, P, T, O]) SetConfig(value C)          { p.config = value }
func (p *Plane[C, A, N, S, P, T, O]) Config() C                  { return p.config }
func (p *Plane[C, A, N, S, P, T, O]) SetAudit(value A)           { p.audit = value }
func (p *Plane[C, A, N, S, P, T, O]) Audit() A                   { return p.audit }
func (p *Plane[C, A, N, S, P, T, O]) SetPorts(value P)           { p.ports = value }
func (p *Plane[C, A, N, S, P, T, O]) Ports() P                   { return p.ports }
func (p *Plane[C, A, N, S, P, T, O]) SetTransactions(value T)    { p.transactions = value }
func (p *Plane[C, A, N, S, P, T, O]) Transactions() T            { return p.transactions }
func (p *Plane[C, A, N, S, P, T, O]) SetLock(close func() error) { p.closeLock = close }
func (p *Plane[C, A, N, S, P, T, O]) SetConsole(value O, close func() error) {
	p.console, p.closeConsole = value, close
}
func (p *Plane[C, A, N, S, P, T, O]) Console() O { return p.console }
func (p *Plane[C, A, N, S, P, T, O]) SetConsoleLog(close func() error) {
	p.closeConsoleLog = close
}
func (p *Plane[C, A, N, S, P, T, O]) SetNetwork(value N, closeBackend func() error, close func()) {
	p.network, p.closeNetworkBackend, p.closeNetwork = value, closeBackend, close
}
func (p *Plane[C, A, N, S, P, T, O]) Network() N { return p.network }
func (p *Plane[C, A, N, S, P, T, O]) SetShares(value S, close func() error) {
	p.shares, p.closeShares = value, close
}
func (p *Plane[C, A, N, S, P, T, O]) Shares() S { return p.shares }

func (p *Plane[C, A, N, S, P, T, O]) CloseShutdownNetwork() error {
	p.networkBackendOnce.Do(func() {
		if p.closeNetworkBackend != nil {
			p.networkBackendErr = p.closeNetworkBackend()
		}
	})
	return p.networkBackendErr
}

func (p *Plane[C, A, N, S, P, T, O]) Close() error {
	p.closeOnce.Do(func() {
		var result error
		if p.closeShares != nil {
			result = errors.Join(result, p.closeShares())
		}
		if p.closeNetwork != nil {
			p.closeNetwork()
		}
		if p.closeConsole != nil {
			result = errors.Join(result, p.closeConsole())
		}
		if p.closeConsoleLog != nil {
			result = errors.Join(result, p.closeConsoleLog())
		}
		if p.closeLock != nil {
			result = errors.Join(result, p.closeLock())
		}
		p.closeErr = result
	})
	return p.closeErr
}
