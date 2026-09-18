package controlplane

import (
	"context"
	"errors"
	"net"
	"os"
	"os/signal"
	"sync"

	"github.com/ejpir/gantry/internal/sandbox/mcpgw"
	"github.com/ejpir/gantry/internal/sandbox/sshgw"
	"github.com/ejpir/gantry/internal/sandbox/supervisor"
	"github.com/ejpir/gantry/internal/workerconf"
)

// Plane owns every host endpoint which can admit new guest/control work.
// B is a non-closing broker capability owned for the plane lifetime.
type Plane[B any] struct {
	closeOnce sync.Once
	closeErr  error

	listener     net.Listener
	credListener net.Listener
	broker       B
	ssh          sshgw.Owner
	sshCleanup   func()
	mcp          mcpgw.Owner
	oauth        supervisor.BackgroundGroup
	servers      supervisor.BackgroundGroup
	signals      chan os.Signal
	shutdown     chan struct{}
}

func (c *Plane[B]) SetListener(listener net.Listener)           { c.listener = listener }
func (c *Plane[B]) Listening() bool                             { return c.listener != nil }
func (c *Plane[B]) SetCredentialListener(listener net.Listener) { c.credListener = listener }
func (c *Plane[B]) SetBroker(broker B)                          { c.broker = broker }
func (c *Plane[B]) Broker() B                                   { return c.broker }
func (c *Plane[B]) SetSSHCleanup(cleanup func())                { c.sshCleanup = cleanup }
func (c *Plane[B]) SSHRunning() bool                            { return c.ssh.Running() }
func (c *Plane[B]) StartSSH(listener net.Listener, serve func(context.Context, net.Listener)) bool {
	return c.ssh.Start(listener, serve)
}
func (c *Plane[B]) StopSSH() { c.ssh.Stop() }
func (c *Plane[B]) StartMCP(listener net.Listener, worker mcpgw.Worker, sessionError, workerExit func()) bool {
	return c.mcp.Start(listener, worker, sessionError, workerExit)
}
func (c *Plane[B]) CloseMCPSessions() { c.mcp.CloseSessions() }
func (c *Plane[B]) MCPConfinementReport() (*workerconf.Report, bool) {
	return c.mcp.ConfinementReport()
}
func (c *Plane[B]) SetSignals(signals chan os.Signal)  { c.signals = signals }
func (c *Plane[B]) Signals() <-chan os.Signal          { return c.signals }
func (c *Plane[B]) SetShutdown(shutdown chan struct{}) { c.shutdown = shutdown }
func (c *Plane[B]) Shutdown() chan struct{}            { return c.shutdown }

func (c *Plane[B]) StartOAuth(run func(context.Context)) bool  { return c.oauth.Start(run) }
func (c *Plane[B]) StopOAuth()                                 { c.oauth.Close() }
func (c *Plane[B]) StartServer(run func(context.Context)) bool { return c.servers.Start(run) }

func (c *Plane[B]) CloseAdmission() {
	if c.listener != nil {
		_ = c.listener.Close()
	}
}

func (c *Plane[B]) Close() error {
	c.closeOnce.Do(func() {
		c.StopOAuth()
		c.CloseAdmission()
		c.ssh.Stop()
		if c.sshCleanup != nil {
			c.sshCleanup()
		}
		var result error
		result = errors.Join(result, c.mcp.Close())
		if c.credListener != nil {
			result = errors.Join(result, c.credListener.Close())
		}
		if c.signals != nil {
			signal.Stop(c.signals)
		}
		c.servers.Close()
		c.closeErr = result
	})
	return c.closeErr
}
