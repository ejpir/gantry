package sandbox

// daemon_mcp.go — trusted MCP capability brokers (docs/mcp-gateway.md).
//
// The guest connects to vsock port 1029 and the VMM bridges to
// <dir>/1029.sock. The supervisor relays opaque bounded streams into the
// confined _mcp-worker. Local helpers still run guest-side through the fixed
// exec mapping and drop to the configured unprivileged identity.

import (
	"context"
	"fmt"
	"io"
	"net"
	"path/filepath"

	"github.com/ejpir/gantry/internal/client"
	"github.com/ejpir/gantry/internal/image"
	"github.com/ejpir/gantry/internal/sandbox/mcpgw"
	"github.com/ejpir/gantry/internal/sandbox/mcpgw/mcpproto"
	mcpworkersup "github.com/ejpir/gantry/internal/sandbox/mcpworker"
)

// startMCPGateway launches the mandatory split MCP worker when -mcp is set.
// The supervisor accepts the local endpoint and relays opaque bytes; parsing,
// policy, HTTP/SSE, and local stdio framing live only in _mcp-worker.
func (d *daemonRuntime) startMCPGateway() error {
	if !d.cfg.MCP {
		return nil
	}
	servers, err := d.resolveMCPServers()
	if err != nil {
		return fmt.Errorf("mcp gateway: %w", err)
	}
	mcpWorker, err := mcpworkersup.Start(servers, d.dir, d.cfg.ProcessIsolation, func(event mcpgw.Event) {
		d.broker.auditf("%s", event.String())
	})
	if err != nil {
		return fmt.Errorf("mcp gateway: %w", err)
	}
	ln, err := net.Listen("unix", filepath.Join(d.dir, mcpproto.SockName))
	if err != nil {
		_ = mcpWorker.Close()
		return fmt.Errorf("mcp gateway listener: %w", err)
	}
	d.mcpWorker, d.mcpListener = mcpWorker, ln
	if err := d.writeIsolationState(); err != nil {
		fmt.Printf("daemon: isolation state after MCP worker start: %v\n", err)
	}
	d.broker.auditf("mcp: gateway enabled in split worker (fs root %s, local servers run as %s, %d remotes)",
		d.cfg.MCPFSRoot, d.cfg.MCPFSUser, len(d.cfg.MCPRemotes))
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				if err := mcpWorker.Serve(context.Background(), conn); err != nil {
					select {
					case <-mcpWorker.Done():
					default:
						d.broker.auditf("mcp: guest session relay failed")
					}
				}
			}()
		}
	}()
	go func() {
		<-mcpWorker.Done()
		_ = ln.Close()
		if err := d.writeIsolationState(); err != nil {
			fmt.Printf("daemon: isolation state after MCP worker exit: %v\n", err)
		}
		d.broker.auditf("mcp: worker exited; MCP disabled for this sandbox")
	}()
	return nil
}

func mcpLauncherImageConfig(config *image.Config) *image.Config {
	rootConfig := new(image.Config)
	if config != nil {
		*rootConfig = *config
	}
	rootConfig.User = "root"
	rootConfig.UID, rootConfig.GID = 0, 0
	return rootConfig
}

// spawnGuestStdio starts a long-running process in the sandbox container
// with live stdio pipes (unlike internalExec's bounded one-shot capture).
// Used by the MCP gateway for local servers. Same rules as internalExec:
// multiplexed over the daemon's guest RPC, session-limit accounted, user
// secrets NOT injected. kill terminates the process and unblocks both
// pipe ends; ctx cancellation kills too.
func (br *broker) spawnGuestStdio(ctx context.Context, args []string) (io.WriteCloser, io.ReadCloser, func(), error) {
	if !br.limits.acquireSession() {
		return nil, nil, nil, fmt.Errorf("sandbox session limit reached")
	}
	stdinR, stdinW := io.Pipe()
	stdoutR, stdoutW := io.Pipe()
	killCh := make(chan struct{}, 1)
	done := make(chan struct{})

	manifest := client.LoadShareManifest(br.dir)
	// Local MCP helpers must start as root so gantry-guest can perform the
	// configured, verified setgroups/setgid/setuid drop itself. Starting them
	// as the image user either made --user ineffective or (after fail-closed
	// validation) made every non-matching image unusable.
	rootImageCfg := mcpLauncherImageConfig(br.cfg.ImageCfg)
	go func() {
		defer close(done)
		defer br.limits.releaseSession()
		defer func() { _ = stdoutW.Close() }() // gateway's reader sees EOF
		var status int
		_ = client.Session(br.rpc, client.SessionOptions{
			StreamSock:     br.streamSock,
			StreamDial:     br.streamDial,
			Shares:         manifest.Shares,
			ShareTransport: manifest.Transport,
			RW:             br.cfg.RW,
			LayerSet:       br.cfg.LayerSet,
			Args:           args,
			ID:             "sb",
			SandboxSession: true,
			ImgCfg:         rootImageCfg,
			Environment:    br.cfg.ProxyEnvironment(),
			Quiet:          true,
			ExitStatus:     &status,
			KillCh:         killCh,
		}, stdinR, stdoutW)
	}()

	kill := func() {
		select {
		case killCh <- struct{}{}:
		default:
		}
		_ = stdinW.Close()
		// Closing the read end makes the session's stdout copy fail, so a
		// session blocked writing to a dead gateway still unwinds.
		_ = stdoutR.Close()
	}
	go func() {
		select {
		case <-ctx.Done():
			kill()
		case <-done:
		}
	}()
	return stdinW, stdoutR, kill, nil
}
