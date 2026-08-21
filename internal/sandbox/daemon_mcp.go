package sandbox

// daemon_mcp.go — the per-sandbox MCP gateway (docs/mcp-gateway.md).
//
// Milestone 1: one built-in local server ("fs", the guest helper's
// contained filesystem server) behind a vsock-bridged session mux. The
// guest connects to vsock port 1029, the VMM bridges to
// <dir>/1029.sock, and mcpgw.Serve handles the session. Local servers are
// spawned guest-side through the exec channel (as the configured
// unprivileged user — never root) with stdio piped back to the gateway.

import (
	"context"
	"fmt"
	"io"
	"net"
	"path/filepath"

	"github.com/ejpir/gantry/internal/client"
	"github.com/ejpir/gantry/internal/sandbox/mcpgw"
	"github.com/ejpir/gantry/internal/sandbox/mcpgw/mcpproto"
)

// startMCPGateway wires and launches the gateway when -mcp is set. The
// built-in fs server's policy is read-only by construction: the gateway
// allows exactly read_file and list_directory through, and the server
// binary exposes nothing else.
func (d *daemonRuntime) startMCPGateway() error {
	if !d.cfg.MCP {
		return nil
	}
	servers, err := d.resolveMCPServers()
	if err != nil {
		return fmt.Errorf("mcp gateway: %w", err)
	}
	gw, err := mcpgw.New(d.broker.auditf, d.broker.spawnGuestStdio, servers)
	if err != nil {
		return fmt.Errorf("mcp gateway: %w", err)
	}
	ln, err := net.Listen("unix", filepath.Join(d.dir, mcpproto.SockName))
	if err != nil {
		return fmt.Errorf("mcp gateway listener: %w", err)
	}
	d.broker.auditf("mcp: gateway enabled (fs root %s, local servers run as %s, %d remotes)",
		d.cfg.MCPFSRoot, d.cfg.MCPFSUser, len(d.cfg.MCPRemotes))
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return // listener closed on shutdown
			}
			go func() { _ = gw.Serve(context.Background(), conn) }()
		}
	}()
	return nil
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
	go func() {
		defer close(done)
		defer br.limits.releaseSession()
		defer func() { _ = stdoutW.Close() }() // gateway's reader sees EOF
		var status int
		_ = client.Session(br.rpc, client.SessionOptions{
			StreamSock:       br.streamSock,
			StreamDial:       br.streamDial,
			Shares:           manifest.Shares,
			ShareTransport:   manifest.Transport,
			RW:               br.cfg.RW,
			LayerSet:         br.cfg.LayerSet,
			Args:             args,
			ID:               "sb",
			ExecIntoExisting: true,
			ImgCfg:           br.cfg.ImageCfg,
			Environment:      br.cfg.ProxyEnvironment(),
			Quiet:            true,
			ExitStatus:       &status,
			KillCh:           killCh,
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
