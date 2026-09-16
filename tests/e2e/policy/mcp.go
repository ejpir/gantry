package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"
)

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      int             `json:"id"`
	Result  json.RawMessage `json:"result"`
	Error   json.RawMessage `json:"error"`
}
type mcpSession struct {
	ctx       context.Context
	cancel    context.CancelFunc
	stdin     io.WriteCloser
	responses chan rpcResponse
	done      chan struct{}
	err       error
	stderr    *commandBuffer
	next      int
}

func (h *harness) openMCP(ctx context.Context) (*mcpSession, error) {
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	cmd := exec.CommandContext(ctx, h.opts.gantry, "exec", "pol-main", "--", "/run/gantry/bin/gantry-guest", "mcp-proxy")
	cmd.Env = h.env
	cmd.Dir = h.root
	cmd.WaitDelay = 3 * time.Second
	stdin, err := cmd.StdinPipe()
	if err != nil {
		cancel()
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		_ = stdin.Close()
		return nil, err
	}
	stderr := &commandBuffer{}
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		cancel()
		_ = stdin.Close()
		_ = stdout.Close()
		return nil, err
	}
	s := &mcpSession{ctx: ctx, cancel: cancel, stdin: stdin, responses: make(chan rpcResponse, 8), done: make(chan struct{}), stderr: stderr}
	go func() {
		scanner := bufio.NewScanner(stdout)
		scanner.Buffer(make([]byte, 4096), maxOutput)
		for scanner.Scan() {
			var response rpcResponse
			if json.Unmarshal(scanner.Bytes(), &response) != nil || response.JSONRPC != "2.0" || response.ID == 0 {
				continue
			}
			select {
			case s.responses <- response:
			case <-ctx.Done():
			}
		}
		readErr := scanner.Err()
		waitErr := cmd.Wait()
		if readErr != nil {
			s.err = readErr
		} else {
			s.err = waitErr
		}
		close(s.done)
	}()
	return s, nil
}
func (s *mcpSession) call(method string, params any) (rpcResponse, error) {
	s.next++
	if err := json.NewEncoder(s.stdin).Encode(map[string]any{"jsonrpc": "2.0", "id": s.next, "method": method, "params": params}); err != nil {
		return rpcResponse{}, err
	}
	select {
	case <-s.ctx.Done():
		return rpcResponse{}, fmt.Errorf("MCP %s: %w", method, s.ctx.Err())
	case <-s.done:
		return rpcResponse{}, fmt.Errorf("MCP process exited before %s response: %v", method, s.err)
	case response := <-s.responses:
		if response.ID != s.next {
			return response, fmt.Errorf("MCP response ID=%d, want %d", response.ID, s.next)
		}
		return response, nil
	}
}
func (s *mcpSession) close() {
	_ = s.stdin.Close()
	select {
	case <-s.done:
	case <-time.After(2 * time.Second):
		s.cancel()
		<-s.done
	}
	s.cancel()
}
func (h *harness) mcp(ctx context.Context, allowed, denied *endpoint) (runErr error) {
	s, err := h.openMCP(ctx)
	if err != nil {
		return err
	}
	defer func() {
		s.close()
		if s.stderr.truncated && runErr == nil {
			runErr = fmt.Errorf("MCP stderr exceeded output limit")
		}
		if runErr != nil {
			fmt.Fprintln(os.Stderr, "MCP diagnostics:", h.redact(s.stderr.String()))
		}
	}()
	response, err := s.call("initialize", map[string]any{"protocolVersion": "2025-06-18", "capabilities": map[string]any{}, "clientInfo": map[string]any{"name": "policy-e2e", "version": "1"}})
	if err != nil {
		return err
	}
	if len(response.Error) != 0 {
		return fmt.Errorf("MCP initialization failed: %s", response.Error)
	}
	if err := json.NewEncoder(s.stdin).Encode(map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"}); err != nil {
		return err
	}
	before := allowed.callCount("read")
	response, err = s.call("tools/call", map[string]any{"name": "mock__read", "arguments": map[string]any{"canary": argumentCanary}})
	if err != nil {
		return err
	}
	if len(response.Error) != 0 || !strings.Contains(string(response.Result), "OPA-MCP-CALL-OK") || allowed.callCount("read") != before+1 {
		return fmt.Errorf("authorized MCP call did not reach real upstream")
	}
	h.pass("authorized MCP tool works without a prior listing")
	response, err = s.call("tools/list", map[string]any{})
	if err != nil {
		return err
	}
	var listing struct {
		Tools []struct {
			Name string `json:"name"`
		} `json:"tools"`
	}
	if len(response.Error) != 0 || json.Unmarshal(response.Result, &listing) != nil {
		return fmt.Errorf("invalid MCP tools/list response")
	}
	names := map[string]bool{}
	for _, tool := range listing.Tools {
		names[tool.Name] = true
	}
	if !names["mock__read"] || !names["mock__listed"] || names["mock__hidden"] {
		return fmt.Errorf("organization listing filter failed: %v", names)
	}
	h.pass("organization policy filters an upstream with local allow=*")
	for _, tool := range []string{"listed", "hidden"} {
		before := allowed.callCount(tool)
		response, err = s.call("tools/call", map[string]any{"name": "mock__" + tool, "arguments": map[string]any{}})
		if err != nil {
			return err
		}
		if !strings.Contains(string(response.Error), "unknown or disallowed tool") || allowed.callCount(tool) != before {
			return fmt.Errorf("denied MCP tool %s was invoked", tool)
		}
		h.pass("listed/hidden tool " + tool + " independently denied at call time")
	}
	beforeConnections := denied.connections.Load()
	response, err = s.call("tools/call", map[string]any{"name": "blocked__read", "arguments": map[string]any{}})
	if err != nil {
		return err
	}
	if !strings.Contains(string(response.Error), "upstream unavailable") || denied.connections.Load() != beforeConnections {
		return fmt.Errorf("MCP dial escaped organization egress policy")
	}
	h.pass("permitted MCP action cannot bypass organization network denial")
	return nil
}
