// SPDX-License-Identifier: Apache-2.0

// mcp_cmd.go — `gantry mcp`: operator inspection for the MCP gateway
// (docs/mcp-gateway.md milestone 4).
//
//	gantry mcp <name>         show the sandbox's configured MCP servers
//	gantry mcp tools <name>   live-probe the effective, policy-filtered
//	                          tool list through the gateway socket
//
// Config view prints auth KINDS and secret NAMES, never values. The live
// probe dials the daemon's gateway socket directly — it is the control
// plane — and runs an ordinary initialize/tools/list session.

package sandbox

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ejpir/gantry/internal/sandbox/config"
	"github.com/ejpir/gantry/internal/sandbox/layout"
	"github.com/ejpir/gantry/internal/sandbox/mcpgw/mcpproto"
)

// CmdMCP implements the mcp subcommand.
func CmdMCP(argv []string) int {
	if len(argv) == 1 && argv[0] != "tools" {
		return mcpShowConfig(argv[0])
	}
	if len(argv) == 2 && argv[0] == "tools" {
		return mcpShowTools(argv[1])
	}
	fmt.Fprintln(os.Stderr, "usage: gantry mcp <name>         show configured MCP servers")
	fmt.Fprintln(os.Stderr, "       gantry mcp tools <name>   list effective tools (sandbox must be running)")
	return 2
}

func mcpLoadConfig(name string) (*config.RunConfig, error) {
	if !layout.ValidName(name) {
		return nil, fmt.Errorf("invalid sandbox name %q", name)
	}
	b, err := os.ReadFile(filepath.Join(layout.Dir(name), "sandbox.json"))
	if err != nil {
		return nil, fmt.Errorf("sandbox %s: %w", name, err)
	}
	cfg := &config.RunConfig{}
	if err := json.Unmarshal(b, cfg); err != nil {
		return nil, fmt.Errorf("sandbox %s: %w", name, err)
	}
	return cfg, nil
}

func mcpShowConfig(name string) int {
	cfg, err := mcpLoadConfig(name)
	if err != nil {
		fmt.Fprintln(os.Stderr, "gantry mcp:", err)
		return 1
	}
	if !cfg.MCP && len(cfg.MCPRemotes) == 0 {
		fmt.Printf("%s: MCP gateway not enabled (start with -mcp or -mcp-remote)\n", name)
		return 0
	}
	root, usr := cfg.MCPFSRoot, cfg.MCPFSUser
	if root == "" {
		root = "/"
	}
	if usr == "" {
		usr = "nobody"
	}
	fmt.Println("SERVER  TYPE   DETAIL")
	fmt.Printf("fs      local  read-only filesystem: root %s, user %s, tools read_file,list_directory\n", root, usr)
	for _, raw := range cfg.MCPRemotes {
		spec, err := parseMCPRemote(raw)
		if err != nil {
			fmt.Printf("%-7s remote INVALID SPEC: %v\n", "? ", err)
			continue
		}
		auth := "none"
		switch spec.AuthKind {
		case "bearer":
			auth = "bearer:" + spec.AuthRef
		case "header":
			auth = "header " + spec.AuthHeader + ":" + spec.AuthRef
		case "custody":
			auth = "custody:" + spec.AuthRef
		}
		policy := "allow=none"
		if len(spec.Allow) > 0 {
			policy = "allow=" + strings.Join(spec.Allow, ",")
		}
		if len(spec.Deny) > 0 {
			policy += " deny=" + strings.Join(spec.Deny, ",")
		}
		fmt.Printf("%-7s remote %s, auth %s, %s\n", spec.Name, spec.URL, auth, policy)
	}
	return 0
}

// mcpShowTools runs one gateway session against the live socket and prints
// the effective tool list grouped by server.
func mcpShowTools(name string) int {
	if _, err := mcpLoadConfig(name); err != nil {
		fmt.Fprintln(os.Stderr, "gantry mcp:", err)
		return 1
	}
	if _, alive := layout.PID(name); !alive {
		fmt.Fprintf(os.Stderr, "gantry mcp: sandbox %s is not running\n", name)
		return 1
	}
	byServer, err := mcpToolsProbe(filepath.Join(layout.Dir(name), mcpproto.SockName))
	if err != nil {
		fmt.Fprintln(os.Stderr, "gantry mcp:", err)
		return 1
	}
	servers := make([]string, 0, len(byServer))
	for s := range byServer {
		servers = append(servers, s)
	}
	sort.Strings(servers)
	for _, s := range servers {
		sort.Strings(byServer[s])
		fmt.Printf("%s: %s\n", s, strings.Join(byServer[s], ", "))
	}
	if len(servers) == 0 {
		fmt.Println("no tools exposed (check allow= policies)")
	}
	return 0
}

// mcpToolsProbe runs an initialize/tools/list session against a gateway
// socket and returns the effective (policy-filtered) tools grouped by
// server.
func mcpToolsProbe(sock string) (map[string][]string, error) {
	conn, err := net.DialTimeout("unix", sock, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("gateway socket: %w (was the sandbox started with -mcp?)", err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(60 * time.Second))

	send := func(v any) error {
		b, err := json.Marshal(v)
		if err != nil {
			return err
		}
		_, err = conn.Write(append(b, '\n'))
		return err
	}
	r := bufio.NewReaderSize(conn, 64*1024)
	read := func(id int) (map[string]any, error) {
		for {
			line, err := r.ReadBytes('\n')
			if err != nil {
				return nil, err
			}
			if len(line) > mcpproto.MaxFrameBytes {
				return nil, fmt.Errorf("gateway frame exceeds %d bytes", mcpproto.MaxFrameBytes)
			}
			var resp map[string]any
			if err := json.Unmarshal(line, &resp); err != nil {
				continue // notifications/progress: skip
			}
			var gotID any
			if raw, ok := resp["id"]; ok {
				_ = json.Unmarshal(mustRaw(raw), &gotID)
			}
			if gotID == float64(id) {
				return resp, nil
			}
		}
	}
	if err := send(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "initialize",
		"params": map[string]any{"protocolVersion": mcpproto.ProtocolVersion,
			"capabilities": map[string]any{}, "clientInfo": map[string]any{"name": "gantry-mcp-cli", "version": "0"}}}); err != nil {
		return nil, err
	}
	if _, err := read(1); err != nil {
		return nil, fmt.Errorf("initialize: %w", err)
	}
	_ = send(map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"})
	if err := send(map[string]any{"jsonrpc": "2.0", "id": 2, "method": "tools/list"}); err != nil {
		return nil, err
	}
	resp, err := read(2)
	if err != nil {
		return nil, fmt.Errorf("tools/list: %w", err)
	}
	result, _ := resp["result"].(map[string]any)
	tools, _ := result["tools"].([]any)
	byServer := map[string][]string{}
	for _, t := range tools {
		tm, _ := t.(map[string]any)
		tname, _ := tm["name"].(string)
		server, tool, ok := strings.Cut(tname, "__")
		if !ok {
			server, tool = "?", tname
		}
		byServer[server] = append(byServer[server], tool)
	}
	return byServer, nil
}

func mustRaw(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}
