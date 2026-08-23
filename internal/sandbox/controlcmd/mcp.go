package controlcmd

import (
	"fmt"
	"strings"

	"github.com/ejpir/gantry/internal/mcpspec"
	"github.com/ejpir/gantry/internal/sandbox/config"
	"github.com/ejpir/gantry/internal/sandbox/controlproto"
	"github.com/ejpir/gantry/internal/sandbox/layout"
)

// ConfigureMCPRemote persists one validated remote MCP server. Running
// sandboxes route through their daemon-owned ConfigStore and apply the change
// on restart; stopped sandboxes mutate under the launch lock.
func ConfigureMCPRemote(name, raw string, replace bool) error {
	if err := layout.ValidateName(name); err != nil {
		return err
	}
	remote, err := mcpspec.Parse(raw)
	if err != nil {
		return err
	}
	canonical, err := mcpspec.Encode(remote)
	if err != nil {
		return err
	}
	return mutateRunningOrStopped(name,
		func() error {
			return mcpControlRPC(name, "mcp.remote.set", controlproto.MCPRequest{Spec: canonical, Replace: replace})
		},
		func() error {
			store, err := config.LoadConfigStore(layout.Dir(name))
			if err != nil {
				return err
			}
			_, err = store.SetMCPRemote(canonical, replace)
			return err
		},
	)
}

// RemoveMCPRemote removes one remote from the next MCP-worker launch.
func RemoveMCPRemote(name, server string) error {
	if err := layout.ValidateName(name); err != nil {
		return err
	}
	if server == "" || server == "fs" {
		return fmt.Errorf("invalid removable MCP server %q", server)
	}
	return mutateRunningOrStopped(name,
		func() error {
			return mcpControlRPC(name, "mcp.remote.remove", controlproto.MCPRequest{Name: server})
		},
		func() error {
			store, err := config.LoadConfigStore(layout.Dir(name))
			if err != nil {
				return err
			}
			return store.RemoveMCPRemote(server)
		},
	)
}

// ConfigureMCPFilesystem persists the built-in read-only filesystem server.
func ConfigureMCPFilesystem(name, root, user string) error {
	if err := layout.ValidateName(name); err != nil {
		return err
	}
	root, user, err := config.NormalizeMCPFilesystem(root, user)
	if err != nil {
		return err
	}
	return mutateRunningOrStopped(name,
		func() error {
			return mcpControlRPC(name, "mcp.filesystem.set", controlproto.MCPRequest{Root: root, User: user})
		},
		func() error {
			store, err := config.LoadConfigStore(layout.Dir(name))
			if err != nil {
				return err
			}
			return store.SetMCPFilesystem(root, user)
		},
	)
}

func mcpControlRPC(name, op string, settings controlproto.MCPRequest) error {
	req := controlproto.Request{
		Op: op, ID: controlproto.NewRequestID("mcp"), MCP: &settings,
	}
	resp, err := controlproto.Call[controlproto.MCPResponse](name, req)
	if err != nil {
		return err
	}
	if !resp.OK {
		if strings.TrimSpace(resp.Error) == "unknown op" {
			// A daemon keeps running the binary that launched it. After Gantry is
			// updated, an existing sandbox can therefore predate these control
			// operations even though the dashboard already exposes them.
			return fmt.Errorf("restart sandbox %q to upgrade its daemon, then retry MCP configuration", name)
		}
		if resp.Error == "" {
			resp.Error = "MCP configuration update failed"
		}
		return fmt.Errorf("%s", resp.Error)
	}
	return nil
}
