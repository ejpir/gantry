package controlcmd

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/ejpir/gantry/internal/sandbox/cliout"
	"github.com/ejpir/gantry/internal/sandbox/config"
	"github.com/ejpir/gantry/internal/sandbox/control"
	"github.com/ejpir/gantry/internal/sandbox/controlproto"
	"github.com/ejpir/gantry/internal/sandbox/layout"
)

// CmdPorts implements `gantry ports ls|publish|unpublish` against a running
// sandbox's ctl.sock broker. The broker owns the netstack's forwarder; this
// command is only the local control-plane client.
func CmdPorts(argv []string) int {
	usage := func() {
		fmt.Fprintln(os.Stderr, `usage:
  gantry ports ls <name>
  gantry ports publish [--ephemeral] <name> [IP:]HOST:GUEST[/udp]
  gantry ports unpublish [--ephemeral] <name> [IP:]HOST:GUEST[/udp]

Published ports listen on the host (loopback unless an IP is given) and
forward into the sandbox. Changes update sandbox.json by default and are
re-applied on the next start; --ephemeral affects only this boot.`)
	}
	if len(argv) == 0 {
		usage()
		return 2
	}
	if argv[0] == "-h" || argv[0] == "--help" {
		usage()
		return 0
	}
	op := argv[0]
	var positional []string
	ephemeral := false
	for _, arg := range argv[1:] {
		if strings.HasPrefix(arg, "--") {
			switch strings.TrimPrefix(arg, "--") {
			case "ephemeral":
				ephemeral = true
			default:
				fmt.Fprintln(os.Stderr, "gantry ports: unknown flag", arg)
				usage()
				return 2
			}
			continue
		}
		positional = append(positional, arg)
	}
	switch op {
	case "publish", "add":
		if len(positional) != 2 {
			usage()
			return 2
		}
		return portMutation("published", positional[0], "port.publish", positional[1], !ephemeral)
	case "unpublish", "remove", "rm":
		if len(positional) != 2 {
			usage()
			return 2
		}
		return portMutation("unpublished", positional[0], "port.unpublish", positional[1], !ephemeral)
	case "ls", "list":
		if len(positional) != 1 {
			usage()
			return 2
		}
		return printPorts(positional[0])
	default:
		usage()
		return 2
	}
}

func portMutation(verb, name, op, spec string, persistent bool) int {
	if err := layout.ValidateName(name); err != nil {
		fmt.Fprintln(os.Stderr, "gantry ports:", err)
		return 2
	}
	resp, err := PortRPC(name, op, controlproto.PortRequest{Spec: spec, Persistent: persistent})
	if err != nil {
		fmt.Fprintf(os.Stderr, "gantry ports %s: %v\n", strings.TrimSuffix(verb, "ed"), err)
		return 1
	}
	if resp.Entry != nil {
		fmt.Printf("port %s: %s (%s)\n", verb, resp.Entry.Mapping.Short(), resp.Entry.State)
	} else {
		fmt.Println("port", verb)
	}
	return 0
}

func PortRPC(name, op string, portReq controlproto.PortRequest) (controlproto.PortResponse, error) {
	if _, alive := layout.PID(name); !alive {
		return controlproto.PortResponse{}, fmt.Errorf("sandbox %q is not running (start it with: gantry start %s)", name, name)
	}
	req := controlproto.Request{
		Op:   op,
		ID:   controlproto.NewRequestID("port"),
		Port: &portReq,
	}
	resp, err := controlproto.Call[controlproto.PortResponse](name, req)
	if err != nil {
		return controlproto.PortResponse{}, err
	}
	if !resp.OK {
		if resp.Error == "" {
			resp.Error = "port operation rejected"
		}
		return resp, fmt.Errorf("%s", resp.Error)
	}
	return resp, nil
}

func printPorts(name string) int {
	if err := layout.ValidateName(name); err != nil {
		fmt.Fprintln(os.Stderr, "gantry ports:", err)
		return 2
	}
	var entries []control.PortEntry
	if _, alive := layout.PID(name); alive {
		resp, err := PortRPC(name, "port.list", controlproto.PortRequest{Persistent: true})
		if err != nil {
			fmt.Fprintln(os.Stderr, "gantry ports ls:", err)
			return 1
		}
		entries = resp.Ports
	} else {
		raw, err := os.ReadFile(filepath.Join(layout.Dir(name), "sandbox.json"))
		if err != nil {
			fmt.Fprintln(os.Stderr, "gantry ports ls:", err)
			return 1
		}
		var cfg config.RunConfig
		if err := json.Unmarshal(raw, &cfg); err != nil {
			fmt.Fprintln(os.Stderr, "gantry ports ls: corrupt sandbox.json:", err)
			return 1
		}
		for _, spec := range cfg.Ports {
			m, err := config.ParsePortSpec(spec)
			if err != nil {
				fmt.Fprintln(os.Stderr, "gantry ports ls: bad saved port spec:", err)
				return 1
			}
			entries = append(entries, control.PortEntry{Mapping: m, State: "saved"})
		}
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Mapping.Key() < entries[j].Mapping.Key() })
	w := cliout.Table(os.Stdout)
	_, _ = fmt.Fprintln(w, "BIND\tGUEST\tPROTO\tSTATE")
	for _, e := range entries {
		_, _ = fmt.Fprintf(w, "%s\t%d\t%s\t%s\n", net.JoinHostPort(e.Mapping.HostIP, fmt.Sprint(e.Mapping.HostPort)),
			e.Mapping.GuestPort, e.Mapping.Proto, e.State)
	}
	_ = w.Flush()
	return 0
}
