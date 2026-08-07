package sandbox

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
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
	if err := ValidateSandboxName(name); err != nil {
		fmt.Fprintln(os.Stderr, "gantry ports:", err)
		return 2
	}
	resp, err := portControlRPC(name, op, brokerPortRequest{Spec: spec, Persistent: persistent})
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

func portControlRPC(name, op string, portReq brokerPortRequest) (brokerPortResponse, error) {
	if _, alive := sandboxPID(name); !alive {
		return brokerPortResponse{}, fmt.Errorf("sandbox %q is not running (start it with: gantry start %s)", name, name)
	}
	conn, err := dialShareControl(name) // same ctl.sock; share dialer is generic
	if err != nil {
		return brokerPortResponse{}, fmt.Errorf("broker: %w", err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	req := brokerRequest{
		Op:   op,
		ID:   fmt.Sprintf("port-%d-%d", os.Getpid(), time.Now().UnixNano()),
		Port: &portReq,
	}
	if err := json.NewEncoder(conn).Encode(&req); err != nil {
		return brokerPortResponse{}, err
	}
	var resp brokerPortResponse
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return brokerPortResponse{}, fmt.Errorf("broker response: %w", err)
	}
	if !resp.OK {
		if resp.Error == "" {
			resp.Error = "port operation rejected"
		}
		return resp, errors.New(resp.Error)
	}
	return resp, nil
}

func printPorts(name string) int {
	if err := ValidateSandboxName(name); err != nil {
		fmt.Fprintln(os.Stderr, "gantry ports:", err)
		return 2
	}
	var entries []PortEntry
	if _, alive := sandboxPID(name); alive {
		resp, err := portControlRPC(name, "port.list", brokerPortRequest{Persistent: true})
		if err != nil {
			fmt.Fprintln(os.Stderr, "gantry ports ls:", err)
			return 1
		}
		entries = resp.Ports
	} else {
		raw, err := os.ReadFile(filepath.Join(sandboxDir(name), "sandbox.json"))
		if err != nil {
			fmt.Fprintln(os.Stderr, "gantry ports ls:", err)
			return 1
		}
		var cfg RunConfig
		if err := json.Unmarshal(raw, &cfg); err != nil {
			fmt.Fprintln(os.Stderr, "gantry ports ls: corrupt sandbox.json:", err)
			return 1
		}
		for _, spec := range cfg.Ports {
			m, err := ParsePortSpec(spec)
			if err != nil {
				fmt.Fprintln(os.Stderr, "gantry ports ls: bad saved port spec:", err)
				return 1
			}
			entries = append(entries, PortEntry{Mapping: m, State: "saved"})
		}
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Mapping.Key() < entries[j].Mapping.Key() })
	w := newCLITable(os.Stdout)
	_, _ = fmt.Fprintln(w, "BIND\tGUEST\tPROTO\tSTATE")
	for _, e := range entries {
		_, _ = fmt.Fprintf(w, "%s\t%d\t%s\t%s\n", net.JoinHostPort(e.Mapping.HostIP, fmt.Sprint(e.Mapping.HostPort)),
			e.Mapping.GuestPort, e.Mapping.Proto, e.State)
	}
	_ = w.Flush()
	return 0
}
