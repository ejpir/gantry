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

	"github.com/ejpir/gantry/internal/shares"
	"github.com/ejpir/gantry/internal/vmm"
)

// CmdShare implements `gantry share add|remove|ls` against a running
// sandbox's ctl.sock broker. The broker owns the VM's FUSE namespace; this
// command is only the local control-plane client.
func CmdShare(argv []string) int {
	usage := func() {
		fmt.Fprintln(os.Stderr, `usage:
  gantry share add [--replace] [--ephemeral] <name> TAG=PATH[@CTRPATH][,ro][,uid=N,gid=N]
  gantry share remove [--force] [--ephemeral] <name> TAG
  gantry share ls <name>

Live shares appear immediately at /host/<tag> in the sandbox container.
Changes update sandbox.json by default; --ephemeral affects only this boot.`)
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
	flags, args, err := parseShareFlags(argv[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, "gantry share:", err)
		usage()
		return 2
	}
	switch op {
	case "add":
		if len(args) != 2 {
			usage()
			return 2
		}
		name := args[0]
		if err := ValidateSandboxName(name); err != nil {
			fmt.Fprintln(os.Stderr, "gantry share:", err)
			return 2
		}
		spec, err := normalizeShareSpecForClient(args[1])
		if err != nil {
			fmt.Fprintln(os.Stderr, "gantry share add:", err)
			return 2
		}
		resp, err := shareControlRPC(name, "share.add", brokerShareRequest{
			Spec:       spec,
			Persistent: !flags["ephemeral"],
			Replace:    flags["replace"],
		})
		if err != nil {
			fmt.Fprintln(os.Stderr, "gantry share add:", err)
			return 1
		}
		printShareMutation("added", resp.Entry)
		return 0
	case "remove", "rm":
		if len(args) != 2 {
			usage()
			return 2
		}
		name := args[0]
		if err := ValidateSandboxName(name); err != nil {
			fmt.Fprintln(os.Stderr, "gantry share:", err)
			return 2
		}
		resp, err := shareControlRPC(name, "share.remove", brokerShareRequest{
			Tag:        args[1],
			Persistent: !flags["ephemeral"],
			Force:      flags["force"],
		})
		if err != nil {
			fmt.Fprintln(os.Stderr, "gantry share remove:", err)
			return 1
		}
		printShareMutation("removed", resp.Entry)
		return 0
	case "ls", "list":
		if len(args) != 1 || len(flags) != 0 {
			usage()
			return 2
		}
		name := args[0]
		if err := ValidateSandboxName(name); err != nil {
			fmt.Fprintln(os.Stderr, "gantry share:", err)
			return 2
		}
		return printShares(name)
	default:
		usage()
		return 2
	}
}

func parseShareFlags(args []string) (map[string]bool, []string, error) {
	flags := map[string]bool{}
	var positional []string
	for _, arg := range args {
		if !strings.HasPrefix(arg, "--") {
			positional = append(positional, arg)
			continue
		}
		name := strings.TrimPrefix(arg, "--")
		switch name {
		case "replace", "ephemeral", "force":
			flags[name] = true
		default:
			return nil, nil, fmt.Errorf("unknown flag --%s", name)
		}
	}
	return flags, positional, nil
}

func shareControlRPC(name, op string, shareReq brokerShareRequest) (brokerShareResponse, error) {
	if _, alive := sandboxPID(name); !alive {
		return brokerShareResponse{}, fmt.Errorf("sandbox %q is not running (start it with: gantry start %s)", name, name)
	}
	conn, err := dialShareControl(name)
	if err != nil {
		return brokerShareResponse{}, fmt.Errorf("broker: %w", err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	req := brokerRequest{
		Op:    op,
		ID:    fmt.Sprintf("share-%d-%d", os.Getpid(), time.Now().UnixNano()),
		Share: &shareReq,
	}
	if err := json.NewEncoder(conn).Encode(&req); err != nil {
		return brokerShareResponse{}, err
	}
	var resp brokerShareResponse
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return brokerShareResponse{}, fmt.Errorf("broker response: %w", err)
	}
	if !resp.OK {
		if resp.Error == "" {
			resp.Error = "share operation rejected"
		}
		return resp, errors.New(resp.Error)
	}
	return resp, nil
}

// configureSandboxShare persists an OCI container mount alias. Running
// sandboxes delegate to their broker because it exclusively owns sandbox.json;
// stopped sandboxes can update the same ConfigStore directly.
func configureSandboxShare(name, spec string, replace bool) error {
	if err := ValidateSandboxName(name); err != nil {
		return err
	}
	normalized, err := normalizeShareSpecForClient(spec)
	if err != nil {
		return err
	}
	if _, alive := sandboxPID(name); alive {
		_, err = shareControlRPC(name, "share.configure", brokerShareRequest{
			Spec: normalized, Persistent: true, Replace: replace,
		})
		return err
	}
	store, err := LoadConfigStore(sandboxDir(name))
	if err != nil {
		return err
	}
	_, err = store.SetShareForRestart(normalized, replace)
	return err
}

// removeSandboxShare removes a live share through the broker or, when the
// sandbox is stopped, removes its persisted configuration for the next boot.
func removeSandboxShare(name, tag string, force bool) error {
	if err := ValidateSandboxName(name); err != nil {
		return err
	}
	if err := shares.ValidateShareTag(tag); err != nil {
		return err
	}
	if _, alive := sandboxPID(name); alive {
		_, err := shareControlRPC(name, "share.remove", brokerShareRequest{
			Tag: tag, Persistent: true, Force: force,
		})
		return err
	}
	store, err := LoadConfigStore(sandboxDir(name))
	if err != nil {
		return err
	}
	_, err = store.RemoveShareForRestart(tag)
	return err
}

func normalizeShareSpecForClient(spec string) (string, error) {
	share, err := vmm.ParseShareSpec(spec, map[string]bool{})
	if err != nil {
		return "", err
	}
	abs, err := filepath.Abs(share.Path)
	if err != nil {
		return "", err
	}
	normalized := share.Tag + "=" + abs
	if share.CtrPath != "" {
		normalized += "@" + share.CtrPath
	}
	if share.RO {
		normalized += ",ro"
	}
	if share.UID != nil {
		normalized += fmt.Sprintf(",uid=%d,gid=%d", *share.UID, *share.GID)
	}
	return normalized, nil
}

func dialShareControl(name string) (net.Conn, error) {
	path := filepath.Join(sandboxDir(name), "ctl.sock")
	var err error
	for range 20 {
		var conn net.Conn
		conn, err = net.DialTimeout("unix", path, time.Second)
		if err == nil {
			return conn, nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return nil, err
}

func printShareMutation(verb string, entry *shares.Entry) {
	if entry == nil {
		fmt.Println("gantry share:", verb)
		return
	}
	mode := "rw"
	if entry.RO {
		mode = "ro"
	}
	fmt.Printf("share %s %s: %s -> %s (%s, %s)\n",
		verb, entry.Tag, entry.Path, entry.CtrPath, mode, defaultShareState(entry.State))
}

func printShares(name string) int {
	var entries []shares.Entry
	if _, alive := sandboxPID(name); alive {
		resp, err := shareControlRPC(name, "share.list", brokerShareRequest{Persistent: true})
		if err != nil {
			fmt.Fprintln(os.Stderr, "gantry share ls:", err)
			return 1
		}
		entries = resp.Shares
	} else {
		raw, err := os.ReadFile(filepath.Join(sandboxDir(name), "sandbox.json"))
		if err != nil {
			fmt.Fprintln(os.Stderr, "gantry share ls:", err)
			return 1
		}
		var cfg RunConfig
		if err := json.Unmarshal(raw, &cfg); err != nil {
			fmt.Fprintln(os.Stderr, "gantry share ls: corrupt sandbox.json:", err)
			return 1
		}
		seen := map[string]bool{}
		for _, spec := range cfg.Shares {
			share, err := vmm.ParseShareSpec(spec, seen)
			if err != nil {
				fmt.Fprintln(os.Stderr, "gantry share ls: bad saved share:", err)
				return 1
			}
			seen[share.Tag] = true
			ctr := share.CtrPath
			if ctr == "" {
				ctr = shares.HubHostPath + "/" + share.Tag
			}
			entries = append(entries, shares.Entry{
				Tag: share.Tag, Path: share.Path, RO: share.RO,
				VMPath:  shares.HubVMPath + "/" + share.Tag,
				CtrPath: ctr, State: "saved",
			})
		}
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Tag < entries[j].Tag })
	w := newCLITable(os.Stdout)
	_, _ = fmt.Fprintln(w, "TAG\tMODE\tSTATE\tHOST PATH\tCONTAINER PATH")
	for _, entry := range entries {
		mode := "rw"
		if entry.RO {
			mode = "ro"
		}
		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", entry.Tag, mode, defaultShareState(entry.State), entry.Path, entry.CtrPath)
	}
	_ = w.Flush()
	return 0
}

func defaultShareState(state string) string {
	if state == "" {
		return "active"
	}
	return state
}
