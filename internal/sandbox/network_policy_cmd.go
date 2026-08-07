package sandbox

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

// CmdNetworkPolicy implements persistent live egress-policy updates.
// Running embedded-netstack sandboxes switch immediately; stopped sandboxes
// save the validated policy for their next start.
func CmdNetworkPolicy(argv []string) int {
	usage := func() {
		fmt.Fprintln(os.Stderr, `usage:
  gantry net-policy set [--allow-local-net] <name> <policy.json>
  gantry net-policy default [--allow-local-net] <name>
  gantry net-policy show <name>`)
	}
	if len(argv) == 0 || argv[0] == "-h" || argv[0] == "--help" {
		usage()
		if len(argv) > 0 {
			return 0
		}
		return 2
	}
	op := argv[0]
	allowLocal := false
	var args []string
	for _, arg := range argv[1:] {
		if arg == "--allow-local-net" {
			allowLocal = true
			continue
		}
		if strings.HasPrefix(arg, "--") {
			fmt.Fprintln(os.Stderr, "gantry net-policy: unknown option", arg)
			return 2
		}
		args = append(args, arg)
	}

	switch op {
	case "set":
		if len(args) != 2 {
			usage()
			return 2
		}
		entry, err := setSandboxNetworkPolicy(args[0], args[1], allowLocal)
		if err != nil {
			fmt.Fprintln(os.Stderr, "gantry net-policy set:", err)
			return 1
		}
		printNetworkPolicyMutation(entry)
		return 0
	case "default", "clear":
		if len(args) != 1 {
			usage()
			return 2
		}
		entry, err := setSandboxNetworkPolicy(args[0], "", allowLocal)
		if err != nil {
			fmt.Fprintln(os.Stderr, "gantry net-policy default:", err)
			return 1
		}
		printNetworkPolicyMutation(entry)
		return 0
	case "show":
		if len(args) != 1 || allowLocal {
			usage()
			return 2
		}
		entry, err := getSandboxNetworkPolicy(args[0])
		if err != nil {
			fmt.Fprintln(os.Stderr, "gantry net-policy show:", err)
			return 1
		}
		printNetworkPolicyShow(os.Stdout, args[0], entry)
		return 0
	default:
		usage()
		return 2
	}
}

func networkPolicyRPC(name, op string, request *brokerNetworkPolicyRequest) (NetworkPolicyEntry, error) {
	conn, err := dialShareControl(name)
	if err != nil {
		return NetworkPolicyEntry{}, fmt.Errorf("broker: %w", err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	req := brokerRequest{Op: op, ID: fmt.Sprintf("netpolicy-%d", os.Getpid()), NetPolicy: request}
	if err := json.NewEncoder(conn).Encode(&req); err != nil {
		return NetworkPolicyEntry{}, err
	}
	var resp brokerNetworkPolicyResponse
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return NetworkPolicyEntry{}, err
	}
	if !resp.OK || resp.Policy == nil {
		if resp.Error == "" {
			resp.Error = "network policy operation rejected"
		}
		return NetworkPolicyEntry{}, fmt.Errorf("%s", resp.Error)
	}
	return *resp.Policy, nil
}

func getSandboxNetworkPolicy(name string) (NetworkPolicyEntry, error) {
	if err := ValidateSandboxName(name); err != nil {
		return NetworkPolicyEntry{}, err
	}
	if _, alive := sandboxPID(name); alive {
		entry, err := networkPolicyRPC(name, "netpolicy.get", nil)
		if err != nil {
			return NetworkPolicyEntry{}, err
		}
		return hydrateNetworkPolicyRules(entry), nil
	}
	store, err := LoadConfigStore(sandboxDir(name))
	if err != nil {
		return NetworkPolicyEntry{}, err
	}
	cfg := store.Snapshot()
	path, policy, err := resolveNetworkPolicy(cfg.NetPol, cfg.AllowLN)
	if err != nil {
		return NetworkPolicyEntry{}, err
	}
	return makeNetworkPolicyEntry(path, cfg.AllowLN, policy, "saved"), nil
}

// hydrateNetworkPolicyRules keeps the new show output useful while talking to
// a sandbox daemon started by the immediately preceding Gantry build, whose
// broker response did not yet include parsed rule summaries.
func hydrateNetworkPolicyRules(entry NetworkPolicyEntry) NetworkPolicyEntry {
	if len(entry.Rules) != 0 {
		return entry
	}
	_, policy, err := resolveNetworkPolicy(entry.Path, entry.AllowLocal)
	if err == nil {
		entry.Rules = policy.RuleSummaries()
	}
	return entry
}

func printNetworkPolicyMutation(entry NetworkPolicyEntry) {
	path := entry.Path
	if path == "" {
		path = "built-in default"
	}
	fmt.Printf("network policy %s: %s (%s, allow-local-net=%t)\n", entry.State, path, entry.Description, entry.AllowLocal)
}

func printNetworkPolicyShow(output io.Writer, sandbox string, entry NetworkPolicyEntry) {
	path := entry.Path
	if path == "" {
		path = "built-in default"
	}
	// AllowLocal is the authoritative posture. The older-daemon compat
	// path leaves Description empty, and rule text is presentation detail
	// — never derive state from either.
	local := "deny"
	if entry.AllowLocal {
		local = "allow"
	}

	summary := newCLITable(output)
	_, _ = fmt.Fprintln(summary, "SANDBOX\tSTATE\tLOCAL NET\tPOLICY")
	_, _ = fmt.Fprintf(summary, "%s\t%s\t%s\t%s\n", sandbox, entry.State, local, path)
	_ = summary.Flush()

	if len(entry.Rules) == 0 {
		return
	}
	_, _ = fmt.Fprintln(output)
	rules := newCLITable(output)
	_, _ = fmt.Fprintln(rules, "ACTION\tTARGET\tPROTO\tPORTS\tSOURCE")
	for _, rule := range entry.Rules {
		ports := rule.Ports
		if ports == "" {
			ports = "-"
		}
		_, _ = fmt.Fprintf(rules, "%s\t%s\t%s\t%s\t%s\n",
			strings.ToUpper(rule.Action), rule.Target, rule.Protocol, ports, rule.Source)
	}
	_ = rules.Flush()
}
