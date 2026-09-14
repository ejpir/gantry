package remote

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/ejpir/gantry/internal/gutil"
	"github.com/ejpir/gantry/internal/policy"
	"github.com/ejpir/gantry/internal/sandbox/layout"

	"golang.org/x/term"
)

// VerbSupported reports whether a gantry verb has a remote implementation.
func VerbSupported(command string) bool {
	switch command {
	case "start", "run", "configure", "exec", "ls", "stop", "delete", "resume", "image", "ssh", "ssh-proxy", "ssh-known-hosts", "events", "net-policy", "policy", "audit":
		return true
	}
	return false
}

// localOnlyFlags produce a targeted error on remote start instead of a bare
// "flag provided but not defined": these sandbox features are host-local by
// design (docs/remote-sandbox-access.md milestones 3+).
var localOnlyFlags = map[string]string{
	"mcp":              "the MCP gateway is local-only",
	"mcp-remote":       "the MCP gateway is local-only",
	"mcp-fs-root":      "the MCP gateway is local-only",
	"mcp-fs-user":      "the MCP gateway is local-only",
	"layerset":         "layersets are local-only",
	"oauth-custody":    "OAuth custody is local-only",
	"oauth-provider":   "OAuth custody is local-only",
	"secret-file":      "secret files are host-local; pass -secret NAME so the manager resolves the value from its own environment",
	"gvproxy":          "the gvproxy backend is local-only",
	"runtime-override": "local-only",
}

// ExtractTarget removes -remote/--remote from argv (scanning stops at "--",
// so exec command lines keep their flags) and resolves the effective target:
// the flag wins over GANTRY_REMOTE; an explicit empty value (-remote="") is
// an override back to local.
func ExtractTarget(argv []string, env string) (target string, rest []string, err error) {
	target = env
	explicit := false
	rest = make([]string, 0, len(argv))
	for i := 0; i < len(argv); i++ {
		arg := argv[i]
		if arg == "--" {
			rest = append(rest, argv[i:]...)
			break
		}
		var value string
		isRemote := false
		switch {
		case arg == "-remote" || arg == "--remote":
			if i+1 >= len(argv) {
				return "", argv, errors.New("gantry: -remote requires a profile name (or \"\" for local)")
			}
			i++
			value, isRemote = argv[i], true
		case strings.HasPrefix(arg, "-remote="):
			value, isRemote = strings.TrimPrefix(arg, "-remote="), true
		case strings.HasPrefix(arg, "--remote="):
			value, isRemote = strings.TrimPrefix(arg, "--remote="), true
		}
		if isRemote {
			if explicit {
				return "", argv, errors.New("gantry: duplicate -remote flag")
			}
			target, explicit = value, true
			continue
		}
		rest = append(rest, arg)
	}
	return target, rest, nil
}

// FlagPresent reports whether argv (up to "--") mentions -remote; it drives
// the clear error for verbs that have no remote implementation yet.
func FlagPresent(argv []string) bool {
	for _, arg := range argv {
		if arg == "--" {
			return false
		}
		if arg == "-remote" || arg == "--remote" || strings.HasPrefix(arg, "-remote=") || strings.HasPrefix(arg, "--remote=") {
			return true
		}
	}
	return false
}

// RunVerb executes one remote-capable verb against a profile.
func RunVerb(verb, target string, argv []string) int {
	profile, token, err := Load(target)
	if err != nil {
		fmt.Fprintln(os.Stderr, "gantry:", err)
		return 1
	}
	client, err := Dial(profile, token)
	if err != nil {
		fmt.Fprintln(os.Stderr, "gantry:", err)
		return 1
	}
	defer client.Close()
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	return runVerb(ctx, os.Stdout, os.Stderr, os.Stdin, verb, profile.Name, client, argv)
}

func runVerb(ctx context.Context, output, errorOutput io.Writer, input *os.File, verb, remoteName string, client *Client, argv []string) int {
	switch verb {
	case "run":
		return remoteRun(ctx, output, errorOutput, input, remoteName, client, argv)
	case "configure":
		return remoteConfigure(ctx, output, errorOutput, remoteName, client, argv)
	case "events":
		return remoteEvents(ctx, output, errorOutput, remoteName, client, argv)
	case "net-policy", "policy", "audit":
		return remotePolicy(ctx, output, errorOutput, remoteName, client, verb, argv)
	case "ssh", "ssh-proxy", "ssh-known-hosts":
		return remoteSSH(ctx, output, errorOutput, input, remoteName, client, verb, argv)
	case "image":
		return remoteImage(ctx, output, errorOutput, remoteName, client, argv)
	case "ls":
		return remoteLs(ctx, output, errorOutput, remoteName, client, argv)
	case "start":
		return remoteStart(ctx, output, errorOutput, remoteName, client, argv)
	case "exec":
		return remoteExec(ctx, output, errorOutput, input, remoteName, client, argv)
	case "stop", "delete", "resume":
		return remoteLifecycle(ctx, output, errorOutput, remoteName, client, verb, argv)
	}
	_, _ = fmt.Fprintf(errorOutput, "gantry: -remote is not supported for %q\n", verb)
	return 2
}

func remoteLs(ctx context.Context, output, errorOutput io.Writer, remoteName string, client *Client, argv []string) int {
	if len(argv) != 0 {
		_, _ = fmt.Fprintln(errorOutput, "usage: gantry ls [-remote NAME]")
		return 2
	}
	listCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	sandboxes, err := client.ListSandboxes(listCtx)
	if err != nil {
		_, _ = fmt.Fprintln(errorOutput, "gantry ls:", err)
		return 1
	}
	if len(sandboxes) == 0 {
		_, _ = fmt.Fprintf(output, "no sandboxes on remote %q\n", remoteName)
		return 0
	}
	_, _ = fmt.Fprintf(output, "%-20s %-10s %-8s %s\n", "NAME", "STATE", "PID", "IMAGE")
	for _, sandbox := range sandboxes {
		pid := "-"
		if sandbox.PID > 0 {
			pid = fmt.Sprint(sandbox.PID)
		}
		image := sandbox.Image
		if image == "" {
			image = sandbox.ImageRef
		}
		if image == "" {
			image = "-"
		}
		_, _ = fmt.Fprintf(output, "%-20s %-10s %-8s %s\n", sandbox.Name, sandbox.State, pid, image)
	}
	return 0
}

func remoteStart(ctx context.Context, output, errorOutput io.Writer, remoteName string, client *Client, argv []string) int {
	fs := flag.NewFlagSet("start", flag.ContinueOnError)
	fs.SetOutput(errorOutput)
	image := fs.String("image", "", "container image already cached on the remote (gantry image pull -remote NAME REF)")
	kernel := fs.String("kernel", "", "Linux kernel image (path on the remote host)")
	rootfs := fs.String("rootfs", "", "VM rootfs (path on the remote host)")
	runtime := fs.String("runtime", "", "container runtime in the guest: crun | runsc")
	rwLayer := fs.String("rwlayer", "", "ext4 writable layer (path on the remote host)")
	ssh := fs.Bool("ssh", false, "enable the sandbox SSH gateway")
	devcontainers := fs.Bool("devcontainers", false, "enable the curated IDE container on the remote")
	rw := fs.Bool("rw", false, "writable overlay container root")
	net := fs.Bool("net", true, "attach virtio-net via the embedded netstack")
	oauthBridge := fs.Bool("oauth-bridge", true, "bridge agent OAuth loopback callbacks to host listeners")
	netPol := fs.String("net-policy", "", "JSON egress policy file (path on the remote host)")
	allowLN := fs.Bool("allow-local-net", false, "let the sandbox reach LAN/link-local/host")
	proxyURL := fs.String("proxy", "", "route guest HTTP(S) through this proxy URL")
	noProxy := fs.String("no-proxy", "", "comma-separated proxy bypasses")
	proxyEnforce := fs.Bool("proxy-enforce", false, "block direct TCP/UDP except to the configured proxy")
	procIso := fs.String("process-isolation", "", "auto | required | off")
	orgPolicy := fs.String("org-policy", "", "signed organization bundle (LOCAL file, uploaded and verified by manager)")
	orgKey := fs.String("org-policy-key", "", "organization PUBLIC key (LOCAL PEM file)")
	orgProfile := fs.String("policy-profile", "", "profile in the signed organization bundle")
	memMB := fs.Uint("mem", 0, "guest RAM in MiB (default: the remote's)")
	diskSize := fs.Uint("disk-size", 0, "persistent writable disk size in MiB (default: the remote's)")
	vcpus := fs.Int("cpus", 0, "guest vCPU count (default: the remote's)")
	var shareArgs, publishArgs, secretArgs gutil.StrList
	fs.Var(&shareArgs, "share", "remote directory exported through virtio-fs as TAG=PATH[,mount=CTRPATH][,ro] (repeatable)")
	fs.Var(&publishArgs, "p", "publish a guest port on the remote host: [IP:]HOST:GUEST[/udp] (repeatable)")
	fs.Var(&publishArgs, "publish", "alias for -p")
	fs.Var(&secretArgs, "secret", "inject a secret BY NAME: the value is resolved from the manager's environment (repeatable)")
	if len(argv) > 0 && (argv[0] == "-h" || argv[0] == "--help") {
		_, _ = fmt.Fprintf(errorOutput, "usage: gantry start <name> [flags] -remote NAME\n\nflags (paths resolve on the remote host):\n")
		fs.PrintDefaults()
		return 0
	}
	if len(argv) == 0 || strings.HasPrefix(argv[0], "-") || !layout.ValidName(argv[0]) {
		_, _ = fmt.Fprintln(errorOutput, "usage: gantry start <name> [flags] -remote NAME   (name: letters, digits, ._-)")
		return 2
	}
	name := argv[0]
	for _, arg := range argv[1:] {
		if arg == "--" {
			break
		}
		if !strings.HasPrefix(arg, "-") {
			continue
		}
		flagName := strings.TrimLeft(strings.SplitN(arg, "=", 2)[0], "-")
		if reason, local := localOnlyFlags[flagName]; local {
			_, _ = fmt.Fprintf(errorOutput, "gantry start: -%s is not supported with -remote: %s\n", flagName, reason)
			return 2
		}
	}
	if err := fs.Parse(argv[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if extras := fs.Args(); len(extras) != 0 {
		_, _ = fmt.Fprintf(errorOutput, "gantry start: unexpected argument %q\n", extras[0])
		return 2
	}
	request := CreateSandboxRequest{
		Name: name, Image: *image, Kernel: *kernel, Rootfs: *rootfs, Runtime: *runtime,
		SSH: *ssh, DevContainers: *devcontainers,
		RWLayer: *rwLayer, NetworkPolicy: *netPol, AllowLocalNetwork: *allowLN,
		Proxy: *proxyURL, NoProxy: *noProxy, ProxyEnforce: *proxyEnforce,
		ProcessIsolation: *procIso, MemoryMiB: *memMB, DiskSizeMiB: *diskSize, CPUs: *vcpus,
		Shares:  append([]string(nil), shareArgs.List()...),
		Publish: append([]string(nil), publishArgs.List()...),
	}
	var err error
	request.OrganizationPolicy, err = policy.ReadConfig(*orgPolicy, *orgKey, *orgProfile)
	if err != nil {
		_, _ = fmt.Fprintln(errorOutput, "gantry start:", err)
		return 2
	}
	fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "rw":
			request.RW = rw
		case "net":
			request.Net = net
		case "oauth-bridge":
			request.OAuthBridge = oauthBridge
		}
	})
	for _, secretName := range secretArgs.List() {
		if strings.ContainsAny(secretName, "=@,") {
			_, _ = fmt.Fprintf(errorOutput, "gantry start: -secret %q is not supported with -remote: pass a plain NAME; the manager resolves the value from its own environment\n", secretName)
			return 2
		}
		request.SecretNames = append(request.SecretNames, secretName)
	}

	_, _ = fmt.Fprintf(errorOutput, "gantry start: creating sandbox %q on remote %q (image must already be cached)...\n", name, remoteName)
	createCtx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()
	operation, err := client.CreateSandbox(createCtx, request)
	if err != nil {
		_, _ = fmt.Fprintln(errorOutput, "gantry start:", err)
		return 1
	}
	for _, warning := range operation.Warnings {
		_, _ = fmt.Fprintln(errorOutput, "gantry start:", warning)
	}
	_, _ = fmt.Fprintf(output, "gantry start: sandbox %q is up on %q — attach with: gantry exec %s -remote %s -- CMD\n", name, remoteName, name, remoteName)
	return 0
}

// maxRemoteStdin mirrors the API's 1 MiB stdin bound.
const maxRemoteStdin = 1 << 20

func remoteExec(ctx context.Context, output, errorOutput io.Writer, input *os.File, remoteName string, client *Client, argv []string) int {
	if len(argv) == 0 {
		_, _ = fmt.Fprintln(errorOutput, "usage: gantry exec <name> [-timeout SECONDS] -remote NAME [-- CMD ...]")
		return 2
	}
	if strings.HasPrefix(argv[0], "-") {
		if argv[0] == "-h" || argv[0] == "--help" {
			_, _ = fmt.Fprintln(errorOutput, "usage: gantry exec <name> [-timeout SECONDS] -remote NAME [-- CMD ...]")
			return 0
		}
		_, _ = fmt.Fprintln(errorOutput, "gantry exec: one-shot exec (no sandbox name) is not supported with -remote; start a named sandbox first")
		return 2
	}
	name, rest := argv[0], argv[1:]
	if !layout.ValidName(name) {
		_, _ = fmt.Fprintf(errorOutput, "gantry exec: invalid sandbox name %q\n", name)
		return 2
	}
	fs := flag.NewFlagSet("exec", flag.ContinueOnError)
	fs.SetOutput(errorOutput)
	timeout := fs.Int("timeout", 300, "command timeout in seconds (max 3600)")
	if err := fs.Parse(rest); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	args := fs.Args()
	if len(args) > 0 && args[0] == "--" {
		args = args[1:]
	}
	if len(args) == 0 {
		_, _ = fmt.Fprintln(errorOutput, "gantry exec: interactive sessions are not available over -remote ; use gantry ssh for a terminal, or run a command:\n  gantry exec "+name+" -remote "+remoteName+" -- CMD ...")
		return 2
	}
	if *timeout < 1 || *timeout > 3600 {
		_, _ = fmt.Fprintln(errorOutput, "gantry exec: -timeout must be between 1 and 3600 seconds")
		return 2
	}
	request := ExecRequest{Argv: args, TimeoutSeconds: *timeout}
	if !term.IsTerminal(int(input.Fd())) {
		stdin, err := io.ReadAll(io.LimitReader(input, maxRemoteStdin+1))
		if err != nil {
			_, _ = fmt.Fprintln(errorOutput, "gantry exec: read stdin:", err)
			return 1
		}
		if len(stdin) > maxRemoteStdin {
			_, _ = fmt.Fprintf(errorOutput, "gantry exec: stdin exceeds the %d-byte API limit\n", maxRemoteStdin)
			return 2
		}
		request.Stdin = string(stdin)
	}
	execCtx, cancel := context.WithTimeout(ctx, time.Duration(*timeout)*time.Second+30*time.Second)
	defer cancel()
	result, err := client.Exec(execCtx, name, request)
	if err != nil {
		var apiErr *Error
		if errors.As(err, &apiErr) && apiErr.Status == http.StatusRequestTimeout {
			_, _ = fmt.Fprintf(errorOutput, "gantry exec: command timed out after %ds\n", *timeout)
			return 124
		}
		_, _ = fmt.Fprintln(errorOutput, "gantry exec:", err)
		return 1
	}
	_, _ = io.WriteString(output, result.Output)
	if result.Truncated {
		_, _ = fmt.Fprintln(errorOutput, "gantry exec: warning: output was truncated by the manager")
	}
	return result.ExitCode
}

func remoteLifecycle(ctx context.Context, output, errorOutput io.Writer, remoteName string, client *Client, verb string, argv []string) int {
	if len(argv) != 1 || !layout.ValidName(argv[0]) {
		_, _ = fmt.Fprintf(errorOutput, "usage: gantry %s <name> -remote NAME\n", verb)
		return 2
	}
	name := argv[0]
	lifecycleCtx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	var operation Operation
	var err error
	switch verb {
	case "stop":
		operation, err = client.StopSandbox(lifecycleCtx, name)
	case "delete":
		operation, err = client.DeleteSandbox(lifecycleCtx, name)
	case "resume":
		operation, err = client.StartSandbox(lifecycleCtx, name)
	}
	if err != nil {
		_, _ = fmt.Fprintf(errorOutput, "gantry %s: %s\n", verb, err)
		return 1
	}
	for _, warning := range operation.Warnings {
		_, _ = fmt.Fprintf(errorOutput, "gantry %s: %s\n", verb, warning)
	}
	switch verb {
	case "stop":
		_, _ = fmt.Fprintf(output, "gantry stop: sandbox %q stopped on %q\n", name, remoteName)
	case "delete":
		_, _ = fmt.Fprintf(output, "gantry delete: sandbox %q deleted on %q\n", name, remoteName)
	case "resume":
		_, _ = fmt.Fprintf(output, "gantry resume: sandbox %q is up on %q — attach with: gantry exec %s -remote %s -- CMD\n", name, remoteName, name, remoteName)
	}
	return 0
}
