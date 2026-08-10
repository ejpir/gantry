package sandbox

// pi.go — `gantry pi`: run the pi coding agent (TUI, agent loop, tools,
// and — crucially — the LLM requests) entirely inside a gantry sandbox,
// with the TUI streamed to the host terminal over the session pty.
//
// Model: one persistent sandbox per project directory (pi-<dirname>),
// the project shared rw at /workspace, pi's own state (~/.pi) in the
// per-sandbox rwlayer. The first run needs a pi-capable image (see
// mkpiimage.sh); later runs attach to the still-running sandbox, so the
// usual flow is: build image once, `gantry pi -image pi-agent.tar` once,
// then plain `gantry pi` forever.
//
// Credentials: the host's ~/.pi/agent (auth.json, sessions, settings)
// is shared into the guest at /root/.pi/agent by default, so the guest
// pi is logged in exactly like host pi — no env vars, no re-login, and
// OAuth refreshes write back to the same file. -pi-auth=false opts out
// (guest-local login then persists in the rwlayer instead). Anything
// running IN the sandbox can read the shared credentials, so pair with
// -net-policy pinned to the provider's domain: a stolen token can then
// only reach the API itself. Host-side credential injection (an auth
// gateway in the netstack) remains the planned stronger option — the
// key then never enters the VM at all.

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ejpir/gantry/internal/gutil"
)

// piSandboxName derives the per-project sandbox name from the directory
// basename (sanitized to the sandbox charset, length-capped).
func piSandboxName(cwd string) string {
	base := filepath.Base(cwd)
	var b strings.Builder
	for _, r := range base {
		ok := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-'
		if ok {
			b.WriteRune(r)
		} else {
			b.WriteByte('-')
		}
	}
	name := "pi-" + b.String()
	if len(name) > 64 {
		name = name[:64]
	}
	return name
}

// piConfig carries the shared boot options for the pi sandboxes.
type piConfig struct {
	image   string
	netpol  string
	mem     uint
	cpus    int
	restart bool
	piAuth  bool
	secrets gutil.StrList
}

func registerPiFlags(fs *flag.FlagSet, cfg *piConfig) {
	fs.StringVar(&cfg.image, "image", os.Getenv("GANTRY_PI_IMAGE"), "pi-capable image (docker save tar, OCI ref/layout, .erofs; default: GANTRY_PI_IMAGE)")
	fs.StringVar(&cfg.netpol, "net-policy", "", "JSON egress policy (recommended: pin to your provider's API domain)")
	fs.UintVar(&cfg.mem, "mem", 1024, "guest RAM in MiB")
	fs.IntVar(&cfg.cpus, "cpus", 2, "guest vCPU count")
	fs.BoolVar(&cfg.restart, "restart", false, "delete and recreate the project's sandbox first")
	fs.BoolVar(&cfg.piAuth, "pi-auth", true, "share host ~/.pi/agent into the guest at /root/.pi/agent (reuse your pi login; pair with -net-policy)")
	fs.Var(&cfg.secrets, "secret", "inject a secret into the sandbox: NAME (from gantry's environment) or NAME=@/path; repeatable")
}

// ensurePiSandbox boots the project's pi sandbox if it isn't running.
func ensurePiSandbox(cfg *piConfig, cwd, name string) int {
	if cfg.restart {
		CmdDelete(name)
	}
	if _, alive := sandboxPID(name); alive {
		return 0
	}
	if cfg.image == "" {
		fmt.Fprintln(os.Stderr, `gantry pi: no image configured and the sandbox is not running.
Build one with ./scripts/mkpiimage.sh, then:
  gantry pi -image ./pi-agent.tar
(or export GANTRY_PI_IMAGE to make it permanent)`)
		return 2
	}
	startArgv := []string{
		name,
		"-image", cfg.image,
		// @/workspace: with two shares the default container paths
		// would be /host/ws + /host/piagent — pin the project mount
		// where the exec and the docs expect it.
		"-share", "ws=" + cwd + "@/workspace",
		"-mem", fmt.Sprint(cfg.mem),
		"-cpus", fmt.Sprint(cfg.cpus),
	}
	if cfg.netpol != "" {
		startArgv = append(startArgv, "-net-policy", cfg.netpol)
	}
	for _, s := range cfg.secrets.List() {
		startArgv = append(startArgv, "-secret", s)
	}
	// Reuse the host pi login: ~/.pi/agent lands at /root/.pi/agent
	// in the container (the pi-agent image runs as root). Shared rw
	// so OAuth refreshes write back; auth, sessions, and settings
	// stay consistent between host pi and guest pi. The trade-off:
	// everything running IN the sandbox can read it too — pin egress
	// with -net-policy so a stolen token can only reach the provider.
	if cfg.piAuth {
		if home, err := os.UserHomeDir(); err == nil {
			agentDir := filepath.Join(home, ".pi", "agent")
			if st, err := os.Stat(agentDir); err == nil && st.IsDir() {
				startArgv = append(startArgv, "-share", "piagent="+agentDir+"@/root/.pi/agent")
				if cfg.netpol == "" {
					fmt.Fprintln(os.Stderr, "gantry pi: sharing ~/.pi/agent with the sandbox; consider -net-policy pinned to your provider's domain")
				}
			} else {
				fmt.Fprintln(os.Stderr, "gantry pi: no ~/.pi/agent on the host — run 'pi login' in the guest (persists in the rwlayer)")
			}
		}
	}
	return CmdStart(startArgv)
}

func CmdPi(argv []string) int {
	fs := flag.NewFlagSet("pi", flag.ExitOnError)
	var cfg piConfig
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, `usage: gantry pi [flags] [-- PI_ARGS]

Run the pi coding agent inside a gantry sandbox: one persistent sandbox
per project directory, the project mounted at /workspace, TUI on this
terminal. Your host ~/.pi/agent (auth, sessions, settings) is shared
into the guest by default — no env vars to pass (-pi-auth=false opts
out). First run needs a pi-capable image (./scripts/mkpiimage.sh builds
./pi-agent.tar); while the sandbox is running, plain 'gantry pi'
reattaches — including from other terminals.

examples:
  gantry pi -image ./pi-agent.tar -net-policy examples/llm-only.json
  gantry pi                       # reattach to this project's sandbox
  gantry pi -restart -image ./pi-agent.tar
  gantry stop pi-$(basename $PWD) # stop it

flags:`)
		fs.PrintDefaults()
	}
	registerPiFlags(fs, &cfg)

	piArgs := []string(nil)
	for i, a := range argv {
		if a == "--" {
			piArgs = argv[i+1:]
			argv = argv[:i]
			break
		}
	}
	_ = fs.Parse(argv)

	cwd, err := os.Getwd()
	if err != nil {
		fmt.Fprintln(os.Stderr, "gantry pi:", err)
		return 1
	}
	name := piSandboxName(cwd)
	if rc := ensurePiSandbox(&cfg, cwd, name); rc != 0 {
		return rc
	}

	// Attach with the project as cwd. sh -c "$0" "$@" form: no quoting
	// hazards, pi's own args pass through untouched.
	execArgv := append([]string{"--", "sh", "-c", `cd /workspace && exec pi "$@"`, "sh"}, piArgs...)
	return CmdSandboxExec(name, execArgv)
}

// CmdPiServe boots (or reuses) the project's sandbox, makes sure the pi
// RPC agent is serving inside it, and prints the host-side attach
// command. The full stock TUI runs on the HOST; the agent — all tool
// execution, LLM calls, file access — lives in the VM.
func CmdPiServe(argv []string) int {
	fs := flag.NewFlagSet("pi-serve", flag.ExitOnError)
	var cfg piConfig
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, `usage: gantry pi-serve [flags]

Boot the project's pi sandbox and serve the pi RPC agent inside it
(guest bridge: /opt/pi/bridge.js, from the pi-attach image built by
integrations/pi-vm/mkpiattach.sh). Then attach the stock TUI from the
host — including repeatedly, and from other terminals:

  pi attach --cmd "gantry exec <sandbox> -- node /opt/pi/bridge.js"

Detach/reattach and takeover follow the agent's single-client socket
semantics. Needs a pi build with 'pi attach' (pi-attach-v1 branch).

flags:`)
		fs.PrintDefaults()
	}
	registerPiFlags(fs, &cfg)
	proxy := fs.String("proxy", "", "write HTTPS_PROXY=<value> into the guest's /etc/pi-bridge.env (e.g. http://192.168.1.1:3128)")
	_ = fs.Parse(argv)

	cwd, err := os.Getwd()
	if err != nil {
		fmt.Fprintln(os.Stderr, "gantry pi-serve:", err)
		return 1
	}
	name := piSandboxName(cwd)
	if rc := ensurePiSandbox(&cfg, cwd, name); rc != 0 {
		return rc
	}

	if *proxy != "" {
		env := fmt.Sprintf("HTTPS_PROXY=%s\nHTTP_PROXY=%s\n", *proxy, *proxy)
		if rc := CmdSandboxExec(name, []string{"--", "sh", "-c", "printf '%s' " + shellQuote(env) + " > /etc/pi-bridge.env"}); rc != 0 {
			fmt.Fprintln(os.Stderr, "gantry pi-serve: failed to write /etc/pi-bridge.env")
			return rc
		}
	}

	// Warm the agent now so the first attach connects instantly. Two steps:
	// poke the bridge's start-on-connect (spawns the guest agent if needed),
	// then WAIT for the guest socket — the poke returns immediately, and an
	// attach landing while the agent is still booting stalls in the client's
	// hello timeout / reconnect loop (the sporadic slow attach).
	if rc := CmdSandboxExec(name, []string{"--", "node", "-e",
		"require('node:net').connect('/tmp/pi-attach/agent.sock').once('error',()=>{require('node:child_process').spawn('node',['/opt/pi/bridge.js'],{stdio:'inherit'})}).once('connect',s=>s.end())",
	}); rc != 0 {
		fmt.Fprintln(os.Stderr, "gantry pi-serve: guest bridge check failed — is this a pi-attach image (integrations/pi-vm/mkpiattach.sh)?")
		return rc
	}
	if rc := CmdSandboxExec(name, []string{"--", "sh", "-c",
		"i=0; while [ $i -lt 120 ]; do [ -S /tmp/pi-attach/agent.sock ] && exit 0; i=$((i+1)); sleep 0.5 2>/dev/null || sleep 1; done; exit 1",
	}); rc != 0 {
		fmt.Fprintln(os.Stderr, "gantry pi-serve: guest agent did not start within 60s — check the guest log:")
		fmt.Fprintf(os.Stderr, "  gantry exec %s -- cat /tmp/pi-attach/agent.log\n", name)
		return rc
	}

	fmt.Printf("sandbox %s is serving. Attach from the host with:\n\n  pi attach --cmd %s\n\n", name, shellQuote("gantry exec "+name+" -- node /opt/pi/bridge.js"))
	return 0
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
