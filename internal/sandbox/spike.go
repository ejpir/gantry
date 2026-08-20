package sandbox

// spike.go — hidden spike commands (docs/kubernetes-runtimeclass.md, Phase
// K0). Each spike boots one VM in the foreground exactly like `gantry start`,
// then replaces supervise() with a scenario hook, prints a pass/fail
// transcript, and shuts the VM down. They exist to validate RuntimeClass
// design assumptions without containerd, CNI, or Kubernetes.

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ejpir/gantry/internal/atomicfile"
	"github.com/ejpir/gantry/internal/client"
	"github.com/ejpir/gantry/internal/gutil"
	"github.com/ejpir/gantry/internal/sandbox/config"
	"github.com/ejpir/gantry/internal/sandbox/layout"
	"github.com/ejpir/gantry/internal/sandbox/localsec"
)

// CmdMCSpike implements `gantry _mc-spike`: the multi-container guest spike.
// It verifies that one booted guest can host several independent task.v3
// containers concurrently — the core assumption behind one-VM-per-Pod.
func CmdMCSpike(argv []string) int {
	launch, code := prepareSpikeLaunch(argv, "_mc-spike", `examples:
  gantry _mc-spike mc1 -image alpine:latest
  gantry _mc-spike mc2 -image debian:bookworm-slim -runtime runsc`)
	if launch == nil {
		return code
	}
	return launch.run((*daemonRuntime).runMCSpike)
}

// runMCSpike is the _mc-spike scenario hook: the daemon is fully booted
// (guest RPC, stream bridge, control socket all live) at this point, and the
// spike uses the same guest connection and stream wiring as broker sessions.
func (d *daemonRuntime) runMCSpike() int {
	err := client.MultiContainerSpike(d.rpc, client.SpikeOptions{
		StreamSock: d.broker.streamSock,
		StreamDial: d.broker.streamDial,
		ImgCfg:     d.cfg.ImageCfg,
		LayerSet:   d.cfg.LayerSet,
		Report:     os.Stdout,
	})
	stopCode := d.gracefulStop("mc-spike complete")
	if err != nil {
		fmt.Fprintln(os.Stderr, "gantry _mc-spike:", err)
		return 1
	}
	return stopCode
}

// spikeLaunch carries a resolved, persisted spike sandbox configuration.
type spikeLaunch struct {
	name string
	cfg  config.RunConfig
	dir  string
}

// run boots the foreground daemon with postReady replaced by hook.
func (l *spikeLaunch) run(hook func(*daemonRuntime) int) int {
	d := &daemonRuntime{
		name:       l.name,
		started:    time.Now(),
		bootTiming: os.Getenv("GANTRY_BOOT_TIMING") != "",
		postReady:  hook,
	}
	return d.run()
}

// prepareSpikeLaunch shares flag resolution, launch locking, and config
// persistence between the hidden spike commands. A nil result means the
// command already reported its error and the returned code is the exit
// status. Spike daemons run in the foreground, so there is no launcher→daemon
// stdin handshake and -secret is refused rather than silently dropped.
func prepareSpikeLaunch(argv []string, label, examples string) (*spikeLaunch, int) {
	fs := flag.NewFlagSet(label, flag.ExitOnError)
	rf := config.RegisterRunFlags(fs)
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: gantry %s <name> [flags]   (hidden: guest spike, docs/kubernetes-runtimeclass.md)\n\n", label)
		fmt.Fprintln(os.Stderr, `Boot one VM like 'gantry start', run the scenario, and exit 0 when
every assertion passes. Accepts the same run flags as 'gantry start'.`)
		if examples != "" {
			fmt.Fprintln(os.Stderr, "\n"+examples)
		}
		fmt.Fprintln(os.Stderr, "\nflags:")
		fs.PrintDefaults()
	}
	if len(argv) > 0 && (argv[0] == "-h" || argv[0] == "--help") {
		fs.Usage()
		return nil, 0
	}
	if len(argv) == 0 || strings.HasPrefix(argv[0], "-") || !layout.ValidName(argv[0]) {
		fs.Usage()
		return nil, 2
	}
	name, fargv := argv[0], argv[1:]

	rf.Name = name
	_ = fs.Parse(fargv)
	prefix := "gantry " + label + ": "
	progress := gutil.NewProgressPrinter(os.Stdout, prefix)
	cfg, warnings, err := resolveFlags(rf, fs, progress.Printf, nil)
	progress.Finish()
	if err != nil {
		fmt.Fprintln(os.Stderr, prefix, err)
		return nil, 1
	}
	for _, w := range warnings {
		fmt.Fprintln(os.Stderr, prefix, w)
	}
	secrets, _, err := rf.ResolveSecrets()
	if err != nil {
		fmt.Fprintln(os.Stderr, prefix, err)
		return nil, 1
	}
	if len(secrets) > 0 {
		fmt.Fprintf(os.Stderr, "%s-secret is not supported by the spike harness\n", prefix)
		return nil, 2
	}

	launchLock, err := holdSandboxLaunchLock(name)
	if err != nil {
		fmt.Fprintln(os.Stderr, prefix, err)
		return nil, 1
	}
	defer func() { _ = launchLock.Close() }()

	dir := layout.Dir(name)
	if _, alive := layout.PID(name); alive || layout.LockHeld(dir) {
		fmt.Fprintf(os.Stderr, "%ssandbox %q is already running\n", prefix, name)
		return nil, 1
	}
	if err := os.RemoveAll(dir); err != nil {
		fmt.Fprintln(os.Stderr, prefix, err)
		return nil, 1
	}
	if err := localsec.CreateDir(dir); err != nil {
		fmt.Fprintln(os.Stderr, prefix, err)
		return nil, 1
	}
	cleanupSandboxRuntime(dir)
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, prefix, err)
		return nil, 1
	}
	if err := atomicfile.WriteFileDurable(filepath.Join(dir, "sandbox.json"), append(b, '\n'), 0o600); err != nil {
		fmt.Fprintln(os.Stderr, prefix, err)
		return nil, 1
	}
	return &spikeLaunch{name: name, cfg: cfg, dir: dir}, 0
}
