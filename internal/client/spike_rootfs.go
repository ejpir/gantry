package client

// spike_rootfs.go — dynamic-rootfs guest spike (docs/kubernetes-runtimeclass.md,
// Phase K0). Verifies the second existential risk of the Kubernetes
// RuntimeClass design: a host directory that arrives after VM boot (a
// containerd-style snapshot) can be exported through the permanent virtio-fs
// hub, bind-mounted by the guest agent as a task bundle rootfs, and used by
// crun with correct OCI rootfs semantics and measurable performance.

import (
	"errors"
	"fmt"
	"io"
	"net"
	"strings"

	"github.com/ejpir/gantry/internal/shares"

	"github.com/containerd/ttrpc"
)

// RootfsSpikeOptions configures RootfsSpike. The host side is expected to have
// published ExportTag (writable) and ROTag (host-enforced read-only) exports
// of the same prepared snapshot directory before the call.
type RootfsSpikeOptions struct {
	StreamSock string
	StreamDial func() (net.Conn, error)
	Report     io.Writer

	// HubTag/HubVMPath locate the permanent virtio-fs hub; the zero values
	// select the production transport.
	HubTag    string
	HubVMPath string
	// ExportTag and ROTag name the published hub exports of the snapshot.
	ExportTag string
	ROTag     string
	// WhiteoutPath is a guest path present in the snapshot's lower layer and
	// hidden by an overlay whiteout in the upper layer. Empty skips the check.
	WhiteoutPath string
	// CheckerArgs override the guest checker invocation (default:
	// /spikecheck -whiteout <WhiteoutPath>). A custom first element also
	// replaces the RO-mode and perf-mode invocations.
	CheckerArgs []string
}

// RootfsSpikeResult carries the guest evidence back to the host side, which
// verifies host-visible effects (e.g. a guest write landing in the overlay
// upper directory).
type RootfsSpikeResult struct {
	RWStatus   int
	RWOutput   string
	ROStatus   int
	ROOutput   string
	PerfOutput string
}

// RootfsSpike runs the dynamic-rootfs scenario against the vminitd at the
// other end of client. A nil return means every guest assertion passed.
func RootfsSpike(client *ttrpc.Client, options RootfsSpikeOptions) (*RootfsSpikeResult, error) {
	s := newMCSpike(client, options.StreamSock, options.StreamDial, options.Report)
	return s.runRootfsSpike(options)
}

func (o *RootfsSpikeOptions) withDefaults() RootfsSpikeOptions {
	out := *o
	if out.HubTag == "" {
		out.HubTag = shares.HubTag
	}
	if out.HubVMPath == "" {
		out.HubVMPath = shares.HubVMPath
	}
	if len(out.CheckerArgs) == 0 {
		out.CheckerArgs = []string{"/spikecheck"}
		if out.WhiteoutPath != "" {
			out.CheckerArgs = append(out.CheckerArgs, "-whiteout", out.WhiteoutPath)
		}
	}
	return out
}

// rootfsTaskConfig renders the spike container's OCI config: the production
// namespace/capability shape, but root.readonly=false even for the RO task so
// that a rejected write can only be credited to host-side export enforcement.
func rootfsTaskConfig(args []string) (string, error) {
	return configJSONWithTransportCwdEnv(nil, nil, true, args, nil, false, "", nil)
}

// runRootfsSpike executes the dynamic-rootfs scenario on s. The hub mount is
// structural and fails fast; the three task scenarios are independent and run
// to completion even when an earlier one failed, so one bad transport
// behavior cannot hide the read-only-enforcement or performance results.
func (s *mcSpike) runRootfsSpike(options RootfsSpikeOptions) (*RootfsSpikeResult, error) {
	if s.report == nil {
		s.report = io.Discard
	}
	options = options.withDefaults()
	result := &RootfsSpikeResult{RWStatus: -1, ROStatus: -1}
	_, _ = fmt.Fprintln(s.report, "rootfs-spike: dynamic rootfs via virtio-fs hub export (docs/kubernetes-runtimeclass.md, Phase K0)")
	defer s.cleanup()

	s.steps = 4
	if err := s.mountShareHub(options.HubTag, options.HubVMPath); err != nil {
		_, _ = fmt.Fprintf(s.report, "rootfs-spike: FAIL guest mounts the permanent share hub: %v\n", err)
		_, _ = fmt.Fprintf(s.report, "rootfs-spike: %d/%d assertions passed\n", s.passed, s.steps)
		return result, fmt.Errorf("guest mounts the permanent share hub: %w", err)
	}
	s.passed++
	_, _ = fmt.Fprintf(s.report, "rootfs-spike: PASS guest mounts the permanent share hub — %s at %s\n", options.HubTag, options.HubVMPath)

	exportPath := func(tag string) string {
		return strings.TrimRight(options.HubVMPath, "/") + "/" + tag
	}
	scenarios := []struct {
		name   string
		detail string
		run    func() error
	}{
		{"export bind-mounted as bundle rootfs, rw battery passes",
			"checker passed: identity, whiteout, xattr, hardlink, setuid, devnode, flock, mmap, rename, fsync, symlink, mknod, guest write",
			func() error {
				config, err := rootfsTaskConfig(options.CheckerArgs)
				if err != nil {
					return err
				}
				status, out, err := s.runToCompletionCustom("mc-rw", config, hubBindRootfs(exportPath(options.ExportTag)))
				result.RWStatus, result.RWOutput = status, out
				if err != nil {
					return err
				}
				if status != 0 {
					return fmt.Errorf("checker exit status %d, want 0:\n%s", status, strings.TrimSpace(out))
				}
				s.deleteTask("mc-rw")
				return nil
			}},
		{"host-enforced read-only export rejects every write",
			"writes, xattrs, and renames all rejected guest-side; reads unaffected",
			func() error {
				roArgs := append(append([]string{}, options.CheckerArgs...), "-ro")
				config, err := rootfsTaskConfig(roArgs)
				if err != nil {
					return err
				}
				status, out, err := s.runToCompletionCustom("mc-ro", config, hubBindRootfs(exportPath(options.ROTag)))
				result.ROStatus, result.ROOutput = status, out
				if err != nil {
					return err
				}
				if status != 0 {
					return fmt.Errorf("ro checker exit status %d, want 0:\n%s", status, strings.TrimSpace(out))
				}
				s.deleteTask("mc-ro")
				return nil
			}},
		{"rootfs metadata and I/O performance measured",
			"",
			func() error {
				perfArgs := append(append([]string{}, options.CheckerArgs...), "-perf")
				config, err := rootfsTaskConfig(perfArgs)
				if err != nil {
					return err
				}
				status, out, err := s.runToCompletionCustom("mc-perf", config, hubBindRootfs(exportPath(options.ExportTag)))
				result.PerfOutput = out
				if err != nil {
					return err
				}
				if status != 0 {
					return fmt.Errorf("perf checker exit status %d, want 0:\n%s", status, strings.TrimSpace(out))
				}
				s.deleteTask("mc-perf")
				return nil
			}},
	}
	var failed error
	for _, scenario := range scenarios {
		if err := scenario.run(); err != nil {
			_, _ = fmt.Fprintf(s.report, "rootfs-spike: FAIL %s: %v\n", scenario.name, err)
			failed = errors.Join(failed, fmt.Errorf("%s: %w", scenario.name, err))
			continue
		}
		s.passed++
		detail := scenario.detail
		if scenario.name == "rootfs metadata and I/O performance measured" {
			detail = strings.TrimSpace(lastPrefixedLine(result.PerfOutput, "PERF "))
		}
		_, _ = fmt.Fprintf(s.report, "rootfs-spike: PASS %s — %s\n", scenario.name, detail)
	}
	_, _ = fmt.Fprintf(s.report, "rootfs-spike: %d/%d assertions passed\n", s.passed, s.steps)
	return result, failed
}

func lastPrefixedLine(s, prefix string) string {
	last := ""
	for _, line := range strings.Split(s, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), prefix) {
			last = strings.TrimSpace(line)
		}
	}
	if last == "" {
		return "(no PERF line captured)"
	}
	return last
}
