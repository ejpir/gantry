//go:build linux || darwin

package sandbox

// Network assembly: how startNetwork picks between the embedded netstack, a
// split netstack worker and gvproxy, and what it hands the VMM. The worker
// itself is tested in the networker package.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ejpir/gantry/internal/sandbox/config"
)

// TestStartNetworkSplitModes exercises StartNetwork's topology decision:
// auto/required split, off stays monolithic, and the backend is functional
// in both. Splitting needs worker confinement, which only Unix has; the
// Windows fallback is covered by network_worker_confinement_windows_test.go.
func TestStartNetworkSplitModes(t *testing.T) {
	for _, tc := range []struct {
		mode string
		want bool
	}{
		{"auto", true},
		{"", true}, // empty behaves as auto (pre-existing configs upgrade)
		{"required", true},
		{"off", false},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			cfg := config.RunConfig{Net: true, ProcessIsolation: tc.mode}
			n, err := startNetworkWithWorkerStart(cfg, t.TempDir(), inProcessNetworkWorkerStart(t))
			if err != nil {
				if tc.mode == "required" && strings.Contains(err.Error(), "mount tier unavailable") {
					t.Skipf("required mount tier unavailable in this test environment: %v", err)
				}
				t.Fatal(err)
			}
			defer n.Close()
			if n.Split != tc.want {
				t.Fatalf("mode %q: split=%v want %v (degraded: %v)", tc.mode, n.Split, tc.want, n.Degraded)
			}
			if n.Backend == nil {
				t.Fatal("no backend")
			}
			if err := n.Backend.Publish("tcp", "127.0.0.1:18083", "192.168.127.2:8083"); err != nil {
				t.Fatal(err)
			}
			fw, err := n.Backend.Forwards()
			if err != nil || len(fw) != 1 {
				t.Fatalf("forwards: %+v err=%v", fw, err)
			}
			if err := n.Backend.Unpublish("tcp", "127.0.0.1:18083"); err != nil {
				t.Fatal(err)
			}
			// split: the worker owns enforcement + per-boot counters;
			// the supervisor keeps display/rollback policy and durable traffic,
			// which Opts must NOT attach to the device. (Fake kernel: just
			// enough header for KernelArch's ARM64 magic at 0x38.)
			kernel := filepath.Join(t.TempDir(), "Image")
			hdr := make([]byte, 64)
			copy(hdr[0x38:], "ARMd")
			if err := os.WriteFile(kernel, hdr, 0o600); err != nil {
				t.Fatal(err)
			}
			cfg.Kernel = kernel
			opts, err := vmmOpts(cfg, n, t.TempDir(), false)
			if err != nil {
				t.Fatal(err)
			}
			if tc.want {
				if n.Traffic == nil {
					t.Fatal("split network lost the supervisor traffic recorder")
				}
				if opts.NetPolicy != nil || opts.NetTraffic != nil {
					t.Fatal("Opts attaches worker-owned policy/traffic to the device")
				}
				if opts.NetConn == nil {
					t.Fatal("split network lost the device data channel")
				}
			} else {
				if n.Policy == nil || n.Traffic == nil {
					t.Fatal("monolithic network lost policy/traffic")
				}
				if opts.NetPolicy == nil || opts.NetTraffic == nil {
					t.Fatal("monolithic Opts lost policy/traffic")
				}
			}
		})
	}
}

func TestStartNetworkPacketCaptureDoesNotDelegateHostPath(t *testing.T) {
	t.Setenv("GANTRY_NET_PCAP", filepath.Join(t.TempDir(), "capture.pcap"))

	auto, err := startNetwork(config.RunConfig{Net: true, ProcessIsolation: "auto"}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer auto.Close()
	if auto.Split {
		t.Fatal("packet capture path was delegated to a split network worker")
	}
	found := false
	for _, degraded := range auto.Degraded {
		if strings.Contains(degraded, "GANTRY_NET_PCAP") {
			found = true
		}
	}
	if !found {
		t.Fatalf("packet capture fallback was not reported: %v", auto.Degraded)
	}

	if _, err := startNetwork(config.RunConfig{Net: true, ProcessIsolation: "required"}, t.TempDir()); err == nil || !strings.Contains(err.Error(), "GANTRY_NET_PCAP") {
		t.Fatalf("required packet capture error = %v", err)
	}
}
