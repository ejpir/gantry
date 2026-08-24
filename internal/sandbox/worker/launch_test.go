package worker

import (
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/ejpir/gantry/internal/workerproto"
)

func TestLaunchSpecRejectsAuthorityAndAmbiguousTables(t *testing.T) {
	tests := []struct {
		name string
		spec LaunchSpec
		want string
	}{
		{
			name: "unknown role",
			spec: LaunchSpec{Role: workerproto.Role("other"), EntryPoint: "_other-worker", Channels: []string{"control"}},
			want: "invalid worker role",
		},
		{
			name: "role entry mismatch",
			spec: LaunchSpec{Role: workerproto.RoleMCP, EntryPoint: "_net-worker", Channels: []string{"control"}},
			want: "requires entry point",
		},
		{
			name: "control is not first",
			spec: LaunchSpec{Role: workerproto.RoleMCP, EntryPoint: "_mcp-worker", Channels: []string{"fd", "control"}},
			want: "channel 0 must be",
		},
		{
			name: "duplicate channel",
			spec: LaunchSpec{Role: workerproto.RoleMCP, EntryPoint: "_mcp-worker", Channels: []string{"control", "control"}},
			want: "duplicated",
		},
		{
			name: "undeclared transferable channel",
			spec: LaunchSpec{
				Role: workerproto.RoleNet, EntryPoint: "_net-worker", Channels: []string{"control", "data"},
				TransferableChannels: []string{"other"},
			},
			want: "is not declared",
		},
		{
			name: "duplicate transferable channel",
			spec: LaunchSpec{
				Role: workerproto.RoleNet, EntryPoint: "_net-worker", Channels: []string{"control", "data"},
				TransferableChannels: []string{"data", "data"},
			},
			want: "is duplicated",
		},
		{
			name: "reserved environment",
			spec: LaunchSpec{
				Role: workerproto.RoleMCP, EntryPoint: "_mcp-worker", Channels: []string{"control"},
				Environment: []string{"GANTRY_WORKER_HANDLE_3=7"},
			},
			want: "reserved worker-bootstrap",
		},
		{
			name: "inherited overlap",
			spec: LaunchSpec{
				Role: workerproto.RoleMCP, EntryPoint: "_mcp-worker", Channels: []string{"control", "fd"},
				InheritedFiles: []InheritedFile{{Slot: 4, File: os.Stdin}},
			},
			want: "overlaps",
		},
		{
			name: "invalid confinement",
			spec: LaunchSpec{
				Role: workerproto.RoleMCP, EntryPoint: "_mcp-worker", Channels: []string{"control"},
				Confinement: "best-effort",
			},
			want: "invalid confinement mode",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := validateLaunchSpec(test.spec); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("validation error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestLaunchEmptyEnvironmentHelper(t *testing.T) {
	if len(os.Args) == 0 || os.Args[len(os.Args)-1] != "launch-empty-environment-helper" {
		return
	}
	environment := os.Environ()
	if runtime.GOOS == "windows" {
		// Windows conveys each anonymous-pipe direction through an exact
		// bootstrap handle variable. These are launcher metadata, not role
		// environment, and are the only entries the child should receive.
		allowed := map[string]bool{
			"GANTRY_WORKER_READ_3":  false,
			"GANTRY_WORKER_WRITE_3": false,
		}
		for _, entry := range environment {
			name, value, ok := strings.Cut(entry, "=")
			if !ok || value == "" {
				os.Exit(91)
			}
			if _, ok := allowed[name]; !ok || allowed[name] {
				os.Exit(91)
			}
			allowed[name] = true
		}
		for _, found := range allowed {
			if !found {
				os.Exit(91)
			}
		}
		os.Exit(0)
	}
	if len(environment) != 0 {
		os.Exit(91)
	}
	os.Exit(0)
}

func TestLaunchDefaultsToEmptyEnvironment(t *testing.T) {
	child, err := Launch(LaunchSpec{
		Role:           workerproto.RoleMCP,
		EntryPoint:     "_mcp-worker",
		Channels:       []string{"control"},
		DiagnosticPath: filepath.Join(t.TempDir(), "worker-mcp.log"),
		Confinement:    "off",
		ConfigureProcess: func(argv, _ *[]string) {
			*argv = []string{
				(*argv)[0], "-test.run", "^TestLaunchEmptyEnvironmentHelper$", "--",
				"launch-empty-environment-helper",
			}
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := child.WaitExit(5 * time.Second); err != nil {
		t.Fatal(err)
	}
}

func TestChildBootstrapAuthenticatesNamedChannels(t *testing.T) {
	ctrlSupervisor, ctrlWorker := net.Pipe()
	fdSupervisor, fdWorker := net.Pipe()
	defer func() { _ = ctrlSupervisor.Close() }()
	defer func() { _ = ctrlWorker.Close() }()
	defer func() { _ = fdSupervisor.Close() }()
	defer func() { _ = fdWorker.Close() }()

	child := &Child{
		Channels: map[string]net.Conn{"control": ctrlSupervisor, "fd": fdSupervisor},
		role:     workerproto.RoleMCP,
	}
	type config struct{ Server string }
	workerErr := make(chan error, 1)
	go func() {
		var got config
		nonce, err := workerproto.ServeHandshake(ctrlWorker, workerproto.RoleMCP, &got)
		if err == nil {
			err = workerproto.ReadNonce(fdWorker, nonce)
		}
		if err == nil && got.Server != "fs" {
			err = &unexpectedBootstrapConfig{got: got.Server}
		}
		workerErr <- err
	}()
	if err := child.Bootstrap(config{Server: "fs"}, "fd"); err != nil {
		t.Fatal(err)
	}
	if err := <-workerErr; err != nil {
		t.Fatal(err)
	}
	if _, err := child.BeginBootstrap(config{Server: "fs"}); err == nil || !strings.Contains(err.Error(), "already sent") {
		t.Fatalf("second bootstrap error = %v, want one-shot refusal", err)
	}
}

type unexpectedBootstrapConfig struct{ got string }

func (e *unexpectedBootstrapConfig) Error() string { return "unexpected bootstrap config: " + e.got }
