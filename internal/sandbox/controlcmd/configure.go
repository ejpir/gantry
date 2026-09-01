package controlcmd

import (
	"flag"
	"fmt"
	"os"

	"github.com/ejpir/gantry/internal/sandbox/config"
	"github.com/ejpir/gantry/internal/sandbox/controlproto"
	devcontainersprofile "github.com/ejpir/gantry/internal/sandbox/devcontainers"
	"github.com/ejpir/gantry/internal/sandbox/layout"
)

func CmdConfigure(argv []string) int {
	flags := flag.NewFlagSet("configure", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	ssh := flags.Bool("ssh", false, "enable the live sandbox-local SSH endpoint")
	devContainers := flags.Bool("devcontainers", false, "enable the in-VM IDE container and nested Podman after restart")
	memMB := flags.Uint("mem", 0, "guest RAM in MiB (applies after restart)")
	vcpus := flags.Int("cpus", 0, "guest vCPU count (applies after restart)")
	isolation := flags.String("process-isolation", "", "process isolation after restart: auto | required | off")
	flags.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: gantry configure NAME [--ssh[=BOOL]] [--devcontainers[=BOOL]] [--mem MIB] [--cpus N] [--process-isolation MODE]")
		flags.PrintDefaults()
	}
	if len(argv) == 0 || argv[0] == "-h" || argv[0] == "--help" {
		flags.Usage()
		if len(argv) > 0 {
			return 0
		}
		return 2
	}
	name := argv[0]
	if err := layout.ValidateName(name); err != nil {
		fmt.Fprintln(os.Stderr, "gantry configure:", err)
		return 2
	}
	if err := flags.Parse(argv[1:]); err != nil {
		return 2
	}
	if flags.NArg() != 0 {
		flags.Usage()
		return 2
	}
	var request controlproto.ConfigureRequest
	flags.Visit(func(value *flag.Flag) {
		switch value.Name {
		case "ssh":
			request.SSH = ssh
		case "devcontainers":
			request.DevContainers = devContainers
		case "mem":
			request.MemMB = memMB
		case "cpus":
			request.VCPUs = vcpus
		case "process-isolation":
			request.ProcessIsolation = isolation
		}
	})
	if configureRequestEmpty(request) {
		fmt.Fprintln(os.Stderr, "gantry configure: at least one setting is required")
		return 2
	}
	restart, err := Configure(name, request)
	if err != nil {
		fmt.Fprintln(os.Stderr, "gantry configure:", err)
		return 1
	}
	fmt.Printf("gantry configure: sandbox %q updated\n", name)
	if restart {
		fmt.Println("gantry configure: restart required to apply VM or Dev Containers changes")
	}
	return 0
}

func configureRequestEmpty(request controlproto.ConfigureRequest) bool {
	return request.SSH == nil && request.DevContainers == nil && request.MemMB == nil &&
		request.VCPUs == nil && request.ProcessIsolation == nil
}

var prepareConfiguredDevContainersProfile = devcontainersprofile.Prepare

func requestedSandboxUpdate(request controlproto.ConfigureRequest) config.SandboxUpdate {
	return config.SandboxUpdate{
		SSH: request.SSH, DevContainers: request.DevContainers,
		MemMB: request.MemMB, VCPUs: request.VCPUs,
		ProcessIsolation: request.ProcessIsolation,
	}
}

func Configure(name string, request controlproto.ConfigureRequest) (bool, error) {
	if err := layout.ValidateName(name); err != nil {
		return false, err
	}
	if configureRequestEmpty(request) {
		return false, fmt.Errorf("at least one setting is required")
	}
	return mutateRunningOrStoppedResult(name,
		func() (bool, error) {
			response, err := controlproto.CallWithTimeout[controlproto.ConfigureResponse](name, controlproto.Request{
				Op: "sandbox.configure", ID: controlproto.NewRequestID("configure"), Configure: &request,
			}, controlproto.ConfigureTimeout)
			if err != nil {
				return false, err
			}
			if !response.OK {
				if response.Error == "" {
					response.Error = "sandbox update failed"
				}
				return false, fmt.Errorf("%s", response.Error)
			}
			return response.RestartRequired, nil
		},
		func() (bool, error) {
			store, err := config.LoadConfigStore(layout.Dir(name))
			if err != nil {
				return false, err
			}
			update := requestedSandboxUpdate(request)
			if request.DevContainers != nil && *request.DevContainers {
				before := store.Snapshot()
				if !before.DevContainers {
					candidate := before
					if err := config.ApplySandboxUpdate(&candidate, update); err != nil {
						return false, err
					}
					prepared, _, _, err := prepareConfiguredDevContainersProfile(name, candidate, nil)
					if err != nil {
						return false, fmt.Errorf("enable Dev Containers: %w", err)
					}
					update.DevContainersProfile = devcontainersprofile.ProfileUpdate(prepared)
				}
			}
			return false, store.Configure(update)
		},
	)
}
