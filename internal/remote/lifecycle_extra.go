package remote

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/ejpir/gantry/api/managerapi"
	"github.com/ejpir/gantry/internal/runvm"
	"github.com/ejpir/gantry/internal/sandbox/controlcmd"
	"github.com/ejpir/gantry/internal/sandbox/controlproto"
	"golang.org/x/term"
)

func (c *Client) keyedOperation(ctx context.Context, method, path string, body any, key string) (Operation, error) {
	var operation Operation
	request, err := c.newRequest(ctx, method, path, body, true)
	if err != nil {
		return operation, err
	}
	if key != "" {
		request.Header.Set("Idempotency-Key", key)
	}
	if err := c.doRequest(request, &operation); err != nil {
		return operation, err
	}
	return c.WaitOperation(ctx, operation, nil)
}

func (c *Client) ConfigureSandbox(ctx context.Context, name string, request managerapi.ConfigureSandboxRequest, key string) (Operation, error) {
	if err := ValidateSandboxName(name); err != nil {
		return Operation{}, err
	}
	return c.keyedOperation(ctx, http.MethodPatch, "/v1/sandboxes/"+name, request, key)
}

// RunVM preserves the low-level launcher's meaning: boot explicit manager-host
// assets, capture a bounded console, and terminate on deadline/disconnection.
func (c *Client) RunVM(ctx context.Context, request managerapi.RunVMRequest, key string) (Operation, error) {
	return c.keyedOperation(ctx, http.MethodPost, "/v1/run", request, key)
}

func remoteConfigure(ctx context.Context, out, errs io.Writer, target string, client *Client, argv []string) int {
	fs := flag.NewFlagSet("configure", flag.ContinueOnError)
	fs.SetOutput(errs)
	ssh := fs.Bool("ssh", false, "enable/disable the sandbox SSH gateway")
	dev := fs.Bool("devcontainers", false, "enable/disable Dev Containers (restart required when running)")
	mem := fs.Uint("mem", 0, "guest RAM in MiB after restart")
	cpus := fs.Int("cpus", 0, "guest vCPU count after restart")
	isolation := fs.String("process-isolation", "", "auto | required | off, after restart")
	key := fs.String("key", "", "idempotency key for safe retries of the same update")
	fs.Usage = func() {
		_, _ = fmt.Fprintln(errs, "usage: gantry configure NAME [settings] [-key KEY] -remote PROFILE")
		fs.PrintDefaults()
	}
	args, err := parseInterleaved(fs, argv)
	if errors.Is(err, flag.ErrHelp) {
		return 0
	}
	if err != nil {
		return 2
	}
	if len(args) != 1 {
		fs.Usage()
		return 2
	}
	if err := ValidateSandboxName(args[0]); err != nil {
		_, _ = fmt.Fprintln(errs, "gantry configure:", err)
		return 2
	}
	var request managerapi.ConfigureSandboxRequest
	fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "ssh":
			request.SSH = ssh
		case "devcontainers":
			request.DevContainers = dev
		case "mem":
			request.MemoryMiB = mem
		case "cpus":
			request.CPUs = cpus
		case "process-isolation":
			request.ProcessIsolation = isolation
		}
	})
	local := controlproto.ConfigureRequest{SSH: request.SSH, DevContainers: request.DevContainers, MemMB: request.MemoryMiB, VCPUs: request.CPUs, ProcessIsolation: request.ProcessIsolation}
	if err := controlcmd.ValidateConfigureRequest(local); err != nil {
		_, _ = fmt.Fprintln(errs, "gantry configure:", err)
		return 2
	}
	ctx, cancel := context.WithTimeout(ctx, controlproto.ConfigureTimeout+30*time.Second)
	defer cancel()
	operation, err := client.ConfigureSandbox(ctx, args[0], request, *key)
	if err != nil {
		_, _ = fmt.Fprintf(errs, "gantry configure (remote %q): %v\n", target, err)
		return 1
	}
	if operation.Configure == nil {
		_, _ = fmt.Fprintln(errs, "gantry configure: manager returned no configuration result")
		return 1
	}
	_, _ = fmt.Fprintf(out, "gantry configure: sandbox %q updated on remote %q\n", args[0], target)
	if operation.Configure.RestartRequired {
		_, _ = fmt.Fprintln(out, "gantry configure: restart required to apply VM or Dev Containers changes")
	}
	return 0
}

func remoteRun(ctx context.Context, out, errs io.Writer, input *os.File, target string, client *Client, argv []string) int {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(errs)
	request := runvm.BindFlags(fs)
	fs.IntVar(&request.TimeoutSeconds, "timeout", request.TimeoutSeconds, "VM deadline in seconds (1..3600; timeout exits 124)")
	fs.IntVar(&request.MaxOutputBytes, "max-output", request.MaxOutputBytes, "console capture limit in bytes (1..65536)")
	key := fs.String("key", "", "idempotency key; reuse it after an ambiguous submission, never for another VM")
	fs.Usage = func() {
		_, _ = fmt.Fprintln(errs, "usage: gantry run -kernel PATH (-initrd PATH | -rootfs PATH) [flags] -remote PROFILE\nAll paths are on the manager. Console input/output is bounded and noninteractive; no saved sandbox is created.")
		fs.PrintDefaults()
	}
	if err := fs.Parse(argv); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() != 0 {
		fs.Usage()
		return 2
	}
	if err := runvm.Validate(*request); err != nil {
		_, _ = fmt.Fprintln(errs, "gantry run:", err)
		return 2
	}
	if !term.IsTerminal(int(input.Fd())) {
		stdin, err := io.ReadAll(io.LimitReader(input, runvm.MaxStdinBytes+1))
		if err != nil {
			_, _ = fmt.Fprintln(errs, "gantry run: read stdin:", err)
			return 1
		}
		if len(stdin) > runvm.MaxStdinBytes {
			_, _ = fmt.Fprintln(errs, "gantry run: stdin exceeds 64 KiB")
			return 2
		}
		request.Stdin = string(stdin)
	}
	_, _ = fmt.Fprintf(errs, "gantry run: booting raw VM on remote %q (captured console, deadline %ds; Ctrl-C cancels the request)\n", target, request.TimeoutSeconds)
	ctx, cancel := context.WithTimeout(ctx, time.Duration(request.TimeoutSeconds)*time.Second+30*time.Second)
	defer cancel()
	operation, err := client.RunVM(ctx, *request, *key)
	if err != nil {
		_, _ = fmt.Fprintf(errs, "gantry run (remote %q): %v\n", target, err)
		if ctx.Err() != nil {
			return 130
		}
		return 1
	}
	if operation.Run == nil {
		_, _ = fmt.Fprintln(errs, "gantry run: manager returned no VM result")
		return 1
	}
	_, _ = io.WriteString(out, operation.Run.Output)
	if operation.Run.Truncated {
		_, _ = fmt.Fprintln(errs, "gantry run: console output truncated")
	}
	if operation.Run.ExitCode == 124 {
		_, _ = fmt.Fprintln(errs, "gantry run: VM deadline reached; helper terminated")
	}
	if operation.Run.ExitCode < 0 || operation.Run.ExitCode > 255 {
		return 1
	}
	return operation.Run.ExitCode
}
