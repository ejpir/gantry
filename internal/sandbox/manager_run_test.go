package sandbox

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ejpir/gantry/internal/runvm"
)

func TestManagerRunHelperProcess(t *testing.T) {
	mode := os.Getenv("GANTRY_TEST_RUN_HELPER")
	if mode == "" {
		return
	}
	switch mode {
	case "echo":
		data, _ := io.ReadAll(os.Stdin)
		fmt.Print("console:" + string(data))
		os.Exit(7)
	case "flood":
		fmt.Print(strings.Repeat("x", 1<<20))
		os.Exit(0)
	case "wait":
		time.Sleep(time.Minute)
		os.Exit(0)
	}
	os.Exit(2)
}

func TestManagerRunUsesIsolatedLocalHelperAndBoundsConsole(t *testing.T) {
	old := newManagerRunCommand
	t.Cleanup(func() { newManagerRunCommand = old })
	r := runvm.Defaults()
	r.Kernel, r.Rootfs, r.Stdin = "/remote/kernel", "/remote/root", "input"
	for _, mode := range []string{"echo", "flood", "wait"} {
		t.Run(mode, func(t *testing.T) {
			var args []string
			var process *exec.Cmd
			newManagerRunCommand = func(ctx context.Context, self string, argv ...string) *exec.Cmd {
				args = append([]string(nil), argv...)
				process = exec.CommandContext(ctx, self, "-test.run=^TestManagerRunHelperProcess$")
				process.Env = append(os.Environ(), "GANTRY_TEST_RUN_HELPER="+mode)
				return process
			}
			request := r
			request.MaxOutputBytes = 32
			ctx := t.Context()
			if mode == "wait" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, 50*time.Millisecond)
				defer cancel()
			}
			result, err := (managerLifecycle{}).RunVM(ctx, request)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(args, runvm.Args(request)) {
				t.Fatal("helper arguments drifted or inherited remote default")
			}
			if process.ProcessState == nil {
				t.Fatal("helper was not reaped")
			}
			switch mode {
			case "echo":
				if result.ExitCode != 7 || result.Output != "console:input" {
					t.Fatalf("result=%+v", result)
				}
			case "flood":
				if len(result.Output) != 32 || !result.Truncated || result.ExitCode != 0 {
					t.Fatalf("result=%+v", result)
				}
			case "wait":
				if result.ExitCode != 124 {
					t.Fatalf("deadline exit=%d", result.ExitCode)
				}
			}
		})
	}
}
