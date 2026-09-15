package remote

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/ejpir/gantry/api/managerapi"
)

func TestRemoteConfigurePreservesFalseOmissionAndRestart(t *testing.T) {
	var got managerapi.ConfigureSandboxRequest
	client, out, errs := verbHarness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPatch || r.URL.Path != "/v1/sandboxes/dev" || r.Header.Get("Idempotency-Key") != "retry-update" {
			t.Errorf("bad route or missing idempotency")
		}
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Error(err)
		}
		_ = json.NewEncoder(w).Encode(managerapi.Operation{ID: "cfg", State: "succeeded", Configure: &managerapi.ConfigureSandboxResult{RestartRequired: true}})
	}))
	defer client.Close()
	status := runVerb(t.Context(), out, errs, stdinPipe(t, ""), "configure", "stub", client, []string{"dev", "-ssh=false", "-mem", "1024", "-key", "retry-update"})
	if status != 0 {
		t.Fatalf("configure=%d %s", status, errs)
	}
	if got.SSH == nil || *got.SSH || got.MemoryMiB == nil || *got.MemoryMiB != 1024 || got.CPUs != nil || got.DevContainers != nil || got.ProcessIsolation != nil {
		t.Fatalf("wire=%+v", got)
	}
	if !strings.Contains(out.String(), `on remote "stub"`) || !strings.Contains(out.String(), "restart required") {
		t.Fatalf("result=%s", out)
	}
}

func TestRemoteConfigureRejectsInvalidInputBeforeRequest(t *testing.T) {
	client, out, errs := verbHarness(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("invalid input reached manager") }))
	defer client.Close()
	for _, args := range [][]string{{}, {"dev"}, {"../escape", "-ssh"}, {"dev", "-cpus", "0"}, {"dev", "-mem", "0"}, {"dev", "-process-isolation", "bad"}, {"dev", "-ssh", "extra"}} {
		errs.Reset()
		if status := runVerb(t.Context(), out, errs, stdinPipe(t, ""), "configure", "stub", client, args); status != 2 {
			t.Fatalf("%v = %d %s", args, status, errs)
		}
	}
}

func TestRemoteRunForwardsRawAssetsAndPropagatesConsoleExit(t *testing.T) {
	var got managerapi.RunVMRequest
	client, out, errs := verbHarness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/run" || r.Header.Get("Idempotency-Key") != "one-raw-vm" {
			t.Error("wrong run route")
		}
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Error(err)
		}
		_ = json.NewEncoder(w).Encode(managerapi.Operation{ID: "run", State: "succeeded", Run: &managerapi.ExecResult{ExitCode: 7, Output: "serial console\n", Truncated: true}})
	}))
	defer client.Close()
	args := []string{"-kernel", "/only/on/remote/kernel", "-rootfs", "/remote/root", "-disk", "/remote/data", "-share", "code=/remote/code,ro", "-net-vfkit=false", "-net-dhcp=false", "-vsocklisten=", "-mem", "1024", "-cpus", "2", "-timeout", "30", "-key", "one-raw-vm"}
	if status := runVerb(t.Context(), out, errs, stdinPipe(t, "serial input"), "run", "stub", client, args); status != 7 {
		t.Fatalf("run=%d %s", status, errs)
	}
	if got.Kernel != args[1] || got.Stdin != "serial input" || got.MemoryMiB != 1024 || got.CPUs != 2 || got.TimeoutSeconds != 30 || got.NetworkVFKIT == nil || *got.NetworkVFKIT || got.VsockListen == nil || *got.VsockListen != "" {
		t.Fatalf("wire=%+v", got)
	}
	if out.String() != "serial console\n" || !strings.Contains(errs.String(), "truncated") {
		t.Fatalf("console=%q errors=%s", out, errs)
	}
}

func TestRemoteRunRefusesInvalidFlagsWithoutLocalFallback(t *testing.T) {
	client, out, errs := verbHarness(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("invalid run reached server") }))
	defer client.Close()
	for _, args := range [][]string{{}, {"-kernel", "/k"}, {"-image", "alpine"}, {"-kernel", "/k", "-rootfs", "/r", "-timeout", "0"}, {"-kernel", "/k", "-rootfs", "/r", "-max-output", "65537"}, {"-kernel", "/k", "-rootfs", "/r", "--", "sh"}} {
		errs.Reset()
		if status := runVerb(t.Context(), out, errs, stdinPipe(t, ""), "run", "stub", client, args); status != 2 {
			t.Fatalf("%v = %d %s", args, status, errs)
		}
	}
}
