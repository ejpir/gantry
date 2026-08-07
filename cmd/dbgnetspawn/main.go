// Temporary diagnostic: exercise the production net-worker spawn path.
package main

import (
	"fmt"
	"os"
	"time"

	"github.com/ejpir/gantry/internal/netpol"
	"github.com/ejpir/gantry/internal/sandbox"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "_net-worker" {
		// Re-exec dispatch: os.Executable() inside startNetWorker comes
		// back here, running the PRODUCTION worker entry point.
		os.Exit(sandbox.CmdNetWorker())
	}
	dir, _ := os.MkdirTemp("", "netspawn-*")
	pol := netpol.DefaultPolicy()
	raw, err := netpol.Marshal(pol)
	if err != nil {
		fmt.Println("marshal:", err)
		os.Exit(1)
	}
	fmt.Println("spawning worker (production path)...")
	start := time.Now()
	w, data, err := sandbox.DbgStartNetWorker("5a:94:ef:e4:0c:ee", raw, dir)
	if err != nil {
		fmt.Println("FAILED after", time.Since(start), ":", err)
		if log, rerr := os.ReadFile(dir + "/worker-net.log"); rerr == nil && len(log) > 0 {
			fmt.Println("--- worker-net.log ---")
			fmt.Print(string(log))
			fmt.Println("--- end ---")
		}
		os.Exit(1)
	}
	fmt.Println("ready in", time.Since(start))
	_ = data
	fmt.Println("closing...")
	if err := w.Close(); err != nil {
		fmt.Println("close:", err)
		os.Exit(1)
	}
	fmt.Println("OK")
}
