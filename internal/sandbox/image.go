package sandbox

// image.go — `gantry image` verbs: inspect and manage the image store
// (~/.gantry/images). See docs/oci-images.md.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"

	"gantry/internal/image"
)

// CmdImage implements `gantry image <ls|pull|rm|prune>`.
func CmdImage(argv []string) int {
	if len(argv) == 0 {
		fmt.Fprintln(os.Stderr, "usage: gantry image <ls|pull|rm|prune>")
		return 2
	}
	st := image.DefaultStore()
	switch argv[0] {
	case "ls":
		metas := st.List()
		sort.Slice(metas, func(i, j int) bool { return metas[i].Ref < metas[j].Ref })
		fmt.Printf("%-40s %-21s %-7s %-9s %s\n", "REF", "DIGEST", "ARCH", "SIZE", "CREATED")
		for _, m := range metas {
			fmt.Printf("%-40s %-21s %-7s %-9s %s\n",
				trunc(m.Ref, 40), trunc(m.Digest, 21), m.Arch, humanSize(m.Size), m.Created)
		}
		if len(metas) == 0 {
			fmt.Println("(no cached images — `gantry image pull REF` or -image with a reference builds one)")
		}
		return 0
	case "pull":
		if len(argv) != 2 {
			fmt.Fprintln(os.Stderr, "usage: gantry image pull REF|OCI-LAYOUT-DIR|DOCKER-SAVE-TAR")
			return 2
		}
		arch := hostGuestArch()
		logf := func(format string, a ...any) { fmt.Printf("gantry image: "+format+"\n", a...) }
		r, err := image.Resolve(argv[1], arch, st, logf)
		if err != nil {
			fmt.Fprintln(os.Stderr, "gantry image pull:", err)
			return 1
		}
		fmt.Printf("gantry image: %s cached at %s\n", trunc(r.Digest, 19), r.Path)
		return 0
	case "rm":
		if len(argv) != 2 {
			fmt.Fprintln(os.Stderr, "usage: gantry image rm REF|DIGEST")
			return 2
		}
		if err := st.Remove(argv[1]); err != nil {
			fmt.Fprintln(os.Stderr, "gantry image rm:", err)
			return 1
		}
		fmt.Println("gantry image: removed", argv[1])
		return 0
	case "prune":
		used := digestsInUse()
		var dropped int
		for _, m := range st.List() {
			if used[m.Digest] {
				continue
			}
			if err := st.Remove(m.Digest); err == nil {
				fmt.Println("gantry image: pruned", trunc(m.Ref, 40), trunc(m.Digest, 19))
				dropped++
			}
		}
		if dropped == 0 {
			fmt.Println("gantry image: nothing to prune")
		}
		return 0
	default:
		fmt.Fprintf(os.Stderr, "unknown gantry image verb %q (ls|pull|rm|prune)\n", argv[0])
		return 2
	}
}

// digestsInUse scans all sandbox.json files for referenced image digests.
func digestsInUse() map[string]bool {
	used := map[string]bool{}
	ents, err := os.ReadDir(sandboxRoot())
	if err != nil {
		return used
	}
	for _, e := range ents {
		if !e.IsDir() {
			continue
		}
		b, err := os.ReadFile(filepath.Join(sandboxDir(e.Name()), "sandbox.json"))
		if err != nil {
			continue
		}
		var cfg RunConfig
		if json.Unmarshal(b, &cfg) == nil && cfg.ImageDigest != "" {
			used[cfg.ImageDigest] = true
		}
	}
	return used
}

// hostGuestArch is the arch a locally-built image must match: the host's
// own, since `gantry image pull` without a guest kernel context builds
// for the machine it runs on (start/exec re-resolve against the kernel).
func hostGuestArch() string {
	if runtime.GOARCH == "arm64" {
		return "arm64"
	}
	return "amd64"
}

func trunc(s string, n int) string {
	if len(s) > n {
		return s[:n-1] + "…"
	}
	return s
}

func humanSize(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%dB", n)
	}
	div, exp := int64(unit), 0
	for x := n / unit; x >= unit; x /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f%c", float64(n)/float64(div), "KMGTPE"[exp])
}
