package sandbox

// image.go — `gantry image` verbs: inspect and manage the image store
// (~/.gantry/images). See docs/oci-images.md.

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"syscall"

	"gantry/internal/gutil"
	"gantry/internal/image"
	"gantry/internal/image/auth"

	"golang.org/x/term"
)

// CmdImage implements `gantry image <ls|pull|rm|prune|login|logout|credentials>`.
func CmdImage(argv []string) int {
	if len(argv) == 0 {
		fmt.Fprintln(os.Stderr, "usage: gantry image <ls|pull|rm|prune|login|logout|credentials>")
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
				trunc(m.Ref, 40), trunc(m.Digest, 21), m.Arch, gutil.HumanSize(m.Size), m.Created)
		}
		if len(metas) == 0 {
			fmt.Println("(no cached images — `gantry image pull REF` or -image with a reference builds one)")
		}
		return 0
	case "pull":
		arch := hostGuestArch()
		var ref string
		for i := 1; i < len(argv); i++ {
			if argv[i] == "-platform" || argv[i] == "--platform" {
				i++
				if i >= len(argv) {
					fmt.Fprintln(os.Stderr, "pull: -platform needs a value (e.g. linux/amd64)")
					return 2
				}
				arch = strings.TrimPrefix(argv[i], "linux/")
			} else {
				ref = argv[i]
			}
		}
		if ref == "" {
			fmt.Fprintln(os.Stderr, "usage: gantry image pull [-platform linux/ARCH] REF|OCI-LAYOUT-DIR|DOCKER-SAVE-TAR")
			return 2
		}
		logf := func(format string, a ...any) { fmt.Printf("gantry image: "+format+"\n", a...) }
		r, err := image.Resolve(ref, arch, st, logf)
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
	case "login":
		return imageLogin(argv[1:])
	case "logout":
		if len(argv) != 2 {
			fmt.Fprintln(os.Stderr, "usage: gantry image logout REGISTRY")
			return 2
		}
		if err := auth.Resolve().Erase(argv[1]); err != nil {
			fmt.Fprintln(os.Stderr, "gantry image logout:", err)
			return 1
		}
		fmt.Println("gantry image: logged out of", argv[1])
		return 0
	case "credentials":
		regs := argv[1:]
		if len(regs) == 0 {
			regs = []string{"docker.io", "ghcr.io", "quay.io", "gcr.io"}
		}
		fmt.Printf("%-24s %-12s %-40s %s\n", "REGISTRY", "USERNAME", "SOURCE", "SECRET")
		for _, row := range auth.Resolve().Table(regs) {
			secret := "no"
			if row.Secret.Raw() != "" {
				secret = "yes"
			}
			fmt.Printf("%-24s %-12s %-40s %s\n", trunc(row.Registry, 24), trunc(row.Username, 12), trunc(row.Source, 40), secret)
		}
		return 0
	default:
		fmt.Fprintf(os.Stderr, "unknown gantry image verb %q (ls|pull|rm|prune|login|logout|credentials)\n", argv[0])
		return 2
	}
}

// imageLogin implements `gantry image login REGISTRY [-u USER]
// [--password-stdin]`. There is deliberately no --password flag: argv is
// world-readable in ps and lands in shell history.
func imageLogin(argv []string) int {
	var registry, user string
	stdin := false
	for i := 0; i < len(argv); i++ {
		switch argv[i] {
		case "-u", "--username":
			i++
			if i >= len(argv) {
				fmt.Fprintln(os.Stderr, "login: -u needs a value")
				return 2
			}
			user = argv[i]
		case "--password-stdin":
			stdin = true
		default:
			if registry != "" {
				fmt.Fprintln(os.Stderr, "usage: gantry image login REGISTRY [-u USER] [--password-stdin]")
				return 2
			}
			registry = argv[i]
		}
	}
	if registry == "" {
		fmt.Fprintln(os.Stderr, "usage: gantry image login REGISTRY [-u USER] [--password-stdin]")
		return 2
	}
	if user == "" {
		fmt.Fprintf(os.Stderr, "Username: ")
		if _, err := fmt.Scanln(&user); err != nil || user == "" {
			fmt.Fprintln(os.Stderr, "login: username required")
			return 1
		}
	}
	var secret string
	if stdin {
		b, err := io.ReadAll(os.Stdin)
		if err != nil {
			fmt.Fprintln(os.Stderr, "login:", err)
			return 1
		}
		secret = strings.TrimSpace(string(b))
	} else {
		fmt.Fprintf(os.Stderr, "Password: ")
		b, err := term.ReadPassword(int(syscall.Stdin))
		fmt.Println()
		if err != nil {
			fmt.Fprintln(os.Stderr, "login:", err)
			return 1
		}
		secret = string(b)
	}
	if secret == "" {
		fmt.Fprintln(os.Stderr, "login: empty password")
		return 1
	}
	warn, err := auth.Resolve().Store(registry, user, auth.Secret(secret))
	if err != nil {
		fmt.Fprintln(os.Stderr, "gantry image login:", err)
		return 1
	}
	if warn != "" {
		fmt.Fprintln(os.Stderr, "WARNING:", warn)
	}
	fmt.Println("gantry image: login stored for", registry)
	return 0
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


