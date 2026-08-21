// Command gantry-guest is the multicall guest-side helper binary: one
// static Linux executable dispatched by argv[0] (busybox-style) or by its
// first argument. The daemon stages it at /run/gantry/bin/ inside the
// guest with one symlink per mode:
//
//	credhelper            git credential.helper — asks the host broker
//	                      (vsock, see internal/sandbox/credhelper) for
//	                      the credential bound to the queried host
//	oauth login <provider>  custody-mode OAuth: the daemon completes
//	                      the exchange host-side and holds the refresh
//	                      token (internal/sandbox/oauthtokens)
//
// Modes are answer-only adapters: they can request credentials from the
// host broker but can never add, swap, or re-point them.
//
// The binary is cross-built for the guest architecture and distributed as
// a sha256-verified release asset (internal/guestasset), never go:embed,
// so host and guest architectures can differ and the payload does not
// bloat every host binary.
package main

import (
	"fmt"
	"os"
	"path/filepath"
)

// version is stamped by release builds (-X main.version=...). Kept local
// — importing guestasset.Version would drag the download machinery (and
// net/http) into a binary that must stay small for fast guest delivery.
var version = "dev"

func main() {
	mode := filepath.Base(os.Args[0])
	args := os.Args[1:]
	if mode == "gantry-guest" {
		if len(args) == 0 {
			usage()
			os.Exit(2)
		}
		mode, args = args[0], args[1:]
	}
	switch mode {
	case "credhelper":
		runCredHelper(args)
	case "oauth":
		runOAuth(args)
	case "version":
		fmt.Println("gantry-guest", version)
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `gantry-guest — multicall guest helper (modes selected by argv[0] or first arg)

modes:
  credhelper   git credential.helper; answers "get" from the host credential broker
  oauth        custody-mode OAuth login: gantry-guest oauth login <provider>
  version      print the release version
`)
}

// debugf reports to stderr only when GANTRY_GUEST_DEBUG=1: git surfaces
// helper stderr to the user, so helpers are quiet by default.
func debugf(format string, a ...any) {
	if os.Getenv("GANTRY_GUEST_DEBUG") == "1" {
		fmt.Fprintf(os.Stderr, "gantry-guest: "+format+"\n", a...)
	}
}
