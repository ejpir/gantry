package networker

import "github.com/ejpir/gantry/internal/sandbox/worker"

// SpawnHook, when set, rewrites the re-exec argv/env (tests only:
// os.Executable() is the test binary under `go test`).
var SpawnHook func(argv *[]string, env *[]string)

// workerEnv selects the pure-Go resolver before package initialization in the
// re-exec'd child. It uses only the private resolver-file snapshot and
// ordinary UDP/TCP sockets, avoiding Darwin's mDNSResponder Unix socket and
// libc NSS module loading after path access has been removed.
func workerEnv() []string {
	return append(worker.Env(), "GODEBUG=netdns=go")
}
