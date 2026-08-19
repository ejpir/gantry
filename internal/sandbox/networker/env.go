package networker

import "github.com/ejpir/gantry/internal/sandbox/worker"

// workerEnv selects the pure-Go resolver before package initialization in the
// re-exec'd child. It uses only the private resolver-file snapshot and
// ordinary UDP/TCP sockets, avoiding Darwin's mDNSResponder Unix socket and
// libc NSS module loading after path access has been removed.
func workerEnv() []string {
	return append(worker.Env(), "GODEBUG=netdns=go")
}
