//go:build linux || darwin

package networker

// workerEnv is the network role's explicit environment. Selecting the pure-Go
// resolver avoids Darwin mDNSResponder sockets and libc NSS loading after path
// access has been removed.
func workerEnv() []string { return []string{"GODEBUG=netdns=go"} }
