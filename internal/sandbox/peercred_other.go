//go:build !linux && !darwin

package sandbox

import "net"

// peerSameUser: AF_UNIX on Windows exposes no peer-credential mechanism.
// Before the broker starts, both its directory and endpoint receive protected
// DACLs that are read back and verified to admit only the process user plus
// trusted operating-system principals. Same-account processes remain one
// trust domain, as they are on Unix.
func peerSameUser(net.Conn) bool { return true }
