//go:build !linux && !darwin

package localsec

import "net"

// PeerSameUser: AF_UNIX on Windows exposes no peer-credential mechanism.
// Before the broker starts, both its directory and endpoint receive protected
// DACLs that are read back and verified to admit only the process user plus
// trusted operating-system principals. Same-account processes remain one
// trust domain, as they are on Unix.
func PeerSameUser(net.Conn) bool { return true }
