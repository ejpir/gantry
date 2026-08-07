//go:build !linux && !darwin

package sandbox

import "net"

// peerSameUser: AF_UNIX on Windows exposes no peer-credential mechanism,
// so the access control is the sandbox directory ACL (the user profile
// keeps other local users out). Same trust domain as on unix: the user
// account itself — per-process authentication between same-account
// processes is not a primitive any of our platforms offers.
func peerSameUser(net.Conn) bool { return true }
