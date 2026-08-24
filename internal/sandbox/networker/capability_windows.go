//go:build windows

package networker

// Windows runs the network worker in a capability-bearing AppContainer inside
// a one-process Job. The role retains socket authority while filesystem and
// child-process denials are verified in-process before the stack starts.
const ConfinementPlatform = true
