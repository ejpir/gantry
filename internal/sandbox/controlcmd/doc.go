// Package controlcmd is the client half of the sandbox control plane: the
// `gantry share`, `gantry port`, `gantry net-policy` and resource commands,
// plus the calls the dashboard makes on their behalf.
//
// A running sandbox is mutated through its daemon over ctl.sock; a stopped one
// is mutated directly through its persisted configuration. Both paths live
// here so the choice between them is made in one place. The daemon-side
// managers these commands drive live in the control package.
package controlcmd
