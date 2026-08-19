// Package localsec keeps gantry's local endpoints and state directories
// reachable only by the user who owns them: restrictive modes on Unix,
// explicit private DACLs on Windows, and peer-credential checks on the
// unix sockets the daemon and manager listen on.
//
// It sits below the sandbox subsystems because the daemon, the launch lock
// and the manager API all bind local endpoints and must secure them the
// same way.
package localsec
