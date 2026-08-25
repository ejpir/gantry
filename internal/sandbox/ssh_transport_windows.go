//go:build windows

package sandbox

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/Microsoft/go-winio"
	"github.com/ejpir/gantry/internal/sandbox/localsec"
)

func sshEndpoint(name, _ string) string {
	return `\\.\pipe\gantry-` + name + `-ssh`
}

func listenSSH(name, dir string) (net.Listener, string, error) {
	path := sshEndpoint(name, dir)
	userSID, err := localsec.CurrentUserSID()
	if err != nil {
		return nil, path, err
	}
	// Protected DACL: administrators and SYSTEM get full access; the owning
	// user gets only the read/write rights needed to carry SSH bytes.
	sddl := fmt.Sprintf(`D:P(A;;GA;;;BA)(A;;GA;;;SY)(A;;GRGW;;;%s)`, userSID.String())
	listener, err := winio.ListenPipe(path, &winio.PipeConfig{
		SecurityDescriptor: sddl,
		InputBufferSize:    1 << 20,
		OutputBufferSize:   1 << 20,
	})
	return listener, path, err
}

func dialSSH(name, dir string, timeout time.Duration) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return winio.DialPipeContext(ctx, sshEndpoint(name, dir))
}

func removeSSHRuntime(string, string) {}
