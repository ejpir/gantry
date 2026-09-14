package sandbox

import (
	"context"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/ejpir/gantry/api/managerapi"
	"github.com/ejpir/gantry/internal/sandbox/layout"
	"github.com/ejpir/gantry/internal/sandbox/sshgw"
	"golang.org/x/crypto/ssh"
)

func (managerLifecycle) SSHHostKey() (managerapi.SSHHostKey, error) {
	key, err := sshgw.EnsureHostKey(sshHostKeyPath())
	if err != nil {
		return managerapi.SSHHostKey{}, err
	}
	return managerapi.SSHHostKey{PublicKey: string(ssh.MarshalAuthorizedKey(key.PublicKey()))}, nil
}

func (managerLifecycle) DialSSH(ctx context.Context, name string) (net.Conn, error) {
	if err := layout.ValidateName(name); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// Test existence separately so the API can distinguish 404 from 409.
	if _, err := os.Stat(layout.Dir(name)); err != nil {
		return nil, err
	}
	cfg, err := readSSHConfig(name)
	if err != nil {
		return nil, err
	}
	if !cfg.SSH {
		return nil, fmt.Errorf("sandbox %q has SSH disabled; restart with -ssh", name)
	}
	if _, alive := layout.PID(name); !alive {
		return nil, fmt.Errorf("sandbox %q is stopped", name)
	}
	// Same transport as the local ProxyCommand, never ctl/credentials sockets.
	return dialSSH(name, layout.Dir(name), 5*time.Second)
}
