package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/ejpir/gantry/internal/atomicfile"
	"github.com/ejpir/gantry/internal/sandbox/sshgw"
	"github.com/ejpir/gantry/internal/sshconfig"
)

const sshCommandMarker = "manager-ssh: spaces ' quotes $literal"

func requireOpenSSH() error {
	for _, program := range []string{"ssh", "sftp"} {
		if _, err := exec.LookPath(program); err != nil {
			return fmt.Errorf("full TLS/SSH battery requires OpenSSH %s in PATH (use -api-only for the no-VM subset): %w", program, err)
		}
	}
	return nil
}

// sshOptions uses only this test's config and trust store. In particular it
// never invokes `ssh setup`, writes ~/.ssh/config, reads user identities or
// disables host-key verification. Both commands exercise the real Gantry
// ProxyCommand and KnownHostsCommand helpers; bearer tokens stay in files.
func (m *m2Client) sshOptions() []string {
	return []string{"-F", filepath.Join(m.dir, "openssh.conf"),
		"-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "-o", "ConnectionAttempts=1",
		"-o", "ServerAliveInterval=5", "-o", "ServerAliveCountMax=2",
		"-o", "User=" + sshgw.DefaultUserSentinel,
		"-o", "IdentityAgent=none", "-o", "IdentityFile=none", "-o", "CertificateFile=none",
		"-o", "PubkeyAuthentication=no",
		"-o", "PasswordAuthentication=no", "-o", "KbdInteractiveAuthentication=no",
		"-o", "ClearAllForwardings=yes", "-o", "ForwardAgent=no", "-o", "ForwardX11=no",
		"-o", "ControlMaster=no", "-o", "ControlPath=none",
		"-o", "ProxyCommand=" + sshconfig.ShellCommand(m.gantry, "ssh-proxy", "-remote", "m2", "%n"),
		"-o", "KnownHostsCommand=" + sshconfig.ShellCommand(m.gantry, "ssh-known-hosts", "-remote", "m2", "%n"),
		"-o", "UserKnownHostsFile=" + sshconfig.QuotePath(m.sshPinPath()),
		"-o", "GlobalKnownHostsFile=none", "-o", "StrictHostKeyChecking=yes"}
}

func (m *m2Client) sshPinPath() string {
	return filepath.Join(filepath.Dir(m.root), "ssh", "known_hosts.m2")
}

func (m *m2Client) prepareSSH(ctx context.Context) error {
	if err := os.WriteFile(filepath.Join(m.dir, "openssh.conf"), nil, 0o600); err != nil {
		return err
	}
	_, _, err := m.cli(ctx, 0, "ssh-known-hosts", "-remote", "m2")
	return err
}

func (m *m2Client) sshCommand(ctx context.Context, name string, want int, argv ...string) (string, string, error) {
	args := append(m.sshOptions(), "-T", name+".m2.gantry", sshconfig.GuestCommand(argv))
	return m.sshProcess(ctx, "ssh", nil, want, args...)
}

func (m *m2Client) sshProcess(ctx context.Context, program string, stdin io.Reader, want int, args ...string) (string, string, error) {
	bounded, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	return m.command(bounded, program, stdin, want, args...)
}

func (m *m2Client) sshExecCheck(ctx context.Context, name string) error {
	// A marker with shell metacharacters exercises quoting as well as stdout
	// and nonzero guest exit propagation through stock OpenSSH and the tunnel.
	out, _, err := m.sshCommand(ctx, name, 7, "/bin/sh", "-c", `printf '%s' "$1"; exit 7`, "gantry-ssh-e2e", sshCommandMarker)
	if err != nil {
		return err
	}
	if out != sshCommandMarker {
		return fmt.Errorf("SSH command output=%q, want %q", out, sshCommandMarker)
	}
	return nil
}

func (m *m2Client) sftpCheck(ctx context.Context, name string) error {
	payload := make([]byte, 32<<10)
	if _, err := rand.Read(payload); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(m.dir, "sftp-upload.bin"), payload, 0o600); err != nil {
		return err
	}
	// Use a unique directory in the disposable guest and relative local paths
	// below the isolated client's cwd. Quoted spaces exercise the batch parser.
	dir := "/tmp/gantry-sftp-" + rand.Text()
	batch := fmt.Sprintf("mkdir %s\nput sftp-upload.bin \"%s/file with spaces.bin\"\nget \"%s/file with spaces.bin\" sftp-download.bin\nrm \"%s/file with spaces.bin\"\nrmdir %s\n", dir, dir, dir, dir, dir)
	args := append(m.sshOptions(), "-b", "-", name+".m2.gantry")
	if _, _, err := m.sshProcess(ctx, "sftp", strings.NewReader(batch), 0, args...); err != nil {
		return err
	}
	got, err := os.ReadFile(filepath.Join(m.dir, "sftp-download.bin"))
	if err != nil {
		return err
	}
	if !bytes.Equal(got, payload) {
		return fmt.Errorf("SFTP round-trip changed binary payload (got %d bytes, want %d)", len(got), len(payload))
	}
	return nil
}

func (m *m2Client) sshForwardRefusal(ctx context.Context, name string) error {
	// TEST-NET-1 is deliberately non-loopback. The gateway must reject the
	// channel before spawning a guest relay; this is not a connectivity test.
	args := append(m.sshOptions(), "-W", "192.0.2.1:22", name+".m2.gantry")
	_, diagnostic, err := m.sshProcess(ctx, "ssh", nil, 255, args...)
	if err != nil {
		return err
	}
	if !strings.Contains(diagnostic, sshgw.GenericChannelRefusal()) {
		return fmt.Errorf("SSH forwarding was not refused by channel policy: %s", diagnostic)
	}
	return nil
}

func (m *m2Client) sshDisabledCheck(ctx context.Context, name string) error {
	status, raw, _, err := m.api.do(ctx, http.MethodPost, "/v1/sandboxes/"+name+"/ssh", nil,
		map[string]string{"Connection": "Upgrade", "Upgrade": "gantry-ssh"})
	if err != nil {
		return err
	}
	if status != http.StatusConflict || !bytes.Contains(raw, []byte("SSH disabled")) {
		return fmt.Errorf("disabled SSH upgrade=%d: %s", status, raw)
	}
	out, diagnostic, err := m.sshCommand(ctx, name, 255, "/bin/echo", "must-not-run")
	if err != nil {
		return err
	}
	if out != "" || !strings.Contains(diagnostic, "SSH disabled") {
		return fmt.Errorf("disabled SSH did not fail closed: stdout=%q stderr=%q", out, diagnostic)
	}
	return nil
}

// rotateSSHKey replaces only the install key inside this runner's private
// manager workspace, while its sole remaining sandbox has SSH disabled.
func (m *m2Client) rotateSSHKey() error {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	der, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		return err
	}
	path := filepath.Join(filepath.Dir(m.managerRoot), "ssh", "host_ed25519")
	return atomicfile.WriteFileDurable(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600)
}

func (m *m2Client) sshChangedKeyCheck(ctx context.Context, name string, before []byte) error {
	_, diagnostic, err := m.cli(ctx, 1, "ssh-known-hosts", "-remote", "m2")
	if err != nil {
		return err
	}
	if !strings.Contains(diagnostic, "REMOTE SSH HOST KEY CHANGED") {
		return fmt.Errorf("SSH key change not reported: %s", diagnostic)
	}
	out, diagnostic, err := m.sshCommand(ctx, name, 255, "/bin/echo", "must-not-run")
	if err != nil {
		return err
	}
	if out != "" || !strings.Contains(diagnostic, "REMOTE SSH HOST KEY CHANGED") {
		return fmt.Errorf("OpenSSH did not refuse changed key: stdout=%q stderr=%q", out, diagnostic)
	}
	after, err := os.ReadFile(m.sshPinPath())
	if err != nil {
		return err
	}
	if !bytes.Equal(before, after) {
		return fmt.Errorf("refused SSH key change overwrote the trusted pin")
	}
	if _, _, err := m.cli(ctx, 0, "ssh-known-hosts", "-remote", "m2", "--accept-new-key"); err != nil {
		return err
	}
	after, err = os.ReadFile(m.sshPinPath())
	if err != nil {
		return err
	}
	if bytes.Equal(before, after) {
		return fmt.Errorf("explicit SSH key acceptance did not update the pin")
	}
	return m.sshExecCheck(ctx, name)
}

func (m *m2Client) sshChecks(ctx context.Context, name string) error {
	if err := m.prepareSSH(ctx); err != nil {
		return err
	}
	for _, check := range []struct {
		name string
		run  func(context.Context, string) error
	}{
		{"SSH exec output and exit status over TLS", m.sshExecCheck},
		{"SFTP binary upload/download over TLS", m.sftpCheck},
		{"SSH non-loopback forwarding refusal", m.sshForwardRefusal},
	} {
		if err := step(check.name, func() error { return check.run(ctx, name) }); err != nil {
			return err
		}
	}
	return step("SSH live disable, key rotation refusal and explicit acceptance", func() error {
		before, err := os.ReadFile(m.sshPinPath())
		if err != nil {
			return err
		}
		if _, _, err := m.cli(ctx, 0, "configure", name, "-remote", "m2", "-ssh=false"); err != nil {
			return err
		}
		if err := m.sshDisabledCheck(ctx, name); err != nil {
			return err
		}
		if err := m.rotateSSHKey(); err != nil {
			return err
		}
		if _, _, err := m.cli(ctx, 0, "configure", name, "-remote", "m2", "-ssh=true"); err != nil {
			return err
		}
		return m.sshChangedKeyCheck(ctx, name, before)
	})
}
