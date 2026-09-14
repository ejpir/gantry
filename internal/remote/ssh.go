package remote

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/ejpir/gantry/api/managerapi"
	"github.com/ejpir/gantry/internal/atomicfile"
	"github.com/ejpir/gantry/internal/gutil"
	"github.com/ejpir/gantry/internal/sandbox/layout"
	"github.com/ejpir/gantry/internal/sandbox/localsec"
	"github.com/ejpir/gantry/internal/sandbox/sshgw"
	"github.com/ejpir/gantry/internal/sshconfig"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func (c *Client) SSHHostKey(ctx context.Context) (managerapi.SSHHostKey, error) {
	var key managerapi.SSHHostKey
	err := c.do(ctx, http.MethodGet, "/v1/ssh/hostkey", nil, false, &key)
	return key, err
}

// SSHTunnel performs the documented HTTP/1.1 upgrade over the same verified
// TLS configuration as JSON calls. Buffered SSH bytes after the 101 response
// are preserved. No bearer credentials go in a URL or shell command.
func (c *Client) SSHTunnel(ctx context.Context, name string) (net.Conn, error) {
	if err := layout.ValidateName(name); err != nil {
		return nil, err
	}
	u, _ := url.Parse(c.base)
	port := u.Port()
	if port == "" {
		port = "443"
	}
	config := c.http.Transport.(*http.Transport).TLSClientConfig.Clone()
	config.NextProtos = []string{"http/1.1"}
	dialer := tls.Dialer{NetDialer: &net.Dialer{Timeout: 15 * time.Second}, Config: config}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(u.Hostname(), port))
	if err != nil {
		return nil, fmt.Errorf("remote %q: %w", c.profile.Name, unwrapTLS(err))
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	success := false
	defer func() {
		if !success {
			stop()
			_ = conn.Close()
		}
	}()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	request, err := c.newRequest(ctx, http.MethodPost, "/v1/sandboxes/"+name+"/ssh", nil, false)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Connection", "Upgrade")
	request.Header.Set("Upgrade", "gantry-ssh")
	if err := request.Write(conn); err != nil {
		return nil, err
	}
	reader := bufio.NewReader(conn)
	response, err := http.ReadResponse(reader, request)
	if err != nil {
		return nil, err
	}
	if response.StatusCode != http.StatusSwitchingProtocols {
		defer func() { _ = response.Body.Close() }()
		var body managerapi.ErrorResponse
		_ = json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&body)
		if body.Error == "" {
			body.Error = response.Status
		}
		return nil, &Error{Status: response.StatusCode, Message: body.Error}
	}
	if !strings.EqualFold(response.Header.Get("Upgrade"), "gantry-ssh") || !strings.Contains(strings.ToLower(response.Header.Get("Connection")), "upgrade") {
		return nil, errors.New("manager returned an invalid SSH upgrade")
	}
	_ = conn.SetDeadline(time.Time{})
	success = true
	return &sshTunnel{Conn: conn, reader: reader, stop: stop}, nil
}

type sshTunnel struct {
	net.Conn
	reader *bufio.Reader
	stop   func() bool
}

func (c *sshTunnel) Read(p []byte) (int, error) { return c.reader.Read(p) }
func (c *sshTunnel) Close() error               { c.stop(); return c.Conn.Close() }
func (c *sshTunnel) CloseWrite() error {
	if half, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return half.CloseWrite()
	}
	return nil
}

func remoteSSHName(host, target string) (string, error) {
	name := strings.TrimSuffix(host, "."+target+".gantry")
	if err := layout.ValidateName(name); err != nil {
		return "", err
	}
	return name, nil
}

func remoteKnownHostsPath(target string) string {
	return filepath.Join(baseDir(), "ssh", "known_hosts."+target)
}

// pinSSHHostKey trusts the initial key via authenticated TLS, then refuses
// changes until explicitly accepted. Refresh must never silently overwrite a
// pin; doing so would conceal SSH host-key rotation from stock clients.
func pinSSHHostKey(ctx context.Context, client *Client, accept bool) (string, error) {
	target := client.profile.Name
	key, err := client.SSHHostKey(ctx)
	if err != nil {
		return "", err
	}
	public, _, _, rest, err := ssh.ParseAuthorizedKey([]byte(key.PublicKey))
	if err != nil || len(bytes.TrimSpace(rest)) != 0 {
		return "", errors.New("manager returned an invalid SSH public key")
	}
	line := knownhosts.Line([]string{"*." + target + ".gantry"}, public) + "\n"
	path := remoteKnownHostsPath(target)
	if err := localsec.CreateManagerDir(filepath.Dir(path)); err != nil {
		return "", err
	}
	lock, err := gutil.LockFile(path + ".lock")
	if err != nil {
		return "", err
	}
	defer func() { _ = lock.Close() }()
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() {
			return "", errors.New("remote known_hosts is not a regular file")
		}
		if err := localsec.SecureRegularFile(path); err != nil {
			return "", err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	previous, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	if err == nil && string(previous) != line && !accept {
		return "", fmt.Errorf("REMOTE SSH HOST KEY CHANGED for %q (presented %s); verify with the server operator, then explicitly accept with: gantry ssh-known-hosts -remote %s --accept-new-key", target, ssh.FingerprintSHA256(public), target)
	}
	if string(previous) != line {
		if err := atomicfile.WriteFileDurable(path, []byte(line), 0o600); err != nil {
			return "", err
		}
		if err := localsec.SecureRegularFile(path); err != nil {
			return "", err
		}
	}
	return line, nil
}

func remoteSSH(ctx context.Context, out, errs io.Writer, input *os.File, target string, client *Client, verb string, argv []string) int {
	fail := func(err error) int {
		_, _ = fmt.Fprintf(errs, "gantry %s (remote %q): %v\n", verb, target, err)
		return 1
	}
	if verb == "ssh" && len(argv) > 0 && argv[0] == "setup" {
		remove := len(argv) == 2 && argv[1] == "--remove"
		if len(argv) > 1 && !remove {
			return fail(errors.New("usage: gantry ssh setup -remote NAME [--remove]"))
		}
		if !remove {
			probe, cancel := context.WithTimeout(ctx, 15*time.Second)
			_, err := pinSSHHostKey(probe, client, false)
			cancel()
			if err != nil {
				return fail(err)
			}
		}
		if err := SetupSSH(target, remove); err != nil {
			return fail(err)
		}
		_, _ = fmt.Fprintf(out, "gantry ssh setup: remote %s configuration updated\n", target)
		return 0
	}
	if verb == "ssh-known-hosts" {
		accept := len(argv) > 0 && argv[0] == "--accept-new-key"
		if accept {
			argv = argv[1:]
		}
		if len(argv) > 1 {
			return 2
		}
		if len(argv) == 1 {
			if _, err := remoteSSHName(argv[0], target); err != nil {
				return fail(err)
			}
		}
		probe, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		line, err := pinSSHHostKey(probe, client, accept)
		if err != nil {
			return fail(err)
		}
		_, _ = io.WriteString(out, line)
		return 0
	}
	if len(argv) == 0 {
		_, _ = fmt.Fprintf(errs, "usage: gantry %s NAME -remote REMOTE [-- CMD ...]\n", verb)
		return 2
	}
	user, host := sshgw.DefaultUserSentinel, argv[0]
	if verb == "ssh" {
		if u, h, found := strings.Cut(host, "@"); found {
			user, host = u, h
		}
	}
	if user == "" || strings.HasPrefix(user, "-") || strings.ContainsAny(user, "\r\n\x00") {
		return 2
	}
	name, err := remoteSSHName(host, target)
	if err != nil {
		return fail(err)
	}
	if verb == "ssh-proxy" {
		if len(argv) != 1 {
			return 2
		}
		conn, err := client.SSHTunnel(ctx, name)
		if err != nil {
			return fail(err)
		}
		defer func() { _ = conn.Close() }()
		go func() {
			_, _ = io.Copy(conn, input)
			if half, ok := conn.(interface{ CloseWrite() error }); ok {
				_ = half.CloseWrite()
			}
		}()
		// Do not wait for blocked terminal stdin after the gateway closes.
		if _, err := io.Copy(out, conn); err != nil && ctx.Err() == nil {
			return fail(err)
		}
		return 0
	}
	command := argv[1:]
	if len(command) != 0 {
		if command[0] != "--" {
			return 2
		}
		command = command[1:]
	}
	probe, cancel := context.WithTimeout(ctx, 15*time.Second)
	_, err = pinSSHHostKey(probe, client, false)
	cancel()
	if err != nil {
		return fail(err)
	}
	self, err := os.Executable()
	if err != nil {
		return fail(err)
	}
	args := []string{"-o", "ProxyCommand=" + sshconfig.ShellCommand(self, "ssh-proxy", "-remote", target, name),
		"-o", "UserKnownHostsFile=" + sshconfig.QuotePath(remoteKnownHostsPath(target)),
		"-o", "GlobalKnownHostsFile=none", "-o", "StrictHostKeyChecking=yes", "-o", "KnownHostsCommand=none",
		"-l", user, name + "." + target + ".gantry"}
	if len(command) > 0 {
		args = append(args, sshconfig.GuestCommand(command))
	}
	process := exec.CommandContext(ctx, "ssh", args...)
	process.Stdin, process.Stdout, process.Stderr = input, out, errs
	if err := process.Run(); err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return exit.ExitCode()
		}
		return fail(err)
	}
	return 0
}
