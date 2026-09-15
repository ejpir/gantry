package main

import (
	"context"
	"crypto/subtle"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ejpir/gantry/api/managerapi"
	"github.com/ejpir/gantry/internal/sandbox/manager"
	"github.com/ejpir/gantry/internal/sandbox/sshgw"
	"github.com/ejpir/gantry/internal/sshconfig"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

type sshFixtureBackend struct {
	manager.Lifecycle // unexpected VM lifecycle calls fail the fixture
	keyPath           string
	mu                sync.Mutex
	address           string
	enabled           bool
}

func (b *sshFixtureBackend) SSHHostKey() (managerapi.SSHHostKey, error) {
	key, err := sshgw.EnsureHostKey(b.keyPath)
	if err != nil {
		return managerapi.SSHHostKey{}, err
	}
	return managerapi.SSHHostKey{PublicKey: string(ssh.MarshalAuthorizedKey(key.PublicKey()))}, nil
}

func (b *sshFixtureBackend) DialSSH(ctx context.Context, _ string) (net.Conn, error) {
	b.mu.Lock()
	address, enabled := b.address, b.enabled
	b.mu.Unlock()
	if !enabled {
		return nil, fmt.Errorf("sandbox has SSH disabled")
	}
	return (&net.Dialer{}).DialContext(ctx, "tcp", address)
}

func (b *sshFixtureBackend) setGateway(address string, enabled bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.address, b.enabled = address, enabled
}

type sftpFixtureStream struct {
	io.Reader
	io.Writer
}

func (sftpFixtureStream) Close() error { return nil }

// This is a protocol/harness regression, not a VM test: stock ssh/sftp, the
// compiled Gantry helpers, production manager upgrade route and SSH gateway
// are real; only guest execution/filesystem storage are fixture-backed.
func TestOpenSSHManagerTunnelHarness(t *testing.T) {
	if testing.Short() {
		t.Skip("builds Gantry and invokes OpenSSH")
	}
	if err := requireOpenSSH(); err != nil {
		t.Skip(err) // the full runner fails rather than skipping
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	work := t.TempDir()
	repo, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatal(err)
	}
	gantry := filepath.Join(work, executableName("gantry ssh fixture"))
	if err := buildGantry(ctx, repo, gantry); err != nil {
		t.Fatal(err)
	}
	clientDir := filepath.Join(work, "client space")
	if err := os.Mkdir(clientDir, 0o700); err != nil {
		t.Fatal(err)
	}
	m := &m2Client{gantry: gantry, dir: clientDir, root: filepath.Join(clientDir, "sandboxes"), managerRoot: filepath.Join(work, "manager", "sandboxes"), token: "ssh-e2e-fixture-token-0123456789"}
	m.env = environment(map[string]string{"GANTRY_HOME": m.root, "GANTRY_REMOTE": "must-not-be-used"})
	backend := &sshFixtureBackend{keyPath: filepath.Join(work, "manager", "ssh", "host_ed25519")}
	files := sftp.InMemHandler()
	if err := files.FileCmd.Filecmd(sftp.NewRequest("Mkdir", "/tmp")); err != nil {
		t.Fatal(err)
	}
	execCommand := sshconfig.GuestCommand([]string{"/bin/sh", "-c", `printf '%s' "$1"; exit 7`, "gantry-ssh-e2e", sshCommandMarker})
	var mu sync.Mutex
	execs, transfers := 0, 0
	startGateway := func() context.CancelFunc {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		gateway, err := sshgw.New(sshgw.Config{Name: "m2-lifecycle", HostKeyPath: backend.keyPath, Spawner: sshgw.SpawnFunc(func(_ context.Context, request sshgw.SpawnRequest) (int, error) {
			if request.User != "root" {
				return 255, fmt.Errorf("image default user was not selected")
			}
			switch {
			case request.Subsystem == "sftp":
				mu.Lock()
				transfers++
				mu.Unlock()
				server := sftp.NewRequestServer(sftpFixtureStream{request.Stdin, request.Stdout}, files)
				defer func() { _ = server.Close() }()
				if err := server.Serve(); err != nil && err != io.EOF {
					return 255, err
				}
				return 0, nil
			case request.Command == execCommand:
				mu.Lock()
				execs++
				mu.Unlock()
				_, err := io.WriteString(request.Stdout, sshCommandMarker)
				return 7, err
			default:
				t.Errorf("unexpected guest execution: command=%q subsystem=%q forward=%+v", request.Command, request.Subsystem, request.Forward)
				return 255, fmt.Errorf("unexpected guest execution")
			}
		})})
		if err != nil {
			_ = listener.Close()
			t.Fatal(err)
		}
		gatewayCtx, stop := context.WithCancel(ctx)
		go func() { _ = gateway.Serve(gatewayCtx, listener) }()
		backend.setGateway(listener.Addr().String(), true)
		t.Cleanup(stop)
		return stop
	}
	stopGateway := startGateway()
	router := manager.NewHandler(backend)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+m.token)) != 1 {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		router.ServeHTTP(w, r)
	}))
	defer server.Close()
	m.api = &apiClient{http: server.Client(), baseURL: server.URL, token: m.token}
	caPath, tokenPath := filepath.Join(work, "ca.pem"), filepath.Join(work, "manager.token")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tokenPath, []byte(m.token), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := m.cli(ctx, 0, "remote", "add", "m2", server.URL, "--ca", caPath, "--token-file", tokenPath); err != nil {
		t.Fatal(err)
	}
	if err := m.prepareSSH(ctx); err != nil {
		t.Fatal(err)
	}
	for _, check := range []func(context.Context, string) error{m.sshExecCheck, m.sftpCheck, m.sshForwardRefusal} {
		if err := check(ctx, "m2-lifecycle"); err != nil {
			t.Fatal(err)
		}
	}
	backend.setGateway("", false)
	stopGateway()
	if err := m.sshDisabledCheck(ctx, "m2-lifecycle"); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(m.sshPinPath())
	if err != nil {
		t.Fatal(err)
	}
	if err := m.rotateSSHKey(); err != nil {
		t.Fatal(err)
	}
	startGateway()
	if err := m.sshChangedKeyCheck(ctx, "m2-lifecycle", before); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if execs != 2 || transfers != 1 {
		t.Fatalf("guest calls: exec=%d sftp=%d", execs, transfers)
	}
}

func TestFullBatteryFailsPreflightWithoutOpenSSH(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	if err := run(options{tls: true}); err == nil || !strings.Contains(err.Error(), "requires OpenSSH ssh") {
		t.Fatalf("missing SSH dependency was not an explicit preflight failure: %v", err)
	}
}

func TestOpenSSHOptionsAreIsolatedAndStrict(t *testing.T) {
	base := t.TempDir()
	m := m2Client{gantry: filepath.Join(base, executableName("gantry")), dir: filepath.Join(base, "client"), root: filepath.Join(base, "client", "sandboxes")}
	options := strings.Join(m.sshOptions(), "\n")
	for _, want := range []string{"-F\n" + filepath.Join(m.dir, "openssh.conf"), "StrictHostKeyChecking=yes", "GlobalKnownHostsFile=none", "IdentityAgent=none", "IdentityFile=none", "CertificateFile=none", "ProxyCommand=", "ssh-proxy", "known_hosts.m2"} {
		if !strings.Contains(options, want) {
			t.Errorf("missing isolated option %q", want)
		}
	}
	config := m.openSSHConfig()
	for _, want := range []string{"Host *", "KnownHostsCommand ", "ssh-known-hosts"} {
		if !strings.Contains(config, want) {
			t.Errorf("missing isolated config value %q", want)
		}
	}
}
