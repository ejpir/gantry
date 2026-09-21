//go:build linux || darwin

package manager

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"github.com/ejpir/gantry/api/managerapi"
	"github.com/ejpir/gantry/internal/gutil"
	"github.com/ejpir/gantry/internal/sandbox/layout"
	"github.com/ejpir/gantry/internal/sandbox/localsec"
)

type managerLauncher func(log *os.File) (*exec.Cmd, error)

// ensureDefaultManager is deliberately local-only. An explicit socket here is
// a confirmation from the desktop, not permission to start at another target.
func ensureDefaultManager(ctx context.Context, expected string) (ensureResult, error) {
	path, err := filepath.Abs(SocketPath())
	if err != nil {
		return ensureResult{}, err
	}
	if expected != "" {
		want, err := filepath.Abs(expected)
		if err != nil || want != path {
			return ensureResult{}, errors.New("--ensure only starts the default local manager; custom sockets must be started explicitly")
		}
	}
	if os.Getenv("GANTRY_MANAGER_SOCKET") != "" {
		// An environment override is as explicit as --socket in the desktop.
		if err := probeLocalManager(ctx, path); err != nil {
			return ensureResult{}, fmt.Errorf("custom GANTRY_MANAGER_SOCKET is connect-only: %w", err)
		}
		return ensureResult{Socket: path, Version: managerAPIVersion}, nil
	}
	ctx, cancel := context.WithTimeout(ctx, ensureTimeout)
	defer cancel()
	return ensureLocalManager(ctx, path, launchLocalManager)
}

func ensureLocalManager(ctx context.Context, path string, launch managerLauncher) (ensureResult, error) {
	if err := ctx.Err(); err != nil {
		return ensureResult{}, err
	}
	result := ensureResult{Socket: path, Version: managerAPIVersion}
	if err := probeLocalManager(ctx, path); err == nil {
		return result, nil
	} else if !errors.Is(err, errManagerAbsent) {
		return ensureResult{}, err
	}
	// Only a genuinely absent/refused endpoint permits startup. Never unlink a
	// live, foreign, symlinked, non-HTTP, or incompatible endpoint to "repair" it.
	if err := layout.EnsureRoot(); err != nil {
		return ensureResult{}, err
	}
	base := filepath.Dir(path)
	if err := localsec.CreateManagerDir(base); err != nil {
		return ensureResult{}, err
	}
	lock, err := openPrivateManagerFile(filepath.Join(base, "manager-start.lock"))
	if err != nil {
		return ensureResult{}, err
	}
	defer func() { _ = lock.Close() }()
	for {
		if _, err := gutil.TryLockFD(lock); err == nil {
			break
		} else if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EAGAIN) {
			return ensureResult{}, err
		}
		if err := waitEnsureTick(ctx); err != nil {
			return ensureResult{}, fmt.Errorf("waiting for another local manager launcher: %w", err)
		}
	}
	// The startup lock serializes launchers; the existing manager-state lock
	// remains the authoritative owner across manual and automatic starts.
	if err := probeLocalManager(ctx, path); err == nil {
		return result, nil
	} else if !errors.Is(err, errManagerAbsent) {
		return ensureResult{}, err
	}
	logPath := filepath.Join(base, "manager.log")
	log, err := openPrivateManagerFile(logPath)
	if err != nil {
		return ensureResult{}, err
	}
	defer func() { _ = log.Close() }()
	if err := ctx.Err(); err != nil {
		return ensureResult{}, err
	}
	command, err := launch(log)
	if err != nil {
		return ensureResult{}, fmt.Errorf("start local manager: %w", err)
	}
	exited := make(chan error, 1)
	go func() { exited <- command.Wait() }()
	ready := false
	defer func() {
		if !ready {
			// Only this invocation's child may be terminated. Never stop a
			// pre-existing manager or any sandbox daemon.
			_ = command.Process.Kill()
		}
	}()
	for {
		select {
		case <-exited:
			// A manual start can win the manager-state lock after our probe.
			if err := probeLocalManager(ctx, path); err == nil {
				ready = true
				return result, nil
			}
			return ensureResult{}, fmt.Errorf("local manager exited before readiness; another manager may own the state, or saved policy-feed configuration may require an explicit serve command; see %s", logPath)
		default:
		}
		if err := probeLocalManager(ctx, path); err == nil {
			ready = true
			result.Started, result.PID = true, command.Process.Pid
			return result, nil
		} else if !errors.Is(err, errManagerAbsent) && !errors.Is(err, errManagerNotPrivate) {
			return ensureResult{}, err
		}
		// A freshly bound socket is chmod'd before publication. During our
		// own child's startup only, wait through that window without dialing
		// an insecure endpoint or modifying its permissions ourselves.
		if err := waitEnsureTick(ctx); err != nil {
			return ensureResult{}, fmt.Errorf("local manager readiness timed out; see %s: %w", logPath, err)
		}
	}
}

func waitEnsureTick(ctx context.Context) error {
	timer := time.NewTimer(50 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func launchLocalManager(log *os.File) (*exec.Cmd, error) {
	self, err := os.Executable()
	if err != nil {
		return nil, err
	}
	command := exec.Command(self, "serve", "--local-background")
	command.Env = append(os.Environ(), "GANTRY_REMOTE=")
	command.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	// Nil stdin is /dev/null. The daemon must not retain the caller's terminal
	// or its stdout/stderr pipes, otherwise a desktop launch never completes.
	command.Stdout, command.Stderr = log, log
	if err := command.Start(); err != nil {
		return nil, err
	}
	return command, nil
}

func openPrivateManagerFile(path string) (*os.File, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_APPEND|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0o600)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err == nil {
		err = privateManagerInfo(path, info, false)
	}
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	return file, nil
}

func privateManagerInfo(path string, info os.FileInfo, directory bool) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Geteuid() {
		return fmt.Errorf("manager path %s must be owned by the current user", path)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%w: %s", errManagerNotPrivate, path)
	}
	if info.Mode()&os.ModeSymlink != 0 || directory && !info.IsDir() || !directory && !info.Mode().IsRegular() && info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("invalid manager path type: %s", path)
	}
	return nil
}

// probeLocalManager validates the local authentication boundary before sending
// a bounded HTTP health request. Only ENOENT/ECONNREFUSED count as absence.
func probeLocalManager(ctx context.Context, path string) error {
	parent, err := os.Lstat(filepath.Dir(path))
	if errors.Is(err, os.ErrNotExist) {
		return errManagerAbsent
	}
	if err != nil {
		return err
	}
	if err := privateManagerInfo(filepath.Dir(path), parent, true); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return errManagerAbsent
	}
	if err != nil {
		return err
	}
	if err := privateManagerInfo(path, info, false); err != nil {
		return err
	}
	if info.Mode()&os.ModeSocket == 0 {
		return errors.New("manager endpoint is not a Unix socket")
	}
	transport := &http.Transport{
		DisableCompression: true, DisableKeepAlives: true,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			conn, err := (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "unix", path)
			if err == nil && !localsec.PeerSameUser(conn) {
				_ = conn.Close()
				return nil, errors.New("local manager belongs to a different user")
			}
			return conn, err
		},
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("manager redirects are refused") }}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://gantry.local/v1/health", nil)
	if err != nil {
		return err
	}
	response, err := client.Do(request)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ECONNREFUSED) {
			return errManagerAbsent
		}
		return fmt.Errorf("local manager health check failed: %w", err)
	}
	defer func() { _ = response.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(response.Body, 4097))
	if err != nil {
		return err
	}
	var health managerapi.Health
	if response.StatusCode != http.StatusOK || len(body) > 4096 || json.Unmarshal(body, &health) != nil || !health.OK || health.Version != managerAPIVersion {
		return errors.New("existing endpoint is not a healthy, compatible Gantry v1 manager; it was not replaced")
	}
	return nil
}
