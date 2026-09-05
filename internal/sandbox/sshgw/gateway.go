// Package sshgw terminates SSH inside the trusted Gantry daemon. The
// transport is a per-sandbox local socket; NoClientAuth is intentional because
// access to that socket is already the same filesystem-permission boundary as
// gantry exec.
package sshgw

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/ejpir/gantry/internal/sshpolicy"
	"golang.org/x/crypto/ssh"
)

const (
	HandshakeTimeout = 10 * time.Second
	MaxChannels      = 16
	// DefaultUserSentinel is the wire username used by the managed OpenSSH
	// configuration when the image's configured user should be selected. It is
	// consumed by the gateway and is never passed to the guest.
	DefaultUserSentinel = "__gantry_image_default__"
)

const genericChannelRefusal = "channel type is not permitted"

// Window is a terminal size in character cells.
type Window struct {
	Width  uint32
	Height uint32
}

// Forward is a permitted guest-loopback direct-tcpip target.
type Forward struct {
	Host string
	Port uint32
}

// SpawnRequest describes one guest process. Exactly one of Command,
// Subsystem, or Forward may be set; all empty means a login shell.
type SpawnRequest struct {
	User      string
	Command   string
	Subsystem string
	Forward   *Forward
	Env       []string
	Terminal  bool
	Window    Window
	Resize    <-chan Window
	Stdin     io.Reader
	Stdout    io.Writer
}

// Spawner is the daemon-to-guest exec seam.
type Spawner interface {
	Spawn(context.Context, SpawnRequest) (exitStatus int, err error)
}

// SpawnFunc adapts a function to Spawner.
type SpawnFunc func(context.Context, SpawnRequest) (int, error)

func (f SpawnFunc) Spawn(ctx context.Context, req SpawnRequest) (int, error) {
	return f(ctx, req)
}

// Config controls one per-sandbox SSH gateway.
type Config struct {
	Name        string
	HostKeyPath string
	DefaultUser string
	Spawner     Spawner
	Auditf      func(string, ...any)
	// PeerAllowed applies the local transport identity check before an SSH
	// handshake. Nil allows the connection (useful only to in-memory tests).
	PeerAllowed func(net.Conn) bool
}

type Gateway struct {
	cfg    Config
	server *ssh.ServerConfig
}

func New(cfg Config) (*Gateway, error) {
	if cfg.Name == "" {
		return nil, errors.New("SSH gateway sandbox name is empty")
	}
	if cfg.Spawner == nil {
		return nil, errors.New("SSH gateway spawner is nil")
	}
	if cfg.DefaultUser == "" {
		cfg.DefaultUser = "root"
	}
	signer, err := EnsureHostKey(cfg.HostKeyPath)
	if err != nil {
		return nil, err
	}
	server := &ssh.ServerConfig{
		NoClientAuth:  true,
		MaxAuthTries:  3,
		ServerVersion: "SSH-2.0-gantry",
	}
	server.AddHostKey(signer)
	return &Gateway{cfg: cfg, server: server}, nil
}

func (g *Gateway) auditf(format string, args ...any) {
	if g.cfg.Auditf != nil {
		g.cfg.Auditf("ssh: "+format, args...)
	}
}

// Serve accepts local socket connections until ctx is canceled or ln closes.
func (g *Gateway) Serve(ctx context.Context, ln net.Listener) error {
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		if g.cfg.PeerAllowed != nil && !g.cfg.PeerAllowed(conn) {
			g.auditf("connection refused by local peer policy")
			_ = conn.Close()
			continue
		}
		go g.serveConn(ctx, conn)
	}
}

func gatewayUser(requested, defaultUser string) string {
	if requested == "" || requested == DefaultUserSentinel {
		return defaultUser
	}
	return requested
}

func (g *Gateway) serveConn(parent context.Context, raw net.Conn) {
	defer func() { _ = raw.Close() }()
	stopClose := context.AfterFunc(parent, func() { _ = raw.Close() })
	defer stopClose()
	_ = raw.SetDeadline(time.Now().Add(HandshakeTimeout))
	conn, channels, requests, err := ssh.NewServerConn(raw, g.server)
	if err != nil {
		g.auditf("handshake refused")
		return
	}
	_ = raw.SetDeadline(time.Time{})
	defer func() { _ = conn.Close() }()

	user := gatewayUser(conn.User(), g.cfg.DefaultUser)
	g.auditf("connection open user=%s", user)
	defer g.auditf("connection close user=%s", user)

	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	go g.rejectGlobalRequests(requests, user)
	var active atomic.Int32
	for newChannel := range channels {
		if active.Add(1) > MaxChannels {
			active.Add(-1)
			g.auditf("channel refused user=%s type=%s limit=%d", user, newChannel.ChannelType(), MaxChannels)
			_ = newChannel.Reject(ssh.ResourceShortage, genericChannelRefusal)
			continue
		}
		go func(ch ssh.NewChannel) {
			defer active.Add(-1)
			g.handleChannel(ctx, user, ch)
		}(newChannel)
	}
}

func (g *Gateway) rejectGlobalRequests(requests <-chan *ssh.Request, user string) {
	for request := range requests {
		g.auditf("global request refused user=%s type=%s", user, request.Type)
		if request.WantReply {
			_ = request.Reply(false, nil)
		}
	}
}

func (g *Gateway) handleChannel(ctx context.Context, user string, newChannel ssh.NewChannel) {
	switch newChannel.ChannelType() {
	case "session":
		g.auditf("channel open user=%s type=session", user)
		defer g.auditf("channel close user=%s type=session", user)
		g.handleSession(ctx, user, newChannel)
	case "direct-tcpip":
		g.handleDirectTCPIP(ctx, user, newChannel)
	default:
		g.auditf("channel refused user=%s type=%s", user, newChannel.ChannelType())
		_ = newChannel.Reject(ssh.UnknownChannelType, genericChannelRefusal)
	}
}

type directTCPIPPayload struct {
	Host       string
	Port       uint32
	OriginHost string
	OriginPort uint32
}

func (g *Gateway) handleDirectTCPIP(parent context.Context, user string, newChannel ssh.NewChannel) {
	var payload directTCPIPPayload
	if err := ssh.Unmarshal(newChannel.ExtraData(), &payload); err != nil || !sshpolicy.ExactLoopbackTarget(payload.Host, uint64(payload.Port)) {
		g.auditf("forward refused user=%s target=%s:%d", user, payload.Host, payload.Port)
		_ = newChannel.Reject(ssh.Prohibited, genericChannelRefusal)
		return
	}
	channel, requests, err := newChannel.Accept()
	if err != nil {
		return
	}
	defer func() { _ = channel.Close() }()
	g.auditf("channel open user=%s type=direct-tcpip target=%s:%d", user, payload.Host, payload.Port)
	defer g.auditf("channel close user=%s type=direct-tcpip target=%s:%d", user, payload.Host, payload.Port)
	g.auditf("forward open user=%s target=%s:%d", user, payload.Host, payload.Port)
	defer g.auditf("forward close user=%s target=%s:%d", user, payload.Host, payload.Port)

	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	// The request stream closes on SSH_MSG_CHANNEL_CLOSE, but remains open for
	// SSH_MSG_CHANNEL_EOF. This preserves TCP half-close semantics while making
	// a full close cancel the guest relay even when its target never sends EOF.
	go func() {
		ssh.DiscardRequests(requests)
		cancel()
	}()
	status, spawnErr := g.cfg.Spawner.Spawn(ctx, SpawnRequest{
		User: user, Forward: &Forward{Host: payload.Host, Port: payload.Port},
		Stdin: channel, Stdout: channel,
	})
	if spawnErr != nil || status != 0 {
		g.auditf("forward guest relay failed user=%s target=%s:%d", user, payload.Host, payload.Port)
	}
}

type envPayload struct {
	Name  string
	Value string
}

type ptyPayload struct {
	Term         string
	Width        uint32
	Height       uint32
	WidthPixels  uint32
	HeightPixels uint32
	Modes        string
}

type windowPayload struct {
	Width        uint32
	Height       uint32
	WidthPixels  uint32
	HeightPixels uint32
}

type execPayload struct{ Command string }
type subsystemPayload struct{ Name string }

type exitStatusPayload struct{ Status uint32 }

func allowedEnv(name string) bool {
	switch name {
	case "TERM", "LANG", "COLORTERM", "TERM_PROGRAM":
		return true
	default:
		return strings.HasPrefix(name, "LC_") && len(name) > len("LC_")
	}
}

func envList(values map[string]string) []string {
	names := make([]string, 0, len(values))
	for name := range values {
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([]string, 0, len(names))
	for _, name := range names {
		out = append(out, name+"="+values[name])
	}
	return out
}

func (g *Gateway) handleSession(parent context.Context, user string, newChannel ssh.NewChannel) {
	channel, requests, err := newChannel.Accept()
	if err != nil {
		return
	}
	defer func() { _ = channel.Close() }()
	g.auditf("session open user=%s", user)
	defer g.auditf("session close user=%s", user)

	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	environment := make(map[string]string)
	resize := make(chan Window, 8)
	var terminal bool
	var window Window
	started := false
	done := make(chan struct{})
	var status int
	var spawnErr error
	var subsystem string

	start := func(command, requestedSubsystem string) {
		started = true
		subsystem = requestedSubsystem
		go func() {
			status, spawnErr = g.cfg.Spawner.Spawn(ctx, SpawnRequest{
				User: user, Command: command, Subsystem: requestedSubsystem,
				Env: envList(environment), Terminal: terminal, Window: window,
				Resize: resize, Stdin: channel, Stdout: channel,
			})
			close(done)
		}()
	}

	for {
		select {
		case <-done:
			if spawnErr != nil {
				status = 255
			}
			if status < 0 || status > 255 {
				status = 255
			}
			_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(exitStatusPayload{Status: uint32(status)}))
			if subsystem == "sftp" {
				g.auditf("sftp close user=%s", user)
			}
			_ = channel.CloseWrite()
			return
		case request, ok := <-requests:
			if !ok {
				cancel()
				if started {
					<-done
				}
				return
			}
			success := false
			switch request.Type {
			case "env":
				var payload envPayload
				if !started && ssh.Unmarshal(request.Payload, &payload) == nil && allowedEnv(payload.Name) {
					environment[payload.Name] = payload.Value
					success = true
				} else if payload.Name != "" && !allowedEnv(payload.Name) {
					g.auditf("dropping non-allowlisted env var user=%s name=%s", user, payload.Name)
				}
			case "pty-req":
				var payload ptyPayload
				if !started && ssh.Unmarshal(request.Payload, &payload) == nil && payload.Width > 0 && payload.Height > 0 {
					terminal = true
					window = Window{Width: payload.Width, Height: payload.Height}
					environment["TERM"] = payload.Term
					success = true
				}
			case "window-change":
				var payload windowPayload
				if terminal && ssh.Unmarshal(request.Payload, &payload) == nil && payload.Width > 0 && payload.Height > 0 {
					window = Window{Width: payload.Width, Height: payload.Height}
					if started {
						select {
						case resize <- window:
						default:
							select {
							case <-resize:
							default:
							}
							select {
							case resize <- window:
							default:
							}
						}
					}
					success = true
				}
			case "shell":
				if !started && len(request.Payload) == 0 {
					start("", "")
					success = true
				}
			case "exec":
				var payload execPayload
				if !started && ssh.Unmarshal(request.Payload, &payload) == nil {
					start(payload.Command, "")
					success = true
				}
			case "subsystem":
				var payload subsystemPayload
				if !started && ssh.Unmarshal(request.Payload, &payload) == nil && payload.Name == "sftp" {
					g.auditf("sftp open user=%s", user)
					start("", "sftp")
					success = true
				}
			case "signal":
				if started {
					cancel()
					success = true
				}
			default:
				g.auditf("session request refused user=%s type=%s", user, request.Type)
			}
			if request.WantReply {
				_ = request.Reply(success, nil)
			}
		}
	}
}

// GenericChannelRefusal is exposed for policy tests and client diagnostics.
func GenericChannelRefusal() string { return genericChannelRefusal }

// ValidateLoopbackTarget is the direct-tcpip policy seam used by tests.
func ValidateLoopbackTarget(host string, port uint32) error {
	if !sshpolicy.ExactLoopbackTarget(host, uint64(port)) {
		return fmt.Errorf("%s", genericChannelRefusal)
	}
	return nil
}
