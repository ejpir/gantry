package sandbox

import (
	"context"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/ejpir/gantry/internal/client"
	"github.com/ejpir/gantry/internal/image"
	"github.com/ejpir/gantry/internal/sandbox/config"
	"github.com/ejpir/gantry/internal/sandbox/layout"
	"github.com/ejpir/gantry/internal/sandbox/localsec"
	"github.com/ejpir/gantry/internal/sandbox/sshgw"
)

func sshInstallDir() string {
	// layout.Root is ~/.gantry/sandboxes (or GANTRY_HOME). Install identity
	// and managed client config are siblings of sandbox state, not a fake
	// sandbox that would appear in gantry ls.
	return filepath.Join(filepath.Dir(layout.Root()), "ssh")
}

func sshHostKeyPath() string { return filepath.Join(sshInstallDir(), "host_ed25519") }

func sshImageConfig(cfg config.RunConfig) *image.Config {
	if cfg.DevContainers && cfg.DevContainersImageCfg != nil {
		return cfg.DevContainersImageCfg
	}
	return cfg.ImageCfg
}

func defaultSSHUser(cfgUser string, uid uint32) string {
	if userName, _, ok := strings.Cut(cfgUser, ":"); ok {
		cfgUser = userName
	}
	if cfgUser != "" {
		return cfgUser
	}
	if uid != 0 {
		return strconv.FormatUint(uint64(uid), 10)
	}
	return "root"
}

func (d *daemonRuntime) startSSHGateway() error {
	d.sshMu.Lock()
	defer d.sshMu.Unlock()
	if d.sshListener != nil {
		return nil
	}
	listener, endpoint, err := listenSSH(d.name, d.dir)
	if err != nil {
		return fmt.Errorf("SSH gateway listener %s: %w", endpoint, err)
	}

	defaultUser := "root"
	sshImageCfg := sshImageConfig(d.cfg)
	if sshImageCfg != nil {
		defaultUser = defaultSSHUser(sshImageCfg.User, sshImageCfg.UID)
	}
	gateway, err := sshgw.New(sshgw.Config{
		Name: d.name, HostKeyPath: sshHostKeyPath(), DefaultUser: defaultUser,
		Spawner: sshgw.SpawnFunc(d.broker.spawnSSH),
		Auditf:  d.broker.auditf, PeerAllowed: localsec.PeerSameUser,
	})
	if err != nil {
		_ = listener.Close()
		removeSSHRuntime(d.name, d.dir)
		return fmt.Errorf("SSH gateway: %w", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	d.sshListener, d.sshCancel = listener, cancel
	d.broker.auditf("ssh: gateway enabled on sandbox-local socket")
	if d.broker.devContainers.Load() {
		d.broker.auditf("devcontainers: curated IDE container enabled inside sandbox VM")
	}
	go func() {
		if err := gateway.Serve(ctx, listener); err != nil {
			d.broker.auditf("ssh: gateway stopped: %v", err)
		}
	}()
	return nil
}

func (d *daemonRuntime) stopSSHGateway() {
	d.sshMu.Lock()
	cancel, listener := d.sshCancel, d.sshListener
	d.sshCancel, d.sshListener = nil, nil
	d.sshMu.Unlock()
	if cancel != nil {
		cancel()
	}
	if listener != nil {
		_ = listener.Close()
	}
	removeSSHRuntime(d.name, d.dir)
}

func (br *broker) spawnSSH(ctx context.Context, request sshgw.SpawnRequest) (int, error) {
	ide := br.devContainers.Load()
	if !br.waitForGuestTools(ctx, ide) {
		return 255, fmt.Errorf("SSH session refused")
	}
	if !br.limits.acquireSession() {
		return 255, fmt.Errorf("SSH session refused")
	}
	defer br.limits.releaseSession()

	args := []string{"/run/gantry/bin/gantry-guest", "ssh-session", request.User}
	switch {
	case request.Forward != nil:
		args = append(args, "tcp", request.Forward.Host, strconv.FormatUint(uint64(request.Forward.Port), 10))
	case request.Subsystem == "sftp":
		args = append(args, "sftp")
	case request.Command != "":
		args = append(args, "exec", request.Command)
	default:
		args = append(args, "shell")
	}

	killCh := make(chan struct{}, 1)
	finished := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			select {
			case killCh <- struct{}{}:
			default:
			}
		case <-finished:
		}
	}()
	defer close(finished)

	var resize <-chan client.WindowSize
	if request.Resize != nil {
		updates := make(chan client.WindowSize, 8)
		resize = updates
		go func() {
			for {
				select {
				case size, ok := <-request.Resize:
					if !ok {
						return
					}
					update := client.WindowSize{Cols: size.Width, Rows: size.Height}
					select {
					case updates <- update:
					default:
						select {
						case <-updates:
						default:
						}
						select {
						case updates <- update:
						default:
						}
					}
				case <-finished:
					return
				}
			}
		}()
	}

	manifest := client.LoadShareManifest(br.dir)
	target := br.sessionTarget(ide)
	var status int
	options := client.SessionOptions{
		StreamSock: br.streamSock, StreamDial: br.streamDial, SetupLocker: &br.sessionSetupMu,
		Shares: manifest.Shares, ShareTransport: manifest.Transport, Args: args,
		SandboxSession: true,
		Environment:    append(br.cfg.ProxyEnvironment(), request.Env...),
		Terminal:       request.Terminal, Cols: request.Window.Width, Rows: request.Window.Height,
		Resize: resize, Quiet: true, KillCh: killCh, WaitContext: ctx, ExitStatus: &status,
	}
	applySessionTarget(&options, target)
	// gantry-guest starts as root and validates/drops to request.User itself.
	options.ImgCfg = mcpLauncherImageConfig(target.imageConfig)
	err := client.Session(br.rpc, options, request.Stdin, request.Stdout)
	if err != nil {
		return 255, fmt.Errorf("SSH session refused")
	}
	return status, nil
}
