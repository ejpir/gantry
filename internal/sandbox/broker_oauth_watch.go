package sandbox

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/ejpir/gantry/internal/client"
)

// runOAuthWatchSession owns one daemon-internal task running the trusted guest
// listener watcher. Its stdout is a private ttrpc stream to the daemon, never a
// user terminal, so terminal emulators and nested tools cannot alter reports.
func (br *broker) runOAuthWatchSession(ctx context.Context, output io.Writer) (int, error) {
	if !br.limits.acquireSession() {
		return 0, fmt.Errorf("oauth watcher: sandbox session limit reached")
	}
	defer br.limits.releaseSession()

	killCh := make(chan struct{}, 1)
	stopKill := context.AfterFunc(ctx, func() {
		select {
		case killCh <- struct{}{}:
		default:
		}
	})
	defer stopKill()

	manifest := client.LoadShareManifest(br.dir)
	target := br.sessionTarget(false)
	var status int
	options := client.SessionOptions{
		StreamSock:      br.streamSock,
		StreamDial:      br.streamDial,
		SetupLocker:     &br.sessionSetupMu,
		Shares:          manifest.Shares,
		ShareTransport:  manifest.Transport,
		Args:            []string{"/run/gantry/bin/gantry-guest", "oauth-watch"},
		SandboxSession:  true,
		ImgCfg:          mcpLauncherImageConfig(target.imageConfig),
		Environment:     br.cfg.ProxyEnvironment(),
		Quiet:           true,
		KillCh:          killCh,
		WaitContext:     ctx,
		ExitStatus:      &status,
		HoldSetupLocker: false,
	}
	applySessionTarget(&options, target)
	// Keep the root identity required to read the trusted helper and procfs;
	// applySessionTarget only selects the workload root/mount chain.
	options.ImgCfg = mcpLauncherImageConfig(target.imageConfig)
	err := client.Session(br.rpc, options, strings.NewReader(""), output)
	return status, err
}
