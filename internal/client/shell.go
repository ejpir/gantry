package client

import (
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"time"

	"github.com/ejpir/gantry/internal/image"

	"github.com/containerd/ttrpc"
	"golang.org/x/term"
)

// ShellOptions configures one interactive container session.
type ShellOptions struct {
	RPCSock     string       // Unix socket accepting vminitd's dial-back.
	RPCListener net.Listener // Optional listener created before VM boot.
	StreamSock  string       // Unix forwarding socket for guest stream port 1026.
	Share       bool         // Mount every share in shares.json.
	RW          bool         // Assemble a writable overlay root.
	LayerSet    *LayerSet    // Optional native multi-device EROFS image.
	Args        []string
	ID          string
	ImgCfg      *image.Config
	Secrets     []string
	Environment []string
	ExitStatus  *int
}

func (options ShellOptions) sessionOptions(entries []ShareEntry) SessionOptions {
	return SessionOptions{
		StreamSock:       options.StreamSock,
		Shares:           entries,
		RW:               options.RW,
		LayerSet:         options.LayerSet,
		Args:             options.Args,
		ID:               options.ID,
		ImgCfg:           options.ImgCfg,
		Secrets:          options.Secrets,
		Environment:      options.Environment,
		ExitStatus:       options.ExitStatus,
		ExecIntoExisting: true,
	}
}

// Shell accepts the guest dial-back, owns the local terminal, and delegates
// the container lifecycle to Session.
func Shell(options ShellOptions) error {
	var entries []ShareEntry
	if options.Share {
		entries = LoadShares(filepath.Dir(options.RPCSock))
		if len(entries) == 0 {
			return fmt.Errorf("no shares exported by the VMM\n(start gantry with -share TAG=/absolute/host/path[,ro]; see shares.json next to the RPC socket)")
		}
	}

	var client *ttrpc.Client
	var err error
	if options.RPCListener != nil {
		client, err = AcceptRPCListener(options.RPCListener, options.RPCSock)
	} else {
		client, err = AcceptRPC(options.RPCSock)
	}
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()

	session := options.sessionOptions(entries)
	session.Terminal = term.IsTerminal(int(os.Stdin.Fd()))
	if session.Terminal {
		old, err := term.MakeRaw(int(os.Stdin.Fd()))
		if err == nil {
			defer func() { _ = term.Restore(int(os.Stdin.Fd()), old) }()
		}
		if width, height, err := term.GetSize(int(os.Stdout.Fd())); err == nil {
			session.Cols, session.Rows = uint32(width), uint32(height)
		}
	}

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt)
	defer signal.Stop(signals)
	kill := make(chan struct{})
	var killOnce sync.Once
	killSession := func() { killOnce.Do(func() { close(kill) }) }
	signalWatcherDone := make(chan struct{})
	defer close(signalWatcherDone)
	go func() {
		select {
		case <-signals:
			killSession()
		case <-signalWatcherDone:
		}
	}()
	session.KillCh = kill
	defer killSession()

	err = Session(client, session, os.Stdin, os.Stdout)
	if options.RW {
		id := session.ID
		if id == "" {
			id = "shell"
		}
		SyncGuest(client, options.StreamSock, id, 5*time.Second)
	}
	return err
}
