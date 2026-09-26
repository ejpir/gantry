package manager

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/ejpir/gantry/internal/policyfeed"
	"github.com/ejpir/gantry/internal/sandbox/layout"
)

func managerBaseDir() string {
	if home := os.Getenv("GANTRY_HOME"); home != "" {
		return filepath.Dir(filepath.Clean(home))
	}
	return filepath.Dir(layout.Root())
}

// SocketPath returns the manager endpoint. GANTRY_MANAGER_SOCKET is an
// explicit test/embedding override; production defaults to ~/.gantry/manager.sock.
func SocketPath() string {
	if path := os.Getenv("GANTRY_MANAGER_SOCKET"); path != "" {
		return path
	}
	return filepath.Join(managerBaseDir(), "manager.sock")
}

// Cmd runs the HTTP/JSON manager over lifecycle. The default listener is the
// same-user Unix socket, whose filesystem permissions are the authentication
// boundary. -listen tls://ADDR:PORT opts into the network transport, which
// requires bearer-token authentication (--token-file) and TLS material
// (--self-signed or --tls-cert/--tls-key); plaintext network listeners are
// refused. An optional -policy-feed adds one outbound mTLS organization-wide
// policy receiver. See docs/gantry/remote-access.md.
func Cmd(argv []string, lifecycle Lifecycle) int {
	flags := flag.NewFlagSet("serve", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	socket := flags.String("socket", "", "deprecated alias for -listen unix://PATH")
	var listens listenFlags
	flags.Var(&listens, "listen", "manager listener: unix://PATH or tls://ADDR:PORT (repeatable); default unix://"+SocketPath())
	selfSigned := flags.Bool("self-signed", false, "generate or reuse self-signed TLS material under <root>/serve/")
	tlsCert := flags.String("tls-cert", "", "TLS certificate chain file (requires --tls-key)")
	tlsKey := flags.String("tls-key", "", "TLS private key file (requires --tls-cert)")
	tokenFile := flags.String("token-file", "", "bearer token file, one token per line (required with tls://)")
	var feedPaths policyFeedFlags
	flags.Var(&feedPaths, "policy-feed", "organization-wide mTLS policy-feed configuration")
	mintToken := flags.Bool("mint-token", false, "print a fresh bearer token and exit")
	ensure := flags.Bool("ensure", false, "ensure the default local manager is running; print JSON readiness and exit")
	localBackground := flags.Bool("local-background", false, "internal Unix-only background manager role")
	if err := flags.Parse(argv); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: gantry serve [-listen unix://PATH | tls://ADDR:PORT] [--self-signed | --tls-cert C --tls-key K] [--token-file PATH] [--policy-feed CONFIG]")
		fmt.Fprintln(os.Stderr, "       gantry serve --mint-token")
		return 2
	}
	if *ensure || *localBackground {
		if *ensure && *localBackground || len(listens) != 0 || *selfSigned || *tlsCert != "" || *tlsKey != "" || *tokenFile != "" || *mintToken || len(feedPaths) != 0 || *localBackground && (*socket != "" || os.Getenv("GANTRY_MANAGER_SOCKET") != "") {
			fmt.Fprintln(os.Stderr, "gantry serve: automatic startup cannot be combined with listener, TLS, token, or policy-feed options")
			return 2
		}
		if *ensure {
			ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer cancel()
			result, err := ensureDefaultManager(ctx, *socket)
			if err != nil {
				fmt.Fprintln(os.Stderr, "gantry serve --ensure:", err)
				return 1
			}
			if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
				return 1
			}
			return 0
		}
	}
	if *mintToken {
		token, err := MintToken()
		if err != nil {
			fmt.Fprintln(os.Stderr, "gantry serve:", err)
			return 1
		}
		fmt.Println(token)
		return 0
	}
	plan, err := resolveServePlan(*socket, listens, *tlsCert, *tlsKey, *selfSigned, *tokenFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "gantry serve:", err)
		return 2
	}
	if len(feedPaths) > 1 {
		fmt.Fprintln(os.Stderr, "gantry serve: only one organization-wide policy feed may be configured")
		return 2
	}
	feeds := make([]*policyfeed.Config, 0, len(feedPaths))
	for _, path := range feedPaths {
		feed, err := policyfeed.LoadConfig(path)
		if err != nil {
			fmt.Fprintln(os.Stderr, "gantry serve:", err)
			return 2
		}
		feeds = append(feeds, feed)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	feedPath := ""
	if len(feedPaths) == 1 {
		feedPath = feedPaths[0]
	}
	if err := serveWithOptions(ctx, serveOptions{plan: plan, policyFeeds: feeds, feedPath: feedPath}, lifecycle); err != nil {
		fmt.Fprintln(os.Stderr, "gantry serve:", err)
		return 1
	}
	return 0
}

// listenFlags collects repeated -listen occurrences.
type listenFlags []string

func (f *listenFlags) String() string { return strings.Join(*f, ",") }

func (f *listenFlags) Set(value string) error {
	if value == "" {
		return errors.New("empty -listen value")
	}
	*f = append(*f, value)
	return nil
}

type policyFeedFlags []string

func (f *policyFeedFlags) String() string { return strings.Join(*f, ",") }

func (f *policyFeedFlags) Set(value string) error {
	if value == "" {
		return errors.New("empty -policy-feed value")
	}
	*f = append(*f, value)
	return nil
}
