package policyservice

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	api "github.com/ejpir/gantry/api/policyservice"
)

const usage = `usage:
  gantry policy-service init -dir DIR -organization ORG -url https://HOST:PORT -public-key org-public.pem
                             [-ring NAME ...] [-name EXTRA-TLS-NAME ...]
  gantry policy-service serve -dir DIR [-listen ADDR:PORT]
  gantry policy-service admin add -dir DIR -name NAME
  gantry policy-service admin rm -dir DIR -name NAME

The policy service is the organization's policy feed: enrolled host managers
(gantry serve -policy-feed) poll it over mutual TLS, and administrators publish
signed generations and roll them out ring by ring through its API, from the
Gantry desktop or with plain HTTPS. It verifies bundles with the pinned
organization public key and never holds the signing key.

init creates DIR with a host CA, a TLS certificate for the URL's host, and
the rings canary, early, and everyone (or -ring, repeated, in order).
admin add prints a new administrator token once; register it with
  gantry remote add NAME https://HOST:PORT --ca DIR/ca.pem --token-stdin
`

// Cmd runs gantry policy-service.
func Cmd(argv []string) int {
	if len(argv) == 0 || argv[0] == "-h" || argv[0] == "--help" || argv[0] == "help" {
		fmt.Fprint(os.Stderr, usage)
		return 0
	}
	switch argv[0] {
	case "init":
		return cmdInit(argv[1:])
	case "serve":
		return cmdServe(argv[1:])
	case "admin":
		return cmdAdmin(argv[1:])
	default:
		fmt.Fprint(os.Stderr, usage)
		return 2
	}
}

type repeated []string

func (r *repeated) String() string { return strings.Join(*r, ",") }
func (r *repeated) Set(value string) error {
	if value == "" {
		return errors.New("empty value")
	}
	*r = append(*r, value)
	return nil
}

func parse(flags *flag.FlagSet, argv []string) int {
	flags.SetOutput(os.Stderr)
	if err := flags.Parse(argv); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprint(os.Stderr, usage)
		return 2
	}
	return -1
}

func cmdInit(argv []string) int {
	flags := flag.NewFlagSet("policy-service init", flag.ContinueOnError)
	dir := flags.String("dir", "", "new service directory")
	organization := flags.String("organization", "", "organization identifier; must match the policy documents")
	serviceURL := flags.String("url", "", "https://HOST:PORT hosts and administrators use")
	publicKey := flags.String("public-key", "", "organization policy verification key (RSA public key PEM)")
	var rings, names repeated
	flags.Var(&rings, "ring", "rollout ring, in order (repeatable; default canary, early, everyone)")
	flags.Var(&names, "name", "additional DNS name or IP for the TLS certificate (repeatable)")
	if code := parse(flags, argv); code >= 0 {
		return code
	}
	if *dir == "" || *organization == "" || *serviceURL == "" || *publicKey == "" {
		fmt.Fprintln(os.Stderr, "gantry policy-service init: -dir, -organization, -url, and -public-key are required")
		return 2
	}
	key, err := os.ReadFile(*publicKey)
	if err != nil {
		fmt.Fprintln(os.Stderr, "gantry policy-service init:", err)
		return 1
	}
	if err := Init(InitOptions{Dir: *dir, Organization: *organization, URL: *serviceURL, PublicKey: key, Rings: rings, ExtraNames: names}); err != nil {
		fmt.Fprintln(os.Stderr, "gantry policy-service init:", err)
		return 1
	}
	fmt.Printf("gantry policy-service: initialized %s for %s\n", *dir, *organization)
	fmt.Printf("  CA for hosts and administrators: %s\n", filepath.Join(*dir, api.CAFile))
	fmt.Printf("  next: gantry policy-service admin add -dir %s -name NAME\n", *dir)
	fmt.Printf("        gantry policy-service serve -dir %s\n", *dir)
	return 0
}

func cmdServe(argv []string) int {
	flags := flag.NewFlagSet("policy-service serve", flag.ContinueOnError)
	dir := flags.String("dir", "", "service directory created by init")
	listen := flags.String("listen", "", "TLS listener ADDR:PORT (default: all addresses on the URL's port)")
	if code := parse(flags, argv); code >= 0 {
		return code
	}
	if *dir == "" {
		fmt.Fprintln(os.Stderr, "gantry policy-service serve: -dir is required")
		return 2
	}
	audit := log.New(os.Stderr, "policy-service: ", log.LstdFlags|log.LUTC)
	service, err := Open(*dir, audit)
	if err != nil {
		fmt.Fprintln(os.Stderr, "gantry policy-service serve:", err)
		return 1
	}
	address := *listen
	if address == "" {
		address = service.ListenAddress()
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := Serve(ctx, service, address, audit); err != nil {
		fmt.Fprintln(os.Stderr, "gantry policy-service serve:", err)
		return 1
	}
	return 0
}

// Serve runs the feed and administrator API on one TLS listener until ctx
// ends. Host reports whose only change is their time are flushed each minute.
func Serve(ctx context.Context, service *Service, address string, audit *log.Logger) error {
	listener, err := tls.Listen("tcp", address, service.TLSConfig())
	if err != nil {
		return err
	}
	server := &http.Server{
		Handler:           service.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		// Long polls hold responses for up to maxWait.
		WriteTimeout:   maxWait + 30*time.Second,
		IdleTimeout:    2 * time.Minute,
		MaxHeaderBytes: 64 << 10,
		ErrorLog:       log.New(io.Discard, "", 0),
	}
	audit.Printf("serving %s on %s (feed %s)", service.Organization(), listener.Addr(), service.FeedURL())
	done := make(chan struct{})
	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				service.FlushReports()
			case <-ctx.Done():
				shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				_ = server.Shutdown(shutdown)
				cancel()
				service.FlushReports()
				close(done)
				return
			}
		}
	}()
	err = server.Serve(listener)
	if errors.Is(err, http.ErrServerClosed) {
		<-done
		return nil
	}
	return err
}

func cmdAdmin(argv []string) int {
	if len(argv) == 0 || argv[0] != "add" && argv[0] != "rm" {
		fmt.Fprint(os.Stderr, usage)
		return 2
	}
	flags := flag.NewFlagSet("policy-service admin "+argv[0], flag.ContinueOnError)
	dir := flags.String("dir", "", "service directory")
	name := flags.String("name", "", "administrator name, recorded on everything they publish")
	if code := parse(flags, argv[1:]); code >= 0 {
		return code
	}
	if *dir == "" || *name == "" {
		fmt.Fprintln(os.Stderr, "gantry policy-service admin: -dir and -name are required")
		return 2
	}
	if argv[0] == "rm" {
		if err := RemoveAdmin(*dir, *name); err != nil {
			fmt.Fprintln(os.Stderr, "gantry policy-service admin rm:", err)
			return 1
		}
		return 0
	}
	token, err := AddAdmin(*dir, *name)
	if err != nil {
		fmt.Fprintln(os.Stderr, "gantry policy-service admin add:", err)
		return 1
	}
	fmt.Println(token)
	return 0
}
