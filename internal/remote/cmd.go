package remote

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"golang.org/x/term"
)

// Cmd implements `gantry remote <verb>`.
func Cmd(argv []string) int {
	return cmd(os.Stdout, os.Stderr, os.Stdin, argv)
}

func cmd(output, errorOutput io.Writer, input *os.File, argv []string) int {
	usage := func() {
		_, _ = fmt.Fprint(errorOutput, `usage: gantry remote <verb>   (docs/remote-sandbox-access.md)

  gantry remote add NAME https://HOST:PORT [auth flags] [tls flags]
  gantry remote ls
  gantry remote rm NAME
  gantry remote test NAME

auth flags (exactly one; the token comes from the server admin):
  --token-file FILE   read the token from a 0600 file
  --token-stdin       read one token line from standard input
  --token VALUE       inline (visible in shell history and ps; avoid)

tls flags:
  --ca FILE           CA bundle for servers using --self-signed
                      (the server's ~/.gantry/serve/ca.crt)
  --fingerprint FP    pin the exact server certificate, sha256:<hex>
                      (printed by 'gantry serve' at startup)
`)
	}
	if len(argv) == 0 {
		usage()
		return 2
	}
	switch argv[0] {
	case "add":
		return cmdAdd(output, errorOutput, input, argv[1:])
	case "ls":
		return cmdList(output, errorOutput)
	case "rm":
		if len(argv) != 2 {
			_, _ = fmt.Fprintln(errorOutput, "usage: gantry remote rm NAME")
			return 2
		}
		if err := Remove(argv[1]); err != nil {
			_, _ = fmt.Fprintln(errorOutput, "gantry remote rm:", err)
			return 1
		}
		_, _ = fmt.Fprintf(output, "gantry remote: removed %q\n", argv[1])
		return 0
	case "test":
		if len(argv) != 2 {
			_, _ = fmt.Fprintln(errorOutput, "usage: gantry remote test NAME")
			return 2
		}
		return cmdTest(output, errorOutput, argv[1])
	case "-h", "--help":
		usage()
		return 0
	default:
		_, _ = fmt.Fprintf(errorOutput, "gantry remote: unknown verb %q\n", argv[0])
		usage()
		return 2
	}
}

func cmdAdd(output, errorOutput io.Writer, input *os.File, argv []string) int {
	fs := flag.NewFlagSet("remote add", flag.ContinueOnError)
	fs.SetOutput(errorOutput)
	tokenFile := fs.String("token-file", "", "read the bearer token from FILE")
	tokenValue := fs.String("token", "", "bearer token value (visible in shell history and ps)")
	tokenStdin := fs.Bool("token-stdin", false, "read one token line from standard input")
	caFile := fs.String("ca", "", "CA bundle PEM for a self-signed server")
	fingerprint := fs.String("fingerprint", "", "pin the server leaf certificate (sha256:<hex>)")
	args, err := parseInterleaved(fs, argv)
	if errors.Is(err, flag.ErrHelp) {
		return 0
	}
	if err != nil {
		return 2
	}
	if len(args) != 2 {
		_, _ = fmt.Fprintln(errorOutput, "usage: gantry remote add NAME https://HOST:PORT [auth flags] [tls flags]")
		return 2
	}
	profile := Profile{Name: args[0], URL: args[1], Fingerprint: *fingerprint}
	if err := validateProfile(profile); err != nil {
		_, _ = fmt.Fprintln(errorOutput, "gantry remote add:", err)
		return 2
	}

	token, err := resolveAddToken(input, errorOutput, *tokenFile, *tokenValue, *tokenStdin)
	if err != nil {
		_, _ = fmt.Fprintln(errorOutput, "gantry remote add:", err)
		return 2
	}
	profile.CACert, err = ReadCA(*caFile)
	if err != nil {
		_, _ = fmt.Fprintln(errorOutput, "gantry remote add:", err)
		return 2
	}
	probeCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	live, err := Register(probeCtx, profile, token)
	if err != nil {
		_, _ = fmt.Fprintln(errorOutput, "gantry remote add:", err)
		return 1
	}
	_, _ = fmt.Fprintf(output, "gantry remote: added %q (%s)\n", profile.Name, profile.URL)
	if live != "" {
		pinned := ""
		if profile.Fingerprint == "" {
			pinned = " (unpinned — re-add with --fingerprint to pin)"
		}
		_, _ = fmt.Fprintf(output, "gantry remote: server fingerprint %s%s\n", live, pinned)
	}
	_, _ = fmt.Fprintf(output, "use with: gantry start dev -remote %s -image IMAGE\n", profile.Name)
	return 0
}

// resolveAddToken enforces exactly one credential source, preferring
// non-interactive ones; on a bare terminal it prompts without echo.
func resolveAddToken(input *os.File, errorOutput io.Writer, tokenFile, tokenValue string, tokenStdin bool) (string, error) {
	sources := 0
	for _, set := range []bool{tokenFile != "", tokenValue != "", tokenStdin} {
		if set {
			sources++
		}
	}
	if sources > 1 {
		return "", errors.New("pass only one of --token-file, --token, --token-stdin")
	}
	var token string
	switch {
	case tokenFile != "":
		data, err := os.ReadFile(tokenFile)
		if err != nil {
			return "", fmt.Errorf("read token file: %w", err)
		}
		token = strings.TrimRight(string(data), "\r\n")
	case tokenValue != "":
		_, _ = fmt.Fprintln(errorOutput, "gantry remote add: warning: --token exposes the token via shell history and ps; prefer --token-file or --token-stdin")
		token = tokenValue
	case tokenStdin:
		line, err := bufio.NewReader(input).ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return "", fmt.Errorf("read token from stdin: %w", err)
		}
		token = strings.TrimRight(line, "\r\n")
	default:
		if !term.IsTerminal(int(input.Fd())) {
			return "", errors.New("no token source: pass --token-file, --token, or --token-stdin")
		}
		_, _ = fmt.Fprint(errorOutput, "token: ")
		data, err := term.ReadPassword(int(input.Fd()))
		_, _ = fmt.Fprintln(errorOutput)
		if err != nil {
			return "", err
		}
		token = string(data)
	}
	if err := ValidateToken(token); err != nil {
		return "", err
	}
	return token, nil
}

func cmdList(output, errorOutput io.Writer) int {
	profiles, err := List()
	if err != nil {
		_, _ = fmt.Fprintln(errorOutput, "gantry remote ls:", err)
		return 1
	}
	if len(profiles) == 0 {
		_, _ = fmt.Fprintln(output, "no remotes (add one with: gantry remote add NAME https://HOST:PORT)")
		return 0
	}
	_, _ = fmt.Fprintf(output, "%-16s %-34s %-12s %s\n", "NAME", "URL", "CA", "FINGERPRINT")
	for _, profile := range profiles {
		ca, pin := "-", "-"
		if profile.CACert != "" {
			ca = "bundle"
		}
		if profile.Fingerprint != "" {
			pin = "pinned"
		}
		_, _ = fmt.Fprintf(output, "%-16s %-34s %-12s %s\n", profile.Name, profile.URL, ca, pin)
	}
	return 0
}

func cmdTest(output, errorOutput io.Writer, name string) int {
	profile, token, err := Load(name)
	if err != nil {
		_, _ = fmt.Fprintln(errorOutput, "gantry remote test:", err)
		return 1
	}
	client, err := Dial(profile, token)
	if err != nil {
		_, _ = fmt.Fprintln(errorOutput, "gantry remote test:", err)
		return 1
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	start := time.Now()
	version, err := client.Health(ctx)
	if err != nil {
		_, _ = fmt.Fprintf(errorOutput, "gantry remote test: %s\n", err)
		return 1
	}
	_, _ = fmt.Fprintf(output, "remote %q (%s): ok, manager version %s, %dms\n", name, profile.URL, version, time.Since(start).Milliseconds())
	if live, ok := client.LiveFingerprint(); ok {
		state := "unpinned"
		if profile.Fingerprint != "" {
			if profile.Fingerprint == live {
				state = "pinned, matches"
			} else {
				state = "PIN MISMATCH"
			}
		}
		_, _ = fmt.Fprintf(output, "fingerprint %s (%s)\n", live, state)
	}
	return 0
}
