package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/ejpir/gantry/internal/sandbox/credhelper/credproto"
)

// runCredHelper speaks git-credential(1): git invokes the helper as
// "credhelper <op>" with a query on stdin and reads attributes back on
// stdout. Only "get" does anything — the host broker is answer-only, so
// "store" and "erase" succeed as no-ops. Every failure path is quiet
// (empty output, exit 0) so git falls through to other helpers instead of
// surfacing broker internals to the user.
func runCredHelper(args []string) {
	if len(args) != 1 || args[0] != "get" {
		return
	}
	query, err := readCredentialQuery(io.LimitReader(os.Stdin, credproto.MaxRequestBytes))
	if err != nil {
		debugf("read query: %v", err)
		return
	}
	host := strings.ToLower(strings.TrimSpace(query["host"]))
	switch query["protocol"] {
	case "https", "http":
	default:
		debugf("unsupported protocol %q", query["protocol"])
		return
	}
	if host == "" {
		return
	}
	resp, err := askBroker(host, query["path"])
	if err != nil {
		debugf("broker: %v", err)
		return
	}
	if resp.Username == "" {
		debugf("no credential for %s", host)
		return
	}
	fmt.Printf("username=%s\npassword=%s\n", resp.Username, resp.Password)
}

// readCredentialQuery parses git's attribute lines (key=value, terminated
// by a blank line or EOF).
func readCredentialQuery(r io.Reader) (map[string]string, error) {
	query := map[string]string{}
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			break
		}
		k, v, ok := strings.Cut(line, "=")
		if ok {
			query[k] = v
		}
	}
	return query, sc.Err()
}
