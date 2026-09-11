//go:build linux

package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ejpir/gantry/internal/sandbox/oauthbridge/watchproto"
)

var oauthProcNetFiles = []struct {
	path     string
	loopback string
}{
	{path: "/proc/net/tcp", loopback: "0100007F"},
	// /proc/net/tcp6 renders each 32-bit address word in host byte order.
	{path: "/proc/net/tcp6", loopback: "00000000000000000000000001000000"},
}

// runOAuthWatch reports loopback TCP listeners from the guest network
// namespace. It observes every application without injecting libraries,
// wrapping commands, tracing processes, or parsing terminal output.
func runOAuthWatch(args []string) int {
	if len(args) != 0 {
		fmt.Fprintln(os.Stderr, "usage: gantry-guest oauth-watch")
		return 2
	}
	encoder := json.NewEncoder(os.Stdout)
	var previous string
	first := true
	for {
		ports, err := readOAuthLoopbackListeners()
		if err != nil {
			fmt.Fprintln(os.Stderr, "gantry-guest: oauth-watch:", err)
			return 1
		}
		key := portsKey(ports)
		if first || key != previous {
			if err := encoder.Encode(watchproto.Snapshot{Ports: ports}); err != nil {
				return 1
			}
			previous, first = key, false
		}
		time.Sleep(watchproto.PollInterval)
	}
}

func readOAuthLoopbackListeners() ([]int, error) {
	seen := make(map[int]struct{})
	for i, source := range oauthProcNetFiles {
		file, err := os.Open(source.path)
		if err != nil {
			// IPv6 procfs can be absent when the kernel has IPv6 disabled.
			if i > 0 && os.IsNotExist(err) {
				continue
			}
			return nil, err
		}
		err = parseProcNetTCP(file, source.loopback, seen)
		_ = file.Close()
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", source.path, err)
		}
	}
	ports := make([]int, 0, len(seen))
	for port := range seen {
		if allowedOAuthWatchPort(port) {
			ports = append(ports, port)
		}
	}
	sort.Ints(ports)
	if len(ports) > watchproto.MaxPorts {
		ports = ports[:watchproto.MaxPorts]
	}
	return ports, nil
}

func parseProcNetTCP(r io.Reader, loopback string, seen map[int]struct{}) error {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 4 || fields[3] != "0A" { // TCP_LISTEN
			continue
		}
		address, portHex, ok := strings.Cut(fields[1], ":")
		if !ok || !strings.EqualFold(address, loopback) {
			continue
		}
		port, err := strconv.ParseUint(portHex, 16, 16)
		if err != nil || port == 0 {
			continue
		}
		seen[int(port)] = struct{}{}
	}
	return scanner.Err()
}

func allowedOAuthWatchPort(port int) bool {
	return port == 1455 || port == 53692 || port >= 32768 && port <= 65535
}

func portsKey(ports []int) string {
	var b strings.Builder
	for _, port := range ports {
		b.WriteString(strconv.Itoa(port))
		b.WriteByte(',')
	}
	return b.String()
}
