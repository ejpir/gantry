//go:build linux

package main

import (
	"strings"
	"testing"
)

func TestParseProcNetTCPFindsOnlyLoopbackListeners(t *testing.T) {
	input := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:8037 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 1 1 0 0 10 0
   1: 00000000:8038 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 2 1 0 0 10 0
   2: 0100007F:8039 00000000:0000 01 00000000:00000000 00:00000000 00000000  1000        0 3 1 0 0 10 0
   3: 0200007F:803A 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 4 1 0 0 10 0
`
	seen := map[int]struct{}{}
	if err := parseProcNetTCP(strings.NewReader(input), "0100007F", seen); err != nil {
		t.Fatal(err)
	}
	if len(seen) != 1 {
		t.Fatalf("listeners = %v, want one", seen)
	}
	if _, ok := seen[0x8037]; !ok {
		t.Fatalf("listeners = %v, want port %d", seen, 0x8037)
	}
}

func TestParseProcNetTCP6Loopback(t *testing.T) {
	input := `  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000001000000:D173 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 1 1 0 0 10 0
`
	seen := map[int]struct{}{}
	if err := parseProcNetTCP(strings.NewReader(input), "00000000000000000000000001000000", seen); err != nil {
		t.Fatal(err)
	}
	if _, ok := seen[0xD173]; !ok {
		t.Fatalf("listeners = %v, want IPv6 loopback port", seen)
	}
}

func TestAllowedOAuthWatchPort(t *testing.T) {
	for _, port := range []int{1455, 32768, 53692, 65535} {
		if !allowedOAuthWatchPort(port) {
			t.Errorf("port %d was rejected", port)
		}
	}
	for _, port := range []int{0, 3000, 32767, 65536} {
		if allowedOAuthWatchPort(port) {
			t.Errorf("port %d was accepted", port)
		}
	}
}
