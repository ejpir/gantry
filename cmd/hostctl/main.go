// hostctl — ttrpc client for the nerdbox guest agent (vminitd) running
// inside a gantry VM. This is the two-terminal/debug tool; for the
// single-command sbx-style flow use `gantry exec` instead.
//
// Usage:
//
//	hostctl info                          — query the guest's system info
//	hostctl shell [flags] [-- CMD ...]    — run a container inside the VM
//
// shell flags:
//
//	--share   bind every virtio-fs share the VMM exported (shares.json)
//	--rw      writable root: overlayfs = /dev/vdb (erofs, ro lower) +
//	          /dev/vdc (ext4 rwlayer with /upper and /work), sbx-style
//	-- CMD    container command (default /bin/sh; try /bin/bash on debian)
//
// Start the VM first:  ./scripts/run-macos.sh container
package main

import (
	"fmt"
	"os"

	"gantry/internal/client"
)

const (
	rpcSock  = "/tmp/gantry-vsock/1025.sock"
	streamSk = "/tmp/gantry-vsock/listen-1026.sock"
)

func main() {
	cmd := "info"
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}
	switch cmd {
	case "info":
		if err := client.Info(rpcSock); err != nil {
			fmt.Fprintf(os.Stderr, "hostctl: %v\n", err)
			os.Exit(1)
		}
	case "shell":
		opts := client.ShellOptions{RPCSock: rpcSock, StreamSock: streamSk}
		for i := 2; i < len(os.Args); i++ {
			switch os.Args[i] {
			case "--share":
				opts.Share = true
			case "--rw":
				opts.RW = true
			case "--":
				if i+1 < len(os.Args) {
					opts.Args = os.Args[i+1:]
				}
				i = len(os.Args)
			default:
				fmt.Fprintf(os.Stderr, "unknown shell option %q (supported: --share, --rw, -- CMD)\n", os.Args[i])
				os.Exit(1)
			}
		}
		if err := client.Shell(opts); err != nil {
			fmt.Fprintf(os.Stderr, "hostctl: %v\n", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q (info|shell)\n", cmd)
		os.Exit(1)
	}
}
