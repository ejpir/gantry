package main

import (
	"fmt"
	"io"
)

// readLineBounded reads one '\n'-terminated line, refusing more than max
// bytes. Local to the guest so cmd/gantry-guest needs no controlproto
// import (which would drag in the control plane's dependency tree).
func readLineBounded(r io.Reader, max int) ([]byte, error) {
	var line []byte
	buf := make([]byte, 512)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			chunk := buf[:n]
			for i, b := range chunk {
				if b == '\n' {
					return append(line, chunk[:i]...), nil
				}
			}
			line = append(line, chunk...)
			if len(line) > max {
				return nil, fmt.Errorf("response exceeds %d bytes", max)
			}
		}
		if err != nil {
			return line, err
		}
	}
}
