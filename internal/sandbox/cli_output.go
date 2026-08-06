package sandbox

import (
	"io"
	"text/tabwriter"
)

// newCLITable keeps command output aligned consistently across shares, ports,
// and network policies.
func newCLITable(output io.Writer) *tabwriter.Writer {
	return tabwriter.NewWriter(output, 0, 0, 2, ' ', 0)
}
