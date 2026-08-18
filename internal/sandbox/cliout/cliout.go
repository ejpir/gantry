// Package cliout holds the presentation policy shared by gantry's
// command output. Shares, ports, network policies and imports all print
// tables; keeping the writer construction here is what makes their columns
// line up with each other.
package cliout

import (
	"io"
	"text/tabwriter"
)

// Table returns the writer every gantry command formats its rows through.
func Table(output io.Writer) *tabwriter.Writer {
	return tabwriter.NewWriter(output, 0, 0, 2, ' ', 0)
}
