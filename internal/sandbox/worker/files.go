package worker

import "os"

// CloseFiles closes every non-nil file, ignoring errors. Spawn paths build a
// slice of inheritable handles incrementally and must release whatever they
// managed to open on any failure return.
func CloseFiles(files []*os.File) {
	for _, f := range files {
		if f != nil {
			_ = f.Close()
		}
	}
}
