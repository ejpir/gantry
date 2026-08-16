package client

import (
	"strings"

	"github.com/ejpir/gantry/internal/image"
)

// processEnvironment applies in-memory values to an image's environment.
// Later groups win and replace matching names instead of leaving duplicate
// entries whose interpretation differs between libc and application runtimes.
func processEnvironment(img *image.Config, groups ...[]string) []string {
	environment := img.EnvWith("TERM=xterm")
	for _, group := range groups {
		for _, entry := range group {
			name, _, ok := strings.Cut(entry, "=")
			if !ok || name == "" {
				continue
			}
			filtered := environment[:0]
			for _, existing := range environment {
				existingName, _, existingOK := strings.Cut(existing, "=")
				if !existingOK || existingName != name {
					filtered = append(filtered, existing)
				}
			}
			environment = append(filtered, entry)
		}
	}
	return environment
}
