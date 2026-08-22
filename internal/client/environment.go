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

// prependPath returns environment with dirs prepended to the PATH entry
// (image PATH preserved). A missing PATH gains the conventional default
// tail so the prepend never yields a bare tools-only PATH.
func prependPath(environment []string, dirs []string) []string {
	if len(dirs) == 0 {
		return environment
	}
	prefix := strings.Join(dirs, ":")
	for i, entry := range environment {
		if name, _, ok := strings.Cut(entry, "="); ok && name == "PATH" {
			out := make([]string, len(environment))
			copy(out, environment)
			out[i] = "PATH=" + prefix + ":" + strings.TrimPrefix(entry, "PATH=")
			return out
		}
	}
	return append(environment, "PATH="+prefix+":/usr/local/bin:/usr/bin:/bin")
}
