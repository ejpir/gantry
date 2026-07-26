package image

import (
	"fmt"
	"strings"
)

// ref.go — OCI image reference parsing with Docker's normalization
// rules: bare names are docker.io/library, "docker.io" and
// "index.docker.io" are the same entry, default tag is "latest".

// Ref is a parsed image reference.
type Ref struct {
	Registry string // normalized host, e.g. "registry-1.docker.io", "ghcr.io"
	Repo     string // "library/debian", "org/app"
	Tag      string // "" when Digest-pinned
	Digest   string // "sha256:..." when @-pinned
}

// String renders the normalized familiar form.
func (r Ref) String() string {
	name := r.Registry + "/" + r.Repo
	if r.Digest != "" {
		return name + "@" + r.Digest
	}
	return name + ":" + r.Tag
}

// DockerHub is the normalized docker.io endpoint.
const DockerHub = "registry-1.docker.io"

// ParseRef parses s into a Ref. Accepts the docker-familiar forms:
//
//	debian                       → registry-1.docker.io/library/debian:latest
//	debian:bookworm-slim         → registry-1.docker.io/library/debian:bookworm-slim
//	docker.io/user/app           → registry-1.docker.io/user/app:latest
//	ghcr.io/org/app@sha256:...   → ghcr.io/org/app@sha256:...
//	localhost:5000/app:dev       → localhost:5000/app:dev
func ParseRef(s string) (Ref, error) {
	var r Ref
	rest := s
	if i := strings.Index(rest, "@"); i >= 0 {
		r.Digest = rest[i+1:]
		if !strings.HasPrefix(r.Digest, "sha256:") || len(r.Digest) != 71 {
			return r, fmt.Errorf("invalid digest in image reference %q", s)
		}
		rest = rest[:i]
	}
	// tag: the last ":" after the last "/"
	if i := strings.LastIndex(rest, ":"); i >= 0 && !strings.Contains(rest[i:], "/") {
		if r.Digest == "" {
			r.Tag = rest[i+1:]
		}
		rest = rest[:i]
	}
	if rest == "" {
		return r, fmt.Errorf("empty image reference")
	}
	parts := strings.SplitN(rest, "/", 2)
	if len(parts) == 2 && (strings.ContainsAny(parts[0], ".:") || parts[0] == "localhost") {
		r.Registry = parts[0]
		r.Repo = parts[1]
	} else {
		r.Registry = DockerHub
		r.Repo = rest
	}
	if r.Registry == "docker.io" || r.Registry == "index.docker.io" {
		r.Registry = DockerHub
	}
	if !strings.Contains(r.Repo, "/") && r.Registry == DockerHub {
		r.Repo = "library/" + r.Repo
	}
	if r.Tag == "" && r.Digest == "" {
		r.Tag = "latest"
	}
	for _, seg := range strings.Split(r.Repo, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return r, fmt.Errorf("invalid repository name in %q", s)
		}
	}
	return r, nil
}

// registryKey normalizes a registry name for credential lookup: all
// docker.io spellings (and its legacy index URL) map to one key.
func registryKey(reg string) string {
	switch reg {
	case "docker.io", "index.docker.io", DockerHub, "https://index.docker.io/v1/", "http://index.docker.io/v1/":
		return DockerHub
	}
	return strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(reg, "https://"), "http://"), "/")
}

// isLoopbackRegistry reports whether the registry is a loopback address —
// the one case where plain HTTP (and credentials over it) is acceptable,
// matching Docker's own insecure exception.
func isLoopbackRegistry(reg string) bool {
	host, _, _ := strings.Cut(reg, ":")
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}
