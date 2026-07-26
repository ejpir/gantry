// Package image loads OCI images into flattened EROFS disks and keeps
// the image config (env, entrypoint, user, workdir) that used to be
// thrown away. The build is pure Go (github.com/erofs/go-erofs): no
// mkfs.erofs, no Linux requirement, no privileges — ownership comes from
// tar metadata, never from host syscalls. See docs/oci-images.md.
package image

import (
	"fmt"
	"strconv"
	"strings"
)

// Config is the part of the OCI image config that affects how we run it.
type Config struct {
	Env        []string `json:"env,omitempty"`
	Entrypoint []string `json:"entrypoint,omitempty"`
	Cmd        []string `json:"cmd,omitempty"`
	User       string   `json:"user,omitempty"` // as written in the image
	UID        uint32   `json:"uid"`            // resolved at build time
	GID        uint32   `json:"gid"`            // resolved at build time
	WorkingDir string   `json:"workingDir,omitempty"`
}

// ociConfig mirrors the OCI image config JSON (the fields we read).
type ociConfig struct {
	Architecture string `json:"architecture"`
	OS           string `json:"os"`
	Config       struct {
		Env        []string `json:"Env"`
		Entrypoint []string `json:"Entrypoint"`
		Cmd        []string `json:"Cmd"`
		User       string   `json:"User"`
		WorkingDir string   `json:"WorkingDir"`
	} `json:"config"`
}

// Command returns the effective process args for a session:
// explicit args > Entrypoint+Cmd > nil (caller falls back to a shell).
func (c *Config) Command(args []string) []string {
	if len(args) > 0 {
		return args
	}
	if c == nil {
		return nil
	}
	return append(append([]string{}, c.Entrypoint...), c.Cmd...)
}

// EnvWith returns the image env with gantry's defaults appended for the
// variables the image does not set (defaults-if-absent, per the design
// doc's precedence table). extra entries (e.g. TERM, PS1) win over the
// built-in fallbacks but never over the image.
func (c *Config) EnvWith(extra ...string) []string {
	base := []string{
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"HOME=/root",
	}
	if c != nil && c.UID != 0 {
		base[1] = "HOME=/"
	}
	base = append(base, extra...)
	if c == nil {
		return base
	}
	out := append([]string{}, c.Env...)
	set := map[string]bool{}
	for _, e := range c.Env {
		if k, _, ok := strings.Cut(e, "="); ok {
			set[k] = true
		}
	}
	for _, d := range base {
		if k, _, ok := strings.Cut(d, "="); ok && set[k] {
			continue
		}
		out = append(out, d)
	}
	return out
}

// WorkdirOr returns the image working dir, default "/".
func (c *Config) WorkdirOr() string {
	if c != nil && c.WorkingDir != "" {
		return c.WorkingDir
	}
	return "/"
}

// IDs returns the resolved uid/gid (default 0:0).
func (c *Config) IDs() (uint32, uint32) {
	if c == nil {
		return 0, 0
	}
	return c.UID, c.GID
}

// resolveUser resolves the image's User field (name, uid, user:group —
// the docker forms) against the merged /etc/passwd and /etc/group read
// at build time. Empty or unresolvable users fall back to 0:0 (docker
// errors on an unknown user; for a dev tool, root-with-a-warning via the
// caller's log is the kinder default).
func resolveUser(user, passwd, group string) (uid, gid uint32, err error) {
	if user == "" {
		return 0, 0, nil
	}
	u, g, hasG := strings.Cut(user, ":")
	isNum := func(s string) bool {
		_, err := strconv.ParseUint(s, 10, 32)
		return err == nil
	}
	toID := func(s string) uint32 {
		n, _ := strconv.ParseUint(s, 10, 32)
		return uint32(n)
	}
	if isNum(u) {
		uid = toID(u)
		gid = uid
		if hasG {
			if isNum(g) {
				return uid, toID(g), nil
			}
			if id, ok := lookupGroup(group, g); ok {
				return uid, id, nil
			}
			return 0, 0, fmt.Errorf("image user %q: group %q not found", user, g)
		}
		return uid, gid, nil
	}
	pwUID, pwGID, ok := lookupPasswd(passwd, u)
	if !ok {
		return 0, 0, fmt.Errorf("image user %q not found in /etc/passwd", user)
	}
	uid, gid = pwUID, pwGID
	if hasG {
		if isNum(g) {
			gid = toID(g)
		} else if id, ok := lookupGroup(group, g); ok {
			gid = id
		} else {
			return 0, 0, fmt.Errorf("image user %q: group %q not found", user, g)
		}
	}
	return uid, gid, nil
}

// lookupPasswd finds a name in passwd-file content: name:x:uid:gid:...
func lookupPasswd(passwd, name string) (uid, gid uint32, ok bool) {
	for _, line := range strings.Split(passwd, "\n") {
		f := strings.Split(line, ":")
		if len(f) >= 4 && f[0] == name {
			u, err1 := strconv.ParseUint(f[2], 10, 32)
			g, err2 := strconv.ParseUint(f[3], 10, 32)
			if err1 == nil && err2 == nil {
				return uint32(u), uint32(g), true
			}
		}
	}
	return 0, 0, false
}

// lookupGroup finds a name in group-file content: name:x:gid:...
func lookupGroup(group, name string) (uint32, bool) {
	for _, line := range strings.Split(group, "\n") {
		f := strings.Split(line, ":")
		if len(f) >= 3 && f[0] == name {
			if g, err := strconv.ParseUint(f[2], 10, 32); err == nil {
				return uint32(g), true
			}
		}
	}
	return 0, false
}
