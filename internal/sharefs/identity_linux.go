//go:build linux

package sharefs

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

func identityFromRoot(root *os.File, info os.FileInfo) (Identity, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return Identity{}, fmt.Errorf("stat share root: unexpected metadata %T", info.Sys())
	}
	path, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", root.Fd()))
	if err != nil {
		return Identity{}, fmt.Errorf("resolve pinned share root: %w", err)
	}
	if !filepath.IsAbs(path) || strings.HasSuffix(path, " (deleted)") {
		return Identity{}, fmt.Errorf("resolve pinned share root: unusable path %q", path)
	}
	identity := newIdentity(path, uint64(stat.Dev), stat.Ino, false)
	scope, filesystem, mountedScopes, err := linuxMountScopes(root, path)
	if err != nil {
		return Identity{}, err
	}
	identity.scope = scope
	identity.scopeValid = true
	identity.filesystem = filesystem
	identity.mountedScopes = mountedScopes
	return identity, nil
}

func identifyRoot(path string) (Identity, error) {
	root, identity, err := openRoot(path)
	if root != nil {
		_ = root.Close()
	}
	return identity, err
}

func linuxMountScopes(root *os.File, canonical string) (string, string, []identityScope, error) {
	fdinfo, err := os.ReadFile(fmt.Sprintf("/proc/self/fdinfo/%d", root.Fd()))
	if err != nil {
		return "", "", nil, fmt.Errorf("read pinned share mount identity: %w", err)
	}
	var mountID uint64
	var found bool
	for _, line := range strings.Split(string(fdinfo), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 || fields[0] != "mnt_id:" {
			continue
		}
		mountID, err = strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			return "", "", nil, fmt.Errorf("parse pinned share mount identity: %w", err)
		}
		found = true
		break
	}
	if !found {
		return "", "", nil, fmt.Errorf("pinned share mount identity is unavailable")
	}
	mountInfo, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return "", "", nil, fmt.Errorf("read mount topology: %w", err)
	}
	scope, filesystem, err := linuxMountRootFromInfo(string(mountInfo), mountID, canonical)
	if err != nil {
		return "", "", nil, err
	}
	mountedScopes, err := linuxMountedScopesFromInfo(string(mountInfo), mountID, canonical)
	if err != nil {
		return "", "", nil, err
	}
	return scope, filesystem, mountedScopes, nil
}

func linuxMountScopeFromInfo(mountInfo string, mountID uint64, canonical string) (string, error) {
	scope, _, err := linuxMountRootFromInfo(mountInfo, mountID, canonical)
	return scope, err
}

func linuxMountRootFromInfo(mountInfo string, mountID uint64, canonical string) (string, string, error) {
	for _, line := range strings.Split(mountInfo, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 6 || fields[0] != strconv.FormatUint(mountID, 10) {
			continue
		}
		mountRoot, err := decodeMountInfoPath(fields[3])
		if err != nil {
			return "", "", fmt.Errorf("decode mount root: %w", err)
		}
		mountPoint, err := decodeMountInfoPath(fields[4])
		if err != nil {
			return "", "", fmt.Errorf("decode mount point: %w", err)
		}
		relative, err := filepath.Rel(mountPoint, canonical)
		if err != nil {
			return "", "", fmt.Errorf("resolve path within mount: %w", err)
		}
		if relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return "", "", fmt.Errorf("pinned path %s is outside mount point %s", canonical, mountPoint)
		}
		filesystem, err := linuxMountFilesystem(fields)
		if err != nil {
			return "", "", err
		}
		return filepath.Clean(filepath.Join(mountRoot, relative)), filesystem, nil
	}
	return "", "", fmt.Errorf("mount identity %d is absent from mount topology", mountID)
}

func linuxMountedScopesFromInfo(mountInfo string, rootMountID uint64, canonical string) ([]identityScope, error) {
	var scopes []identityScope
	for _, line := range strings.Split(mountInfo, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		mountID, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("parse mount identity: %w", err)
		}
		if mountID == rootMountID {
			continue
		}
		mountPoint, err := decodeMountInfoPath(fields[4])
		if err != nil {
			return nil, fmt.Errorf("decode mount point: %w", err)
		}
		if !pathChildOf(filepath.Clean(mountPoint), filepath.Clean(canonical), false) {
			continue
		}
		mountRoot, err := decodeMountInfoPath(fields[3])
		if err != nil {
			return nil, fmt.Errorf("decode nested mount root: %w", err)
		}
		volume, err := linuxMountVolume(fields[2])
		if err != nil {
			return nil, err
		}
		filesystem, err := linuxMountFilesystem(fields)
		if err != nil {
			return nil, err
		}
		scopes = append(scopes, identityScope{
			path: filepath.Clean(mountRoot), volume: volume, filesystem: filesystem,
		})
	}
	return scopes, nil
}

func linuxMountFilesystem(fields []string) (string, error) {
	for index := 6; index < len(fields); index++ {
		if fields[index] != "-" {
			continue
		}
		if index+1 >= len(fields) || fields[index+1] == "" {
			break
		}
		return fields[index+1], nil
	}
	return "", fmt.Errorf("mount entry has no filesystem type")
}

func linuxMountVolume(value string) (uint64, error) {
	majorText, minorText, ok := strings.Cut(value, ":")
	if !ok {
		return 0, fmt.Errorf("parse mount device %q", value)
	}
	major, err := strconv.ParseUint(majorText, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("parse mount device major %q: %w", value, err)
	}
	minor, err := strconv.ParseUint(minorText, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("parse mount device minor %q: %w", value, err)
	}
	return unix.Mkdev(uint32(major), uint32(minor)), nil
}

func decodeMountInfoPath(encoded string) (string, error) {
	var decoded strings.Builder
	decoded.Grow(len(encoded))
	for index := 0; index < len(encoded); {
		if encoded[index] != '\\' {
			decoded.WriteByte(encoded[index])
			index++
			continue
		}
		if index+3 >= len(encoded) {
			return "", fmt.Errorf("truncated escape in %q", encoded)
		}
		value := byte(0)
		for offset := 1; offset <= 3; offset++ {
			digit := encoded[index+offset]
			if digit < '0' || digit > '7' {
				return "", fmt.Errorf("invalid escape in %q", encoded)
			}
			value = value*8 + digit - '0'
		}
		decoded.WriteByte(value)
		index += 4
	}
	return decoded.String(), nil
}
