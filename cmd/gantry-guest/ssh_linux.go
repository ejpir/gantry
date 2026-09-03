//go:build linux

package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/ejpir/gantry/internal/sshpolicy"
	"github.com/pkg/sftp"
)

type guestUser struct {
	Name  string
	UID   int
	GID   int
	Home  string
	Shell string
}

// lookupGuestUser deliberately parses the guest's files in our static binary;
// images do not need getent, NSS libraries, or even a shell for verification.
func lookupGuestUser(name string) (guestUser, error) {
	file, err := os.Open("/etc/passwd")
	if err != nil {
		return guestUser{}, err
	}
	defer func() { _ = file.Close() }()
	numericUID, numericErr := strconv.ParseUint(name, 10, 32)
	scanner := bufio.NewScanner(io.LimitReader(file, 4<<20))
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), ":")
		if len(fields) < 7 {
			continue
		}
		uid, uidErr := strconv.ParseUint(fields[2], 10, 32)
		gid, gidErr := strconv.ParseUint(fields[3], 10, 32)
		if uidErr != nil || gidErr != nil {
			continue
		}
		if fields[0] != name && (numericErr != nil || uid != numericUID) {
			continue
		}
		shell := fields[6]
		if shell == "" {
			shell = "/bin/sh"
		}
		home := fields[5]
		if home == "" {
			home = "/"
		}
		return guestUser{Name: fields[0], UID: int(uid), GID: int(gid), Home: home, Shell: shell}, nil
	}
	if err := scanner.Err(); err != nil {
		return guestUser{}, err
	}
	return guestUser{}, errors.New("user not found")
}

func supplementaryGroups(user guestUser) []int {
	file, err := os.Open("/etc/group")
	if err != nil {
		return nil
	}
	defer func() { _ = file.Close() }()
	return parseSupplementaryGroups(file, user)
}

func parseSupplementaryGroups(reader io.Reader, user guestUser) []int {
	seen := map[int]bool{user.GID: true}
	var groups []int
	scanner := bufio.NewScanner(io.LimitReader(reader, 4<<20))
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), ":")
		if len(fields) < 4 {
			continue
		}
		// Linux gid_t is uint32, matching the passwd parser above. Using 31
		// bits here silently discarded valid supplementary groups >= 2^31.
		gid, err := strconv.ParseUint(fields[2], 10, 32)
		if err != nil || seen[int(gid)] {
			continue
		}
		for _, member := range strings.Split(fields[3], ",") {
			if member == user.Name {
				seen[int(gid)] = true
				groups = append(groups, int(gid))
				break
			}
		}
	}
	return groups
}

func assumeGuestUser(user guestUser) error {
	if os.Geteuid() == 0 {
		if err := syscall.Setgroups(supplementaryGroups(user)); err != nil {
			return err
		}
		if err := syscall.Setgid(user.GID); err != nil {
			return err
		}
		if err := syscall.Setuid(user.UID); err != nil {
			return err
		}
	} else if os.Geteuid() != user.UID || os.Getegid() != user.GID {
		return errors.New("cannot assume requested identity")
	}
	if os.Geteuid() != user.UID {
		return errors.New("identity change did not take effect")
	}
	return nil
}

func prepareSSHUser(name string) (guestUser, error) {
	user, err := lookupGuestUser(name)
	if err != nil {
		return guestUser{}, err
	}
	if err := os.Chdir(user.Home); err != nil {
		return guestUser{}, err
	}
	_ = os.Setenv("HOME", user.Home)
	_ = os.Setenv("USER", user.Name)
	_ = os.Setenv("LOGNAME", user.Name)
	_ = os.Setenv("SHELL", user.Shell)
	if err := assumeGuestUser(user); err != nil {
		return guestUser{}, err
	}
	return user, nil
}

func runUserExists(args []string) int {
	if len(args) != 1 {
		return 2
	}
	if _, err := lookupGuestUser(args[0]); err != nil {
		return 1
	}
	return 0
}

func runSSHSession(args []string) int {
	refuse := func(err error) int {
		debugf("ssh session refusal: %v", err)
		fmt.Fprintln(os.Stderr, "ssh session refused")
		return 1
	}
	if len(args) < 2 {
		return refuse(errors.New("missing user or mode"))
	}
	user, err := prepareSSHUser(args[0])
	if err != nil {
		return refuse(err)
	}
	switch args[1] {
	case "shell":
		if len(args) != 2 {
			return refuse(errors.New("bad shell request"))
		}
		shellName := user.Shell[strings.LastIndex(user.Shell, "/")+1:]
		if err := syscall.Exec(user.Shell, []string{"-" + shellName}, os.Environ()); err != nil {
			return refuse(err)
		}
	case "exec":
		if len(args) != 3 {
			return refuse(errors.New("bad exec request"))
		}
		if err := syscall.Exec(user.Shell, []string{user.Shell, "-c", args[2]}, os.Environ()); err != nil {
			return refuse(err)
		}
	case "sftp":
		if len(args) != 2 {
			return refuse(errors.New("bad sftp request"))
		}
		if err := serveSFTP(); err != nil && !errors.Is(err, io.EOF) {
			return refuse(err)
		}
		return 0
	case "tcp":
		if len(args) != 4 {
			return refuse(errors.New("bad tcp relay request"))
		}
		return runTCPRelay(args[2:])
	default:
		return refuse(errors.New("unknown session mode"))
	}
	return 0
}

type stdioReadWriteCloser struct{}

func (stdioReadWriteCloser) Read(p []byte) (int, error)  { return os.Stdin.Read(p) }
func (stdioReadWriteCloser) Write(p []byte) (int, error) { return os.Stdout.Write(p) }
func (stdioReadWriteCloser) Close() error                { return nil }

func serveSFTP() error {
	server, err := sftp.NewServer(stdioReadWriteCloser{})
	if err != nil {
		return err
	}
	defer func() { _ = server.Close() }()
	return server.Serve()
}

func runTCPRelay(args []string) int {
	if len(args) != 2 {
		fmt.Fprintln(os.Stderr, "tcp-relay requires HOST PORT")
		return 2
	}
	port, err := strconv.ParseUint(args[1], 10, 16)
	if err != nil || !sshpolicy.ExactLoopbackTarget(args[0], port) {
		fmt.Fprintln(os.Stderr, "tcp-relay target refused")
		return 1
	}
	ip := net.ParseIP(args[0]) // validated by ExactLoopbackTarget
	address := net.JoinHostPort(ip.String(), strconv.FormatUint(port, 10))
	conn, err := net.DialTimeout("tcp", address, 10*time.Second)
	if err != nil {
		debugf("tcp-relay dial: %v", err)
		return 1
	}
	defer func() { _ = conn.Close() }()
	done := make(chan struct{}, 1)
	go func() {
		_, _ = io.Copy(conn, os.Stdin)
		// stdin EOF is an SSH channel half-close: preserve target responses by
		// closing only its write side. A full SSH channel close is distinguished
		// by the host gateway and cancels this guest task.
		if tcp, ok := conn.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
		done <- struct{}{}
	}()
	_, _ = io.Copy(os.Stdout, conn)
	select {
	case <-done:
	default:
	}
	return 0
}
