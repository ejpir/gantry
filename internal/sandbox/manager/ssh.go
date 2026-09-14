package manager

import (
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

const sshUpgrade = "gantry-ssh"

func (m *managerService) handleSSHHostKey(w http.ResponseWriter, _ *http.Request) {
	service, ok := m.lifecycle.(SSHService)
	if !ok {
		writeManagerError(w, http.StatusNotImplemented, errors.New("SSH service unavailable"), "")
		return
	}
	key, err := service.SSHHostKey()
	if err != nil {
		writeManagerError(w, http.StatusInternalServerError, err, "")
		return
	}
	writeManagerJSON(w, http.StatusOK, key)
}

func hasUpgrade(header string) bool {
	for _, token := range strings.Split(header, ",") {
		if strings.EqualFold(strings.TrimSpace(token), "upgrade") {
			return true
		}
	}
	return false
}

// handleSSH admits and validates before the protocol switch. The stream goes
// through the existing gateway (session limits and channel policy unchanged),
// with a separate manager-wide budget for long-lived tunnels.
func (m *managerService) handleSSH(w http.ResponseWriter, r *http.Request) {
	name, ok := managerSandboxName(w, r)
	if !ok {
		return
	}
	if r.ProtoMajor != 1 || !hasUpgrade(r.Header.Get("Connection")) || r.Header.Get("Upgrade") != sshUpgrade || r.ContentLength != 0 {
		writeManagerError(w, http.StatusBadRequest, errors.New("SSH requires a bodyless HTTP/1.1 gantry-ssh upgrade"), "")
		return
	}
	service, ok := m.lifecycle.(SSHService)
	if !ok {
		writeManagerError(w, http.StatusNotImplemented, errors.New("SSH service unavailable"), "")
		return
	}
	if !tryAcquireSlot(m.sshSlots) {
		writeManagerError(w, http.StatusServiceUnavailable, errors.New("too many SSH tunnels"), "")
		return
	}
	defer releaseSlot(m.sshSlots)
	lock := m.sandboxLock(name)
	lock.RLock()
	guest, err := service.DialSSH(r.Context(), name)
	lock.RUnlock()
	if err != nil {
		status := http.StatusConflict
		if errors.Is(err, os.ErrNotExist) {
			status = http.StatusNotFound
		}
		writeManagerError(w, status, err, "")
		return
	}
	defer func() { _ = guest.Close() }()
	conn, buffered, err := http.NewResponseController(w).Hijack()
	if err != nil {
		return
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(readHeaderTimeout))
	if _, err := buffered.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: gantry-ssh\r\n\r\n"); err != nil {
		return
	}
	if err := buffered.Flush(); err != nil {
		return
	}
	_ = conn.SetDeadline(time.Time{})
	// Read from the hijacked buffer, not directly from the connection: an
	// eager SSH client may have pipelined its identification after headers.
	inputDone := make(chan struct{})
	go func() {
		defer close(inputDone)
		_, _ = io.Copy(guest, buffered)
		if half, ok := guest.(interface{ CloseWrite() error }); ok {
			_ = half.CloseWrite()
		}
	}()
	outputDone := make(chan struct{})
	go func() { defer close(outputDone); _, _ = io.Copy(conn, guest) }()
	select {
	case <-outputDone:
	case <-r.Context().Done():
	case <-m.context.Done():
	}
	_ = conn.Close()
	_ = guest.Close()
	<-inputDone
	<-outputDone
}
