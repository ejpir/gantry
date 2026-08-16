package client

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

const (
	maxStreamHandshakeString = 4 << 10
	streamHandshakeTimeout   = 10 * time.Second
)

// startStream connects to the guest streaming service through its Unix
// forwarding socket and claims id.
func startStream(streamSock, id string) (net.Conn, error) {
	return dialStream(func() (net.Conn, error) {
		return net.DialTimeout("unix", streamSock, 30*time.Second)
	}, id)
}

// startStream uses the split-worker bridge when configured and otherwise the
// session's Unix forwarding socket.
func (options SessionOptions) startStream(id string) (net.Conn, error) {
	if options.StreamDial != nil {
		return dialStream(options.StreamDial, id)
	}
	return startStream(options.StreamSock, id)
}

// dialStream performs nerdbox's length-prefixed stream-ID handshake. One
// reusable packet backs the write and acknowledgement, keeping the common path
// to one allocation and one write syscall. The bounded acknowledgement prevents
// a malformed guest from choosing a host allocation size.
func dialStream(dial func() (net.Conn, error), id string) (net.Conn, error) {
	if len(id) == 0 || len(id) > maxStreamHandshakeString-4 {
		return nil, fmt.Errorf("stream ID length %d out of bounds", len(id))
	}
	conn, err := dial()
	if err != nil {
		return nil, err
	}
	if err := claimStream(conn, id); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

func claimStream(conn net.Conn, id string) error {
	return claimStreamWithTimeout(conn, id, streamHandshakeTimeout)
}

func claimStreamWithTimeout(conn net.Conn, id string, timeout time.Duration) (resultErr error) {
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return fmt.Errorf("stream %s: set handshake deadline: %w", id, err)
	}
	defer func() {
		if err := conn.SetDeadline(time.Time{}); err != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("stream %s: clear handshake deadline: %w", id, err))
		}
	}()
	packet := make([]byte, 4+len(id))
	binary.BigEndian.PutUint32(packet[:4], uint32(len(id)))
	copy(packet[4:], id)
	written, err := conn.Write(packet)
	if err != nil {
		return err
	}
	if written != len(packet) {
		return io.ErrShortWrite
	}

	if _, err := io.ReadFull(conn, packet[:4]); err != nil {
		return fmt.Errorf("stream %s: ack: %w", id, err)
	}
	ackLen := int(binary.BigEndian.Uint32(packet[:4]))
	if ackLen == 0 || ackLen > maxStreamHandshakeString {
		return fmt.Errorf("stream %s: ack length %d out of bounds", id, ackLen)
	}
	if cap(packet) < ackLen {
		packet = make([]byte, ackLen)
	} else {
		packet = packet[:ackLen]
	}
	if _, err := io.ReadFull(conn, packet); err != nil {
		return fmt.Errorf("stream %s: ack body: %w", id, err)
	}
	if !bytes.Equal(packet, []byte(id)) {
		return fmt.Errorf("stream %s: rejected: %s", id, packet)
	}
	return nil
}

func streamID(prefix string) (string, error) {
	var entropy [4]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		return "", fmt.Errorf("generate stream ID: %w", err)
	}
	return fmt.Sprintf("%s-%s", prefix, base64.RawURLEncoding.EncodeToString(entropy[:])), nil
}

type sessionStream struct {
	id   string
	conn net.Conn
}

type sessionStreams struct {
	stdin  sessionStream
	stdout sessionStream
}

func (options SessionOptions) openStreams() (*sessionStreams, error) {
	open := func(prefix string) (sessionStream, error) {
		id, err := streamID(prefix)
		if err != nil {
			return sessionStream{}, err
		}
		conn, err := options.startStream(id)
		return sessionStream{id: id, conn: conn}, err
	}
	stdin, err := open("stdin")
	if err != nil {
		return nil, fmt.Errorf("stdin stream: %w", err)
	}
	stdout, err := open("stdout")
	if err != nil {
		_ = stdin.conn.Close()
		return nil, fmt.Errorf("stdout stream: %w", err)
	}
	return &sessionStreams{stdin: stdin, stdout: stdout}, nil
}

func (streams *sessionStreams) close() {
	_ = streams.stdin.conn.Close()
	_ = streams.stdout.conn.Close()
}

func (streams *sessionStreams) relayInput(stdin io.Reader) {
	go func() {
		_, _ = io.Copy(streams.stdin.conn, stdin)
		// stdin is a dedicated one-way stream. Closing it after the source
		// reaches EOF is the protocol's EOF signal to the guest process. Merely
		// returning from io.Copy leaves readers such as cat blocked until the
		// whole session is torn down, which in turn waits for that process.
		_ = streams.stdin.conn.Close()
	}()
}

func (streams *sessionStreams) relayOutput(stdout io.Writer) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(stdout, streams.stdout.conn)
		close(done)
	}()
	return done
}

func awaitOutput(done <-chan struct{}) {
	select {
	case <-done:
	case <-time.After(2 * time.Second):
	}
}

// watchKill scopes a kill watcher to one session. stop must be called before
// the session returns so a never-fired signal cannot retain the goroutine.
func watchKill(signal <-chan struct{}, kill func()) (stop func()) {
	if signal == nil {
		return func() {}
	}
	done := make(chan struct{})
	var once sync.Once
	go func() {
		select {
		case <-signal:
			kill()
		case <-done:
		}
	}()
	return func() { once.Do(func() { close(done) }) }
}
