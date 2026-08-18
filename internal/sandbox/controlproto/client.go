package controlproto

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/ejpir/gantry/internal/sandbox/layout"
)

var controlRequestSequence atomic.Uint64

func Call[Response any](name string, request Request) (Response, error) {
	var response Response
	conn, err := dial(name)
	if err != nil {
		return response, fmt.Errorf("connect to broker: %w", err)
	}
	defer func() { _ = conn.Close() }()
	if err := conn.SetDeadline(time.Now().Add(CallTimeout)); err != nil {
		return response, fmt.Errorf("set broker deadline: %w", err)
	}
	if err := json.NewEncoder(conn).Encode(&request); err != nil {
		return response, fmt.Errorf("send broker request: %w", err)
	}
	line, err := ReadBoundedLine(bufio.NewReader(conn), MaxResponseBytes)
	if err != nil {
		return response, fmt.Errorf("read broker response: %w", err)
	}
	if err := json.Unmarshal(line, &response); err != nil {
		return response, fmt.Errorf("decode broker response: %w", err)
	}
	return response, nil
}

func NewRequestID(kind string) string {
	return fmt.Sprintf("%s-%d-%d", kind, os.Getpid(), controlRequestSequence.Add(1))
}

func dial(name string) (net.Conn, error) {
	path := filepath.Join(layout.Dir(name), "ctl.sock")
	var err error
	for range 20 {
		var conn net.Conn
		conn, err = net.DialTimeout("unix", path, time.Second)
		if err == nil {
			return conn, nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return nil, err
}
