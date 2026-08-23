package main

// mcp.go — guest side of the MCP gateway (docs/mcp-gateway.md).
//
//   mcp-proxy                    agent-facing stdio proxy: pumps MCP
//                                (newline-delimited JSON-RPC) between the
//                                agent's stdio and the host gateway over
//                                vsock port 1029.
//   mcp-serve filesystem         a minimal, contained filesystem MCP
//                                server. Spawned by the host gateway
//                                through the daemon's exec channel; drops
//                                to an unprivileged user before reading a
//                                byte of input and serves only within an
//                                os.Root jail.
//
// Security notes:
//   - the fs server refuses to run as root — the gateway names a user and
//     the drop happens before any request is served;
//   - all file access goes through os.OpenRoot, which resolves symlinks
//     inside the root and refuses escapes (race-free containment);
//   - responses are capped (1 MiB files, 1024 directory entries) and
//     binary files are refused.

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/ejpir/gantry/internal/sandbox/mcpgw/mcpproto"
)

// --- mcp-proxy -----------------------------------------------------------

// proxyGraceAfterStdinEOF bounds how long mcp-proxy waits for late
// responses after the agent closes its stdin before exiting.
const proxyGraceAfterStdinEOF = 30 * time.Second

func runMCPProxy() int {
	conn, err := dialVsockFile(mcpproto.VsockPort, 0)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gantry-guest mcp-proxy: %v\n", err)
		return 1
	}
	proxyMCP(conn, os.Stdin, os.Stdout, proxyGraceAfterStdinEOF)
	return 0
}

func proxyMCP(conn io.ReadWriteCloser, stdin io.Reader, stdout io.Writer, grace time.Duration) {
	defer interruptMCPConn(conn)
	tracker := newMCPProxyTracker()
	inputObserver := newMCPLineObserver(tracker.observeRequest)
	outputObserver := newMCPLineObserver(tracker.observeResponse)

	// Agent → gateway. Do not half-close AF_VSOCK here: the VMM's stream
	// bridge can observe the FIN before forwarding data already queued behind
	// the first frame. Instead, retain the connection until every trackable
	// request has received its response. Malformed/non-JSON input falls back to
	// the bounded grace period because its completion cannot be correlated.
	go func() {
		_, _ = io.Copy(conn, io.TeeReader(stdin, inputObserver))
		inputObserver.finish()
		tracker.finishInput()
		tracker.wait(grace)
		interruptMCPConn(conn)
	}()

	// Gateway → agent: observe only bytes successfully written to stdout, then
	// release the connection as soon as stdin is closed and no request IDs are
	// outstanding. interruptMCPConn uses shutdown(2) for raw AF_VSOCK files so
	// a blocked Read is actually woken rather than retaining the exec forever.
	_, _ = io.Copy(io.MultiWriter(stdout, outputObserver), conn)
	outputObserver.finish()
}

type mcpProxyTracker struct {
	mu          sync.Mutex
	pending     map[string]int
	inputDone   bool
	trackedIDs  bool
	untrackable bool
	complete    chan struct{}
	completeOne sync.Once
}

func newMCPProxyTracker() *mcpProxyTracker {
	return &mcpProxyTracker{pending: make(map[string]int), complete: make(chan struct{})}
}

func (tracker *mcpProxyTracker) observeRequest(line []byte) {
	var message struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Method  string          `json:"method"`
	}
	if json.Unmarshal(line, &message) != nil || message.JSONRPC != "2.0" || message.Method == "" {
		tracker.markUntrackable()
		return
	}
	key, hasID := mcpProxyIDKey(message.ID)
	if !hasID {
		return
	}
	tracker.mu.Lock()
	tracker.trackedIDs = true
	tracker.pending[key]++
	tracker.mu.Unlock()
}

func (tracker *mcpProxyTracker) observeResponse(line []byte) {
	var message struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
	}
	if json.Unmarshal(line, &message) != nil || message.JSONRPC != "2.0" {
		return
	}
	key, hasID := mcpProxyIDKey(message.ID)
	if !hasID {
		return
	}
	tracker.mu.Lock()
	if count := tracker.pending[key]; count > 1 {
		tracker.pending[key] = count - 1
	} else if count == 1 {
		delete(tracker.pending, key)
	}
	tracker.checkCompleteLocked()
	tracker.mu.Unlock()
}

func (tracker *mcpProxyTracker) markUntrackable() {
	tracker.mu.Lock()
	tracker.untrackable = true
	tracker.mu.Unlock()
}

func (tracker *mcpProxyTracker) finishInput() {
	tracker.mu.Lock()
	tracker.inputDone = true
	tracker.checkCompleteLocked()
	tracker.mu.Unlock()
}

func (tracker *mcpProxyTracker) checkCompleteLocked() {
	if tracker.inputDone && tracker.trackedIDs && !tracker.untrackable && len(tracker.pending) == 0 {
		tracker.completeOne.Do(func() { close(tracker.complete) })
	}
}

func (tracker *mcpProxyTracker) wait(grace time.Duration) {
	if grace <= 0 {
		grace = proxyGraceAfterStdinEOF
	}
	timer := time.NewTimer(grace)
	defer timer.Stop()
	select {
	case <-tracker.complete:
	case <-timer.C:
	}
}

func mcpProxyIDKey(raw json.RawMessage) (string, bool) {
	if len(raw) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return "", false
	}
	var value any
	if json.Unmarshal(raw, &value) != nil {
		return "", false
	}
	canonical, err := json.Marshal(value)
	if err != nil {
		return "", false
	}
	return string(canonical), true
}

type mcpLineObserver struct {
	line     []byte
	overflow bool
	observe  func([]byte)
}

func newMCPLineObserver(observe func([]byte)) *mcpLineObserver {
	return &mcpLineObserver{observe: observe}
}

func (observer *mcpLineObserver) Write(data []byte) (int, error) {
	written := len(data)
	for len(data) != 0 {
		newline := bytes.IndexByte(data, '\n')
		part := data
		if newline >= 0 {
			part = data[:newline]
		}
		if !observer.overflow {
			if len(observer.line)+len(part) > mcpproto.MaxFrameBytes {
				observer.line = nil
				observer.overflow = true
			} else {
				observer.line = append(observer.line, part...)
			}
		}
		if newline < 0 {
			break
		}
		observer.emit()
		data = data[newline+1:]
	}
	return written, nil
}

func (observer *mcpLineObserver) finish() {
	if observer.overflow || len(observer.line) != 0 {
		observer.emit()
	}
}

func (observer *mcpLineObserver) emit() {
	if observer.overflow {
		observer.observe(nil)
	} else if line := bytes.TrimRight(observer.line, "\r"); len(line) != 0 {
		observer.observe(line)
	}
	observer.line = nil
	observer.overflow = false
}

// --- mcp-serve filesystem ------------------------------------------------

const (
	fsMaxFileBytes  = mcpproto.MaxFrameBytes / 2 // well under the frame cap after JSON encoding
	fsMaxDirEntries = 1024
	fsProtocolVer   = "2025-06-18"
	fsServerName    = "gantry-guest-fs"
	fsServerVersion = "1.0.0"
)

func runMCPServe(args []string) int {
	// Positional kind first: mcp-serve filesystem --root ... --user ...
	// (stdlib flag parsing stops at the first non-flag argument).
	kind := "filesystem"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		kind, args = args[0], args[1:]
	}
	fs := flag.NewFlagSet("mcp-serve", flag.ContinueOnError)
	root := fs.String("root", "/", "directory the filesystem server is jailed to")
	userName := fs.String("user", "", "unprivileged user to drop to before serving (required)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if kind != "filesystem" {
		fmt.Fprintf(os.Stderr, "gantry-guest mcp-serve: unknown server kind %q\n", kind)
		return 2
	}
	if err := dropToUser(*userName); err != nil {
		fmt.Fprintf(os.Stderr, "gantry-guest mcp-serve: %v\n", err)
		return 1
	}
	jail, err := os.OpenRoot(*root)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gantry-guest mcp-serve: open root %s: %v\n", *root, err)
		return 1
	}
	defer func() { _ = jail.Close() }()
	if err := serveFS(jail, *root, os.Stdin, os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "gantry-guest mcp-serve: %v\n", err)
		return 1
	}
	return 0
}

// --- the filesystem server proper -----------------------------------------

type fsRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

var fsTools = []map[string]any{
	{
		"name":        "read_file",
		"description": "Read a UTF-8 text file inside the sandbox workspace.",
		"inputSchema": map[string]any{
			"type":       "object",
			"properties": map[string]any{"path": map[string]any{"type": "string", "description": "absolute path inside the server root"}},
			"required":   []string{"path"},
		},
	},
	{
		"name":        "list_directory",
		"description": "List entries of a directory inside the sandbox workspace.",
		"inputSchema": map[string]any{
			"type":       "object",
			"properties": map[string]any{"path": map[string]any{"type": "string", "description": "absolute directory path inside the server root"}},
			"required":   []string{"path"},
		},
	},
}

// serveFS runs the JSON-RPC loop: one NDJSON request per line on in,
// responses on out. Requests arriving after in closes end the loop.
// rootPath is the jail's absolute path, used for the lexical prefix check
// (os.Root is the race-free backstop).
//
// Reads go through a bufio.Reader: agents pipeline requests, and an
// unbuffered readLineBounded-style read would DISCARD bytes past the
// first newline in each chunk (eating every second request).
func serveFS(jail *os.Root, rootPath string, in io.Reader, out io.Writer) error {
	r := bufio.NewReaderSize(in, 64*1024)
	for {
		line, err := readLineBuffered(r, mcpproto.MaxFrameBytes)
		if len(line) > 0 {
			if resp := handleFSFrame(jail, rootPath, line); resp != nil {
				if _, werr := out.Write(append(resp, '\n')); werr != nil {
					return werr
				}
			}
		}
		if err != nil {
			return nil // EOF (possibly after a final unterminated line)
		}
	}
}

// readLineBuffered reads one '\n'-terminated line from a buffered reader,
// refusing more than max bytes. A trailing unterminated line is returned
// with io.EOF so the caller can serve it before ending.
func readLineBuffered(r *bufio.Reader, max int) ([]byte, error) {
	var line []byte
	for {
		frag, err := r.ReadSlice('\n')
		line = append(line, frag...)
		if len(line) > max {
			return nil, fmt.Errorf("frame exceeds %d bytes", max)
		}
		if err == bufio.ErrBufferFull {
			continue
		}
		if err == io.EOF && len(line) > 0 {
			return bytes.TrimRight(line, "\r\n"), io.EOF
		}
		if err != nil {
			return nil, err
		}
		return bytes.TrimRight(line, "\r\n"), nil
	}
}

// handleFSFrame answers one request; nil means "notification, no answer".
func handleFSFrame(jail *os.Root, rootPath string, line []byte) []byte {
	var req fsRequest
	if err := json.Unmarshal(line, &req); err != nil {
		return fsReply(nil, nil, &rpcErr{code: -32700, msg: "malformed JSON-RPC frame"})
	}
	if len(req.ID) == 0 {
		return nil // notification
	}
	switch req.Method {
	case "initialize":
		return fsReply(req.ID, map[string]any{
			"protocolVersion": fsProtocolVer,
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo":      map[string]any{"name": fsServerName, "version": fsServerVersion},
		}, nil)
	case "ping":
		return fsReply(req.ID, map[string]any{}, nil)
	case "tools/list":
		return fsReply(req.ID, map[string]any{"tools": fsTools}, nil)
	case "tools/call":
		return fsReply(req.ID, fsToolCall(jail, rootPath, req.Params), nil)
	default:
		return fsReply(req.ID, nil, &rpcErr{code: -32601, msg: "method not found"})
	}
}

type rpcErr struct {
	code int
	msg  string
}

func fsReply(id json.RawMessage, result any, rerr *rpcErr) []byte {
	resp := map[string]any{"jsonrpc": "2.0", "id": id}
	if rerr != nil {
		resp["error"] = map[string]any{"code": rerr.code, "message": rerr.msg}
	} else {
		resp["result"] = result
	}
	raw, err := json.Marshal(resp)
	if err != nil {
		return nil
	}
	if len(raw) <= mcpproto.MaxFrameBytes {
		return raw
	}
	// JSON escaping can expand an otherwise capped text file (for example,
	// control bytes become six-byte \u00XX sequences). Return a bounded error
	// instead of emitting an oversized frame that makes the gateway kill this
	// upstream session.
	resp = map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"error":   map[string]any{"code": -32603, "message": "filesystem response exceeds the MCP frame limit"},
	}
	raw, err = json.Marshal(resp)
	if err == nil && len(raw) <= mcpproto.MaxFrameBytes {
		return raw
	}
	return []byte(`{"jsonrpc":"2.0","id":null,"error":{"code":-32603,"message":"filesystem response exceeds the MCP frame limit"}}`)
}

// fsToolCall executes read_file / list_directory and wraps the outcome in
// an MCP tool result (errors are isError results, not JSON-RPC errors, so
// the agent sees them as tool feedback).
func fsToolCall(jail *os.Root, rootPath string, params json.RawMessage) map[string]any {
	var p struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return fsToolError("malformed tools/call params")
	}
	var args struct {
		Path string `json:"path"`
	}
	if len(p.Arguments) > 0 {
		if err := json.Unmarshal(p.Arguments, &args); err != nil {
			return fsToolError("malformed arguments")
		}
	}
	switch p.Name {
	case "read_file":
		text, err := fsReadFile(jail, rootPath, args.Path)
		if err != nil {
			return fsToolError(err.Error())
		}
		return fsToolText(text)
	case "list_directory":
		text, err := fsListDir(jail, rootPath, args.Path)
		if err != nil {
			return fsToolError(err.Error())
		}
		return fsToolText(text)
	default:
		return fsToolError("unknown tool")
	}
}

func fsToolText(text string) map[string]any {
	return map[string]any{
		"content": []map[string]any{{"type": "text", "text": text}},
	}
}

func fsToolError(msg string) map[string]any {
	return map[string]any{
		"content": []map[string]any{{"type": "text", "text": msg}},
		"isError": true,
	}
}

// relInRoot maps a client path into root-relative form. Paths are
// interpreted as absolute guest paths confined to the jail (the MCP
// filesystem-server convention: agents think in absolute paths); a
// relative path is joined onto the root. The lexical prefix check is the
// policy layer — os.Root's traversal containment is the race-free
// enforcement layer underneath it (symlink escapes, including ones
// created between check and open, are refused there).
func relInRoot(rootPath, p string) (string, error) {
	root := filepath.Clean(rootPath)
	abs := p
	if abs == "" {
		abs = root
	} else if !filepath.IsAbs(abs) {
		abs = filepath.Join(root, abs)
	}
	abs = filepath.Clean(abs)
	if abs != root && !strings.HasPrefix(abs, strings.TrimSuffix(root, "/")+"/") {
		return "", fmt.Errorf("path %q is outside the server root %s", p, root)
	}
	rel := strings.TrimPrefix(strings.TrimPrefix(abs, root), "/")
	if rel == "" {
		return ".", nil
	}
	return rel, nil
}

func fsReadFile(jail *os.Root, rootPath, path string) (string, error) {
	rel, err := relInRoot(rootPath, path)
	if err != nil {
		return "", err
	}
	f, err := jail.Open(rel)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, fsMaxFileBytes+1))
	if err != nil {
		return "", err
	}
	if len(data) > fsMaxFileBytes {
		return "", fmt.Errorf("file exceeds the %d-byte limit", fsMaxFileBytes)
	}
	if strings.IndexByte(string(data), 0) >= 0 {
		return "", fmt.Errorf("binary file refused")
	}
	return string(data), nil
}

func fsListDir(jail *os.Root, rootPath, path string) (string, error) {
	rel, err := relInRoot(rootPath, path)
	if err != nil {
		return "", err
	}
	f, err := jail.Open(rel)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	entries, err := f.ReadDir(fsMaxDirEntries + 1)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	truncated := len(entries) > fsMaxDirEntries
	for i, e := range entries {
		if i >= fsMaxDirEntries {
			break
		}
		kind := "file"
		if e.IsDir() {
			kind = "dir"
		} else if e.Type()&os.ModeSymlink != 0 {
			kind = "symlink"
		}
		fmt.Fprintf(&b, "%s (%s)\n", e.Name(), kind)
	}
	if truncated {
		fmt.Fprintf(&b, "... truncated at %d entries\n", fsMaxDirEntries)
	}
	return b.String(), nil
}
