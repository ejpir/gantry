// Package mcpworker is the trusted supervisor half of the split MCP gateway.
package mcpworker

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	workerapi "github.com/ejpir/gantry/internal/mcpworker"
	"github.com/ejpir/gantry/internal/sandbox/mcpgw"
	"github.com/ejpir/gantry/internal/sandbox/worker"
	"github.com/ejpir/gantry/internal/workerconf"
	"github.com/ejpir/gantry/internal/workerproto"
)

// Server binds one immutable public worker configuration to supervisor-only
// capabilities. Credential and Spawn closures contain authority and are never
// serialized into worker bootstrap.
type Server struct {
	Config     workerapi.ServerConfig
	Credential func() (workerapi.CredentialResponse, error)
	Spawn      func(context.Context) (io.WriteCloser, io.ReadCloser, func(), error)
}

type Worker struct {
	child  *worker.Child
	client *workerproto.Client
	mux    *workerapi.Mux

	servers map[string]Server
	audit   func(mcpgw.Event)
	conf    *workerconf.Report

	sessions  chan struct{}
	closeOnce sync.Once
	closeErr  error
}

func Start(servers []Server, workdir, confinement string, audit func(mcpgw.Event)) (*Worker, error) {
	return start(servers, workdir, confinement, audit, nil)
}

func start(servers []Server, workdir, confinement string, audit func(mcpgw.Event),
	configureProcess func(argv, environment *[]string)) (*Worker, error) {
	if len(servers) == 0 {
		return nil, fmt.Errorf("mcp worker: no configured servers")
	}
	mode := confinement
	if mode == "" {
		mode = "auto"
	}
	config := workerapi.Config{Version: workerapi.ProtocolVersion, Confinement: mode}
	serverMap := make(map[string]Server, len(servers))
	for _, server := range servers {
		if _, exists := serverMap[server.Config.Name]; exists {
			return nil, fmt.Errorf("mcp worker: duplicate server %q", server.Config.Name)
		}
		serverMap[server.Config.Name] = server
		config.Servers = append(config.Servers, server.Config)
	}
	if runtime.GOOS == "linux" && mode != "off" {
		config.ConfRoot = filepath.Join(workdir, "mcproot")
		if err := os.MkdirAll(config.ConfRoot, 0o700); err != nil {
			return nil, fmt.Errorf("mcp worker confinement root: %w", err)
		}
		if err := os.Chmod(config.ConfRoot, 0o700); err != nil {
			return nil, fmt.Errorf("mcp worker confinement root: %w", err)
		}
	}

	child, err := worker.Launch(worker.LaunchSpec{
		Role: workerproto.RoleMCP, EntryPoint: "_mcp-worker",
		Environment: workerEnvironment(), Channels: []string{"control", "broker", "streams"},
		DiagnosticPath: filepath.Join(workdir, "worker-mcp.log"), Confinement: mode,
		ConfigureProcess: configureProcess,
	})
	if err != nil {
		return nil, err
	}
	handle := &Worker{
		child: child, servers: serverMap, audit: audit,
		sessions: make(chan struct{}, 16),
	}
	fail := func(cause error) (*Worker, error) {
		_ = child.Terminate(5 * time.Second)
		return nil, cause
	}

	bootstrap, err := child.BeginBootstrap(config)
	if err != nil {
		return fail(fmt.Errorf("mcp worker handshake: %w", err))
	}
	if err := bootstrap.BindChannels("broker", "streams"); err != nil {
		return fail(fmt.Errorf("mcp worker channel nonce: %w", err))
	}

	handle.mux = workerapi.NewMux(child.Channels["streams"], true, handle.openWorkerStream)
	brokerDone := make(chan error, 1)
	go func() {
		brokerDone <- workerproto.ServeRequests(child.Channels["broker"], map[string]workerproto.Handler{
			workerapi.OpCredential: handle.credential,
			workerapi.OpAudit:      handle.auditEvent,
		})
	}()

	control := child.Channels["control"]
	var ack workerapi.BootAck
	_ = control.SetReadDeadline(time.Now().Add(30 * time.Second))
	if err := workerproto.ReadMessage(control, &ack); err != nil {
		return fail(fmt.Errorf("mcp worker ready: %w", err))
	}
	_ = control.SetReadDeadline(time.Time{})
	if !ack.OK {
		if ack.Error == "" {
			ack.Error = "worker refused bootstrap"
		}
		return fail(fmt.Errorf("mcp worker bootstrap failed: %s", ack.Error))
	}
	if ack.Confinement == nil || ack.Confinement.Platform != runtime.GOOS || ack.Confinement.Mode != mode {
		return fail(fmt.Errorf("mcp worker bootstrap failed: invalid confinement report for %s/%s", runtime.GOOS, mode))
	}
	if mode == "required" {
		if failed := ack.Confinement.Failed(workerapi.RequiredConfinementProperties(runtime.GOOS)...); len(failed) != 0 {
			return fail(fmt.Errorf("mcp worker bootstrap failed: required confinement not enforced: %v", failed))
		}
	}
	handle.conf = ack.Confinement
	handle.client = workerproto.NewClient(control)
	go handle.observe(brokerDone)
	return handle, nil
}

func (worker *Worker) observe(brokerDone <-chan error) {
	select {
	case <-worker.child.Done():
		_ = worker.mux.Close()
	case <-brokerDone:
		select {
		case <-worker.child.Done():
			return
		case <-worker.child.Lifecycle.Stopping():
			return
		default:
		}
		_ = worker.child.Terminate(5 * time.Second)
	}
}

func (worker *Worker) openWorkerStream(ctx context.Context, request workerapi.OpenRequest, stream *workerapi.Stream) error {
	if !validSessionToken(request.Session) {
		return fmt.Errorf("invalid MCP session capability")
	}
	server, ok := worker.servers[request.Server]
	if !ok {
		return fmt.Errorf("unknown MCP server")
	}
	switch request.Kind {
	case workerapi.StreamRemote:
		if server.Config.Local || server.Config.URL == "" {
			return fmt.Errorf("server is not remote")
		}
		conn, err := mcpgw.DialRemote(ctx, server.Config.URL)
		if err != nil {
			return err
		}
		go proxy(stream, conn)
		return nil
	case workerapi.StreamLocal:
		if !server.Config.Local || server.Config.Name != "fs" || server.Spawn == nil {
			return fmt.Errorf("server is not the fixed local helper")
		}
		// The mux open deadline bounds creation only. The helper needs a
		// separate lifetime context; canceling the open context after its ACK
		// must not immediately kill the newly created guest process.
		helperCtx, helperCancel := context.WithCancel(context.Background())
		stdin, stdout, kill, err := server.Spawn(helperCtx)
		if err != nil {
			helperCancel()
			return err
		}
		endpoint := &stdioEndpoint{reader: stdout, writer: stdin, kill: func() {
			helperCancel()
			if kill != nil {
				kill()
			}
		}}
		go proxy(stream, endpoint)
		return nil
	default:
		return fmt.Errorf("worker may open only local or remote capabilities")
	}
}

func (worker *Worker) credential(request workerproto.Request) (any, error) {
	var body workerapi.CredentialRequest
	if err := decodeStrictBody(request, &body); err != nil {
		return nil, err
	}
	if !validSessionToken(body.Session) {
		return nil, fmt.Errorf("invalid MCP session capability")
	}
	server, ok := worker.servers[body.Server]
	if !ok || server.Config.Local || !server.Config.Credential || server.Credential == nil {
		return nil, fmt.Errorf("credential unavailable for server")
	}
	credential, err := server.Credential()
	if err != nil {
		return nil, fmt.Errorf("credential unavailable for server")
	}
	return credential, nil
}

func (worker *Worker) auditEvent(request workerproto.Request) (any, error) {
	var body workerapi.AuditRequest
	if err := decodeStrictBody(request, &body); err != nil {
		return nil, err
	}
	allowed := make(map[string]bool, len(worker.servers))
	for name := range worker.servers {
		allowed[name] = true
	}
	if err := mcpgw.ValidateEvent(body.Event, allowed); err != nil {
		return nil, err
	}
	if body.Event.Type == mcpgw.EventUpstreamRemote {
		// Origin metadata is supervisor-derived; the worker cannot smuggle a
		// query/path or substitute another host into the audit trail.
		body.Event.Origin = mcpgw.AuditRemoteOrigin(worker.servers[body.Event.Server].Config.URL)
	}
	if worker.audit != nil {
		worker.audit(body.Event)
	}
	return nil, nil
}

func decodeStrictBody(request workerproto.Request, value any) error {
	if len(request.Body) == 0 {
		return fmt.Errorf("missing request body")
	}
	decoder := json.NewDecoder(bytes.NewReader(request.Body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("trailing request value")
		}
		return err
	}
	return nil
}

// Serve relays one accepted guest stream without parsing MCP payload bytes in
// the supervisor. Session accounting is independently enforced on both sides.
func (worker *Worker) Serve(ctx context.Context, conn net.Conn) error {
	defer func() { _ = conn.Close() }()
	select {
	case worker.sessions <- struct{}{}:
		defer func() { <-worker.sessions }()
	default:
		return fmt.Errorf("mcp supervisor session limit reached")
	}
	stream, err := worker.mux.Open(ctx, workerapi.OpenRequest{Kind: workerapi.StreamGuest})
	if err != nil {
		return err
	}
	proxy(stream, conn)
	return nil
}

func (worker *Worker) Done() <-chan struct{} { return worker.child.Done() }
func (worker *Worker) Err() error            { return worker.child.Err() }

func (worker *Worker) ConfinementReport() *workerconf.Report {
	if worker == nil || worker.conf == nil {
		return nil
	}
	report := *worker.conf
	report.Results = append([]workerconf.PropertyResult(nil), report.Results...)
	report.Notes = append([]string(nil), report.Notes...)
	return &report
}

func (worker *Worker) Close() error {
	if worker == nil {
		return nil
	}
	worker.closeOnce.Do(func() {
		worker.child.BeginStop()
		if worker.client != nil {
			worker.closeErr = worker.client.CallWithTimeout(workerapi.OpShutdown, nil, nil, 3*time.Second)
		}
		_ = worker.mux.Close()
		worker.child.CloseChannels()
		worker.closeErr = errors.Join(worker.closeErr, worker.child.WaitExit(3*time.Second))
	})
	return worker.closeErr
}

func validSessionToken(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 16
}

func proxy(left, right io.ReadWriteCloser) {
	var once sync.Once
	closeBoth := func() {
		once.Do(func() {
			_ = left.Close()
			_ = right.Close()
		})
	}
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(left, right); done <- struct{}{} }()
	go func() { _, _ = io.Copy(right, left); done <- struct{}{} }()
	<-done
	closeBoth()
	<-done
}

type stdioEndpoint struct {
	reader io.ReadCloser
	writer io.WriteCloser
	kill   func()
	once   sync.Once
}

func (endpoint *stdioEndpoint) Read(data []byte) (int, error)  { return endpoint.reader.Read(data) }
func (endpoint *stdioEndpoint) Write(data []byte) (int, error) { return endpoint.writer.Write(data) }
func (endpoint *stdioEndpoint) Close() error {
	var result error
	endpoint.once.Do(func() {
		result = errors.Join(endpoint.writer.Close(), endpoint.reader.Close())
		if endpoint.kill != nil {
			endpoint.kill()
		}
	})
	return result
}
