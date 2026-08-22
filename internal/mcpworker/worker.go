package mcpworker

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/ejpir/gantry/internal/sandbox/mcpgw"
	"github.com/ejpir/gantry/internal/workerproto"
)

var serverNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,30}$`)

func (config *Config) UnmarshalJSON(raw []byte) error {
	type plain Config
	var decoded plain
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&decoded); err != nil {
		return err
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return fmt.Errorf("trailing MCP bootstrap data: %w", err)
	}
	*config = Config(decoded)
	return nil
}

// Cmd is the hidden _mcp-worker entry point. Descriptors 3..5 are the control,
// reverse broker, and stream-mux channels from the exact launch table.
func Cmd() int {
	control, err := workerproto.InheritedConn(3, "control")
	if err != nil {
		fmt.Fprintln(os.Stderr, "mcp-worker:", err)
		return 1
	}
	broker, err := workerproto.InheritedConn(4, "broker")
	if err != nil {
		_ = control.Close()
		fmt.Fprintln(os.Stderr, "mcp-worker:", err)
		return 1
	}
	streams, err := workerproto.InheritedConn(5, "streams")
	if err != nil {
		_ = control.Close()
		_ = broker.Close()
		fmt.Fprintln(os.Stderr, "mcp-worker:", err)
		return 1
	}
	if err := Run(control, broker, streams); err != nil {
		fmt.Fprintln(os.Stderr, "mcp-worker:", err)
		return 1
	}
	return 0
}

func Run(control, broker, streams net.Conn) (retErr error) {
	defer func() { _ = control.Close() }()
	defer func() { _ = broker.Close() }()
	defer func() { _ = streams.Close() }()

	var config Config
	nonce, err := workerproto.ServeHandshake(control, workerproto.RoleMCP, &config)
	if err != nil {
		return err
	}
	if err := validateConfig(config); err != nil {
		return fmt.Errorf("bootstrap: %w", err)
	}
	if err := workerproto.ReadNonce(broker, nonce); err != nil {
		return fmt.Errorf("broker channel: %w", err)
	}
	if err := workerproto.ReadNonce(streams, nonce); err != nil {
		return fmt.Errorf("streams channel: %w", err)
	}

	// Load roots before path confinement. A brokered transport performs TLS in
	// this process but never opens the trust-store paths after this point.
	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		if err == nil {
			err = fmt.Errorf("empty system root pool")
		}
		ack := BootAck{Error: "load system TLS roots: " + err.Error()}
		_ = workerproto.WriteMessage(control, ack)
		return fmt.Errorf("load system TLS roots: %w", err)
	}

	confinement, confErr := ApplyConfinement(config, control, broker, streams)
	if confErr != nil {
		_ = workerproto.WriteMessage(control, BootAck{Error: confErr.Error(), Confinement: confinement})
		return confErr
	}

	brokerClient := workerproto.NewClient(broker)
	brokerClient.Timeout = 10 * time.Second
	var mux *Mux
	servers := make([]mcpgw.Server, 0, len(config.Servers))
	for _, serverConfig := range config.Servers {
		serverConfig := serverConfig
		server := mcpgw.Server{
			Name: serverConfig.Name, URL: serverConfig.URL, Tools: serverConfig.Tools,
			TLSRoots: roots,
		}
		if serverConfig.Local {
			// Argv is a non-empty marker for the engine's local-server branch. It
			// is never sent to the supervisor or executed by this worker.
			server.Argv = []string{"brokered:" + serverConfig.Name}
			server.Spawn = func(ctx context.Context, session string) (io.WriteCloser, io.ReadCloser, func(), error) {
				stream, err := mux.Open(ctx, OpenRequest{Kind: StreamLocal, Server: serverConfig.Name, Session: session})
				if err != nil {
					return nil, nil, nil, err
				}
				kill := func() { _ = stream.Close() }
				return stream, stream, kill, nil
			}
		} else {
			server.Dial = func(ctx context.Context, session string) (net.Conn, error) {
				return mux.Open(ctx, OpenRequest{Kind: StreamRemote, Server: serverConfig.Name, Session: session})
			}
			if serverConfig.Credential {
				server.Credentials = func(ctx context.Context, session string) (mcpgw.CredentialSet, error) {
					var response CredentialResponse
					if err := brokerClient.CallContext(ctx, OpCredential,
						CredentialRequest{Server: serverConfig.Name, Session: session}, &response); err != nil {
						return mcpgw.CredentialSet{}, err
					}
					if err := validateCredentialResponse(response); err != nil {
						return mcpgw.CredentialSet{}, err
					}
					redact := make([][]byte, 0, len(response.Redact))
					for _, value := range response.Redact {
						redact = append(redact, []byte(value))
					}
					return mcpgw.CredentialSet{Headers: response.Headers, Redact: redact}, nil
				}
			}
		}
		servers = append(servers, server)
	}

	gateway, err := mcpgw.NewWithEvents(func(event mcpgw.Event) {
		// The result is deliberately ignored: audit backpressure or shutdown
		// must not turn an otherwise bounded MCP call into a secret-bearing error.
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = brokerClient.CallContext(ctx, OpAudit, AuditRequest{Event: event}, nil)
	}, servers)
	if err != nil {
		_ = workerproto.WriteMessage(control, BootAck{Error: err.Error(), Confinement: confinement})
		return err
	}

	mux = NewMux(streams, false, func(_ context.Context, request OpenRequest, stream *Stream) error {
		if request.Kind != StreamGuest || request.Server != "" || !ValidSessionCapability(request.Session) {
			return fmt.Errorf("worker accepts only supervisor-capability guest streams")
		}
		go func() { _ = gateway.ServeWithSessionCapability(context.Background(), stream, request.Session) }()
		return nil
	})
	if err := workerproto.WriteMessage(control, BootAck{OK: true, Confinement: confinement}); err != nil {
		_ = mux.Close()
		return err
	}

	serveDone := make(chan error, 1)
	shutdown := make(chan struct{})
	var shutdownOnce sync.Once
	go func() {
		serveDone <- workerproto.ServeRequests(control, map[string]workerproto.Handler{
			OpShutdown: func(request workerproto.Request) (any, error) {
				if len(request.Body) != 0 {
					return nil, fmt.Errorf("mcp shutdown takes no body")
				}
				shutdownOnce.Do(func() { close(shutdown) })
				_ = mux.Close()
				return nil, workerproto.ErrShutdown
			},
		})
	}()
	select {
	case err := <-serveDone:
		_ = mux.Close()
		return err
	case <-mux.Done():
		select {
		case <-shutdown:
			return <-serveDone
		default:
			_ = control.Close()
			<-serveDone
			return fmt.Errorf("stream transport: %w", mux.Err())
		}
	}
}

func validateConfig(config Config) error {
	if config.Version != ProtocolVersion {
		return fmt.Errorf("unsupported protocol version %d", config.Version)
	}
	if config.Confinement != "off" && config.Confinement != "auto" && config.Confinement != "required" {
		return fmt.Errorf("invalid confinement mode %q", config.Confinement)
	}
	if len(config.Servers) == 0 || len(config.Servers) > 64 {
		return fmt.Errorf("server count %d out of bounds", len(config.Servers))
	}
	seen := make(map[string]bool, len(config.Servers))
	for _, server := range config.Servers {
		if !serverNamePattern.MatchString(server.Name) || strings.Contains(server.Name, "__") || seen[server.Name] {
			return fmt.Errorf("invalid or duplicate server %q", server.Name)
		}
		seen[server.Name] = true
		if server.Local == (server.URL != "") {
			return fmt.Errorf("server %s must be exactly one of local or remote", server.Name)
		}
		if server.Local {
			if server.Name != "fs" || server.Credential {
				return fmt.Errorf("unsupported local server %q", server.Name)
			}
		} else if _, err := mcpgw.ValidateRemoteURL(server.URL); err != nil {
			return fmt.Errorf("server %s URL: %w", server.Name, err)
		}
		for _, patterns := range [][]string{server.Tools.Allow, server.Tools.Deny} {
			for _, pattern := range patterns {
				if len(pattern) > 256 {
					return fmt.Errorf("server %s tool pattern too long", server.Name)
				}
			}
		}
	}
	if runtime.GOOS == "linux" && config.Confinement != "off" && config.ConfRoot == "" {
		return fmt.Errorf("linux MCP confinement root is required")
	}
	return nil
}

func validateCredentialResponse(response CredentialResponse) error {
	if len(response.Headers) > 8 || len(response.Redact) > 16 {
		return fmt.Errorf("credential response exceeds entry limits")
	}
	total := 0
	for name, value := range response.Headers {
		if len(name) > 64 || !validHeaderName(name) || len(value) > 64<<10 || !validHeaderValue(value) {
			return fmt.Errorf("invalid credential header")
		}
		total += len(name) + len(value)
	}
	for _, value := range response.Redact {
		if value == "" || len(value) > 64<<10 {
			return fmt.Errorf("invalid redaction value")
		}
		total += len(value)
	}
	if total > 256<<10 {
		return fmt.Errorf("credential response exceeds byte limit")
	}
	return nil
}

func validHeaderName(name string) bool {
	return http.CanonicalHeaderKey(name) != ""
}

func validHeaderValue(value string) bool {
	return !strings.ContainsAny(value, "\r\n\x00")
}
