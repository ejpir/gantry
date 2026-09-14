package remote

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/ejpir/gantry/api/managerapi"
	"github.com/ejpir/gantry/internal/sandbox/layout"
)

// Client speaks the manager's OpenAPI HTTP/JSON protocol
// (api/managerapi/openapi.yaml) to one remote over verified TLS.
type Client struct {
	base    string
	token   string
	profile Profile
	http    *http.Client

	// observed records the leaf the server actually presented, so
	// `remote test` can display the live fingerprint regardless of pinning.
	observedMu sync.Mutex
	observed   [32]byte
	observedOK bool
}

// Error is a non-2xx manager response.
type Error struct {
	Status      int
	Message     string
	OperationID string
}

func (e *Error) Error() string {
	if e.Status == http.StatusForbidden {
		return "access denied (the remote rejected the token; mint a fresh one on the server with: gantry serve --mint-token)"
	}
	if e.OperationID != "" {
		return fmt.Sprintf("%s (operation %s)", e.Message, e.OperationID)
	}
	return e.Message
}

// The wire types are the manager's canonical protocol definition,
// contract-tested against api/managerapi/openapi.yaml; they are aliased
// here so callers use one vocabulary whether they import the client or the
// protocol package.
type (
	Health               = managerapi.Health
	Sandbox              = managerapi.Sandbox
	CreateSandboxRequest = managerapi.CreateSandboxRequest
	ExecRequest          = managerapi.ExecRequest
	ExecResult           = managerapi.ExecResult
	Operation            = managerapi.Operation
)

// Dial builds the verified transport for a profile. Verification is never
// disabled: the chain is checked against the profile's CA bundle (or the
// system roots), and a configured fingerprint additionally pins the exact
// leaf certificate.
func Dial(profile Profile, token string) (*Client, error) {
	if err := validateProfile(profile); err != nil {
		return nil, err
	}
	u, _ := url.Parse(profile.URL)
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: u.Hostname()}
	if profile.CACert != "" {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(profile.CACert)) {
			return nil, fmt.Errorf("remote %q: CA bundle has no PEM certificates", profile.Name)
		}
		tlsConfig.RootCAs = pool
	}
	client := &Client{base: strings.TrimSuffix(profile.URL, "/"), token: token, profile: profile}
	if profile.Fingerprint != "" {
		expected, err := hex.DecodeString(strings.TrimPrefix(profile.Fingerprint, "sha256:"))
		if err != nil {
			return nil, fmt.Errorf("remote %q: invalid fingerprint: %w", profile.Name, err)
		}
		tlsConfig.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errors.New("server presented no certificates")
			}
			sum := sha256.Sum256(rawCerts[0])
			client.recordObserved(sum)
			if !bytes.Equal(sum[:], expected) {
				return fmt.Errorf("tls fingerprint mismatch: server presents sha256:%x, remote %q pins %s", sum, profile.Name, profile.Fingerprint)
			}
			return nil
		}
	} else {
		tlsConfig.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) > 0 {
				client.recordObserved(sha256.Sum256(rawCerts[0]))
			}
			return nil
		}
	}
	transport := &http.Transport{TLSClientConfig: tlsConfig, DisableCompression: true}
	client.http = &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error {
		return errors.New("manager redirects are refused (credentials must stay on the configured origin)")
	}}
	return client, nil
}

func (c *Client) recordObserved(sum [32]byte) {
	c.observedMu.Lock()
	defer c.observedMu.Unlock()
	c.observed, c.observedOK = sum, true
}

// LiveFingerprint is the sha256 of the leaf the server presented on the most
// recent handshake, formatted like the server's startup log line.
func (c *Client) LiveFingerprint() (string, bool) {
	c.observedMu.Lock()
	defer c.observedMu.Unlock()
	if !c.observedOK {
		return "", false
	}
	return "sha256:" + hex.EncodeToString(c.observed[:]), true
}

func (c *Client) newRequest(ctx context.Context, method, path string, body any, idempotent bool) (*http.Request, error) {
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		reader = bytes.NewReader(data)
	}
	request, err := http.NewRequestWithContext(ctx, method, c.base+path, reader)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", "Bearer "+c.token)
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if idempotent {
		key := make([]byte, 16)
		if _, err := rand.Read(key); err != nil {
			return nil, err
		}
		request.Header.Set("Idempotency-Key", hex.EncodeToString(key))
	}
	return request, nil
}

// do runs one request and decodes the JSON response into out (when non-nil).
// Non-2xx statuses become *Error with the manager's message.
func (c *Client) do(ctx context.Context, method, path string, body any, idempotent bool, out any) error {
	request, err := c.newRequest(ctx, method, path, body, idempotent)
	if err != nil {
		return err
	}
	return c.doRequest(request, out)
}

func (c *Client) doRequest(request *http.Request, out any) (err error) {
	defer func() {
		// Even a hostile manager's error body must not turn a write-only
		// credential into a CLI diagnostic or TUI result message.
		if err != nil && c.token != "" && strings.Contains(err.Error(), c.token) {
			if apiErr, ok := err.(*Error); ok {
				apiErr.Message = strings.ReplaceAll(apiErr.Message, c.token, "[redacted]")
				apiErr.OperationID = strings.ReplaceAll(apiErr.OperationID, c.token, "[redacted]")
			} else {
				err = errors.New(strings.ReplaceAll(err.Error(), c.token, "[redacted]"))
			}
		}
	}()
	response, err := c.http.Do(request)
	if err != nil {
		return fmt.Errorf("remote %q (%s): %w", c.profile.Name, c.profile.URL, unwrapTLS(err))
	}
	defer func() { _ = response.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(response.Body, 32<<20))
	if err != nil {
		return err
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		apiErr := &Error{Status: response.StatusCode, Message: http.StatusText(response.StatusCode)}
		var parsed managerapi.ErrorResponse
		if json.Unmarshal(data, &parsed) == nil && parsed.Error != "" {
			apiErr.Message = parsed.Error
			apiErr.OperationID = parsed.OperationID
		}
		return apiErr
	}
	if out != nil && len(data) > 0 {
		if err := json.Unmarshal(data, out); err != nil {
			return fmt.Errorf("remote %q: invalid response: %w", c.profile.Name, err)
		}
	}
	return nil
}

// unwrapTLS keeps certificate and fingerprint failures recognizable instead
// of burying them under "Post ...:" wrappers. The x509 failures arrive as
// value types, so the errors.As targets are values too.
func unwrapTLS(err error) error {
	var unknownAuthority x509.UnknownAuthorityError
	var hostnameErr x509.HostnameError
	var certInvalid x509.CertificateInvalidError
	switch {
	case errors.As(err, &unknownAuthority):
		return fmt.Errorf("server certificate is not trusted (self-signed server? pass its ~/.gantry/serve/ca.crt with: gantry remote add ... --ca FILE)")
	case errors.As(err, &hostnameErr):
		return fmt.Errorf("server certificate is not valid for this host: %w", hostnameErr)
	case errors.As(err, &certInvalid):
		return fmt.Errorf("server certificate is invalid: %w", certInvalid)
	}
	return err
}

// Health checks manager liveness; the token is validated by the call itself.
func (c *Client) Health(ctx context.Context) (string, error) {
	var health managerapi.Health
	if err := c.do(ctx, http.MethodGet, "/v1/health", nil, false, &health); err != nil {
		return "", err
	}
	if !health.OK {
		return "", errors.New("manager reports not ok")
	}
	return health.Version, nil
}

// ListSandboxes returns the remote's current sandboxes.
func (c *Client) ListSandboxes(ctx context.Context) ([]Sandbox, error) {
	var list struct {
		Sandboxes []Sandbox `json:"sandboxes"`
	}
	if err := c.do(ctx, http.MethodGet, "/v1/sandboxes", nil, false, &list); err != nil {
		return nil, err
	}
	return list.Sandboxes, nil
}

// ValidateSandboxName exposes the shared name rule without exposing host
// state paths to clients such as the dashboard.
func ValidateSandboxName(name string) error { return layout.ValidateName(name) }

// CreateSandbox creates and boots one sandbox, waiting for completion.
func (c *Client) CreateSandbox(ctx context.Context, request CreateSandboxRequest) (Operation, error) {
	if err := ValidateSandboxName(request.Name); err != nil {
		return Operation{}, err
	}
	var operation Operation
	if err := c.do(ctx, http.MethodPost, "/v1/sandboxes", request, true, &operation); err != nil {
		return Operation{}, err
	}
	return c.waitOperation(ctx, operation)
}

// StartSandbox boots a previously created (stopped) sandbox.
func (c *Client) StartSandbox(ctx context.Context, name string) (Operation, error) {
	var operation Operation
	if err := c.do(ctx, http.MethodPost, "/v1/sandboxes/"+name+"/start", nil, true, &operation); err != nil {
		return Operation{}, err
	}
	return c.waitOperation(ctx, operation)
}

// StopSandbox stops a sandbox; its saved configuration remains.
func (c *Client) StopSandbox(ctx context.Context, name string) (Operation, error) {
	var operation Operation
	if err := c.do(ctx, http.MethodPost, "/v1/sandboxes/"+name+"/stop", nil, true, &operation); err != nil {
		return Operation{}, err
	}
	return c.waitOperation(ctx, operation)
}

// DeleteSandbox stops and removes a sandbox.
func (c *Client) DeleteSandbox(ctx context.Context, name string) (Operation, error) {
	var operation Operation
	if err := c.do(ctx, http.MethodDelete, "/v1/sandboxes/"+name, nil, true, &operation); err != nil {
		return Operation{}, err
	}
	return c.waitOperation(ctx, operation)
}

// Exec runs one bounded, non-interactive command in a running sandbox.
func (c *Client) Exec(ctx context.Context, name string, request ExecRequest) (ExecResult, error) {
	var result ExecResult
	if err := c.do(ctx, http.MethodPost, "/v1/sandboxes/"+name+"/exec", request, false, &result); err != nil {
		return ExecResult{}, err
	}
	return result, nil
}

// waitOperation resolves the rare asynchronous (202) form: a replayed or
// superseded idempotent operation still running. Fresh keys make this a
// no-op on the happy path, where the manager answers synchronously.
func (c *Client) waitOperation(ctx context.Context, operation Operation) (Operation, error) {
	return c.WaitOperation(ctx, operation, nil)
}

// WaitOperation polls a committed operation. The last known operation is
// returned even on transport failure, allowing callers to resume by ID.
func (c *Client) WaitOperation(ctx context.Context, operation Operation, progress func(Operation)) (Operation, error) {
	for {
		if progress != nil {
			progress(operation)
		}
		switch operation.State {
		case "succeeded":
			return operation, nil
		case "failed":
			return operation, &Error{Status: http.StatusConflict, Message: operation.Error, OperationID: operation.ID}
		case "running":
		default:
			return operation, fmt.Errorf("remote %q: invalid operation state %q", c.profile.Name, operation.State)
		}
		select {
		case <-ctx.Done():
			return operation, ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
		next, err := c.GetOperation(ctx, operation.ID)
		if err != nil {
			return operation, err
		}
		if next.ID != operation.ID {
			return operation, fmt.Errorf("remote %q: operation %s vanished", c.profile.Name, operation.ID)
		}
		operation = next
	}
}

// GetOperation retrieves an operation after reconnecting to the same manager.
func (c *Client) GetOperation(ctx context.Context, id string) (Operation, error) {
	var operation Operation
	if !layout.ValidName(id) {
		return operation, errors.New("invalid operation ID")
	}
	err := c.do(ctx, http.MethodGet, "/v1/operations/"+id, nil, false, &operation)
	return operation, err
}

// Close releases idle HTTP connections. Active calls are canceled by their contexts.
func (c *Client) Close() { c.http.CloseIdleConnections() }
