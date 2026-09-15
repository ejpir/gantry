// Remote (TLS) transport for the manager: listen-spec parsing, bearer-token
// authentication, self-signed TLS material, and request audit. The design and
// its normative requirements live in docs/remote-sandbox-access.md
// (milestone 1); the unix socket remains the default and its
// filesystem-permission model is unchanged.

package manager

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/ejpir/gantry/internal/atomicfile"
	"github.com/ejpir/gantry/internal/sandbox/localsec"
)

const (
	// minTokenLength / maxTokenLength bound accepted bearer tokens. 16
	// printable characters is a floor, not a target; MintToken emits 64.
	minTokenLength = 16
	maxTokenLength = 256

	// serveTLSValidity is the lifetime of self-signed material. Rotation is
	// deliberate (delete the serve directory and restart), so the window is
	// long rather than silently short.
	serveTLSValidity = 10 * 365 * 24 * time.Hour
)

// errAccessDenied is the single response for every authentication failure:
// missing, malformed, and unknown tokens are indistinguishable on the wire.
var errAccessDenied = errors.New("access denied")

// listenSpec is one parsed manager listener.
type listenSpec struct {
	network string // "unix" or "tls"
	address string // socket path or host:port
}

func (s listenSpec) String() string { return s.network + "://" + s.address }

// parseListenSpec accepts unix://PATH, tls://ADDR:PORT, or a bare socket path
// (the historical -socket spelling). Plaintext network schemes are refused
// outright: the manager has no insecure network mode.
func parseListenSpec(raw string) (listenSpec, error) {
	if raw == "" {
		return listenSpec{}, errors.New("empty listen address")
	}
	if !strings.Contains(raw, "://") {
		if strings.ContainsRune(raw, 0) {
			return listenSpec{}, fmt.Errorf("invalid socket path %q", raw)
		}
		return listenSpec{network: "unix", address: raw}, nil
	}
	scheme, address, _ := strings.Cut(raw, "://")
	switch scheme {
	case "unix":
		if address == "" || strings.ContainsRune(address, 0) {
			return listenSpec{}, fmt.Errorf("invalid unix listen address %q", raw)
		}
		return listenSpec{network: "unix", address: address}, nil
	case "tls":
		host, port, err := net.SplitHostPort(address)
		if err != nil || port == "" {
			return listenSpec{}, fmt.Errorf("invalid tls listen address %q: want tls://ADDR:PORT", raw)
		}
		if strings.ContainsRune(host, 0) {
			return listenSpec{}, fmt.Errorf("invalid tls listen address %q", raw)
		}
		return listenSpec{network: "tls", address: address}, nil
	case "tcp", "http", "https", "ws", "wss":
		return listenSpec{}, fmt.Errorf("plaintext manager transport %q is refused: the manager has no insecure network mode; use tls://ADDR:PORT with --token-file (see docs/remote-sandbox-access.md)", raw)
	default:
		return listenSpec{}, fmt.Errorf("unknown listen scheme %q: use unix://PATH or tls://ADDR:PORT", scheme)
	}
}

// servePlan is the validated result of serve flag resolution.
type servePlan struct {
	listeners   []listenSpec
	selfSigned  bool
	tlsCertFile string
	tlsKeyFile  string
	tokenFile   string
}

func (p servePlan) hasTLS() bool {
	for _, spec := range p.listeners {
		if spec.network == "tls" {
			return true
		}
	}
	return false
}

// resolveServePlan turns raw flags into a plan or a usage error. socket is
// the deprecated -socket value ("" when unset); listens collects each
// -listen occurrence.
func resolveServePlan(socket string, listens []string, tlsCert, tlsKey string, selfSigned bool, tokenFile string) (servePlan, error) {
	if socket != "" && len(listens) > 0 {
		return servePlan{}, errors.New("-socket and -listen are mutually exclusive; prefer -listen")
	}
	raw := listens
	if socket != "" {
		raw = []string{socket}
	}
	if len(raw) == 0 {
		raw = []string{SocketPath()}
	}
	plan := servePlan{
		selfSigned:  selfSigned,
		tlsCertFile: tlsCert,
		tlsKeyFile:  tlsKey,
		tokenFile:   tokenFile,
	}
	for _, value := range raw {
		spec, err := parseListenSpec(value)
		if err != nil {
			return servePlan{}, err
		}
		plan.listeners = append(plan.listeners, spec)
	}
	if !plan.hasTLS() {
		if selfSigned || tlsCert != "" || tlsKey != "" || tokenFile != "" {
			return servePlan{}, errors.New("--self-signed, --tls-cert, --tls-key and --token-file require a tls:// listener")
		}
		return plan, nil
	}
	// Bearer authentication is mandatory on the network transport (design
	// MUST 2); there is no opt-out to misconfigure.
	if tokenFile == "" {
		return servePlan{}, errors.New("tls:// listeners require --token-file: every remote-served request must carry a valid bearer token")
	}
	if selfSigned && (tlsCert != "" || tlsKey != "") {
		return servePlan{}, errors.New("--self-signed conflicts with --tls-cert/--tls-key")
	}
	if !selfSigned && (tlsCert == "" || tlsKey == "") {
		return servePlan{}, errors.New("tls:// requires --self-signed or both --tls-cert and --tls-key")
	}
	return plan, nil
}

// MintToken returns a fresh 256-bit bearer token, hex-encoded. Tokens are
// compared by hash, so the encoding is arbitrary; hex keeps token files
// grep-able and shell-safe.
func MintToken() (string, error) {
	var entropy [32]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		return "", fmt.Errorf("mint token: %w", err)
	}
	return hex.EncodeToString(entropy[:]), nil
}

// fingerprintToken is the only token-derived value that may appear in logs:
// 32 bits of SHA-256, enough to distinguish tokens, useless as a credential.
func fingerprintToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:4])
}

// tokenAuth authenticates Authorization headers against the hashes in a
// token file. The file is reloaded when it changes on disk; a failed reload
// keeps the last-good set so a half-written edit revokes nothing.
type tokenAuth struct {
	path    string
	audit   *log.Logger
	mu      sync.RWMutex
	hashes  [][sha256.Size]byte
	modOk   bool
	modTime time.Time
	size    int64
}

func newTokenAuth(path string, audit *log.Logger) (*tokenAuth, error) {
	auth := &tokenAuth{path: path, audit: audit}
	if err := auth.reload(); err != nil {
		return nil, err
	}
	return auth, nil
}

// parseTokenFile hashes every token line. Blank lines and # comments are
// skipped; anything malformed fails the whole file so a truncated write can
// never silently narrow the accepted set to a prefix.
func parseTokenFile(data []byte) ([][sha256.Size]byte, error) {
	var hashes [][sha256.Size]byte
	for index, line := range strings.Split(string(data), "\n") {
		token := strings.TrimSpace(line)
		if token == "" || strings.HasPrefix(token, "#") {
			continue
		}
		if len(token) < minTokenLength || len(token) > maxTokenLength {
			return nil, fmt.Errorf("token line %d: length must be %d..%d characters", index+1, minTokenLength, maxTokenLength)
		}
		valid := true
		for _, character := range token {
			if character < 0x21 || character > 0x7e {
				valid = false
				break
			}
		}
		if !valid {
			return nil, fmt.Errorf("token line %d: must be printable non-space ASCII", index+1)
		}
		hashes = append(hashes, sha256.Sum256([]byte(token)))
	}
	if len(hashes) == 0 {
		return nil, errors.New("token file contains no tokens")
	}
	return hashes, nil
}

// reload replaces the accepted set if the file parses. Parse or read
// failures keep the previous set and are audited; startup treats them as
// fatal via newTokenAuth.
func (auth *tokenAuth) reload() error {
	data, err := os.ReadFile(auth.path)
	if err != nil {
		auth.audit.Printf("token file %s unreadable: %v (keeping previous tokens)", auth.path, err)
		return fmt.Errorf("read token file: %w", err)
	}
	hashes, err := parseTokenFile(data)
	if err != nil {
		auth.audit.Printf("token file %s invalid: %v (keeping previous tokens)", auth.path, err)
		return fmt.Errorf("parse token file %s: %w", auth.path, err)
	}
	info, err := os.Stat(auth.path)
	if err != nil {
		return fmt.Errorf("stat token file: %w", err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		auth.audit.Printf("WARNING: token file %s is readable by other accounts (%04o); chmod 600 is required by the remote-access design", auth.path, info.Mode().Perm())
	}
	auth.mu.Lock()
	auth.hashes = hashes
	auth.modTime = info.ModTime()
	auth.size = info.Size()
	auth.modOk = true
	auth.mu.Unlock()
	auth.audit.Printf("token file %s loaded: %d token(s)", auth.path, len(hashes))
	return nil
}

// maybeReload reloads when the file changed on disk. Stat failure keeps the
// last-good set quietly; reload failure is audited by reload itself.
func (auth *tokenAuth) maybeReload() {
	info, err := os.Stat(auth.path)
	if err != nil {
		return
	}
	auth.mu.RLock()
	changed := !auth.modOk || !info.ModTime().Equal(auth.modTime) || info.Size() != auth.size
	auth.mu.RUnlock()
	if changed {
		_ = auth.reload()
	}
}

// authenticate reports whether header carries a known bearer token. The
// returned fingerprint identifies the presented token (valid or not) for
// audit; every failure mode returns ok == false with no distinguishing
// detail.
func (auth *tokenAuth) authenticate(header string) (fingerprint string, ok bool) {
	scheme, token, found := strings.Cut(header, " ")
	if !found || !strings.EqualFold(scheme, "bearer") || token == "" {
		return "", false
	}
	presented := sha256.Sum256([]byte(token))
	auth.mu.RLock()
	defer auth.mu.RUnlock()
	var match byte
	for _, known := range auth.hashes {
		// No early exit: comparison cost is independent of which token
		// matched and of how many leading bytes did.
		match |= byte(subtle.ConstantTimeCompare(presented[:], known[:]))
	}
	return fingerprintToken(token), match == 1
}

// statusRecorder captures the response status for audit without disturbing
// streaming handlers (SSE) that rely on http.Flusher.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

func (r *statusRecorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }

func (r *statusRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	conn, buffered, err := http.NewResponseController(r.ResponseWriter).Hijack()
	if err == nil {
		r.status = http.StatusSwitchingProtocols
	}
	return conn, buffered, err
}

func (r *statusRecorder) Flush() {
	if flusher, ok := r.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func isMutatingMethod(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	}
	return false
}

// authenticatedHandler wraps the service mux with bearer authentication.
// Authentication runs before any body read (design MUST 2); mutating
// requests are audited after completion with remote address, token
// fingerprint, and status (design MUST 8). Token values never appear.
func (m *managerService) authenticatedHandler(auth *tokenAuth, audit *log.Logger) http.Handler {
	inner := m.handler()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth.maybeReload()
		fingerprint, ok := auth.authenticate(r.Header.Get("Authorization"))
		if !ok {
			if fingerprint == "" {
				fingerprint = "none"
			}
			audit.Printf("remote=%s tokenfp=%s result=denied", r.RemoteAddr, fingerprint)
			writeManagerError(w, http.StatusForbidden, errAccessDenied, "")
			return
		}
		if !isMutatingMethod(r.Method) {
			inner.ServeHTTP(w, r)
			return
		}
		recorder := &statusRecorder{ResponseWriter: w}
		inner.ServeHTTP(recorder, r)
		status := recorder.status
		if status == 0 {
			status = http.StatusOK
		}
		audit.Printf("remote=%s tokenfp=%s method=%s path=%s status=%d", r.RemoteAddr, fingerprint, r.Method, r.URL.Path, status)
	})
}

// serveTLS is the TLS configuration and identity material for tls://
// listeners.
type serveTLS struct {
	config      *tls.Config
	fingerprint string // "sha256:<hex>" over the leaf certificate DER
}

// loadServeTLS resolves the plan's TLS material: user-supplied certificate
// and key, or the install-scoped self-signed hierarchy.
func loadServeTLS(plan servePlan) (*serveTLS, error) {
	if !plan.selfSigned {
		return loadServeTLSFromFiles(plan.tlsCertFile, plan.tlsKeyFile)
	}
	dir := filepath.Join(managerBaseDir(), "serve")
	if err := localsec.CreateManagerDir(dir); err != nil {
		return nil, fmt.Errorf("secure serve directory: %w", err)
	}
	dnsNames, ipAddresses := serveSANHosts(plan.listeners)
	return loadOrCreateSelfSigned(dir, dnsNames, ipAddresses)
}

func fingerprintCertificateDER(der []byte) string {
	sum := sha256.Sum256(der)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func tlsConfigFor(cert tls.Certificate, fingerprint string) *serveTLS {
	return &serveTLS{
		config: &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		},
		fingerprint: fingerprint,
	}
}

// loadServeTLSFromFiles loads org-PKI material supplied via --tls-cert and
// --tls-key.
func loadServeTLSFromFiles(certFile, keyFile string) (*serveTLS, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load TLS material: %w", err)
	}
	if len(cert.Certificate) == 0 {
		return nil, errors.New("load TLS material: certificate file has no certificates")
	}
	return tlsConfigFor(cert, fingerprintCertificateDER(cert.Certificate[0])), nil
}

// serveSANHosts derives server-certificate SANs from the tls:// listen
// addresses: IP literal hosts become IP SANs, named hosts become DNS SANs,
// and loopback is always included.
func serveSANHosts(specs []listenSpec) (dns []string, ips []net.IP) {
	dns = []string{"localhost"}
	ips = []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}
	seen := map[string]bool{"localhost": true, "127.0.0.1": true, "::1": true}
	for _, spec := range specs {
		if spec.network != "tls" {
			continue
		}
		host, _, err := net.SplitHostPort(spec.address)
		if err != nil || host == "" || seen[host] {
			continue
		}
		seen[host] = true
		if ip := net.ParseIP(host); ip != nil {
			ips = append(ips, ip)
		} else {
			dns = append(dns, host)
		}
	}
	return dns, ips
}

// Self-signed material lives in four files under <root>/serve/: ca.key,
// ca.crt, server.key, server.crt. Existing material is reused so the
// fingerprint is stable across restarts; corrupt or partial material fails
// loudly with a repair hint rather than silently re-keying (same doctrine
// as the ssh host key).
func loadOrCreateSelfSigned(dir string, dnsNames []string, ipAddresses []net.IP) (*serveTLS, error) {
	paths := []string{
		filepath.Join(dir, "ca.key"),
		filepath.Join(dir, "ca.crt"),
		filepath.Join(dir, "server.key"),
		filepath.Join(dir, "server.crt"),
	}
	present := 0
	for _, path := range paths {
		if info, err := os.Lstat(path); err == nil && info.Mode().IsRegular() {
			present++
		}
	}
	switch {
	case present == len(paths):
		return loadSelfSigned(dir, paths)
	case present == 0:
		return createSelfSigned(dir, paths, dnsNames, ipAddresses)
	default:
		return nil, fmt.Errorf("incomplete TLS material in %s (%d of %d files present); delete the directory and restart to regenerate", dir, present, len(paths))
	}
}

func loadSelfSigned(dir string, paths []string) (*serveTLS, error) {
	repair := fmt.Sprintf("delete %s and restart to regenerate", dir)
	cert, err := tls.LoadX509KeyPair(paths[3], paths[2])
	if err != nil {
		return nil, fmt.Errorf("load self-signed TLS material: %w; %s", err, repair)
	}
	if len(cert.Certificate) == 0 {
		return nil, fmt.Errorf("load self-signed TLS material: server certificate is empty; %s", repair)
	}
	caPEM, err := os.ReadFile(paths[1])
	if err != nil {
		return nil, fmt.Errorf("load self-signed CA: %w; %s", err, repair)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("load self-signed CA: no certificates in %s; %s", paths[1], repair)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("parse self-signed server certificate: %w; %s", err, repair)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		return nil, fmt.Errorf("self-signed server certificate does not verify: %w; %s", err, repair)
	}
	return tlsConfigFor(cert, fingerprintCertificateDER(cert.Certificate[0])), nil
}

func createSelfSigned(dir string, paths []string, dnsNames []string, ipAddresses []net.IP) (*serveTLS, error) {
	now := time.Now()
	caPublic, caPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate CA key: %w", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          randomSerial(),
		Subject:               pkix.Name{CommonName: "gantry serve CA"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(serveTLSValidity),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caPublic, caPrivate)
	if err != nil {
		return nil, fmt.Errorf("create CA certificate: %w", err)
	}
	serverPublic, serverPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate server key: %w", err)
	}
	serverTemplate := &x509.Certificate{
		SerialNumber: randomSerial(),
		Subject:      pkix.Name{CommonName: "gantry serve"},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(serveTLSValidity),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     dnsNames,
		IPAddresses:  ipAddresses,
	}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caTemplate, serverPublic, caPrivate)
	if err != nil {
		return nil, fmt.Errorf("create server certificate: %w", err)
	}
	caKeyDER, err := x509.MarshalPKCS8PrivateKey(caPrivate)
	if err != nil {
		return nil, fmt.Errorf("encode CA key: %w", err)
	}
	serverKeyDER, err := x509.MarshalPKCS8PrivateKey(serverPrivate)
	if err != nil {
		return nil, fmt.Errorf("encode server key: %w", err)
	}
	files := []struct {
		path string
		pem  *pem.Block
	}{
		{paths[0], &pem.Block{Type: "PRIVATE KEY", Bytes: caKeyDER}},
		{paths[1], &pem.Block{Type: "CERTIFICATE", Bytes: caDER}},
		{paths[2], &pem.Block{Type: "PRIVATE KEY", Bytes: serverKeyDER}},
		{paths[3], &pem.Block{Type: "CERTIFICATE", Bytes: serverDER}},
	}
	for _, file := range files {
		if err := atomicfile.WriteFile(file.path, pem.EncodeToMemory(file.pem), 0o600); err != nil {
			return nil, fmt.Errorf("write %s: %w", file.path, err)
		}
	}
	cert, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverDER}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: serverKeyDER}),
	)
	if err != nil {
		return nil, fmt.Errorf("load generated TLS material: %w", err)
	}
	return tlsConfigFor(cert, fingerprintCertificateDER(serverDER)), nil
}

func randomSerial() *big.Int {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		// x509 refuses non-positive serials; fall back to time so key
		// generation cannot fail on entropy exhaustion mid-write.
		return big.NewInt(time.Now().UnixNano())
	}
	return serial
}
