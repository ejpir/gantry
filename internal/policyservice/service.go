// Package policyservice runs an organization's policy service: the mTLS feed
// that enrolled host managers poll (internal/policyfeed), and the
// administrator API that publishes signed generations and rolls them out ring
// by ring. The service never holds the policy signing key: administrators
// sign bundles on their own machines and the service verifies them with the
// same public key every host pins.
package policyservice

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	api "github.com/ejpir/gantry/api/policyservice"
	"github.com/ejpir/gantry/internal/atomicfile"
	"github.com/ejpir/gantry/internal/policy"
	"github.com/ejpir/gantry/internal/sandbox/localsec"
)

const (
	configVersion = 1
	stateVersion  = 1
	maxStateBytes = 32 << 20
	maxHosts      = 4096
	maxRings      = 8

	configFile    = "service.json"
	stateFile     = "state.json"
	adminsFile    = "admins.json"
	caKeyFile     = "ca-key.pem"
	serverFile    = "server.pem"
	serverKeyFile = "server-key.pem"
	bundlesDir    = "generations"
)

// DefaultRings are the rollout stages created by init unless overridden.
var DefaultRings = []string{"canary", "early", "everyone"}

type serviceConfig struct {
	Version      int       `json:"version"`
	Organization string    `json:"organization"`
	URL          string    `json:"url"`
	Rings        []string  `json:"rings"`
	CreatedAt    time.Time `json:"createdAt"`
}

type storedRing struct {
	Name       string     `json:"name"`
	Generation uint64     `json:"generation"`
	PromotedAt *time.Time `json:"promotedAt,omitempty"`
	PromotedBy string     `json:"promotedBy,omitempty"`
}

type storedRollout struct {
	Generation uint64    `json:"generation"`
	StartedAt  time.Time `json:"startedAt"`
	StartedBy  string    `json:"startedBy"`
}

type storedHost struct {
	Name             string              `json:"name"`
	Profile          string              `json:"profile"`
	Ring             string              `json:"ring"`
	Certificate      api.HostCertificate `json:"certificate"`
	Revoked          bool                `json:"revoked,omitempty"`
	RevokedAt        *time.Time          `json:"revokedAt,omitempty"`
	RevokedBy        string              `json:"revokedBy,omitempty"`
	Served           uint64              `json:"served,omitempty"`
	ServedAt         *time.Time          `json:"servedAt,omitempty"`
	AcknowledgedAt   *time.Time          `json:"acknowledgedAt,omitempty"`
	PollsSinceServed int                 `json:"pollsSinceServed,omitempty"`
	Report           *api.HostReport     `json:"report,omitempty"`
}

type storedDraft struct {
	Base      uint64          `json:"base"`
	Data      json.RawMessage `json:"data"`
	UpdatedAt time.Time       `json:"updatedAt"`
	UpdatedBy string          `json:"updatedBy"`
}

type storedState struct {
	Version     int              `json:"version"`
	Generations []api.Generation `json:"generations"`
	Rings       []storedRing     `json:"rings"`
	Rollout     *storedRollout   `json:"rollout,omitempty"`
	Hosts       []*storedHost    `json:"hosts"`
	Draft       *storedDraft     `json:"draft,omitempty"`
}

type storedAdmin struct {
	Name        string    `json:"name"`
	TokenSHA256 string    `json:"tokenSha256"`
	CreatedAt   time.Time `json:"createdAt"`
}

// Service is one organization's policy service rooted in a private directory.
type Service struct {
	dir           string
	config        serviceConfig
	publicKey     []byte
	keyPrint      string
	keyBits       int
	caPEM         []byte
	ca            *x509.Certificate
	caKey         crypto.Signer
	caPool        *x509.CertPool
	serverCert    tls.Certificate
	audit         *log.Logger
	now           func() time.Time
	mu            sync.Mutex
	state         storedState
	changed       chan struct{}
	lastSeen      map[string]time.Time
	documents     map[uint64]policy.Document
	digests       map[string]string
	admins        []storedAdmin
	adminsModTime time.Time
	adminsSize    int64
	reportsDirty  bool
	// wait bounds long polls; tests shorten it.
	wait time.Duration
}

// InitOptions configures a new service directory.
type InitOptions struct {
	Dir          string
	Organization string
	URL          string
	PublicKey    []byte
	Rings        []string
	// ExtraNames are additional DNS names or IPs for the TLS certificate.
	ExtraNames []string
}

// Init creates a new service directory: configuration, host CA, TLS
// certificate, and the pinned organization public key. It never overwrites.
func Init(options InitOptions) error {
	if !validName(options.Organization) {
		return fmt.Errorf("organization must be 1-128 letters, digits, '.', '_', ':' or '-'")
	}
	base, host, err := parseServiceURL(options.URL)
	if err != nil {
		return err
	}
	rings := options.Rings
	if len(rings) == 0 {
		rings = DefaultRings
	}
	if len(rings) > maxRings {
		return fmt.Errorf("at most %d rings are supported", maxRings)
	}
	for i, ring := range rings {
		if !validName(ring) || slices.Contains(rings[:i], ring) {
			return fmt.Errorf("ring names must be unique identifiers")
		}
	}
	if _, _, err := publicKeyInfo(options.PublicKey); err != nil {
		return err
	}
	if _, err := os.Lstat(options.Dir); err == nil {
		if entries, err := os.ReadDir(options.Dir); err != nil || len(entries) != 0 {
			return fmt.Errorf("%s already exists and is not empty; choose a new directory", options.Dir)
		}
	}
	if err := localsec.CreateDir(options.Dir); err != nil {
		return fmt.Errorf("create service directory: %w", err)
	}
	now := time.Now().UTC()
	ca, caKey, err := newCA(options.Organization, now)
	if err != nil {
		return err
	}
	names := append([]string{host}, options.ExtraNames...)
	serverPEM, serverKeyPEM, err := issueServer(ca, caKey, options.Organization, names, now)
	if err != nil {
		return err
	}
	caKeyDER, err := x509.MarshalPKCS8PrivateKey(caKey)
	if err != nil {
		return err
	}
	config := serviceConfig{Version: configVersion, Organization: options.Organization, URL: base, Rings: rings, CreatedAt: now}
	state := storedState{Version: stateVersion, Generations: []api.Generation{}, Hosts: []*storedHost{}}
	for _, ring := range rings {
		state.Rings = append(state.Rings, storedRing{Name: ring})
	}
	// Everything is owner-only; the CA certificate and public key are
	// handed out through enrollment, not by reading this directory.
	files := []struct {
		name string
		data []byte
	}{
		{api.CAFile, pemBlock("CERTIFICATE", ca.Raw)},
		{caKeyFile, pemBlock("PRIVATE KEY", caKeyDER)},
		{serverFile, serverPEM},
		{serverKeyFile, serverKeyPEM},
		{api.PublicKeyFile, options.PublicKey},
		{adminsFile, []byte("[]\n")},
	}
	for _, file := range files {
		if err := writePrivate(filepath.Join(options.Dir, file.name), file.data); err != nil {
			return err
		}
	}
	if err := localsec.CreateDir(filepath.Join(options.Dir, bundlesDir)); err != nil {
		return err
	}
	if err := writeJSON(filepath.Join(options.Dir, stateFile), state); err != nil {
		return err
	}
	// The configuration is written last: a directory without it is not a
	// service and can be removed and initialized again.
	return writeJSON(filepath.Join(options.Dir, configFile), config)
}

// Open loads a service directory created by Init.
func Open(dir string, audit *log.Logger) (*Service, error) {
	if audit == nil {
		audit = log.New(io.Discard, "", 0)
	}
	if err := localsec.ValidateManagerDir(dir); err != nil {
		return nil, fmt.Errorf("service directory: %w", err)
	}
	service := &Service{dir: dir, audit: audit, now: time.Now, changed: make(chan struct{}), wait: maxWait,
		lastSeen: map[string]time.Time{}, documents: map[uint64]policy.Document{}, digests: map[string]string{}}
	if err := readJSON(filepath.Join(dir, configFile), &service.config); err != nil {
		return nil, fmt.Errorf("read service configuration: %w", err)
	}
	if service.config.Version != configVersion || !validName(service.config.Organization) || len(service.config.Rings) == 0 {
		return nil, fmt.Errorf("unsupported or invalid service configuration")
	}
	var err error
	if service.publicKey, err = readFile(filepath.Join(dir, api.PublicKeyFile)); err != nil {
		return nil, err
	}
	if service.keyPrint, service.keyBits, err = publicKeyInfo(service.publicKey); err != nil {
		return nil, err
	}
	if service.caPEM, err = readFile(filepath.Join(dir, api.CAFile)); err != nil {
		return nil, err
	}
	if service.ca, err = parseCertificatePEM(service.caPEM); err != nil {
		return nil, fmt.Errorf("host CA: %w", err)
	}
	caKeyPEM, err := readPrivate(filepath.Join(dir, caKeyFile))
	if err != nil {
		return nil, err
	}
	if service.caKey, err = parseSignerPEM(caKeyPEM); err != nil {
		return nil, fmt.Errorf("host CA key: %w", err)
	}
	service.caPool = x509.NewCertPool()
	service.caPool.AddCert(service.ca)
	serverPEM, err := readFile(filepath.Join(dir, serverFile))
	if err != nil {
		return nil, err
	}
	serverKeyPEM, err := readPrivate(filepath.Join(dir, serverKeyFile))
	if err != nil {
		return nil, err
	}
	if service.serverCert, err = tls.X509KeyPair(serverPEM, serverKeyPEM); err != nil {
		return nil, fmt.Errorf("server certificate: %w", err)
	}
	if err := readJSON(filepath.Join(dir, stateFile), &service.state); err != nil {
		return nil, fmt.Errorf("read service state: %w", err)
	}
	if err := service.validateState(); err != nil {
		return nil, err
	}
	for _, host := range service.state.Hosts {
		if host.Report != nil {
			service.lastSeen[host.Certificate.Fingerprint] = host.Report.At
		}
	}
	if err := service.reloadAdmins(); err != nil {
		return nil, err
	}
	return service, nil
}

func (s *Service) validateState() error {
	st := &s.state
	if st.Version != stateVersion || len(st.Rings) != len(s.config.Rings) || len(st.Hosts) > maxHosts {
		return fmt.Errorf("invalid service state")
	}
	for i, ring := range st.Rings {
		if ring.Name != s.config.Rings[i] {
			return fmt.Errorf("service state rings do not match its configuration")
		}
	}
	for i, generation := range st.Generations {
		if generation.Number != uint64(i+1) {
			return fmt.Errorf("service state generations are not contiguous")
		}
	}
	for _, host := range st.Hosts {
		if !validName(host.Name) || s.ringIndex(host.Ring) < 0 || !strings.HasPrefix(host.Certificate.Fingerprint, "sha256:") {
			return fmt.Errorf("invalid enrolled host in service state")
		}
	}
	if st.Generations == nil {
		st.Generations = []api.Generation{}
	}
	return nil
}

// Organization is the organization this service publishes for.
func (s *Service) Organization() string { return s.config.Organization }

// FeedURL is the URL hosts poll.
func (s *Service) FeedURL() string { return s.config.URL + "/v1/feed" }

// URL is the service's base URL.
func (s *Service) URL() string { return s.config.URL }

// TLSConfig serves the feed and the administrator API on one listener:
// client certificates are verified when presented and required by the feed.
func (s *Service) TLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{s.serverCert},
		ClientAuth:   tls.VerifyClientCertIfGiven,
		ClientCAs:    s.caPool,
	}
}

// AddAdmin creates a named administrator token, stores only its hash, and
// returns the token. A running service picks it up on the next request.
func AddAdmin(dir, name string) (string, error) {
	if !validName(name) || len(name) > 64 {
		return "", fmt.Errorf("administrator name must be a short identifier")
	}
	path := filepath.Join(dir, adminsFile)
	var admins []storedAdmin
	if err := readJSON(path, &admins); err != nil {
		return "", fmt.Errorf("read administrators: %w", err)
	}
	for _, admin := range admins {
		if admin.Name == name {
			return "", fmt.Errorf("administrator %q already exists; remove it first", name)
		}
	}
	token, err := newToken()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(token))
	admins = append(admins, storedAdmin{Name: name, TokenSHA256: hex.EncodeToString(sum[:]), CreatedAt: time.Now().UTC()})
	return token, writeJSON(path, admins)
}

// RemoveAdmin revokes an administrator token.
func RemoveAdmin(dir, name string) error {
	path := filepath.Join(dir, adminsFile)
	var admins []storedAdmin
	if err := readJSON(path, &admins); err != nil {
		return fmt.Errorf("read administrators: %w", err)
	}
	kept := slices.DeleteFunc(slices.Clone(admins), func(admin storedAdmin) bool { return admin.Name == name })
	if len(kept) == len(admins) {
		return fmt.Errorf("no administrator named %q", name)
	}
	return writeJSON(path, kept)
}

// reloadAdmins rereads admins.json when it changed on disk.
func (s *Service) reloadAdmins() error {
	path := filepath.Join(s.dir, adminsFile)
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("administrators: %w", err)
	}
	if info.ModTime().Equal(s.adminsModTime) && info.Size() == s.adminsSize && s.admins != nil {
		return nil
	}
	var admins []storedAdmin
	if err := readJSON(path, &admins); err != nil {
		return fmt.Errorf("read administrators: %w", err)
	}
	if admins == nil {
		admins = []storedAdmin{}
	}
	s.admins, s.adminsModTime, s.adminsSize = admins, info.ModTime(), info.Size()
	return nil
}

// save persists state. Callers hold s.mu.
func (s *Service) saveLocked() error {
	s.reportsDirty = false
	return writeJSON(filepath.Join(s.dir, stateFile), s.state)
}

// FlushReports persists host reports whose only change was their time.
func (s *Service) FlushReports() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.reportsDirty {
		if err := s.saveLocked(); err != nil {
			s.audit.Printf("persist host reports: %v", err)
		}
	}
}

// notifyLocked wakes every waiting feed request. Callers hold s.mu.
func (s *Service) notifyLocked() {
	close(s.changed)
	s.changed = make(chan struct{})
}

func (s *Service) ringIndex(name string) int {
	return slices.Index(s.config.Rings, name)
}

// targetLocked is the generation a host should run: its ring's, but never
// below a generation it has already been served, since hosts refuse to go
// back and a host can move to an earlier ring.
func (s *Service) targetLocked(host *storedHost) uint64 {
	index := s.ringIndex(host.Ring)
	if index < 0 {
		return host.Served
	}
	return max(s.state.Rings[index].Generation, host.Served)
}

func (s *Service) latestLocked() uint64 { return uint64(len(s.state.Generations)) }

func (s *Service) bundlePath(generation uint64) string {
	return filepath.Join(s.dir, bundlesDir, strconv.FormatUint(generation, 10)+".tar.gz")
}

func (s *Service) bundleLocked(generation uint64) ([]byte, error) {
	if generation == 0 || generation > s.latestLocked() {
		return nil, fmt.Errorf("generation %d does not exist", generation)
	}
	raw, err := readFile(s.bundlePath(generation))
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != s.state.Generations[generation-1].BundleSHA256 {
		return nil, fmt.Errorf("stored bundle for generation %d does not match its record", generation)
	}
	return raw, nil
}

// documentLocked returns a generation's document as verified when it was
// published. History stays readable after a generation expires.
func (s *Service) documentLocked(generation uint64) (policy.Document, error) {
	if document, ok := s.documents[generation]; ok {
		return document, nil
	}
	if generation == 0 || generation > s.latestLocked() {
		return policy.Document{}, fmt.Errorf("generation %d does not exist", generation)
	}
	raw, err := readFile(s.documentPath(generation))
	if err != nil {
		return policy.Document{}, err
	}
	var root struct {
		Gantry policy.Document `json:"gantry"`
	}
	if err := json.Unmarshal(raw, &root); err != nil {
		return policy.Document{}, fmt.Errorf("stored document for generation %d: %w", generation, err)
	}
	s.documents[generation] = root.Gantry
	return root.Gantry, nil
}

func (s *Service) documentPath(generation uint64) string {
	return filepath.Join(s.dir, bundlesDir, strconv.FormatUint(generation, 10)+".json")
}

// expectedDigest is the digest a host reports for generation under profile;
// it binds the profile, bundle, and the pinned public key exactly as the
// receiver computes it.
func (s *Service) expectedDigestLocked(generation uint64, profile string) string {
	key := strconv.FormatUint(generation, 10) + "\x00" + profile
	if digest, ok := s.digests[key]; ok {
		return digest
	}
	raw, err := s.bundleLocked(generation)
	if err != nil {
		return ""
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte(profile))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write(raw)
	_, _ = hash.Write(s.publicKey)
	digest := hex.EncodeToString(hash.Sum(nil))
	s.digests[key] = digest
	return digest
}

func (s *Service) hostByFingerprintLocked(identity string) *storedHost {
	for _, host := range s.state.Hosts {
		if host.Certificate.Fingerprint == identity {
			return host
		}
	}
	return nil
}

func (s *Service) hostByNameLocked(name string) *storedHost {
	for _, host := range s.state.Hosts {
		if host.Name == name && !host.Revoked {
			return host
		}
	}
	for _, host := range s.state.Hosts {
		if host.Name == name {
			return host
		}
	}
	return nil
}

// statusLocked classifies a host from its latest report.
func (s *Service) statusLocked(host *storedHost, now time.Time) string {
	if host.Revoked {
		return api.HostRevoked
	}
	target := s.targetLocked(host)
	report := host.Report
	if report == nil {
		return api.HostNever
	}
	if seen, ok := s.lastSeen[host.Certificate.Fingerprint]; ok && now.Sub(seen) > api.SilentAfter {
		return api.HostSilent
	}
	if target == 0 {
		return api.HostIdle
	}
	switch {
	case report.RejectedGeneration == target && report.Applied < target && report.Pending != target:
		return api.HostRejected
	case report.Pending == target:
		if report.Attempts > 0 && (report.Failed == nil || *report.Failed > 0 || report.Attempts > 1) {
			return api.HostStalled
		}
		return api.HostPending
	case report.Applied >= target:
		if report.Applied == target && !report.DigestMatches {
			return api.HostMismatch
		}
		return api.HostCurrent
	case host.Served >= target:
		return api.HostOffered
	}
	return api.HostWaiting
}

func (s *Service) hostViewLocked(host *storedHost, now time.Time) api.Host {
	view := api.Host{
		Name: host.Name, Profile: host.Profile, Ring: host.Ring, Certificate: host.Certificate,
		Revoked: host.Revoked, RevokedAt: host.RevokedAt, RevokedBy: host.RevokedBy,
		Target: s.targetLocked(host), Served: host.Served, ServedAt: host.ServedAt,
		AcknowledgedAt: host.AcknowledgedAt, PollsSinceServed: host.PollsSinceServed,
		Status: s.statusLocked(host, now),
	}
	if seen, ok := s.lastSeen[host.Certificate.Fingerprint]; ok {
		seen := seen
		view.LastSeen = &seen
	}
	if host.Report != nil {
		report := *host.Report
		view.Report = &report
	}
	return view
}

func parseServiceURL(raw string) (base, host string, err error) {
	endpoint, err := url.Parse(raw)
	if err != nil || endpoint.Scheme != "https" || endpoint.Hostname() == "" || endpoint.User != nil ||
		endpoint.RawQuery != "" || endpoint.Fragment != "" || strings.Trim(endpoint.Path, "/") != "" {
		return "", "", fmt.Errorf("service URL must be https://HOST[:PORT] without a path, credentials, query, or fragment")
	}
	return "https://" + endpoint.Host, endpoint.Hostname(), nil
}

// ListenAddress is the default listener for the service URL's port.
func (s *Service) ListenAddress() string {
	endpoint, err := url.Parse(s.config.URL)
	if err != nil || endpoint.Port() == "" {
		return ":443"
	}
	return net.JoinHostPort("", endpoint.Port())
}

func validName(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, c := range value {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("._:-", c) {
			continue
		}
		return false
	}
	return true
}

func writeJSON(path string, value any) error {
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return writePrivate(path, append(raw, '\n'))
}

func writePrivate(path string, data []byte) error {
	if err := atomicfile.WriteFileDurable(path, data, 0o600); err != nil {
		return err
	}
	return localsec.SecureRegularFile(path)
}

func readJSON(path string, value any) error {
	raw, err := readFile(path)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	return decoder.Decode(value)
}

// readFile reads a bounded regular file owned by this account.
func readFile(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > maxStateBytes {
		return nil, fmt.Errorf("%s must be a regular file under %d bytes", filepath.Base(path), maxStateBytes)
	}
	if err := localsec.SecureRegularFile(path); err != nil {
		return nil, err
	}
	return os.ReadFile(path)
}

func readPrivate(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s must not be accessible to other accounts", filepath.Base(path))
	}
	return readFile(path)
}

var errNotFound = errors.New("not found")
