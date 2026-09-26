package manager

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/ejpir/gantry/api/managerapi"
	api "github.com/ejpir/gantry/api/policyservice"
	"github.com/ejpir/gantry/internal/atomicfile"
	"github.com/ejpir/gantry/internal/policyfeed"
	"github.com/ejpir/gantry/internal/policyservice"
	"github.com/ejpir/gantry/internal/sandbox/localsec"
)

// Feed enrollment is deliberately staged: the manager cannot claim to enforce
// the new organization policy until it restarts with -policy-feed. This is
// manager-owned state, never a general-purpose remote filesystem write API.
type feedEnrollment struct {
	ID string `json:"id"`
	managerapi.PolicyFeedPrepareRequest
}

func (m *managerService) feedStatus() (managerapi.PolicyFeedStatus, error) {
	status := managerapi.PolicyFeedStatus{EnrollmentState: "none"}
	if m.feedConfigured {
		status.EnrollmentState = "configured"
	}
	if m.feedEnrollmentDir == "" {
		return status, nil
	}
	if _, err := os.Lstat(m.feedEnrollmentDir); errors.Is(err, os.ErrNotExist) {
		return status, nil
	} else if err != nil {
		return status, err
	}
	meta, err := readEnrollment(m.feedEnrollmentDir)
	if err != nil {
		return status, err
	}
	status.Host, status.Organization, status.Profile = meta.Host, meta.Organization, meta.Profile
	config := filepath.Join(m.feedEnrollmentDir, api.FeedConfigFile)
	if !m.feedConfigured {
		status.EnrollmentState = "awaiting-enrollment"
	}
	if _, err := readEnrollmentFile(filepath.Join(m.feedEnrollmentDir, "installed.json"), 256); err == nil {
		status.ConfigPath = config
		status.EnrollmentState = "restart-required"
		if m.feedConfigured {
			status.EnrollmentState = "configured"
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return status, err
	}
	return status, nil
}

func (m *managerService) handleFeedEnrollmentStatus(w http.ResponseWriter, _ *http.Request) {
	m.feedMu.Lock()
	defer m.feedMu.Unlock()
	status, err := m.feedStatus()
	if err != nil {
		writeManagerError(w, http.StatusConflict, err, "")
		return
	}
	writeManagerJSON(w, http.StatusOK, status)
}

func (m *managerService) handlePrepareFeedEnrollment(w http.ResponseWriter, r *http.Request) {
	var request managerapi.PolicyFeedPrepareRequest
	if _, err := decodeManagerJSON(r, &request); err != nil {
		writeManagerError(w, http.StatusBadRequest, err, "")
		return
	}
	if !validEnrollmentName(request.Host) || !validEnrollmentName(request.Organization) || !validEnrollmentName(request.Profile) ||
		!validFingerprint(request.PublicKeyFingerprint) || !validFingerprint(request.CAFingerprint) ||
		!validFeedURL(request.URL) {
		writeManagerError(w, http.StatusBadRequest, fmt.Errorf("invalid feed identity or trust pin"), "")
		return
	}
	m.feedMu.Lock()
	defer m.feedMu.Unlock()
	if m.feedEnrollmentDir == "" || m.feedConfigured {
		writeManagerError(w, http.StatusConflict, fmt.Errorf("manager feed enrollment is unavailable or already configured"), "")
		return
	}
	if current, err := readEnrollment(m.feedEnrollmentDir); err == nil {
		if current.PolicyFeedPrepareRequest != request {
			writeManagerError(w, http.StatusConflict, fmt.Errorf("another feed enrollment is already staged"), "")
			return
		}
		csr, err := readEnrollmentFile(filepath.Join(m.feedEnrollmentDir, api.HostRequestFile), 64<<10)
		if err != nil {
			writeManagerError(w, http.StatusConflict, err, "")
			return
		}
		writeManagerJSON(w, http.StatusOK, managerapi.PolicyFeedPrepareResponse{ID: current.ID, CSR: string(csr)})
		return
	} else if !errors.Is(err, os.ErrNotExist) {
		writeManagerError(w, http.StatusConflict, err, "")
		return
	}
	parent := filepath.Dir(m.feedEnrollmentDir)
	if err := localsec.CreateManagerDir(parent); err != nil {
		writeManagerError(w, http.StatusConflict, err, "")
		return
	}
	// os.Mkdir is exclusive. A planted or incomplete directory is never reused.
	if err := os.Mkdir(m.feedEnrollmentDir, 0o700); err != nil {
		writeManagerError(w, http.StatusConflict, err, "")
		return
	}
	if err := localsec.CreateManagerDir(m.feedEnrollmentDir); err != nil {
		writeManagerError(w, http.StatusConflict, err, "")
		return
	}
	key, csr, err := policyservice.NewHostRequest(request.Host)
	var random [16]byte
	if err == nil {
		_, err = rand.Read(random[:])
	}
	meta := feedEnrollment{ID: hex.EncodeToString(random[:]), PolicyFeedPrepareRequest: request}
	if err == nil {
		err = atomicfile.WriteFileDurable(filepath.Join(m.feedEnrollmentDir, api.HostKeyFile), key, 0o600)
	}
	if err == nil {
		err = localsec.SecureRegularFile(filepath.Join(m.feedEnrollmentDir, api.HostKeyFile))
	}
	if err == nil {
		err = atomicfile.WriteFileDurable(filepath.Join(m.feedEnrollmentDir, api.HostRequestFile), csr, 0o600)
	}
	if err == nil {
		var raw []byte
		raw, err = json.Marshal(meta)
		if err == nil {
			err = atomicfile.WriteFileDurable(filepath.Join(m.feedEnrollmentDir, "request.json"), raw, 0o600)
		}
	}
	if err != nil {
		writeManagerError(w, http.StatusConflict, fmt.Errorf("stage feed request: %w", err), "")
		return
	}
	writeManagerJSON(w, http.StatusCreated, managerapi.PolicyFeedPrepareResponse{ID: meta.ID, CSR: string(csr)})
}

func (m *managerService) handleInstallFeedEnrollment(w http.ResponseWriter, r *http.Request) {
	var request managerapi.PolicyFeedInstallRequest
	if _, err := decodeManagerJSON(r, &request); err != nil {
		writeManagerError(w, http.StatusBadRequest, err, "")
		return
	}
	m.feedMu.Lock()
	defer m.feedMu.Unlock()
	meta, err := readEnrollment(m.feedEnrollmentDir)
	if err != nil || meta.ID != request.ID {
		writeManagerError(w, http.StatusConflict, fmt.Errorf("no matching pending host request"), "")
		return
	}
	if err := validateEnrollmentFiles(meta, m.feedEnrollmentDir, request.Files); err != nil {
		writeManagerError(w, http.StatusUnprocessableEntity, err, "")
		return
	}
	for _, name := range []string{api.HostCertFile, api.CAFile, api.PublicKeyFile, api.FeedConfigFile} {
		path := filepath.Join(m.feedEnrollmentDir, name)
		if raw, err := readEnrollmentFile(path, 64<<10); err == nil {
			if !bytes.Equal(raw, []byte(request.Files[name])) {
				writeManagerError(w, http.StatusConflict, fmt.Errorf("enrollment file already differs"), "")
				return
			}
			continue
		} else if !errors.Is(err, os.ErrNotExist) {
			writeManagerError(w, http.StatusConflict, err, "")
			return
		}
		if err := atomicfile.WriteFileDurable(path, []byte(request.Files[name]), 0o600); err != nil {
			writeManagerError(w, http.StatusConflict, err, "")
			return
		}
		if err := localsec.SecureRegularFile(path); err != nil {
			writeManagerError(w, http.StatusConflict, err, "")
			return
		}
	}
	if _, err := policyfeed.LoadConfig(filepath.Join(m.feedEnrollmentDir, api.FeedConfigFile)); err != nil {
		writeManagerError(w, http.StatusUnprocessableEntity, err, "")
		return
	}
	// Only a verified, installed feed reserves the mandatory policy-feeds
	// state. A CSR with no enrollment must not brick a later manager restart.
	if err := localsec.CreateManagerDir(filepath.Join(filepath.Dir(m.feedEnrollmentDir), "policy-feeds")); err != nil {
		writeManagerError(w, http.StatusConflict, err, "")
		return
	}
	if err := atomicfile.WriteFileDurable(filepath.Join(m.feedEnrollmentDir, "installed.json"), []byte("{}\n"), 0o600); err != nil {
		writeManagerError(w, http.StatusConflict, err, "")
		return
	}
	status, err := m.feedStatus()
	if err != nil {
		writeManagerError(w, http.StatusConflict, err, "")
		return
	}
	writeManagerJSON(w, http.StatusOK, status)
}

func readEnrollment(dir string) (feedEnrollment, error) {
	var meta feedEnrollment
	if dir == "" {
		return meta, os.ErrNotExist
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return meta, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return meta, fmt.Errorf("feed enrollment directory is not private")
	}
	raw, err := readEnrollmentFile(filepath.Join(dir, "request.json"), 64<<10)
	if err != nil {
		return meta, err
	}
	if err := json.Unmarshal(raw, &meta); err != nil || len(meta.ID) != 32 {
		return meta, fmt.Errorf("invalid saved feed enrollment")
	}
	return meta, nil
}

func readEnrollmentFile(path string, limit int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() > limit {
		return nil, fmt.Errorf("unsafe feed enrollment file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	if stat, err := file.Stat(); err != nil || !stat.Mode().IsRegular() || stat.Size() > limit {
		return nil, fmt.Errorf("unsafe feed enrollment file")
	}
	raw, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(raw)) > limit {
		return nil, fmt.Errorf("read feed enrollment file failed or exceeds limit")
	}
	return raw, nil
}

func validateEnrollmentFiles(meta feedEnrollment, dir string, files map[string]string) error {
	if len(files) != 4 {
		return fmt.Errorf("expected exactly four public enrollment files")
	}
	for _, name := range []string{api.FeedConfigFile, api.HostCertFile, api.CAFile, api.PublicKeyFile} {
		if files[name] == "" || len(files[name]) > 64<<10 {
			return fmt.Errorf("missing or oversized enrollment file %s", name)
		}
	}
	var cfg policyfeed.Config
	decoder := json.NewDecoder(strings.NewReader(files[api.FeedConfigFile]))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cfg); err != nil {
		return fmt.Errorf("invalid feed configuration: %w", err)
	}
	if cfg.Version != 1 || cfg.Organization != meta.Organization || cfg.Profile != meta.Profile || cfg.URL != meta.URL ||
		cfg.ClientKey != api.HostKeyFile || cfg.ClientCertificate != api.HostCertFile ||
		cfg.CAFile != api.CAFile || cfg.PublicKeyFile != api.PublicKeyFile {
		return fmt.Errorf("feed configuration differs from the approved identity")
	}
	pub, rest := pem.Decode([]byte(files[api.PublicKeyFile]))
	if pub == nil || len(bytes.TrimSpace(rest)) != 0 {
		return fmt.Errorf("invalid organization verification key")
	}
	var parsed any
	var err error
	switch pub.Type {
	case "PUBLIC KEY":
		parsed, err = x509.ParsePKIXPublicKey(pub.Bytes)
	case "RSA PUBLIC KEY":
		parsed, err = x509.ParsePKCS1PublicKey(pub.Bytes)
	default:
		return fmt.Errorf("invalid organization verification key")
	}
	if err != nil {
		return err
	}
	der, err := x509.MarshalPKIXPublicKey(parsed)
	if err != nil || pin(der) != meta.PublicKeyFingerprint {
		return fmt.Errorf("organization verification key does not match the approved pin")
	}
	caBlock, rest := pem.Decode([]byte(files[api.CAFile]))
	if caBlock == nil || caBlock.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return fmt.Errorf("invalid feed CA")
	}
	ca, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil || pin(ca.Raw) != meta.CAFingerprint {
		return fmt.Errorf("feed CA does not match the approved pin")
	}
	certBlock, rest := pem.Decode([]byte(files[api.HostCertFile]))
	if certBlock == nil || certBlock.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return fmt.Errorf("invalid host certificate")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return err
	}
	if cert.Subject.CommonName != meta.Host || len(cert.Subject.Organization) != 1 || cert.Subject.Organization[0] != meta.Organization {
		return fmt.Errorf("host certificate belongs to another identity")
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	if _, err := cert.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return fmt.Errorf("host certificate is not signed by the approved CA: %w", err)
	}
	key, err := readEnrollmentFile(filepath.Join(dir, api.HostKeyFile), 64<<10)
	if err != nil {
		return err
	}
	if _, err := tls.X509KeyPair([]byte(files[api.HostCertFile]), key); err != nil {
		return fmt.Errorf("host certificate does not match the private key")
	}
	return nil
}

func pin(raw []byte) string {
	digest := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func validFingerprint(value string) bool {
	if !strings.HasPrefix(value, "sha256:") || len(value) != 71 {
		return false
	}
	for _, c := range value[7:] {
		if !strings.ContainsRune("0123456789abcdef", c) {
			return false
		}
	}
	return true
}

func validEnrollmentName(value string) bool {
	if len(value) == 0 || len(value) > 64 || value == "." || value == ".." {
		return false
	}
	for _, r := range value {
		if r != '-' && r != '_' && r != '.' && (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') {
			return false
		}
	}
	return true
}

func validFeedURL(value string) bool {
	// The exact service URL is pinned by the administrator's verified profile.
	endpoint, err := url.Parse(value)
	return err == nil && len(value) <= 2048 && endpoint.Scheme == "https" && endpoint.Hostname() != "" &&
		endpoint.User == nil && endpoint.RawQuery == "" && !endpoint.ForceQuery && endpoint.Fragment == "" && endpoint.Opaque == "" &&
		!strings.ContainsAny(value, "\\\r\n\t ")
}
