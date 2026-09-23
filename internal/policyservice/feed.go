package policyservice

import (
	"encoding/json"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	api "github.com/ejpir/gantry/api/policyservice"
	"github.com/ejpir/gantry/internal/policyfeed"
)

// maxWait bounds a long poll below the receiver's 45 s client timeout.
const maxWait = 30 * time.Second

type feedResponse struct {
	Version      int    `json:"version"`
	Organization string `json:"organization"`
	Generation   uint64 `json:"generation"`
	Bundle       []byte `json:"bundle"`
}

// handleFeed serves one host its target generation. The host is identified
// only by its verified client certificate. A request whose If-None-Match
// already names the target is held until something changes or the host's
// Prefer: wait expires, so publishing reaches connected hosts at once.
func (s *Service) handleFeed(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.VerifiedChains[0]) == 0 {
		writeError(w, http.StatusForbidden, "a client certificate issued by this service is required")
		return
	}
	identity := fingerprint(r.TLS.VerifiedChains[0][0].Raw)
	s.mu.Lock()
	host := s.hostByFingerprintLocked(identity)
	if host == nil || host.Revoked {
		s.mu.Unlock()
		writeError(w, http.StatusForbidden, "this host is not enrolled")
		return
	}
	s.recordReportLocked(host, r)
	s.mu.Unlock()

	wait := min(preferWait(r.Header.Get("Prefer")), s.wait)
	timer := time.NewTimer(wait)
	defer timer.Stop()
	for {
		s.mu.Lock()
		if host.Revoked {
			s.mu.Unlock()
			writeError(w, http.StatusForbidden, "this host is not enrolled")
			return
		}
		target := s.targetLocked(host)
		changed := s.changed
		etag := `"g` + strconv.FormatUint(target, 10) + `"`
		if target == 0 || r.Header.Get("If-None-Match") == etag {
			s.mu.Unlock()
			if wait <= 0 {
				w.WriteHeader(http.StatusNotModified)
				return
			}
			select {
			case <-changed:
				continue
			case <-timer.C:
				w.WriteHeader(http.StatusNotModified)
				return
			case <-r.Context().Done():
				return
			}
		}
		bundle, err := s.bundleLocked(target)
		if err != nil {
			s.mu.Unlock()
			s.audit.Printf("feed %s: %v", host.Name, err)
			writeError(w, http.StatusInternalServerError, "generation unavailable")
			return
		}
		s.markServedLocked(host, target)
		s.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("ETag", etag)
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(feedResponse{Version: 1, Organization: s.config.Organization, Generation: target, Bundle: bundle})
		return
	}
}

func (s *Service) markServedLocked(host *storedHost, generation uint64) {
	if generation <= host.Served {
		return
	}
	now := s.now().UTC()
	host.Served = generation
	host.ServedAt = &now
	host.AcknowledgedAt = nil
	host.PollsSinceServed = 0
	if err := s.saveLocked(); err != nil {
		s.audit.Printf("persist served generation for %s: %v", host.Name, err)
	}
	s.audit.Printf("feed: served generation %d to %s", generation, host.Name)
}

// recordReportLocked stores what the host reported about itself. Invalid
// values are dropped rather than trusted; the report is advisory and never
// changes what the host is served.
func (s *Service) recordReportLocked(host *storedHost, r *http.Request) {
	now := s.now().UTC()
	header := r.Header
	report := api.HostReport{At: now}
	report.Applied = parseGeneration(header.Get("X-Gantry-Policy-Generation"))
	if report.Applied != 0 {
		digest := header.Get("X-Gantry-Policy-Digest")
		report.DigestMatches = len(digest) == 64 && digest == s.expectedDigestLocked(report.Applied, host.Profile)
	}
	report.Pending = parseGeneration(header.Get("X-Gantry-Policy-Pending-Generation"))
	if report.Pending != 0 {
		report.Attempts = parseCount(header.Get("X-Gantry-Policy-Pending-Attempts"))
		if failed := header.Get("X-Gantry-Policy-Pending-Failed"); failed != "" && failed != "unknown" {
			count := parseCount(failed)
			report.Failed = &count
		}
	}
	switch reason := header.Get("X-Gantry-Policy-Rejected-Reason"); reason {
	case policyfeed.RejectInvalid, policyfeed.RejectVerification, policyfeed.RejectOrganization, policyfeed.RejectRollback, policyfeed.RejectChanged:
		report.RejectedReason = reason
		report.RejectedGeneration = parseGeneration(header.Get("X-Gantry-Policy-Rejected-Generation"))
	}
	if profile := header.Get("X-Gantry-Policy-Profile"); validName(profile) {
		report.Profile = profile
	}
	if agent := header.Get("User-Agent"); len(agent) <= 64 && printable(agent) {
		report.Agent = agent
	}
	if address, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		report.Address = address
	}
	s.lastSeen[host.Certificate.Fingerprint] = now

	if host.Served != 0 && report.Applied < host.Served {
		host.PollsSinceServed++
	}
	if host.Served != 0 && report.Applied >= host.Served && host.AcknowledgedAt == nil {
		host.AcknowledgedAt = &now
		s.audit.Printf("feed: %s acknowledged generation %d", host.Name, report.Applied)
	}
	previous := host.Report
	host.Report = &report
	if previous != nil && sameReport(*previous, report) {
		s.reportsDirty = true
		return
	}
	if err := s.saveLocked(); err != nil {
		s.audit.Printf("persist report for %s: %v", host.Name, err)
	}
}

func sameReport(a, b api.HostReport) bool {
	failed := func(value *int) int {
		if value == nil {
			return -1
		}
		return *value
	}
	return a.Applied == b.Applied && a.DigestMatches == b.DigestMatches && a.Pending == b.Pending &&
		a.Attempts == b.Attempts && failed(a.Failed) == failed(b.Failed) &&
		a.RejectedGeneration == b.RejectedGeneration && a.RejectedReason == b.RejectedReason &&
		a.Profile == b.Profile && a.Agent == b.Agent && a.Address == b.Address
}

// preferWait parses RFC 7240 "Prefer: wait=N", bounded by maxWait.
func preferWait(value string) time.Duration {
	for _, part := range strings.Split(value, ",") {
		name, number, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok || !strings.EqualFold(strings.TrimSpace(name), "wait") {
			continue
		}
		seconds, err := strconv.Atoi(strings.TrimSpace(number))
		if err != nil || seconds <= 0 {
			return 0
		}
		return min(time.Duration(seconds)*time.Second, maxWait)
	}
	return 0
}

func parseGeneration(value string) uint64 {
	if value == "" || len(value) > 20 {
		return 0
	}
	number, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		return 0
	}
	return number
}

func parseCount(value string) int {
	number, err := strconv.Atoi(value)
	if err != nil || number < 0 || number > 1<<20 {
		return 0
	}
	return number
}

func printable(value string) bool {
	for _, r := range value {
		if r < 0x20 || r > 0x7e {
			return false
		}
	}
	return true
}
