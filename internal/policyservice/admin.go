package policyservice

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	api "github.com/ejpir/gantry/api/policyservice"
	"github.com/ejpir/gantry/internal/netpol"
	"github.com/ejpir/gantry/internal/policy"
)

const maxAdminBody = 3 << 20

// Handler routes the feed and the administrator API.
func (s *Service) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/feed", s.handleFeed)
	admin := func(pattern string, handler func(http.ResponseWriter, *http.Request, string)) {
		mux.HandleFunc(pattern, s.authenticated(handler))
	}
	admin("GET /v1/health", s.handleHealth)
	admin("GET /v1/admin/overview", s.handleOverview)
	admin("GET /v1/admin/hosts", s.handleHosts)
	admin("POST /v1/admin/hosts", s.handleEnroll)
	admin("PATCH /v1/admin/hosts/{name}", s.handleUpdateHost)
	admin("POST /v1/admin/hosts/{name}/revoke", s.handleRevoke)
	admin("GET /v1/admin/generations", s.handleGenerations)
	admin("POST /v1/admin/generations", s.handlePublish)
	admin("GET /v1/admin/generations/{n}", s.handleGeneration)
	admin("GET /v1/admin/generations/{n}/bundle", s.handleBundle)
	admin("POST /v1/admin/generations/{n}/republish", s.handleRepublish)
	admin("POST /v1/admin/rollout/promote", s.handlePromote)
	admin("GET /v1/admin/draft", s.handleDraft)
	admin("PUT /v1/admin/draft", s.handleSaveDraft)
	admin("DELETE /v1/admin/draft", s.handleDiscardDraft)
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		writeError(w, http.StatusNotFound, "not found: this is a Gantry policy service, not a sandbox manager")
	})
	return mux
}

// authenticated requires a named administrator's bearer token. Every failure
// is the same 403; the token is compared by hash in constant time.
func (s *Service) authenticated(handler func(http.ResponseWriter, *http.Request, string)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		scheme, token, found := strings.Cut(r.Header.Get("Authorization"), " ")
		if !found || !strings.EqualFold(scheme, "bearer") || len(token) < 16 || len(token) > 256 {
			writeError(w, http.StatusForbidden, "access denied")
			return
		}
		presented := sha256.Sum256([]byte(token))
		s.mu.Lock()
		if err := s.reloadAdmins(); err != nil {
			s.audit.Printf("administrators: %v", err)
		}
		name := ""
		for _, admin := range s.admins {
			known, err := hex.DecodeString(admin.TokenSHA256)
			if err == nil && subtle.ConstantTimeCompare(presented[:], known) == 1 {
				name = admin.Name
			}
		}
		s.mu.Unlock()
		if name == "" {
			writeError(w, http.StatusForbidden, "access denied")
			return
		}
		if r.Method != http.MethodGet {
			s.audit.Printf("admin %s: %s %s", name, r.Method, r.URL.Path)
		}
		handler(w, r, name)
	}
}

func (s *Service) handleHealth(w http.ResponseWriter, _ *http.Request, _ string) {
	writeJSONResponse(w, http.StatusOK, api.Health{OK: true, Version: "v1", Capabilities: []string{api.CapabilityAdmin}})
}

func (s *Service) handleOverview(w http.ResponseWriter, _ *http.Request, admin string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	writeJSONResponse(w, http.StatusOK, s.overviewLocked(admin, s.now().UTC()))
}

func (s *Service) overviewLocked(admin string, now time.Time) api.Overview {
	overview := api.Overview{
		Organization: s.config.Organization, FeedURL: s.FeedURL(), PublicKeyFingerprint: s.keyPrint,
		PublicKeyBits: s.keyBits, CAFingerprint: fingerprint(s.ca.Raw), CAExpiresAt: s.ca.NotAfter.UTC(),
		Admin: admin, Latest: s.latestLocked(), Rings: []api.Ring{},
	}
	ringHosts := map[string]int{}
	applied := map[uint64]bool{}
	for _, host := range s.state.Hosts {
		status := s.statusLocked(host, now)
		if host.Revoked {
			overview.Hosts.Revoked++
			continue
		}
		overview.Hosts.Enrolled++
		ringHosts[host.Ring]++
		switch status {
		case api.HostCurrent:
			overview.Hosts.Current++
		case api.HostStalled:
			overview.Hosts.Stalled++
		case api.HostRejected, api.HostMismatch:
			overview.Hosts.Rejected++
		case api.HostSilent, api.HostNever:
			overview.Hosts.Silent++
		case api.HostWaiting, api.HostOffered, api.HostPending:
			overview.Hosts.Behind++
		}
		if host.Report != nil && host.Report.Applied != 0 {
			applied[host.Report.Applied] = true
		}
	}
	for _, ring := range s.state.Rings {
		overview.Rings = append(overview.Rings, api.Ring{Name: ring.Name, Generation: ring.Generation, Hosts: ringHosts[ring.Name]})
	}
	for generation := range applied {
		if generation <= s.latestLocked() {
			expires := s.state.Generations[generation-1].ExpiresAt
			if overview.NextExpiry == nil || expires.Before(*overview.NextExpiry) {
				overview.NextExpiry = &expires
			}
		}
	}
	if rollout := s.state.Rollout; rollout != nil {
		view := &api.Rollout{Generation: rollout.Generation, StartedAt: rollout.StartedAt, StartedBy: rollout.StartedBy, Complete: true}
		for _, ring := range s.state.Rings {
			entry := api.RolloutRing{Name: ring.Name}
			if ring.Generation >= rollout.Generation {
				entry.PromotedAt, entry.PromotedBy = ring.PromotedAt, ring.PromotedBy
			}
			for _, host := range s.state.Hosts {
				if host.Revoked || host.Ring != ring.Name {
					continue
				}
				entry.Hosts++
				if s.targetLocked(host) < rollout.Generation {
					continue
				}
				switch s.statusLocked(host, now) {
				case api.HostCurrent:
					entry.Acknowledged++
				case api.HostStalled:
					entry.Stalled++
				case api.HostRejected, api.HostMismatch:
					entry.Rejected++
				default:
					entry.Offered++
				}
			}
			if entry.Acknowledged != entry.Hosts {
				view.Complete = false
			}
			view.Rings = append(view.Rings, entry)
		}
		overview.Rollout = view
	}
	return overview
}

func (s *Service) handleHosts(w http.ResponseWriter, _ *http.Request, _ string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now().UTC()
	hosts := make([]api.Host, 0, len(s.state.Hosts))
	for _, host := range s.state.Hosts {
		hosts = append(hosts, s.hostViewLocked(host, now))
	}
	slices.SortStableFunc(hosts, func(a, b api.Host) int {
		if a.Revoked != b.Revoked {
			if a.Revoked {
				return 1
			}
			return -1
		}
		if ring := s.ringIndex(a.Ring) - s.ringIndex(b.Ring); ring != 0 {
			return ring
		}
		return strings.Compare(a.Name, b.Name)
	})
	writeJSONResponse(w, http.StatusOK, hosts)
}

func (s *Service) handleEnroll(w http.ResponseWriter, r *http.Request, admin string) {
	var request api.EnrollRequest
	if !decodeBody(w, r, &request) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !validName(request.Name) || len(request.Name) > 64 {
		writeError(w, http.StatusUnprocessableEntity, "host name must be a short identifier")
		return
	}
	if existing := s.hostByNameLocked(request.Name); existing != nil && !existing.Revoked {
		writeError(w, http.StatusConflict, fmt.Sprintf("host %q is already enrolled; revoke it first", request.Name))
		return
	}
	if s.ringIndex(request.Ring) < 0 {
		writeError(w, http.StatusUnprocessableEntity, "unknown ring "+strconv.Quote(request.Ring))
		return
	}
	if !validName(request.Profile) {
		writeError(w, http.StatusUnprocessableEntity, "profile must be an identifier")
		return
	}
	if latest := s.latestLocked(); latest != 0 {
		document, err := s.documentLocked(latest)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if _, ok := document.Profiles[request.Profile]; !ok {
			writeError(w, http.StatusUnprocessableEntity, fmt.Sprintf("profile %q is not in generation %d", request.Profile, latest))
			return
		}
	}
	if len(s.state.Hosts) >= maxHosts {
		writeError(w, http.StatusConflict, "host limit reached")
		return
	}
	now := s.now().UTC()
	certificate, err := signHostRequest(s.ca, s.caKey, s.config.Organization, request.Name, []byte(request.CSR), now)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	host := &storedHost{Name: request.Name, Profile: request.Profile, Ring: request.Ring, Certificate: api.HostCertificate{
		Serial: certificate.SerialNumber.Text(16), Fingerprint: fingerprint(certificate.Raw),
		NotAfter: certificate.NotAfter.UTC(), IssuedAt: now, IssuedBy: admin,
	}}
	s.state.Hosts = append(s.state.Hosts, host)
	if err := s.saveLocked(); err != nil {
		s.state.Hosts = s.state.Hosts[:len(s.state.Hosts)-1]
		writeError(w, http.StatusInternalServerError, "save enrollment: "+err.Error())
		return
	}
	s.audit.Printf("admin %s: enrolled %s (%s, %s)", admin, host.Name, host.Profile, host.Ring)
	feed, _ := json.MarshalIndent(map[string]any{
		"version":            1,
		"organization":       s.config.Organization,
		"profile":            host.Profile,
		"url":                s.FeedURL(),
		"public_key":         api.PublicKeyFile,
		"ca_file":            api.CAFile,
		"client_certificate": api.HostCertFile,
		"client_key":         api.HostKeyFile,
	}, "", "  ")
	writeJSONResponse(w, http.StatusCreated, api.Enrollment{
		Host: s.hostViewLocked(host, now),
		Files: map[string]string{
			api.FeedConfigFile: string(feed) + "\n",
			api.HostCertFile:   string(pemBlock("CERTIFICATE", certificate.Raw)),
			api.CAFile:         string(s.caPEM),
			api.PublicKeyFile:  string(s.publicKey),
		},
	})
}

func (s *Service) handleUpdateHost(w http.ResponseWriter, r *http.Request, admin string) {
	var request api.HostUpdate
	if !decodeBody(w, r, &request) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	host := s.hostByNameLocked(r.PathValue("name"))
	if host == nil || host.Revoked {
		writeError(w, http.StatusNotFound, "no enrolled host by that name")
		return
	}
	if s.ringIndex(request.Ring) < 0 {
		writeError(w, http.StatusUnprocessableEntity, "unknown ring "+strconv.Quote(request.Ring))
		return
	}
	previous := host.Ring
	host.Ring = request.Ring
	if err := s.saveLocked(); err != nil {
		host.Ring = previous
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit.Printf("admin %s: moved %s from %s to %s", admin, host.Name, previous, host.Ring)
	s.notifyLocked()
	writeJSONResponse(w, http.StatusOK, s.hostViewLocked(host, s.now().UTC()))
}

func (s *Service) handleRevoke(w http.ResponseWriter, r *http.Request, admin string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	host := s.hostByNameLocked(r.PathValue("name"))
	if host == nil || host.Revoked {
		writeError(w, http.StatusNotFound, "no enrolled host by that name")
		return
	}
	now := s.now().UTC()
	host.Revoked, host.RevokedAt, host.RevokedBy = true, &now, admin
	if err := s.saveLocked(); err != nil {
		host.Revoked, host.RevokedAt, host.RevokedBy = false, nil, ""
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit.Printf("admin %s: revoked %s", admin, host.Name)
	s.notifyLocked()
	writeJSONResponse(w, http.StatusOK, s.hostViewLocked(host, now))
}

func (s *Service) handleGenerations(w http.ResponseWriter, _ *http.Request, _ string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	counts := s.appliedCountsLocked()
	generations := make([]api.Generation, 0, len(s.state.Generations))
	for i := len(s.state.Generations) - 1; i >= 0; i-- {
		generation := s.state.Generations[i]
		generation.Hosts = counts[generation.Number]
		generations = append(generations, generation)
	}
	writeJSONResponse(w, http.StatusOK, generations)
}

func (s *Service) appliedCountsLocked() map[uint64]int {
	counts := map[uint64]int{}
	for _, host := range s.state.Hosts {
		if !host.Revoked && host.Report != nil && host.Report.Applied != 0 {
			counts[host.Report.Applied]++
		}
	}
	return counts
}

func (s *Service) generationParam(w http.ResponseWriter, r *http.Request) (uint64, bool) {
	number, err := strconv.ParseUint(r.PathValue("n"), 10, 64)
	if err != nil || number == 0 || number > s.latestLocked() {
		writeError(w, http.StatusNotFound, "no such generation")
		return 0, false
	}
	return number, true
}

func (s *Service) handleGeneration(w http.ResponseWriter, r *http.Request, _ string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	number, ok := s.generationParam(w, r)
	if !ok {
		return
	}
	document, err := s.documentLocked(number)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	data, err := rootData(document)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	generation := s.state.Generations[number-1]
	generation.Hosts = s.appliedCountsLocked()[number]
	writeJSONResponse(w, http.StatusOK, api.GenerationDetail{Generation: generation, Data: data})
}

func (s *Service) handleBundle(w http.ResponseWriter, r *http.Request, _ string) {
	s.mu.Lock()
	number, ok := s.generationParam(w, r)
	if !ok {
		s.mu.Unlock()
		return
	}
	raw, err := s.bundleLocked(number)
	s.mu.Unlock()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s-g%d.tar.gz"`, s.config.Organization, number))
	_, _ = w.Write(raw)
}

func (s *Service) handlePublish(w http.ResponseWriter, r *http.Request, admin string) {
	var request api.PublishRequest
	if !decodeBody(w, r, &request) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(request.Bundle) == 0 || len(request.Bundle) > policy.MaxBundleBytes {
		writeError(w, http.StatusUnprocessableEntity, fmt.Sprintf("bundle must be 1..%d bytes", policy.MaxBundleBytes))
		return
	}
	if latest := s.latestLocked(); latest != 0 {
		sum := sha256.Sum256(request.Bundle)
		if hex.EncodeToString(sum[:]) == s.state.Generations[latest-1].BundleSHA256 {
			writeError(w, http.StatusConflict, fmt.Sprintf("this bundle is already generation %d", latest))
			return
		}
	}
	generation, status, err := s.publishLocked(request.Bundle, request.FirstRing, 0, admin)
	if err != nil {
		writeError(w, status, err.Error())
		return
	}
	writeJSONResponse(w, http.StatusCreated, generation)
}

func (s *Service) handleRepublish(w http.ResponseWriter, r *http.Request, admin string) {
	var request api.RepublishRequest
	if !decodeBody(w, r, &request) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	number, ok := s.generationParam(w, r)
	if !ok {
		return
	}
	raw, err := s.bundleLocked(number)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	generation, status, err := s.publishLocked(raw, request.FirstRing, number, admin)
	if err != nil {
		writeError(w, status, err.Error())
		return
	}
	writeJSONResponse(w, http.StatusCreated, generation)
}

// publishLocked verifies a signed bundle with the pinned key, records it as
// the next generation, and starts its rollout at firstRing (earlier rings
// included). Generation numbers are never reused.
func (s *Service) publishLocked(raw []byte, firstRing string, republishOf uint64, admin string) (api.Generation, int, error) {
	document, err := policy.VerifyBundle(raw, string(s.publicKey))
	if err != nil {
		return api.Generation{}, http.StatusUnprocessableEntity, fmt.Errorf("bundle does not verify with the organization key: %w", err)
	}
	if document.Organization != s.config.Organization {
		return api.Generation{}, http.StatusUnprocessableEntity, fmt.Errorf("bundle is for organization %q, not %q", document.Organization, s.config.Organization)
	}
	missing := map[string]int{}
	for _, host := range s.state.Hosts {
		if _, ok := document.Profiles[host.Profile]; !ok && !host.Revoked {
			missing[host.Profile]++
		}
	}
	if len(missing) > 0 {
		profile := sortedKeys(keysOf(missing))[0]
		return api.Generation{}, http.StatusUnprocessableEntity, fmt.Errorf("profile %q is used by %d enrolled hosts but missing from this bundle; they would refuse it", profile, missing[profile])
	}
	ring := 0
	if firstRing != "" {
		if ring = s.ringIndex(firstRing); ring < 0 {
			return api.Generation{}, http.StatusUnprocessableEntity, fmt.Errorf("unknown ring %q", firstRing)
		}
	}
	var previous *policy.Document
	if latest := s.latestLocked(); latest != 0 {
		document, err := s.documentLocked(latest)
		if err != nil {
			return api.Generation{}, http.StatusInternalServerError, err
		}
		previous = &document
	}
	data, err := rootData(document)
	if err != nil {
		return api.Generation{}, http.StatusInternalServerError, err
	}
	now := s.now().UTC()
	number := s.latestLocked() + 1
	sum := sha256.Sum256(raw)
	rules, dns := documentCounts(document)
	generation := api.Generation{
		Number: number, Revision: document.Revision, ExpiresAt: document.ExpiresAt.UTC(), PublishedAt: now,
		PublishedBy: admin, BundleSHA256: hex.EncodeToString(sum[:]), Size: len(raw),
		Profiles: sortedProfiles(document), Rules: rules, DNSNames: dns, RepublishOf: republishOf,
		Changes: diffDocuments(previous, document),
	}
	if err := writePrivate(s.bundlePath(number), raw); err != nil {
		return api.Generation{}, http.StatusInternalServerError, err
	}
	if err := writePrivate(s.documentPath(number), data); err != nil {
		return api.Generation{}, http.StatusInternalServerError, err
	}
	saved := s.state
	saved.Rings = slices.Clone(s.state.Rings)
	s.state.Generations = append(s.state.Generations, generation)
	s.state.Rollout = &storedRollout{Generation: number, StartedAt: now, StartedBy: admin}
	for i := 0; i <= ring; i++ {
		s.state.Rings[i].Generation = number
		s.state.Rings[i].PromotedAt = &now
		s.state.Rings[i].PromotedBy = admin
	}
	if s.state.Draft != nil {
		if draft, err := policy.ParseDocument(s.state.Draft.Data); err == nil {
			if canonical, err := rootData(draft); err == nil && bytes.Equal(canonical, data) {
				s.state.Draft = nil
			}
		}
	}
	if err := s.saveLocked(); err != nil {
		s.state = saved
		return api.Generation{}, http.StatusInternalServerError, err
	}
	s.documents[number] = document
	s.audit.Printf("admin %s: published generation %d (revision %s) to %s", admin, number, document.Revision, strings.Join(s.config.Rings[:ring+1], ", "))
	s.notifyLocked()
	return generation, http.StatusCreated, nil
}

func (s *Service) handlePromote(w http.ResponseWriter, r *http.Request, admin string) {
	var request api.PromoteRequest
	if !decodeBody(w, r, &request) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rollout := s.state.Rollout
	if rollout == nil {
		writeError(w, http.StatusConflict, "nothing has been published")
		return
	}
	index := s.ringIndex(request.Ring)
	if index < 0 {
		writeError(w, http.StatusUnprocessableEntity, "unknown ring "+strconv.Quote(request.Ring))
		return
	}
	now := s.now().UTC()
	saved := slices.Clone(s.state.Rings)
	for i := 0; i <= index; i++ {
		if s.state.Rings[i].Generation < rollout.Generation {
			s.state.Rings[i].Generation = rollout.Generation
			s.state.Rings[i].PromotedAt = &now
			s.state.Rings[i].PromotedBy = admin
		}
	}
	if err := s.saveLocked(); err != nil {
		s.state.Rings = saved
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit.Printf("admin %s: promoted generation %d through %s", admin, rollout.Generation, request.Ring)
	s.notifyLocked()
	writeJSONResponse(w, http.StatusOK, s.overviewLocked(admin, now))
}

func (s *Service) handleDraft(w http.ResponseWriter, _ *http.Request, _ string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	draft, err := s.draftLocked()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSONResponse(w, http.StatusOK, draft)
}

// draftLocked is the saved draft, or the newest generation as a starting
// point, or a minimal default-deny template before anything is published.
func (s *Service) draftLocked() (api.Draft, error) {
	latest := s.latestLocked()
	var base *policy.Document
	if latest != 0 {
		document, err := s.documentLocked(latest)
		if err != nil {
			return api.Draft{}, err
		}
		base = &document
	}
	if saved := s.state.Draft; saved != nil {
		draft := api.Draft{Base: saved.Base, Data: saved.Data, Saved: true, UpdatedAt: &saved.UpdatedAt, UpdatedBy: saved.UpdatedBy, Changes: []api.Change{}}
		document, err := policy.ParseDocument(saved.Data)
		if err != nil {
			draft.Problem = err.Error()
			return draft, nil
		}
		if saved.Base != 0 && saved.Base <= latest {
			previous, err := s.documentLocked(saved.Base)
			if err != nil {
				return api.Draft{}, err
			}
			draft.Changes = diffDocuments(&previous, document)
		} else {
			draft.Changes = diffDocuments(nil, document)
		}
		return draft, nil
	}
	if base != nil {
		data, err := rawRoot(*base)
		if err != nil {
			return api.Draft{}, err
		}
		return api.Draft{Base: latest, Data: data, Changes: []api.Change{}}, nil
	}
	template := policy.Document{
		Version: 1, Organization: s.config.Organization, Revision: "draft-1",
		ExpiresAt: s.now().UTC().Add(30 * 24 * time.Hour).Truncate(time.Second),
		Profiles:  map[string]policy.Profile{"developer": {Rules: []policy.Rule{}, Network: policy.Network{Rules: []netpol.GuardRule{}, DNS: []string{}}}},
	}
	data, err := rawRoot(template)
	if err != nil {
		return api.Draft{}, err
	}
	return api.Draft{Data: data, Changes: diffDocuments(nil, template)}, nil
}

func (s *Service) handleSaveDraft(w http.ResponseWriter, r *http.Request, admin string) {
	var request api.DraftRequest
	if !decodeBody(w, r, &request) {
		return
	}
	document, err := policy.ParseDocument(request.Data)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if document.Organization != s.config.Organization {
		writeError(w, http.StatusUnprocessableEntity, fmt.Sprintf("draft is for organization %q, not %q", document.Organization, s.config.Organization))
		return
	}
	if request.Base > s.latestLocked() {
		writeError(w, http.StatusUnprocessableEntity, "draft base generation does not exist")
		return
	}
	data, err := rootData(document)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	saved := s.state.Draft
	s.state.Draft = &storedDraft{Base: request.Base, Data: data, UpdatedAt: s.now().UTC(), UpdatedBy: admin}
	if err := s.saveLocked(); err != nil {
		s.state.Draft = saved
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	draft, err := s.draftLocked()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSONResponse(w, http.StatusOK, draft)
}

func (s *Service) handleDiscardDraft(w http.ResponseWriter, _ *http.Request, admin string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	saved := s.state.Draft
	s.state.Draft = nil
	if err := s.saveLocked(); err != nil {
		s.state.Draft = saved
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	draft, err := s.draftLocked()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit.Printf("admin %s: discarded the draft", admin)
	writeJSONResponse(w, http.StatusOK, draft)
}

// rootData renders a validated document as canonical root data.json.
func rootData(document policy.Document) ([]byte, error) {
	raw, err := policy.MarshalDocument(document)
	if err != nil {
		return nil, err
	}
	return bytes.TrimSpace(raw), nil
}

// rawRoot renders a document without validating expiry, for history and
// starting points that may have expired.
func rawRoot(document policy.Document) (json.RawMessage, error) {
	return json.Marshal(struct {
		Gantry policy.Document `json:"gantry"`
	}{document})
}

func keysOf(counts map[string]int) map[string]bool {
	set := map[string]bool{}
	for key := range counts {
		set[key] = true
	}
	return set
}

func decodeBody(w http.ResponseWriter, r *http.Request, value any) bool {
	if r.Body == nil {
		writeError(w, http.StatusBadRequest, "request body required")
		return false
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, maxAdminBody+1))
	if err != nil || len(raw) > maxAdminBody {
		writeError(w, http.StatusRequestEntityTooLarge, "request body too large")
		return false
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		raw = []byte("{}")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request: "+err.Error())
		return false
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, "invalid request: trailing data")
		return false
	}
	return true
}

func writeJSONResponse(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSONResponse(w, status, api.ErrorResponse{Error: message})
}
