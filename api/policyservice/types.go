// Package policyservice is the wire contract of gantry policy-service: the
// organization's policy feed for enrolled host managers and the administrator
// API used by the desktop, scripts, and the end-to-end battery.
//
// The feed itself is the protocol in internal/policyfeed: GET /v1/feed over
// mutually authenticated TLS. This package covers the bearer-authenticated
// administrator routes below /v1/admin.
package policyservice

import (
	"encoding/json"
	"time"
)

// CapabilityAdmin in Health.Capabilities marks a policy service rather than a
// sandbox manager, so a client registered with `gantry remote add` can tell
// which workspace to open.
const CapabilityAdmin = "policy-service-admin-v1"

// Health is GET /v1/health. It has the manager's shape so that the existing
// remote-profile tooling can register and test a policy service.
type Health struct {
	OK           bool     `json:"ok"`
	Version      string   `json:"version"`
	Capabilities []string `json:"capabilities,omitempty"`
}

// ErrorResponse is the failure body for every administrator route.
type ErrorResponse struct {
	Error string `json:"error"`
}

// Host statuses, from the service's view of each host's latest report.
const (
	HostCurrent  = "current"  // applied its target generation, digest matches
	HostWaiting  = "waiting"  // its target moved; not polled since
	HostOffered  = "offered"  // served its target; no report of it yet
	HostPending  = "pending"  // applying its target
	HostStalled  = "stalled"  // its target failed on some sandboxes; retrying
	HostRejected = "rejected" // refused its target (see RejectedReason)
	HostMismatch = "mismatch" // applied its target with an unexpected digest
	HostSilent   = "silent"   // no poll for SilentAfter
	HostNever    = "never"    // enrolled, never polled
	HostRevoked  = "revoked"  // identity revoked; the feed refuses it
	HostIdle     = "idle"     // nothing published yet
)

// SilentAfter is how long a host may go without polling before it is
// reported silent. Long-polling hosts check in at least every 30 s.
const SilentAfter = 10 * time.Minute

// Overview is GET /v1/admin/overview.
type Overview struct {
	Organization         string     `json:"organization"`
	FeedURL              string     `json:"feedUrl"`
	PublicKeyFingerprint string     `json:"publicKeyFingerprint"`
	PublicKeyBits        int        `json:"publicKeyBits"`
	CAFingerprint        string     `json:"caFingerprint"`
	CAExpiresAt          time.Time  `json:"caExpiresAt"`
	Admin                string     `json:"admin"`
	Latest               uint64     `json:"latest"`
	Rings                []Ring     `json:"rings"`
	Rollout              *Rollout   `json:"rollout,omitempty"`
	Hosts                HostCounts `json:"hosts"`
	// NextExpiry is the soonest expiry among generations hosts still run.
	NextExpiry *time.Time `json:"nextExpiry,omitempty"`
}

// Ring is one rollout stage and the generation it currently serves.
type Ring struct {
	Name       string `json:"name"`
	Generation uint64 `json:"generation"`
	Hosts      int    `json:"hosts"`
}

// Rollout follows the newest published generation ring by ring.
type Rollout struct {
	Generation uint64        `json:"generation"`
	StartedAt  time.Time     `json:"startedAt"`
	StartedBy  string        `json:"startedBy"`
	Rings      []RolloutRing `json:"rings"`
	Complete   bool          `json:"complete"`
}

// RolloutRing counts where the rollout generation stands within one ring.
type RolloutRing struct {
	Name         string     `json:"name"`
	PromotedAt   *time.Time `json:"promotedAt,omitempty"`
	PromotedBy   string     `json:"promotedBy,omitempty"`
	Hosts        int        `json:"hosts"`
	Acknowledged int        `json:"acknowledged"`
	Offered      int        `json:"offered"`
	Stalled      int        `json:"stalled"`
	Rejected     int        `json:"rejected"`
}

// HostCounts summarizes host statuses for the overview tiles.
type HostCounts struct {
	Enrolled int `json:"enrolled"`
	Current  int `json:"current"`
	Behind   int `json:"behind"`
	Stalled  int `json:"stalled"`
	Rejected int `json:"rejected"`
	Silent   int `json:"silent"`
	Revoked  int `json:"revoked"`
}

// Host is one enrolled host manager as the service sees it.
type Host struct {
	Name        string          `json:"name"`
	Profile     string          `json:"profile"`
	Ring        string          `json:"ring"`
	Certificate HostCertificate `json:"certificate"`
	Revoked     bool            `json:"revoked"`
	RevokedAt   *time.Time      `json:"revokedAt,omitempty"`
	RevokedBy   string          `json:"revokedBy,omitempty"`
	// Target is the generation this host should run: its ring's, but never
	// lower than one already served to it.
	Target uint64 `json:"target"`
	// Served is the newest generation handed to this host, first at ServedAt.
	Served   uint64     `json:"served"`
	ServedAt *time.Time `json:"servedAt,omitempty"`
	// AcknowledgedAt is when the host first reported Served as applied.
	AcknowledgedAt *time.Time `json:"acknowledgedAt,omitempty"`
	// PollsSinceServed counts reports since Served was handed out.
	PollsSinceServed int         `json:"pollsSinceServed"`
	Status           string      `json:"status"`
	LastSeen         *time.Time  `json:"lastSeen,omitempty"`
	Report           *HostReport `json:"report,omitempty"`
}

// HostCertificate describes the client identity issued at enrollment.
type HostCertificate struct {
	Serial      string    `json:"serial"`
	Fingerprint string    `json:"fingerprint"`
	NotAfter    time.Time `json:"notAfter"`
	IssuedAt    time.Time `json:"issuedAt"`
	IssuedBy    string    `json:"issuedBy"`
}

// HostReport is what the host said about itself on its latest poll.
type HostReport struct {
	At            time.Time `json:"at"`
	Applied       uint64    `json:"applied"`
	DigestMatches bool      `json:"digestMatches"`
	Pending       uint64    `json:"pending,omitempty"`
	Attempts      int       `json:"attempts,omitempty"`
	// Failed counts sandboxes that could not accept Pending; nil when the
	// host could not reach its sandboxes at all.
	Failed             *int   `json:"failed,omitempty"`
	RejectedGeneration uint64 `json:"rejectedGeneration,omitempty"`
	RejectedReason     string `json:"rejectedReason,omitempty"`
	Profile            string `json:"profile,omitempty"`
	Agent              string `json:"agent,omitempty"`
	Address            string `json:"address,omitempty"`
}

// Generation is one published, immutable policy generation.
type Generation struct {
	Number       uint64    `json:"number"`
	Revision     string    `json:"revision"`
	ExpiresAt    time.Time `json:"expiresAt"`
	PublishedAt  time.Time `json:"publishedAt"`
	PublishedBy  string    `json:"publishedBy"`
	BundleSHA256 string    `json:"bundleSha256"`
	Size         int       `json:"size"`
	Profiles     []string  `json:"profiles"`
	Rules        int       `json:"rules"`
	DNSNames     int       `json:"dnsNames"`
	// RepublishOf names the generation whose signed bundle this one reuses.
	RepublishOf uint64   `json:"republishOf,omitempty"`
	Changes     []Change `json:"changes"`
	// Hosts counts hosts whose latest report applied this generation.
	Hosts int `json:"hosts"`
}

// GenerationDetail adds the signed document (root data.json object).
type GenerationDetail struct {
	Generation
	Data json.RawMessage `json:"data"`
}

// Change kinds, verbs and effects.
const (
	ChangeProfile  = "profile"
	ChangeRule     = "rule"
	ChangeNetwork  = "network"
	ChangeDNS      = "dns"
	ChangeExpiry   = "expiry"
	ChangeRevision = "revision"

	ChangeAdded   = "added"
	ChangeRemoved = "removed"
	ChangeChanged = "changed"

	EffectLoosens  = "loosens"
	EffectTightens = "tightens"
	EffectNeutral  = "neutral"
)

// Change is one difference between two policy documents.
type Change struct {
	Profile string `json:"profile,omitempty"`
	Kind    string `json:"kind"`
	ID      string `json:"id,omitempty"`
	Change  string `json:"change"`
	Effect  string `json:"effect"`
	Summary string `json:"summary"`
	Before  string `json:"before,omitempty"`
	After   string `json:"after,omitempty"`
}

// Draft is GET /v1/admin/draft: the next generation being edited. Without a
// saved draft it is the newest generation's document with no changes.
type Draft struct {
	Base      uint64          `json:"base"`
	Data      json.RawMessage `json:"data"`
	Changes   []Change        `json:"changes"`
	Saved     bool            `json:"saved"`
	UpdatedAt *time.Time      `json:"updatedAt,omitempty"`
	UpdatedBy string          `json:"updatedBy,omitempty"`
	// Problem is non-empty when the saved draft no longer validates, for
	// example because its expiry has passed.
	Problem string `json:"problem,omitempty"`
}

// DraftRequest is PUT /v1/admin/draft. Data is a complete root data.json
// object, validated exactly as signing and activation would.
type DraftRequest struct {
	Base uint64          `json:"base"`
	Data json.RawMessage `json:"data"`
}

// PublishRequest is POST /v1/admin/generations. The bundle is signed by the
// administrator's client; the service only verifies it with the pinned key.
type PublishRequest struct {
	Bundle []byte `json:"bundle"`
	// FirstRing is the last ring served immediately; earlier rings are
	// included. Empty selects the first ring.
	FirstRing string `json:"firstRing,omitempty"`
}

// RepublishRequest is POST /v1/admin/generations/{n}/republish: the same
// signed bundle under the next generation number (a rollback).
type RepublishRequest struct {
	FirstRing string `json:"firstRing,omitempty"`
}

// PromoteRequest is POST /v1/admin/rollout/promote. Every ring up to and
// including Ring then serves the rollout generation.
type PromoteRequest struct {
	Ring string `json:"ring"`
}

// EnrollRequest is POST /v1/admin/hosts. CSR is the host's PEM certificate
// request; its private key never leaves the host.
type EnrollRequest struct {
	Name    string `json:"name"`
	Profile string `json:"profile"`
	Ring    string `json:"ring"`
	CSR     string `json:"csr"`
}

// Enrollment is the response to EnrollRequest: everything the host needs
// besides its own key. Files maps file names to contents for feed.json and
// the PEM files it references.
type Enrollment struct {
	Host  Host              `json:"host"`
	Files map[string]string `json:"files"`
}

// HostUpdate is PATCH /v1/admin/hosts/{name}.
type HostUpdate struct {
	Ring string `json:"ring"`
}

// Enrollment file names, referenced by the generated feed.json.
const (
	FeedConfigFile  = "feed.json"
	HostCertFile    = "host.pem"
	HostKeyFile     = "host-key.pem"
	HostRequestFile = "host.csr"
	CAFile          = "ca.pem"
	PublicKeyFile   = "org-public.pem"
)
