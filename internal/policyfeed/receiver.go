package policyfeed

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ejpir/gantry/internal/atomicfile"
	"github.com/ejpir/gantry/internal/guestasset"
	"github.com/ejpir/gantry/internal/policy"
	"github.com/ejpir/gantry/internal/sandbox/localsec"
)

const (
	feedVersion         = 1
	maxFeedResponseSize = 384 << 10
	maxFeedStateSize    = 1 << 20
	stateVersion        = 2
)

// Update is one verified, non-rollback policy generation ready for the host
// lifecycle coordinator. PublicKey is the locally pinned key, never supplied
// by the policy service.
type Update struct {
	Generation uint64
	Digest     string
	Snapshot   *policy.Config
	Info       policy.SnapshotInfo
}

// RolloutError reports an incomplete fan-out: the coordinator could not move
// Failed of the Total saved sandboxes to the generation and stopped them.
type RolloutError struct {
	Failed int
	Total  int
	Err    error
}

func (e *RolloutError) Error() string { return e.Err.Error() }
func (e *RolloutError) Unwrap() error { return e.Err }

// Rejection reasons reported to the policy service. They describe the
// service's own response, so they reveal nothing about the host.
const (
	RejectInvalid      = "invalid"
	RejectVerification = "verification"
	RejectOrganization = "organization"
	RejectRollback     = "rollback"
	RejectChanged      = "changed"
)

// pendingStatus describes the last attempt to fan out the pending generation.
type pendingStatus struct {
	attempts int
	// failed counts sandboxes that could not accept it; -1 when the attempt
	// failed before reaching any sandbox (for example, a busy manager).
	failed int
}

// incompleteError marks a Sync whose exchange with the service succeeded
// while the pending generation still could not be applied everywhere.
type incompleteError struct{ err error }

func (e incompleteError) Error() string { return e.err.Error() }
func (e incompleteError) Unwrap() error { return e.err }

type feedResponse struct {
	Version      int    `json:"version"`
	Organization string `json:"organization"`
	Generation   uint64 `json:"generation"`
	Bundle       []byte `json:"bundle"`
}

type receiverState struct {
	Version           int    `json:"version"`
	Organization      string `json:"organization"`
	Profile           string `json:"profile"`
	URL               string `json:"url"`
	TrustDigest       string `json:"trust_digest"`
	Generation        uint64 `json:"generation"`
	Digest            string `json:"digest,omitempty"`
	ETag              string `json:"etag,omitempty"`
	Bundle            []byte `json:"bundle,omitempty"`
	PendingGeneration uint64 `json:"pending_generation,omitempty"`
	PendingDigest     string `json:"pending_digest,omitempty"`
	PendingETag       string `json:"pending_etag,omitempty"`
	PendingBundle     []byte `json:"pending_bundle,omitempty"`
}

// Receiver owns one organization-wide manager subscription.
type Receiver struct {
	config         *Config
	client         *http.Client
	close          func()
	statePath      string
	state          receiverState
	latest         *Update
	pending        *Update
	restorePending bool
	logger         *log.Logger
	apply          func(context.Context, Update) error
	ownsClient     bool
	// Reported to the service on every poll; memory-only, rebuilt by the next
	// attempt after a restart.
	pendingStatus      pendingStatus
	rejectedGeneration uint64
	rejectedReason     string
}

// NewReceiver initializes persistent anti-rollback state and an mTLS client.
func NewReceiver(config *Config, stateDir string, logger *log.Logger, apply func(context.Context, Update) error) (*Receiver, error) {
	if config == nil || apply == nil {
		return nil, fmt.Errorf("policy channel requires configuration and an apply callback")
	}
	if err := localsec.CreateManagerDir(stateDir); err != nil {
		return nil, fmt.Errorf("create policy channel state: %w", err)
	}
	client, closeClient, err := config.httpClient()
	if err != nil {
		return nil, err
	}
	receiver, err := newReceiver(config, stateDir, logger, apply, client)
	if err != nil {
		closeClient()
		return nil, err
	}
	receiver.close = closeClient
	receiver.ownsClient = true
	return receiver, nil
}

func newReceiver(config *Config, stateDir string, logger *log.Logger, apply func(context.Context, Update) error, client *http.Client) (*Receiver, error) {
	trust := sha256.Sum256([]byte(config.publicKey))
	trustDigest := hex.EncodeToString(trust[:])
	identity := sha256.Sum256([]byte(config.Organization + "\x00" + config.Profile + "\x00" + config.URL + "\x00" + trustDigest))
	path := filepath.Join(stateDir, "feed-"+hex.EncodeToString(identity[:12])+".json")
	state := receiverState{Version: stateVersion, Organization: config.Organization, Profile: config.Profile, URL: config.URL, TrustDigest: trustDigest}
	if raw, err := readRegular(path, maxFeedStateSize); err == nil {
		if err := strictJSON(raw, &state); err != nil || state.Version != stateVersion || state.Organization != config.Organization || state.Profile != config.Profile || state.URL != config.URL || state.TrustDigest != trustDigest || !validETag(state.ETag) || !validETag(state.PendingETag) {
			return nil, fmt.Errorf("invalid policy channel state for organization %s", config.Organization)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read policy channel state: %w", err)
	}
	receiver := &Receiver{config: config, client: client, statePath: path, state: state, logger: logger, apply: apply}
	if state.Generation == 0 {
		if state.Digest != "" || state.ETag != "" || len(state.Bundle) != 0 {
			return nil, fmt.Errorf("invalid policy channel state for organization %s", config.Organization)
		}
	} else {
		if len(state.Digest) != 64 {
			return nil, fmt.Errorf("invalid policy channel state for organization %s", config.Organization)
		}
		update, err := receiver.update(state.Generation, state.Bundle, state.Digest)
		if err != nil {
			return nil, fmt.Errorf("invalid policy channel state for organization %s", config.Organization)
		}
		receiver.latest = update
	}
	if state.PendingGeneration == 0 {
		if state.PendingDigest != "" || state.PendingETag != "" || len(state.PendingBundle) != 0 {
			return nil, fmt.Errorf("invalid policy channel state for organization %s", config.Organization)
		}
	} else {
		if state.PendingGeneration <= state.Generation || len(state.PendingDigest) != 64 {
			return nil, fmt.Errorf("invalid policy channel state for organization %s", config.Organization)
		}
		update, err := receiver.update(state.PendingGeneration, state.PendingBundle, state.PendingDigest)
		if err != nil {
			return nil, fmt.Errorf("invalid policy channel state for organization %s", config.Organization)
		}
		receiver.pending = update
	}
	receiver.restorePending = receiver.pending != nil || receiver.latest != nil
	return receiver, nil
}

// Close releases idle transport connections. Run calls it automatically.
func (receiver *Receiver) Close() {
	if receiver != nil && receiver.close != nil {
		receiver.close()
		receiver.close = nil
	}
}

// Restore reapplies the newest durable desired generation after manager
// restart. A pending generation is promoted only after aggregate fan-out;
// otherwise the last acknowledged snapshot is restored for admission.
func (receiver *Receiver) Restore(ctx context.Context) error {
	if receiver == nil || !receiver.restorePending {
		return nil
	}
	update := receiver.latest
	promote := false
	if receiver.pending != nil {
		update = receiver.pending
		promote = true
	}
	if update == nil {
		return fmt.Errorf("restore policy state has no snapshot")
	}
	if err := receiver.apply(ctx, *update); err != nil {
		if promote {
			receiver.pendingStatus.attempts++
			receiver.pendingStatus.failed = -1
			var rollout *RolloutError
			if errors.As(err, &rollout) {
				receiver.pendingStatus.failed = rollout.Failed
			}
		}
		return fmt.Errorf("restore generation %d: %w", update.Generation, err)
	}
	if promote {
		next := receiver.state
		next.Generation = receiver.state.PendingGeneration
		next.Digest = receiver.state.PendingDigest
		next.ETag = receiver.state.PendingETag
		next.Bundle = bytes.Clone(receiver.state.PendingBundle)
		next.PendingGeneration = 0
		next.PendingDigest = ""
		next.PendingETag = ""
		next.PendingBundle = nil
		if err := receiver.saveState(next); err != nil {
			return fmt.Errorf("promote generation %d: %w", update.Generation, err)
		}
		receiver.state = next
		receiver.latest = update
		receiver.pending = nil
		receiver.pendingStatus = pendingStatus{}
	}
	receiver.restorePending = false
	return nil
}

// Run reconciles immediately and then at the configured interval. Network and
// rollout failures are retried; cancellation is the only normal exit.
func (receiver *Receiver) Run(ctx context.Context) {
	if receiver == nil {
		return
	}
	if receiver.ownsClient {
		defer receiver.Close()
	}
	for {
		started := time.Now()
		applied, pending := receiver.state.Generation, receiver.state.PendingGeneration
		err := receiver.Sync(ctx)
		if err != nil && ctx.Err() == nil && receiver.logger != nil {
			receiver.logger.Printf("policy feed %s: %v", receiver.config.Organization, err)
		}
		// A completed exchange paces from its start, so a service that holds
		// the request (long poll) is asked again at once; failures back off.
		// A newly applied or staged generation is reported right away rather
		// than a poll interval later.
		delay := receiver.config.poll
		var incomplete incompleteError
		if err == nil || errors.As(err, &incomplete) {
			delay = max(0, receiver.config.poll-time.Since(started))
			if receiver.state.Generation != applied || receiver.state.PendingGeneration != pending {
				delay = 0
			}
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return
		case <-timer.C:
		}
	}
}

// Sync fetches and, when newer, applies one desired generation. A pending
// generation that still cannot reach every sandbox is retried first, but the
// poll still happens: the service learns about the failure, and a newer
// generation can replace the stuck one.
func (receiver *Receiver) Sync(ctx context.Context) error {
	restoreErr := receiver.Restore(ctx)
	if restoreErr != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	incomplete := func() error {
		if restoreErr == nil {
			return nil
		}
		return incompleteError{restoreErr}
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, receiver.config.URL, nil)
	if err != nil {
		return fmt.Errorf("construct policy request")
	}
	receiver.reportHeaders(request.Header)
	response, err := receiver.client.Do(request)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return errors.Join(restoreErr, fmt.Errorf("policy channel request failed (check connectivity, mTLS and server trust)"))
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode == http.StatusNotModified {
		return incomplete()
	}
	if response.StatusCode != http.StatusOK {
		return errors.Join(restoreErr, fmt.Errorf("policy channel returned HTTP %d", response.StatusCode))
	}
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return receiver.reject(0, RejectInvalid, fmt.Errorf("policy channel response must be application/json"))
	}
	if response.ContentLength > maxFeedResponseSize {
		return receiver.reject(0, RejectInvalid, fmt.Errorf("policy channel response exceeds %d bytes", maxFeedResponseSize))
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, maxFeedResponseSize+1))
	if err != nil || len(raw) > maxFeedResponseSize {
		return errors.Join(restoreErr, fmt.Errorf("policy channel response read failed or exceeds %d bytes", maxFeedResponseSize))
	}
	var desired feedResponse
	if err := strictJSON(raw, &desired); err != nil || desired.Version != feedVersion || desired.Generation == 0 || len(desired.Bundle) == 0 || len(desired.Bundle) > policy.MaxBundleBytes {
		return receiver.reject(0, RejectInvalid, fmt.Errorf("policy channel response is invalid"))
	}
	if desired.Organization != receiver.config.Organization {
		return receiver.reject(desired.Generation, RejectOrganization, fmt.Errorf("policy channel response is for another organization"))
	}
	etag := response.Header.Get("ETag")
	if !validETag(etag) {
		return receiver.reject(desired.Generation, RejectInvalid, fmt.Errorf("policy channel returned an invalid ETag"))
	}
	update, err := receiver.update(desired.Generation, desired.Bundle, "")
	if err != nil {
		reason := RejectVerification
		if errors.Is(err, errOtherOrganization) {
			reason = RejectOrganization
		}
		return receiver.reject(desired.Generation, reason, err)
	}
	digest := update.Digest
	switch {
	case desired.Generation < receiver.state.Generation, receiver.state.PendingGeneration != 0 && desired.Generation < receiver.state.PendingGeneration:
		newest := max(receiver.state.Generation, receiver.state.PendingGeneration)
		return receiver.reject(desired.Generation, RejectRollback, fmt.Errorf("policy generation rollback refused: received %d after %d", desired.Generation, newest))
	case desired.Generation == receiver.state.Generation && digest != receiver.state.Digest,
		desired.Generation == receiver.state.PendingGeneration && digest != receiver.state.PendingDigest:
		return receiver.reject(desired.Generation, RejectChanged, fmt.Errorf("policy generation %d changed content", desired.Generation))
	case desired.Generation == receiver.state.PendingGeneration:
		// Still the generation being retried; Restore reported its outcome.
		return incomplete()
	case desired.Generation == receiver.state.Generation:
		if etag != receiver.state.ETag {
			next := receiver.state
			next.ETag = etag
			if err := receiver.saveState(next); err != nil {
				return err
			}
			receiver.state = next
		}
		return incomplete()
	}
	// Persist desired state before touching sandboxes. If the manager crashes
	// during fan-out, startup restores this pending generation before serving
	// lifecycle requests, while request headers still report only the older
	// completely applied cursor. A newer generation replaces a pending one
	// that never completed, so a fix can reach a host stuck on a bad rollout.
	staged := receiver.state
	staged.PendingGeneration = desired.Generation
	staged.PendingDigest = digest
	staged.PendingETag = etag
	staged.PendingBundle = bytes.Clone(desired.Bundle)
	if err := receiver.saveState(staged); err != nil {
		return fmt.Errorf("stage generation %d: %w", desired.Generation, err)
	}
	receiver.state = staged
	receiver.pending = update
	receiver.restorePending = true
	receiver.pendingStatus = pendingStatus{}
	receiver.rejectedGeneration, receiver.rejectedReason = 0, ""
	if err := receiver.Restore(ctx); err != nil {
		return incompleteError{fmt.Errorf("apply generation %d: %w", desired.Generation, err)}
	}
	if receiver.logger != nil {
		receiver.logger.Printf("policy feed %s: applied generation %d revision %s to all sandboxes", receiver.config.Organization, desired.Generation, update.Info.Revision)
	}
	return nil
}

// reportHeaders describes this host's position to the service: the fully
// applied cursor, a pending generation and how its last fan-out went, and the
// last response it refused. Values are numbers and fixed words only.
func (receiver *Receiver) reportHeaders(header http.Header) {
	header.Set("Accept", "application/json")
	header.Set("Cache-Control", "no-cache")
	header.Set("Prefer", "wait=30")
	header.Set("User-Agent", "gantry/"+userAgentVersion())
	header.Set("X-Gantry-Policy-Profile", receiver.config.Profile)
	// Ask about the newest generation this host holds, so an unchanged answer
	// can wait for news instead of returning the same pending bundle again.
	if receiver.state.PendingGeneration != 0 {
		if receiver.state.PendingETag != "" {
			header.Set("If-None-Match", receiver.state.PendingETag)
		}
		header.Set("X-Gantry-Policy-Pending-Generation", fmt.Sprint(receiver.state.PendingGeneration))
		if receiver.pendingStatus.attempts > 0 {
			header.Set("X-Gantry-Policy-Pending-Attempts", fmt.Sprint(receiver.pendingStatus.attempts))
			if receiver.pendingStatus.failed >= 0 {
				header.Set("X-Gantry-Policy-Pending-Failed", fmt.Sprint(receiver.pendingStatus.failed))
			} else {
				header.Set("X-Gantry-Policy-Pending-Failed", "unknown")
			}
		}
	} else if receiver.state.ETag != "" {
		header.Set("If-None-Match", receiver.state.ETag)
	}
	if receiver.state.Generation != 0 {
		header.Set("X-Gantry-Policy-Generation", fmt.Sprint(receiver.state.Generation))
		header.Set("X-Gantry-Policy-Digest", receiver.state.Digest)
	}
	if receiver.rejectedReason != "" {
		header.Set("X-Gantry-Policy-Rejected-Reason", receiver.rejectedReason)
		if receiver.rejectedGeneration != 0 {
			header.Set("X-Gantry-Policy-Rejected-Generation", fmt.Sprint(receiver.rejectedGeneration))
		}
	}
}

// reject remembers a refused response for the next report and returns err.
func (receiver *Receiver) reject(generation uint64, reason string, err error) error {
	receiver.rejectedGeneration, receiver.rejectedReason = generation, reason
	return err
}

func userAgentVersion() string {
	version := guestasset.Version
	if version == "" || len(version) > 64 || strings.ContainsFunc(version, func(r rune) bool { return r <= 0x20 || r > 0x7e }) {
		return "dev"
	}
	return version
}

var errOtherOrganization = errors.New("policy channel bundle belongs to another organization")

func (receiver *Receiver) update(generation uint64, bundle []byte, expectedDigest string) (*Update, error) {
	if generation == 0 || len(bundle) == 0 || len(bundle) > policy.MaxBundleBytes {
		return nil, fmt.Errorf("policy channel bundle is invalid")
	}
	snapshot := &policy.Config{Bundle: bytes.Clone(bundle), PublicKey: receiver.config.publicKey, Profile: receiver.config.Profile}
	engine, err := policy.New(snapshot, nil)
	if err != nil {
		return nil, fmt.Errorf("policy channel bundle verification failed")
	}
	info := engine.Info()
	if info.Organization != receiver.config.Organization {
		return nil, errOtherOrganization
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte(receiver.config.Profile))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write(bundle)
	_, _ = hash.Write([]byte(receiver.config.publicKey))
	digest := hex.EncodeToString(hash.Sum(nil))
	if expectedDigest != "" && (len(expectedDigest) != 64 || digest != expectedDigest) {
		return nil, fmt.Errorf("policy channel bundle digest does not match cursor")
	}
	return &Update{Generation: generation, Digest: digest, Snapshot: snapshot, Info: info}, nil
}

func (receiver *Receiver) saveState(state receiverState) error {
	raw, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	if len(raw)+1 > maxFeedStateSize {
		return fmt.Errorf("policy channel state exceeds %d bytes", maxFeedStateSize)
	}
	if err := atomicfile.WriteFileDurable(receiver.statePath, append(raw, '\n'), 0o600); err != nil {
		return err
	}
	return localsec.SecureRegularFile(receiver.statePath)
}

func validETag(value string) bool {
	if len(value) > 256 || strings.ContainsAny(value, "\r\n") {
		return false
	}
	for _, r := range value {
		if r < 0x20 || r > 0x7e {
			return false
		}
	}
	return true
}
