package sharefs

import (
	"fmt"
	"os"
	"time"

	"github.com/hanwen/go-fuse/v2/fuse"
)

// descendantMetadataTTL keeps READDIRPLUS/LOOKUP attributes alive long enough
// for the guest to consume them without turning every stat into another
// cross-worker round trip. Negative entries remain uncached, so lookups for
// names which do not exist never go stale. Export roots and the synthetic hub
// root additionally stay uncached until the reverse notification channel is
// live; after that Publish/Swap/Remove invalidate affected dentries actively
// (Hub NotifyEntry), so they can use the watched TTL as well. Revocation is
// enforced by Export.usable on every operation independently of this advisory
// cache.
const (
	descendantMetadataTTL = 100 * time.Millisecond
	// watchedMetadataTTL removes periodic GETATTR validation from warm tree
	// walks. Reverse FUSE invalidations, not this timeout, provide coherence;
	// the finite ceiling remains a final safety net for implementation bugs.
	watchedMetadataTTL = time.Hour
)

// prefetchReadDirPlusEntry combines directory enumeration with LOOKUP only
// for child directories. Tree walkers need those inodes to descend, while
// eagerly instantiating every regular file makes the guest retain an nlookup
// reference for each one until memory reclaim and defeats the supervisor's
// bounded-node policy. A false result still emits a valid READDIRPLUS record
// with a zero node ID, as prescribed by the Linux FUSE ABI.
func prefetchReadDirPlusEntry(entry fuse.DirEntry) bool {
	return entry.Mode&0o170000 == fuse.S_IFDIR
}

func metadataTTL(export *Export) time.Duration {
	if export != nil && export.longCacheHealthy() {
		return watchedMetadataTTL
	}
	return descendantMetadataTTL
}

// reportTTL logs the effective cache policy for one export once, so field
// diagnostics can distinguish "long TTL never served" from "guest ignores
// the TTL". Gated on GANTRY_VHOST_STATS because the share daemon already
// keys its periodic statistics off that switch.
func reportTTL(export *Export, ttl time.Duration) {
	if export == nil || os.Getenv("GANTRY_VHOST_STATS") != "1" ||
		!export.ttlReported.CompareAndSwap(false, true) {
		return
	}
	fmt.Fprintf(os.Stderr, "sharefs-ttl: tag=%q ttl=%s notifications=%v watcher-healthy=%v\n",
		export.Tag, ttl, export.hub != nil && export.hub.notificationsReady.Load(),
		export.coherence != nil && export.coherence.Healthy())
}

func cacheEntry(export *Export, out *fuse.EntryOut) {
	if out == nil {
		return
	}
	ttl := metadataTTL(export)
	reportTTL(export, ttl)
	out.SetEntryTimeout(ttl)
	out.SetAttrTimeout(ttl)
}

func cacheAttr(export *Export, out *fuse.AttrOut) {
	if out != nil {
		out.SetTimeout(metadataTTL(export))
	}
}

func cacheStatx(export *Export, out *fuse.StatxOut) { //nolint:unused // Windows has no STATX backend.
	if out != nil {
		out.SetTimeout(metadataTTL(export))
	}
}
