package sharefs

import (
	"time"

	"github.com/hanwen/go-fuse/v2/fuse"
)

// descendantMetadataTTL keeps READDIRPLUS/LOOKUP attributes alive long enough
// for the guest to consume them without turning every stat into another
// cross-worker round trip. The synthetic share-hub root and negative entries
// remain uncached, so hot-add appears immediately. Revocation is enforced by
// Export.usable on every operation independently of this advisory cache.
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

func cacheEntry(export *Export, out *fuse.EntryOut) {
	if out == nil {
		return
	}
	ttl := metadataTTL(export)
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
