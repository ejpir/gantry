# review: internal/image (OCI phases 1+2)

*Reviewed at `50e26ff`. Findings 1, 3 and 6 were reproduced against the
package's own test helpers; the probe file was removed afterwards, and the
repros are inlined below so they can become regression tests.*

## Headline

The structure matches the design and the security-sensitive parts are done
properly — digest verification on blobs, the port-aware redirect strip with
a test behind it, `Secret` with redacted `String`/`GoString`, helpers that
degrade to anonymous instead of crashing, no `--password` flag, credentials
that never reach the daemon. The read-back `verify()` after every build is
better than the `fsck.erofs` step it replaced.

Five real bugs, though, and two of them interact in a way that gets worse
when either is fixed alone.

---

## 1. A whiteout of a directory leaves its children behind

`flatten.go:96`

```go
delete(idx.entries, path.Join(path.Dir(name), base[len(whPrefix):]))
```

`.wh.foo` deletes the entry `foo` and nothing else. Per the OCI spec it
must delete `foo` and everything beneath it. The opaque-dir path right
above already has the helper (`removeChildren`); the plain path doesn't
use it.

Reproduced:

```go
l1 := writeLayer(t,
    tarEntry{Name: "./opt/", Type: tar.TypeDir, Mode: 0o755},
    tarEntry{Name: "./opt/keep.txt", Type: tar.TypeReg, Body: "old"},
    tarEntry{Name: "./opt/sub/", Type: tar.TypeDir, Mode: 0o755},
    tarEntry{Name: "./opt/sub/deep.txt", Type: tar.TypeReg, Body: "deep"},
)
l2 := writeLayer(t, tarEntry{Name: "./.wh.opt", Type: tar.TypeReg})
// want: nothing under opt/ survives
// got:  [opt opt/keep.txt opt/sub opt/sub/deep.txt]
```

Impact: files an image author deliberately deleted in a later layer are
present in the flattened image. That is frequently build tooling, old
dependency versions, or credentials that a `RUN rm -rf` was meant to
remove — the deletion is a security boundary in plenty of Dockerfiles.

Fix: `idx.removeChildren(victim)` after the `delete`, or make
`removeChildren` take the victim path and handle both call sites.

## 2. The opaque marker deletes the directory itself

Same helper, other call site. `removeChildren(dir)` matches `p == dir` as
well as `dir + "/"`, so `opt/.wh..wh..opq` drops the `opt` entry too.
Layers normally emit `./opt/` *before* the opaque marker, so the directory's
own mode/ownership is lost and `ensureParent` recreates it as root-owned
0755; if the layer adds no children under it, `/opt` disappears entirely.

Fix: opaque should clear strictly-below (`strings.HasPrefix(p, dir+"/")`),
while a plain whiteout clears the path *and* below.

## 3. The image cache never hits for multi-arch images

`loadRegistry` descends an index to the platform manifest and reassigns
`manDigest`, so the cache key is the **platform manifest** digest
(`registry.go:386`, `p.digest` at `:415`). Every lookup path compares
against something else:

- `cachedRef` tag path: `headManifest(tag)` returns the **index** digest.
- `cachedRef` digest path: a user-pinned index digest has no meta entry.

Reproduced with a fake registry serving an index plus one platform
manifest:

```
cached digest (from pull)   = sha256:ab928981f7ed...
HEAD digest (cache compare) = sha256:9ed3e5c80608...
```

So `cachedRef` always falls through to a full pull for anything with a
manifest list — which is essentially every image on Docker Hub. The whole
"cache-first refs (HEAD compare, offline hit)" feature from d2f9ef7 is
inert for the common case, including the offline-degradation path that was
its point. Single-arch images work, which is why the battery passes.

Fix: record both digests in `Meta` — the index/tag digest that lookups
compare against, and the platform digest that names the content — and
compare like with like.

## 4. The cache is not keyed by architecture

`index.json` maps `ref -> digest` with no arch (`store.go:157`), and
`cachedRef`'s `hit()` never checks `Meta.Arch` even though it is recorded
(`resolve.go:43-49`). `gantry image pull` defaults to the **host** arch
(`sandbox/image.go: hostGuestArch`), not the guest kernel's.

Path to a wrong-arch boot: `gantry image pull debian` on an arm64 Mac
caches arm64 under `debian`; `gantry start … -kernel nerdbox-kernel-x86_64`
resolves the same ref, gets the arm64 digest, and attaches an arm64 rootfs
to an x86-64 guest. That is the exact footgun the design set out to remove.

Bug 3 currently masks most of this, because tag lookups miss anyway.
**Fixing 3 without fixing 4 turns this from rare into routine**, so they
should land together. Key the index by `ref + "/" + arch`, and have `hit()`
reject a meta whose `Arch` differs.

## 5. The manifest digest is trusted from a header

`registry.go:278`

```go
digest := resp.Header.Get("Docker-Content-Digest")
if digest == "" {
    digest = fmt.Sprintf("sha256:%x", sha256.Sum256(b))
}
```

Every blob is verified against its descriptor, but the manifest's digest is
taken from a response header without checking it against the body. If the
header disagrees with the content, gantry caches that content under the
header's digest — and a later digest-pinned pull of that digest is served
from cache. TLS makes this a compromised/buggy-registry scenario rather
than a MITM one, but it is the single place where the "verify every digest"
rule isn't applied, and the fix is to always hash the body and require a
match when the header is present.

## 6. The depth ordering is O(n²) with a recomputed key

`flatten.go:303-309` is an exchange sort, and `depth()` recounts the
separators on every comparison. Measured on this machine:

| entries | time |
|---|---|
| 2,000 | 42 ms |
| 10,000 | 1.10 s |
| 20,000 | 2.87 s |

A debian-slim image is ~25k entries, so this is several seconds of pure CPU
per build, and it grows quadratically for anything larger (a language
runtime image is 100k+). `sort.SliceStable` on a precomputed depth is a
one-liner, and it also delivers the "first-seen order within a depth" the
comment claims — an exchange sort is not stable, so that property does not
currently hold.

---

## Smaller things

- **Blob downloads are unbounded.** `fetchBlob` copies until EOF; the
  descriptor's `Size` is known and should cap it, otherwise a broken or
  hostile registry can fill the disk before the digest check runs.
- **`http.Client.Timeout` is 5 minutes for the whole request, body
  included** (`registry.go:57`), so a large layer on a slow link fails
  mid-download. Use context deadlines per operation, or
  `Transport.ResponseHeaderTimeout`, and leave the body untimed.
- **Basic-auth comment contradicts the code.** `do()` says "loopback
  excepted, per isLoopbackRegistry" but refuses when `scheme() != "https"`,
  which is exactly the loopback case — so a local registry with Basic auth
  cannot be used.
- **`Resolved.Cached` is always true**, including on the build path, though
  the field comment says "false when built during this call".
- **The store's `tmp/` is vestigial.** `ensure` creates and wipes it on
  every call, but `Build` writes `<final>.erofs.tmp` and renames, so
  nothing ever lands there. The wipe would also delete a concurrent
  process's in-flight files if anything ever did use it. Either use it as
  the design doc describes or drop it — and note the `.erofs.tmp` next to
  the final path is what a crash leaves behind, which nothing cleans.
- `verify(finalPath, tmpPath, …)` never uses `finalPath`.
- The anonymous manifest struct in `loadRegistry` is written out twice
  verbatim (`registry.go:356` and `:393`); it wants a name.
- `itoa` is a wrapper around `strconv.Itoa`.
- `readConfig` silently returns nil for a malformed `~/.docker/config.json`,
  so a JSON typo becomes a confusing anonymous 401. `gantry image
  credentials` is the natural place to surface "found but unparseable".
- `GANTRY_REGISTRY_AUTH` splits on `,` then `=` then `:`, so a secret
  containing a comma can't be expressed. Worth a doc line.
- `Config.Command(args)` returns `args` alone when args are given, dropping
  the image's `Entrypoint`; docker would run `Entrypoint + args`. For an
  interactive sandbox this is probably the behaviour you want — but it is a
  deliberate divergence and should say so.
- **gofmt is not enforced.** `internal/client/client.go`,
  `internal/sandbox/image.go` and `internal/sandbox/runconf.go` are
  currently unformatted (trivial: alignment and a trailing blank line). CI
  runs vet and test; adding `gofmt -l` as a failing step removes the need
  for cleanup commits like 467eec3.

## What's good

The credential path does what the design promised, including the parts that
are easy to skip: `Secret` redacts through `%v` on the containing struct
because fmt honours Stringer on fields, the helper protocol handles the
`<token>` identity-token convention, a failing helper degrades to anonymous
rather than failing a public pull, and the plaintext fallback warns in
plain language instead of pretending base64 is storage security.

The redirect strip compares host *and* port against `via[0]`, which is
stricter than Go's built-in and is the one thing in the auth path that
protects a real vulnerability. It has a test.

`flatten.go` gets the hard parts of image fidelity right — hardlinks
materialized by reading the target's data back (with the note about
alpine's busybox links, which is exactly the case that would silently
break), setuid/setgid/sticky preserved through `goFileMode`, device nodes
via `Mknod`, `SCHILY.xattr.*` carried through, and `..` rejected before it
reaches the writer. Those were the spike's findings and they all survived
the port to the pure-Go builder.
