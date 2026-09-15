# Images

Gantry pulls OCI images without Docker or containerd and caches a read-only
filesystem for each selected platform digest.

## Supported sources

`-image` accepts:

- an OCI registry reference or digest;
- a local OCI layout directory or archive;
- a Docker save archive; or
- a prebuilt `.erofs` filesystem.

```console
$ gantry start dev -image debian:bookworm-slim
$ gantry start pinned -image ghcr.io/example/app@sha256:0123...
$ gantry start local -image ./app.oci.tar
```

OCI sources preserve environment, entrypoint, command, user, and working
directory settings. A plain EROFS file has no OCI metadata and uses Gantry's
defaults.

## Pull and cache images

The cache is `~/.gantry/images` unless `GANTRY_IMAGES` is set. Gantry prefers a
verified cached tag, so mutable tags are not refreshed on every start. Pull
again when you want the current digest:

```console
$ gantry image pull debian:bookworm-slim
$ gantry image pull -platform linux/amd64 alpine:latest
$ gantry image ls
```

Concurrent pulls of the same digest are serialized. Platform variants have
separate cache entries.

## Export and import a sandbox

Stop a sandbox, then export its base image and writable changes as an OCI
image-layout archive:

```console
$ gantry stop dev
$ gantry export dev -o dev.oci.tar --name team/dev:v3
```

Host shares and the optional Dev Containers IDE disk are not included. Import
and run the archive elsewhere:

```console
$ gantry image import dev.oci.tar
$ gantry start copy -image team/dev:v3
```

Use `gantry image import -name REF ARCHIVE` to add or replace the local
reference. You can also use an archive directly with `-image`.

> [!WARNING]
> An export contains files that guest programs persisted, which may include
> credentials, keys, history, or agent login state. Review it before sharing.

Export requires a stopped sandbox and an exclusive writable-disk lock. See
[Architecture](architecture.md#filesystems-and-persistence) for the image,
ext4, and export implementation.

## Remove images

```console
$ gantry image rm alpine:latest
$ gantry image rm sha256:0123...
$ gantry image prune
```

Removing a reference removes its cached platform variants. `prune` removes
only digests not referenced by saved sandboxes. It does not remove writable
disks or sandbox state.

A stopped sandbox whose digest was removed cannot resume until that exact
image is available again.

## Registry credentials

Inspect the credential source without printing values:

```console
$ gantry image credentials
$ gantry image credentials registry.example.com
```

Log in and out:

```console
$ gantry image login registry.example.com -u alice
$ printf '%s' "$REGISTRY_TOKEN" | \
    gantry image login registry.example.com -u alice --password-stdin
$ gantry image logout registry.example.com
```

There is no password flag because argv and shell history are not private. When
no credential helper is configured, Gantry uses Docker-compatible
`~/.gantry/credentials.json`; its base64 values are encoded, not encrypted.
Registry credentials stay in the host image puller and are not injected into
the guest. See [Host shares and secrets](shares-secrets.md#inject-secrets) for
workload credentials.

## Native layer sets

`-layerset` is an advanced input used by `gantry import`. It attaches a Gantry
EROFS layer-set manifest directly and requires a private writable layer. Prefer
`-image` for normal use.
