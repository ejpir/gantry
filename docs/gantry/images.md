# Images

Gantry pulls and runs OCI images without a Docker daemon. It flattens image
layers into a verified EROFS filesystem and caches the result by platform
manifest digest.

## Supported sources

Use `-image` with any of these inputs:

- An OCI registry reference, such as `debian:bookworm-slim`.
- A digest-pinned reference, such as
  `ghcr.io/example/app@sha256:...`.
- A local OCI image-layout directory containing `oci-layout`.
- A Docker save archive.
- A prebuilt `.erofs` filesystem.

Examples:

```console
$ gantry start dev -image debian:bookworm-slim
$ gantry start pinned -image ghcr.io/example/app@sha256:0123...
$ gantry start local -image ./image-layout
$ gantry start archive -image ./app.tar
$ gantry start erofs -image ./app.erofs
```

An existing file or OCI-layout directory is treated as a local source.
Otherwise Gantry parses the value as a registry reference.

## Image configuration

For OCI sources, Gantry preserves the image fields that affect execution:

- environment variables;
- entrypoint and command;
- numeric or named user and group;
- working directory.

Gantry resolves named users while it builds the flattened image, then records
numeric IDs in cache metadata. An explicit command after `--` replaces the
image's default command. If neither supplies a command, Gantry runs
`/bin/sh`.

A plain `.erofs` input has no associated OCI configuration metadata, so it
uses Gantry's execution defaults.

## Cache behavior

The cache lives at `~/.gantry/images` by default. `GANTRY_IMAGES` overrides
that location.

Gantry keys image files by the selected Linux platform-manifest digest. An
amd64 image and an arm64 image do not share a cache entry. Concurrent pulls of
the same digest are serialized, and completed images and metadata are
published atomically.

Ordinary `start` and `exec` operations prefer an already verified cached
entry. They do not refresh a mutable tag on every boot. Pull explicitly when
you need to resolve the tag again:

```console
$ gantry image pull debian:bookworm-slim
```

For a different target architecture:

```console
$ gantry image pull -platform linux/amd64 alpine:latest
```

## Inspect and remove images

```console
$ gantry image ls
$ gantry image rm alpine:latest
$ gantry image rm sha256:0123...
$ gantry image prune
```

Removing a reference removes every cached architecture variant for that
reference. Removing a digest targets that exact cached image.

`gantry image prune` removes cached digests not referenced by any saved
sandbox. It does not remove writable layers or sandbox state.

> [!WARNING]
> A stopped sandbox still references its cached image. Removing that digest
> makes `gantry resume` fail until you pull the image reference again.

## Authenticate to registries

Gantry resolves registry credentials from Gantry and Docker-compatible
configuration, including configured credential helpers. Inspect which source
would be selected without printing secret values:

```console
$ gantry image credentials
$ gantry image credentials registry.example.com
```

Log in interactively:

```console
$ gantry image login registry.example.com -u alice
Password:
```

For automation, send the password on standard input:

```console
$ printf '%s' "$REGISTRY_TOKEN" | \
    gantry image login registry.example.com -u alice --password-stdin
```

Gantry deliberately has no password command-line flag. Values in argv can be
visible through process inspection and shell history.

Log out with:

```console
$ gantry image logout registry.example.com
```

When no credential helper is configured, Gantry stores Docker-compatible
base64-encoded credentials in `~/.gantry/credentials.json` with mode `0600`.
Base64 is encoding, not encryption.

Registry credentials are used only by the host-side image puller. They are
never injected into the guest. Workload credentials use the separate
[secret injection](shares-secrets.md#inject-secrets) path.

## Native layer sets

`-layerset` accepts a Gantry layer-set manifest containing an EROFS fsmeta
disk and ordered layer blobs. Gantry attaches those immutable devices
directly instead of flattening them. A layer set requires a private writable
layer.

This is an advanced integration surface used by `gantry import`; prefer
`-image` for normal workloads.

