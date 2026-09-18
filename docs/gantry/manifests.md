# Sandbox manifests

A Gantry manifest is the versioned, declarative way to create or reconcile a
sandbox. YAML is the public configuration format; the `sandbox.json` file in
Gantry's state directory remains an internal resolved snapshot and must not be
edited directly.

## Create a sandbox

Create `gantry.yaml`:

```yaml
apiVersion: gantry.dev/v1alpha1
kind: Sandbox

metadata:
  name: dev

spec:
  image: debian:bookworm-slim
  runtime: crun

  resources:
    cpus: 2
    memory: 2GiB
    disk: 4GiB

  root:
    writable: true

  shares:
    - name: source
      source: .
      target: /workspace

  network:
    enabled: true
    ports:
      - host: 127.0.0.1:8080
        guest: 80
        protocol: tcp

  secrets:
    - name: GITHUB_TOKEN
      environment: GITHUB_TOKEN
    - name: NPM_TOKEN
      file: ./secrets/npm-token
      ttl: 1m

  ssh:
    enabled: true

  devContainers:
    enabled: true

  processIsolation: required
```

Validate and apply it:

```console
$ gantry manifest validate gantry.yaml
manifest valid: sandbox "dev" (gantry.dev/v1alpha1)

$ gantry apply --check -f gantry.yaml
sandbox "dev": would create and start

$ gantry apply -f gantry.yaml
```

Relative host paths are resolved from the manifest's directory, not from the
shell's current directory. An image beginning with `./` or `../` is likewise a
manifest-relative local image; other image strings are OCI references.
Manifest apply/export currently target the local Gantry host; remote-manager
manifest reconciliation is not yet exposed.

## Reconciliation

`gantry apply` ensures that the declared sandbox is running:

- a missing sandbox is created and started;
- an unchanged running sandbox is left untouched;
- an unchanged stopped sandbox is resumed;
- a changed stopped sandbox is updated and started; and
- a changed running sandbox is shut down cleanly, updated, and restarted.

The update path preserves the existing sandbox state directory and writable
layer. If replacement startup fails, Gantry restores the previous saved
configuration and attempts to restart it.

Gantry records the digest of the last applied normalized manifest. An
imperative persistent mutation such as `gantry configure`, `gantry share add`,
or `gantry net-policy set` invalidates that provenance, so the next apply
observes drift. Use `--force` when a referenced non-secret file or mutable
image tag changed without the YAML itself changing. `--check` validates and
reports the action without changing sandbox state.

## Strict and safe YAML

Manifest decoding is intentionally narrow:

- unknown and duplicate fields are rejected;
- exactly one YAML document is accepted;
- aliases, anchors, merge keys, and custom tags are rejected;
- `apiVersion` and `kind` are required; and
- there is no implicit `${ENV}` or shell expansion.

Secret values are never valid manifest fields. Environment entries name the
host environment variable to read at launch and must match the guest secret
name. File entries persist only a canonical source path and optional refresh
TTL:

```yaml
secrets:
  - name: API_TOKEN
    environment: API_TOKEN
    bind: api.example.com
  - name: ROTATING_TOKEN
    file: ./private/token
    bind: registry.example.com
    ttl: 30s
```

## Main fields

### Resources and storage

Memory and disk sizes are whole `MiB`, `GiB`, or `TiB` values. CPU counts and
all resource bounds use the same validation as `gantry start`.

```yaml
spec:
  resources:
    cpus: 4
    memory: 4GiB
    disk: 8GiB
  root:
    writable: true
    # layer: /explicit/writable.ext4
```

Advanced boot inputs are available without exposing resolved runtime fields:

```yaml
spec:
  boot:
    kernel: ./artifacts/kernel
    rootfs: ./artifacts/rootfs.erofs
  root:
    layerSet:
      fsmeta: ./layers/fsmeta.erofs
      layers:
        - ./layers/1.erofs
        - ./layers/2.erofs
```

### Shares and networking

```yaml
spec:
  shares:
    - name: source
      source: ./src
      target: /workspace
      readOnly: true
      uid: 1000
      gid: 1000

  network:
    enabled: true
    allowLocal: false
    policy: ./network-policy.json
    ports:
      - host: 8080
        guest: 80
      - host: "[::1]:5353"
        guest: 53
        protocol: udp
    proxy:
      url: http://proxy.example:3128
      noProxy: [localhost, 127.0.0.1]
      enforce: true
```

### OAuth and MCP

OAuth provider registrations contain public client metadata only. Tokens and
client secrets are not accepted.

```yaml
spec:
  oauth:
    bridge: true
    custody: true
    providerFiles:
      - ./oauth/company.json

  mcp:
    enabled: true
    filesystem:
      root: /workspace
      user: nobody
    remotes:
      - name: company
        url: https://mcp.example.com/rpc
        auth:
          type: custody
          reference: company
        allow: ["docs_*"]
        deny: ["admin_*"]
        redact: [API_TOKEN]
```

MCP authentication types are `bearer`, `header`, and `custody`. A header
registration also supplies `header`; `reference` is always a secret or custody
provider name, never its value.

### Organization policy

A source manifest normally references the signed bundle and key:

```yaml
spec:
  organizationPolicy:
    bundle: ./policy/bundle.tar.gz
    publicKey: ./policy/public.pem
    profile: developer
```

Gantry snapshots and verifies those files during apply. Exported manifests use
an inline, base64-encoded copy of the already pinned signed bundle so they do
not silently reload mutable source files.

## Export an existing sandbox

```console
gantry manifest export dev > gantry.yaml
```

Export projects resolved state back into a public manifest. No secret value is
available to the exporter. Legacy value-only secret entries become same-name
environment references, so the corresponding environment variables must be
set before applying the result. Generated image metadata and runtime-only
handles are not exposed.

The exported manifest is strict-decodable and can be checked before use:

```console
gantry manifest validate gantry.yaml
gantry apply --check -f gantry.yaml
```
