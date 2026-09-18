# Sandbox manifests

Gantry supports strict, versioned YAML for repeatable sandbox creation. The
saved `sandbox.json` remains internal resolved state and must not be edited.

## Define and apply

```yaml
apiVersion: gantry.dev/v1alpha1
kind: Sandbox
metadata:
  name: dev
spec:
  image: debian:bookworm-slim
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
  secrets:
    - name: GITHUB_TOKEN
      environment: GITHUB_TOKEN
  ssh:
    enabled: true
```

```console
gantry manifest validate gantry.yaml
gantry apply --check -f gantry.yaml
gantry apply -f gantry.yaml
```

`apply` creates a missing sandbox, resumes an unchanged stopped sandbox, and
cleanly restarts a changed running sandbox. Use `--force` when a referenced
file or mutable image tag changed without changing the YAML.

Relative host paths resolve from the manifest directory. Local image paths
must begin with `./` or `../`; other image strings are treated as OCI
references. Apply and export currently target the local Gantry host.

## Safety rules

- Unknown and duplicate fields are rejected.
- YAML aliases, merge keys, custom tags, and multiple documents are rejected.
- There is no shell or `${ENV}` expansion.
- Secret values are not valid manifest fields; use environment or file
  references.
- Memory and disk sizes use whole `MiB`, `GiB`, or `TiB` values.

Shares, networking, OAuth, MCP, organization policy, Dev Containers, and
advanced boot settings use the same validation and security rules as their CLI
counterparts. See [`examples/sandbox.yaml`](../../examples/sandbox.yaml) and
the corresponding topic guides for examples.

## Export

```console
gantry manifest export dev > gantry.yaml
gantry manifest validate gantry.yaml
```

Export never includes secret values. Legacy value-only secret entries become
same-name environment references that must be supplied before applying the
result.

See [Architecture](architecture.md#declarative-sandbox-manifests) for compiler,
provenance, drift detection, restart, and rollback details.
