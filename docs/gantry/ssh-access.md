# SSH and Dev Containers

Use SSH when a terminal, editor, or file-transfer tool needs to connect to a
persistent Gantry sandbox. Add the Dev Containers profile when you also want to
run a nested development container inside that sandbox.

For implementation and security-boundary details, see
[Architecture](architecture.md) and [Security](security.md).

## Connect with SSH

Enable SSH when creating the sandbox:

```console
$ gantry start dev -image debian:bookworm-slim -ssh
$ gantry ssh doctor dev
$ gantry ssh dev
```

Run a single command without opening an interactive shell:

```console
$ gantry ssh dev -- uname -a
```

The username defaults to the OCI image user. Select another user by prefixing
the sandbox name:

```console
$ gantry ssh root@dev -- id
```

The selected user must exist in the image's `/etc/passwd`. A stopped sandbox,
or one created without `-ssh`, is refused.

## Use regular `*.gantry` hostnames

Run setup once if you want to use stock SSH tools directly:

```console
$ gantry ssh setup
$ ssh dev.gantry
$ ssh dev.gantry hostname
```

This requires OpenSSH 8.4 or newer. Remove Gantry's SSH configuration with:

```console
$ gantry ssh setup --remove
```

You can always use `gantry ssh dev` without installing the persistent SSH
configuration.

## Connect from VS Code

1. Check that the image has the tools required by Remote SSH:

   ```console
   $ gantry ssh doctor dev
   ```

2. Configure the `*.gantry` hostname:

   ```console
   $ gantry ssh setup
   ```

3. Tell VS Code to download its server locally and upload it to the sandbox:

   ```json
   {
     "remote.SSH.localServerDownload": "always"
   }
   ```

4. Open a directory using its path inside the sandbox:

   ```console
   $ code --remote ssh-remote+dev.gantry /workspace/project
   ```

Remote terminals, tasks, and workspace extensions run inside the sandbox.
UI-only extensions may continue to run locally.

Remote SSH needs a Bourne shell, `tar`, a writable home directory, and a
compatible libc/libstdc++ runtime. The curated development image includes
these requirements.

## Use Dev Containers

Create a sandbox with SSH, nested Podman, and the curated development image:

```console
$ gantry start dev -ssh -devcontainers
$ gantry ssh doctor dev
$ gantry ssh setup
```

Then:

1. Connect to `dev.gantry` with VS Code Remote SSH.
2. Open the project at its path inside the sandbox.
3. Install the **Dev Containers** extension.
4. Run **Dev Containers: Reopen in Container**.

The extension can use its normal Docker-compatible workflow. Gantry does not
mount or expose a container engine from the host.

Unless overridden, `-devcontainers` selects:

| Resource | Default |
|---|---:|
| Memory | 4096 MiB |
| vCPUs | 4, capped by the host |
| Writable disk | 32768 MiB |

Override any value when creating the sandbox:

```console
$ gantry start dev -ssh -devcontainers -mem 8192 -cpus 6 -disk-size 49152
```

Nested images, volumes, and filesystem layers are stored on the sandbox's
private writable disk and persist across stop/resume. Running inner containers
do not survive a VM restart. They share the VM's memory and CPU allocation,
and can bind-mount only paths already available inside the outer sandbox.

### Enable Dev Containers on an existing sandbox

```console
$ gantry configure dev -ssh -devcontainers
```

SSH and the nested-runtime profile apply to new sessions immediately; reconnect
before opening the Dev Container. Memory, CPU, and process-isolation changes
apply after the next VM start. The writable-disk size is fixed when the
sandbox is created.

Enabling the profile later does not replace a custom base image or install
Podman into it. Use a sandbox created with the curated image, or ensure your
custom image already provides Podman and its dependencies. Check it with:

```console
$ gantry ssh doctor dev
```

Guest-helper setup does not delay `start`, `resume`, or dashboard readiness. A
first SSH connection made immediately after boot may wait briefly for setup to
finish.

### Install additional tools

The curated image's `gantry` user has passwordless `sudo`:

```console
$ sudo apt-get update
$ sudo apt-get install -y jq ripgrep python3
```

Installed packages persist on the sandbox's private writable disk until the
sandbox is deleted.

## Transfer files and forward a local port

After `gantry ssh setup`, standard SSH tools work with the managed hostname:

```console
$ sftp dev.gantry
$ scp -O ./file dev.gantry:/workspace/
$ rsync -av ./src/ dev.gantry:/workspace/src/
```

SFTP follows the selected guest user's filesystem permissions.

Forward a host port to a service listening on guest loopback:

```console
$ ssh -L 8080:127.0.0.1:3000 dev.gantry
```

Forward targets are limited to guest `127.0.0.1` and `::1`. Remote forwarding,
SSH agent forwarding, password authentication, and public-key authentication
are not supported.

## Diagnose a connection

```console
$ gantry ssh doctor dev
$ gantry audit dev
```

Also see [Troubleshooting](troubleshooting.md) for sandbox logs and common
startup failures.
