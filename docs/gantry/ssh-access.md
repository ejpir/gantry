# SSH and Dev Containers

Use SSH for terminals, editors, and file transfer. Enable Dev Containers when
you also need a nested development container inside the sandbox.

## Connect with SSH

```console
$ gantry start dev -image debian:bookworm-slim -ssh
$ gantry ssh doctor dev
$ gantry ssh dev
$ gantry ssh dev -- uname -a
```

SSH defaults to the OCI image user. Select another existing `/etc/passwd` user
with `gantry ssh root@dev`. Stopped sandboxes and sandboxes without SSH are
refused.

Gantry uses a private host-side SSH gateway, not an `sshd` TCP listener inside
the VM.

## Use regular `*.gantry` hostnames

Install Gantry's managed OpenSSH block:

```console
$ gantry ssh setup
$ ssh dev.gantry
```

OpenSSH 8.4 or newer is required. Remove the block with:

```console
$ gantry ssh setup --remove
```

`gantry ssh dev` works without persistent setup.

## Connect from VS Code

1. Run `gantry ssh doctor dev`.
2. Run `gantry ssh setup`.
3. Tell VS Code to download its server locally and upload it:

   ```json
   {"remote.SSH.localServerDownload": "always"}
   ```

4. Open a guest path:

   ```console
   $ code --remote ssh-remote+dev.gantry /workspace/project
   ```

The image needs a Bourne shell, `tar`, a writable home, and compatible runtime
libraries. The curated Dev Containers image includes them.

## Use Dev Containers

```console
$ gantry start dev -image ubuntu:latest -ssh -devcontainers
$ gantry ssh setup
```

The same microVM then contains two peer environments:

- `gantry exec dev` enters the workload selected by `-image`;
- SSH enters a curated IDE image with nested Podman.

Connect with VS Code Remote SSH, open the project, install the **Dev
Containers** extension, and choose **Reopen in Container**. Its normal
Docker-compatible workflow uses the curated image's Podman wrapper. No host
container-engine socket is exposed.

Default Dev Containers resources are 4096 MiB memory, four vCPUs (capped by the
host), and a 32768 MiB IDE writable disk. Override normal resource flags when
creating the sandbox.

Nested images, volumes, and filesystem data persist across stop/resume. Running
inner containers do not survive a VM restart. They can mount only paths already
visible inside the IDE environment.

### Enable Dev Containers on an existing sandbox

```console
$ gantry configure dev -ssh -devcontainers
$ gantry stop dev
$ gantry resume dev
```

The topology change requires a reboot. It does not replace the workload image.
The IDE disk size is fixed when first prepared.

Guest-helper setup runs after VM readiness. A first SSH connection immediately
after boot may wait briefly.

### Install additional tools

The curated `gantry` user has passwordless `sudo` inside the microVM:

```console
$ sudo apt-get update
$ sudo apt-get install -y jq ripgrep python3
```

Packages persist on the IDE writable disk until deletion.

## Transfer files and forward a port

After `gantry ssh setup`, standard tools work:

```console
$ sftp dev.gantry
$ scp -O ./file dev.gantry:/workspace/
$ rsync -av ./src/ dev.gantry:/workspace/src/
```

Forward a host port to guest loopback:

```console
$ ssh -L 8080:127.0.0.1:3000 dev.gantry
```

Targets are limited to guest `127.0.0.1` and `::1`. Remote forwarding, agent
forwarding, passwords, and public-key client authentication are unsupported.

## Diagnose a connection

```console
$ gantry ssh doctor dev
$ gantry audit dev
```

See [Troubleshooting](troubleshooting.md),
[Architecture](architecture.md#ssh-gateway-and-guest-helper), and
[Security](security.md#local-control-surfaces).
