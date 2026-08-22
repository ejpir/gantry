# Run coding agents in Gantry

Gantry gives an agent a VM, only the host directories you name, and the
network policy you choose. The agent can install packages and run arbitrary
commands without receiving ambient access to the rest of the host.

## Create an agent sandbox

The following sandbox can modify the current project, receives one token, and
can reach only common model and development services from the included policy:

```console
$ cd ~/my-project
$ export GITHUB_TOKEN=...
$ gantry start agent \
    -image python:3.12 \
    -cpus 2 \
    -mem 2048 \
    -share "workspace=$PWD,mount=/workspace" \
    -secret GITHUB_TOKEN \
    -net-policy ./examples/llm-only.json
```

Install or run the agent in the sandbox:

```console
$ gantry exec agent -- sh -lc 'cd /workspace && python -m pytest'
```

The writable image root, installed packages, command history, and agent state
survive a stop and resume. Project edits appear immediately on the host
because `/workspace` is a direct share.

Use `,ro` for source that the agent should inspect but not change:

```console
$ gantry start reviewer -image alpine:latest \
    -share "source=$PWD,mount=/workspace,ro" \
    -net-policy ./examples/llm-only.json
```

## Choose an isolation posture

For unattended or untrusted work, use fail-closed worker isolation:

```console
$ gantry start agent -image python:3.12 \
    -process-isolation=required \
    -share "workspace=$PWD,mount=/workspace" \
    -net-policy ./examples/llm-only.json
```

`required` refuses startup if Gantry cannot establish and verify its split
worker topology. This mode is not currently available on Windows because the
experimental Windows worker cannot verify all required filesystem and network
restrictions.

Add `-runtime runsc` to place gVisor inside the microVM when the guest workload
needs another boundary:

```console
$ gantry start agent-gvisor -image python:3.12 -runtime runsc
```

See [Security](security.md) before treating a sandbox as a boundary for
hostile multi-tenant workloads.

## Run Pi

`gantry pi` maintains one persistent sandbox per project directory, mounts the
project at `/workspace`, and streams Pi's terminal UI to the host terminal.

Build a Pi-capable image from a source checkout:

```console
$ ./scripts/mkpiimage.sh
```

Start Pi with a constrained policy:

```console
$ gantry pi -image ./pi-agent.tar -net-policy ./examples/llm-only.json
```

While that sandbox is running, reattach from the project directory with:

```console
$ gantry pi
```

Use `GANTRY_PI_IMAGE` to configure the image permanently, or `-restart` to
delete and recreate the project sandbox.

By default, Gantry shares `~/.pi/agent` read-write at `/root/.pi/agent` so the
guest can reuse the host login, sessions, and settings. Everything inside the
sandbox can read that share. Pair it with a narrow egress policy, or disable
the share and log in inside the guest:

```console
$ gantry pi -pi-auth=false -image ./pi-agent.tar
```

The guest-local login then persists in the sandbox's writable layer.

