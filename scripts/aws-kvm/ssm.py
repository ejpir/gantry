#!/usr/bin/env python3
"""SSM send-command helper: run shell commands on the gantry KVM test instance.

Usage:
  GANTRY_TEST_IID=i-xxx python3 ssm.py <script.sh|-c 'cmd'> [timeout]
  python3 ssm.py i-xxx <script.sh|-c 'cmd'> [timeout]

Reads AWS creds from the environment (source your keys file first).
NOTE: the SSM document prepends `set -e` — start scripts with `set +e`
if you expect benign failures (e.g. `gantry stop` on a fresh box).
"""
import os
import sys
import time

import boto3

REGION = os.environ.get("GANTRY_TEST_REGION", "eu-west-1")


def main():
    args = sys.argv[1:]
    iid = os.environ.get("GANTRY_TEST_IID", "")
    if args and args[0].startswith("i-"):
        iid, args = args[0], args[1:]
    if not iid:
        sys.exit("instance id required (GANTRY_TEST_IID or first arg)")
    if not args:
        sys.exit("usage: ssm.py [i-xxx] <script.sh|-c 'cmd'> [timeout]")
    src = args[0]
    timeout = int(args[1]) if len(args) > 1 else 300
    script = args[2] if src == "-c" else open(src).read()

    ssm = boto3.client("ssm", region_name=REGION)
    resp = ssm.send_command(
        InstanceIds=[iid],
        DocumentName="AWS-RunShellScript",
        Parameters={"commands": ["set -e", script]},
        TimeoutSeconds=timeout,
    )
    cid = resp["Command"]["CommandId"]
    print(f"command-id: {cid}", file=sys.stderr)
    deadline = time.time() + timeout + 120
    while time.time() < deadline:
        time.sleep(4)
        inv = ssm.get_command_invocation(CommandId=cid, InstanceId=iid)
        status = inv["Status"]
        if status in ("Pending", "InProgress", "Delayed"):
            continue
        print(f"=== status: {status}")
        if inv.get("StandardOutputContent"):
            print(inv["StandardOutputContent"])
        if inv.get("StandardErrorContent"):
            print("=== stderr:", file=sys.stderr)
            print(inv["StandardErrorContent"], file=sys.stderr)
        sys.exit(0 if status == "Success" else 1)
    sys.exit("timed out waiting for command")


if __name__ == "__main__":
    main()
