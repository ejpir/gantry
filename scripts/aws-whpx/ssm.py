#!/usr/bin/env python3
"""Run PowerShell validation commands on a Windows EC2 instance over SSM.

Usage:
  python3 ssm.py [i-xxx] script.ps1 [timeout]
  python3 ssm.py [i-xxx] -c 'Get-Process' [timeout]
  python3 ssm.py [i-xxx] --s3-download BUCKET KEY DESTINATION [timeout]

The instance id may instead be supplied as GANTRY_TEST_IID. AWS credentials
come from the environment; this helper never reads or prints them.
"""

import os
import sys
import time

import boto3


REGION = os.environ.get("GANTRY_TEST_REGION", "eu-west-1")


def invocation_args():
    args = sys.argv[1:]
    instance = os.environ.get("GANTRY_TEST_IID", "")
    if args and args[0].startswith("i-"):
        instance, args = args[0], args[1:]
    if not instance:
        sys.exit("instance id required (GANTRY_TEST_IID or first argument)")
    if not args:
        sys.exit("PowerShell script, -c command, or --s3-download required")

    mode = args.pop(0)
    if mode == "-c":
        if not args:
            sys.exit("-c requires a PowerShell command")
        script = args.pop(0)
    elif mode == "--s3-download":
        if len(args) < 3:
            sys.exit("--s3-download requires BUCKET KEY DESTINATION")
        bucket, key, destination = args[:3]
        args = args[3:]
        s3 = boto3.client("s3", region_name=REGION)
        url = s3.generate_presigned_url(
            "get_object",
            Params={"Bucket": bucket, "Key": key},
            ExpiresIn=3600,
        )
        script = (
            "$ProgressPreference='SilentlyContinue'; "
            f"Invoke-WebRequest -Uri '{url}' -OutFile '{destination}'"
        )
    else:
        with open(mode, encoding="utf-8") as source:
            script = source.read()

    timeout = int(args.pop(0)) if args else 600
    if args:
        sys.exit("too many arguments")
    return instance, script, timeout


def main():
    instance, script, timeout = invocation_args()
    ssm = boto3.client("ssm", region_name=REGION)
    response = ssm.send_command(
        InstanceIds=[instance],
        DocumentName="AWS-RunPowerShellScript",
        TimeoutSeconds=timeout,
        Parameters={"commands": [script]},
    )
    command_id = response["Command"]["CommandId"]
    print(f"command-id: {command_id}", file=sys.stderr, flush=True)

    deadline = time.time() + timeout + 120
    while time.time() < deadline:
        time.sleep(4)
        invocation = ssm.get_command_invocation(
            CommandId=command_id, InstanceId=instance
        )
        status = invocation["Status"]
        if status in ("Pending", "InProgress", "Delayed"):
            continue
        print(f"=== status: {status}")
        output = invocation.get("StandardOutputContent", "")
        errors = invocation.get("StandardErrorContent", "")
        if output:
            print(output)
        if errors:
            print("=== stderr:", file=sys.stderr)
            print(errors, file=sys.stderr)
        sys.exit(0 if status == "Success" else 1)
    sys.exit("timed out waiting for SSM command")


if __name__ == "__main__":
    main()
