"""Exercise policy-battery orchestration without AWS credentials, hosts or VMs."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("aws-e2e-validation.sh")

# Every external cloud/build tool is replaced inside a private fake checkout.
# The one real Python invocation only renders a PowerShell command from stdin.
TOOL = r'''
import json
import os
from pathlib import Path
import sys

name = Path(sys.argv[0]).name
args = sys.argv[1:]
if name == "python3" and args and args[0] == "-":
    os.execv(os.environ["REAL_PYTHON"], [os.environ["REAL_PYTHON"], *args])
with open(os.environ["CALL_LOG"], "a", encoding="utf-8") as stream:
    stream.write(json.dumps({"tool": name, "args": args, "goos": os.environ.get("GOOS")}) + "\n")
failure = os.environ.get("FAKE_FAILURE", "")
if name == "aws":
    if args[:2] == ["sts", "get-caller-identity"]:
        print("123456789012")
    elif args[:2] == ["ec2", "describe-instances"]:
        print("running")
    elif args[:2] == ["ssm", "describe-instance-information"]:
        print("Online")
elif name == "go":
    output = Path(args[args.index("-o") + 1])
    output.write_text("#!" + os.environ["REAL_PYTHON"] + "\n" + os.environ["TOOL_BODY"], encoding="utf-8")
    output.chmod(0o755)
elif name == "uname":
    print("Darwin" if args == ["-s"] else "arm64")
elif name == "python3" and "-c" in args:
    command = args[args.index("-c") + 1]
    if failure == "kvm" and "/opt/gantry/policy-e2e" in command:
        sys.exit(9)
    if failure == "whpx" and "C:/gantry/policy-e2e.exe" in command:
        sys.exit(9)
elif name == "policy-e2e":
    if failure == "macos":
        sys.exit(9)
    print("Policy E2E: 1 checks passed")
'''


class PolicyOrchestrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        scripts = self.root / "scripts"
        (scripts / "aws-kvm").mkdir(parents=True)
        (scripts / "aws-whpx").mkdir()
        shutil.copyfile(SCRIPT, scripts / SCRIPT.name)
        for relative in (
            "aws-whpx/replay.sh", "aws-kvm/run-tests.sh", "aws-kvm/test-battery.sh",
            "aws-kvm/directory-validation.sh", "test-manager-api-e2e.sh",
        ):
            (scripts / relative).write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        (scripts / "build.sh").write_text(
            '#!/bin/sh\nmkdir -p "$GANTRY_ARTIFACTS"\n'
            'for name in gantry-darwin-arm64 gantry-guest-arm64; do\n'
            '  printf dummy > "$GANTRY_ARTIFACTS/$name"\n'
            '  chmod +x "$GANTRY_ARTIFACTS/$name"\ndone\n',
            encoding="utf-8",
        )
        self.bin = self.root / "bin"
        self.bin.mkdir()
        for name in ("aws", "go", "python3", "uname", "codesign", "curl", "perl", "ssh", "sftp"):
            path = self.bin / name
            path.write_text(f"#!{sys.executable}\n{TOOL}", encoding="utf-8")
            path.chmod(0o755)
        self.log = self.root / "calls.jsonl"
        image = self.root / "fixture.erofs"
        image.write_bytes(b"fixture")
        self.env = {key: value for key, value in os.environ.items() if not key.startswith(("GANTRY_", "AWS_"))}
        self.env.update({
            "PATH": str(self.bin) + os.pathsep + os.environ["PATH"],
            "HOME": str(self.root), "CALL_LOG": str(self.log),
            "REAL_PYTHON": sys.executable, "TOOL_BODY": TOOL,
            "AWS_ACCESS_KEY_ID": "not-a-real-credential",
            "GANTRY_LINUX_IID": "i-linux", "GANTRY_WINDOWS_IID": "i-windows",
            "GANTRY_TEST_IDE_IMAGE": str(image), "GANTRY_TEST_WORKLOAD_IMAGE": str(image),
            "GANTRY_TEST_KERNEL": str(image), "GANTRY_TEST_ROOTFS": str(image),
            "GANTRY_SKIP_SELFUPDATE": "1", "GANTRY_SKIP_DEVCONTAINERS": "1",
            "GANTRY_TEST_PUBLIC_EGRESS": "skip",
        })

    def invoke(self, mode="aws", failure=""):
        env = dict(self.env, FAKE_FAILURE=failure)
        # Exercise quoting of a real Windows override without creating that path.
        if mode == "aws":
            env["GANTRY_TEST_EXE"] = "C:/Owner's Gantry/gantry-field.exe"
            env["GANTRY_TEST_WORKLOAD_IMAGE"] = "C:/gantry/workload.erofs"
        result = subprocess.run(
            ["sh", str(self.root / "scripts" / SCRIPT.name), mode],
            env=env, capture_output=True, text=True, timeout=30,
        )
        calls = [json.loads(line) for line in self.log.read_text(encoding="utf-8").splitlines()] if self.log.exists() else []
        return result, calls

    def test_aws_stages_fresh_drivers_and_runs_both_vm_batteries(self):
        result, calls = self.invoke()
        self.assertEqual(result.returncode, 0, result.stderr)
        builds = [call for call in calls if call["tool"] == "go"]
        self.assertEqual({call["goos"] for call in builds}, {"linux", "windows"})
        self.assertTrue(all("./tests/e2e/policy" in call["args"] for call in builds))
        uploads = [call for call in calls if call["tool"] == "aws" and call["args"][:2] == ["s3", "cp"]]
        self.assertEqual(sum("e2e/policy-" in " ".join(call["args"]) for call in uploads), 2)
        downloads = [call for call in calls if "--s3-download" in call["args"]]
        self.assertEqual(len(downloads), 2)
        commands = [call["args"][call["args"].index("-c") + 1] for call in calls if call["tool"] == "python3" and "-c" in call["args"]]
        self.assertEqual(len(commands), 2)
        self.assertTrue(any("/opt/gantry/policy-e2e" in command for command in commands))
        windows = next(command for command in commands if "C:/gantry/policy-e2e.exe" in command)
        self.assertIn("C:/Owner''s Gantry/gantry-field.exe", windows)
        self.assertIn("exit $LASTEXITCODE", windows)
        self.assertTrue(all("-cli-only" not in command for command in commands))
        self.assertIn("AWS E2E VALIDATION PASSED", result.stdout)

    def test_policy_failure_fails_orchestrator_and_still_stops_instances(self):
        for platform in ("kvm", "whpx"):
            with self.subTest(platform=platform):
                self.log.unlink(missing_ok=True)
                result, calls = self.invoke(failure=platform)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("AWS E2E VALIDATION PASSED", result.stdout)
                self.assertTrue(any(call["tool"] == "aws" and call["args"][:2] == ["ec2", "stop-instances"] for call in calls))

    def test_macos_policy_is_not_skipped_with_devcontainers_or_public_egress(self):
        result, calls = self.invoke("macos")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(any(call["tool"] == "aws" for call in calls))
        drivers = [call for call in calls if call["tool"] == "policy-e2e"]
        self.assertEqual(len(drivers), 1)
        self.assertNotIn("-cli-only", drivers[0]["args"])
        self.assertIn("-artifacts", drivers[0]["args"])
        self.assertIn("macOS E2E VALIDATION PASSED", result.stdout)

    def test_macos_policy_failure_is_not_swallowed(self):
        result, calls = self.invoke("macos", "macos")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(any(call["tool"] == "aws" for call in calls))
        self.assertNotIn("macOS E2E VALIDATION PASSED", result.stdout)


if __name__ == "__main__":
    unittest.main()
