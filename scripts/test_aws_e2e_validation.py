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
# PowerShell command rendering still uses the real interpreter so Windows argv
# quoting is tested without passing through an MSYS shebang shim.
TOOL = r'''
import json
import os
from pathlib import Path
import sys

name = Path(sys.argv[0]).name
args = sys.argv[1:]
with open(os.environ["CALL_LOG"], "a", encoding="utf-8") as stream:
    stream.write(json.dumps({"tool": name, "args": args, "goos": os.environ.get("GOOS"), "goarch": os.environ.get("GOARCH")}) + "\n")
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
    output.write_text("#!" + os.environ["SHELL_PYTHON"] + "\n" + os.environ["TOOL_BODY"], encoding="utf-8")
    output.chmod(0o755)
elif name == "uname":
    print("Darwin" if args == ["-s"] else "arm64")
elif name == "policy-e2e":
    if failure == "macos":
        sys.exit(9)
    print("Policy E2E: 1 checks passed")
'''

SSM_TOOL = r'''
import json
import os
import sys

args = sys.argv[1:]
with open(os.environ["CALL_LOG"], "a", encoding="utf-8") as stream:
    stream.write(json.dumps({"tool": "python3", "args": args, "goos": os.environ.get("GOOS"), "goarch": os.environ.get("GOARCH")}) + "\n")
if "-c" in args:
    command = args[args.index("-c") + 1]
    failure = os.environ.get("FAKE_FAILURE", "")
    if failure == "kvm" and "/opt/gantry/policy-e2e" in command:
        raise SystemExit(9)
    if failure == "whpx" and "C:/gantry/policy-e2e.exe" in command:
        raise SystemExit(9)
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
            "aws-whpx/replay.sh", "aws-kvm/run-tests.sh", "aws-kvm/run-tests-arm64.sh",
            "aws-kvm/test-battery.sh", "aws-kvm/ssh-devcontainers-validation.sh",
            "aws-kvm/directory-validation.sh", "test-manager-api-e2e.sh",
        ):
            (scripts / relative).write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        for relative in ("aws-kvm/ssm.py", "aws-whpx/ssm.py"):
            (scripts / relative).write_text(SSM_TOOL, encoding="utf-8")
        (scripts / "build.sh").write_text(
            '#!/bin/sh\nmkdir -p "$GANTRY_ARTIFACTS"\n'
            'for name in gantry-darwin-arm64 gantry-guest-arm64; do\n'
            '  printf "#!/bin/sh\\nexit 0\\n" > "$GANTRY_ARTIFACTS/$name"\n'
            '  chmod +x "$GANTRY_ARTIFACTS/$name"\ndone\n',
            encoding="utf-8",
        )
        self.bin = self.root / "bin"
        self.bin.mkdir()
        shell_python = sys.executable
        if os.name == "nt":
            # Fake tools execute under Git for Windows' POSIX shell. Convert the
            # native interpreter path for a valid shebang while retaining the
            # native path for Python's os.execv below.
            shell_python = subprocess.run(
                ["cygpath", "-u", sys.executable],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
        for name in ("aws", "go", "uname", "codesign", "curl", "perl", "ssh", "sftp"):
            path = self.bin / name
            path.write_text(f"#!{shell_python}\n{TOOL}", encoding="utf-8")
            path.chmod(0o755)
        self.log = self.root / "calls.jsonl"
        image = self.root / "fixture.erofs"
        image.write_bytes(b"fixture")
        self.env = {key: value for key, value in os.environ.items() if not key.startswith(("GANTRY_", "AWS_"))}
        self.env.update({
            "PATH": str(self.bin) + os.pathsep + os.environ["PATH"],
            "HOME": str(self.root), "CALL_LOG": str(self.log),
            "SHELL_PYTHON": shell_python, "TOOL_BODY": TOOL,
            "AWS_ACCESS_KEY_ID": "not-a-real-credential",
            "GANTRY_LINUX_IID": "i-linux", "GANTRY_ARM_IID": "i-arm", "GANTRY_WINDOWS_IID": "i-windows",
            "GANTRY_TEST_IDE_IMAGE": str(image), "GANTRY_TEST_ARM_IDE_IMAGE": str(image),
            "GANTRY_TEST_WORKLOAD_IMAGE": str(image),
            "GANTRY_TEST_KERNEL": str(image), "GANTRY_TEST_ROOTFS": str(image),
            "GANTRY_SKIP_SELFUPDATE": "1", "GANTRY_SKIP_DEVCONTAINERS": "1",
            "GANTRY_TEST_PUBLIC_EGRESS": "skip",
        })

    def invoke(self, mode="aws", failure="", overrides=None):
        env = dict(self.env, FAKE_FAILURE=failure)
        env.update(overrides or {})
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

    def test_aws_stages_fresh_drivers_and_runs_all_platform_batteries(self):
        result, calls = self.invoke()
        self.assertEqual(result.returncode, 0, result.stderr)
        builds = [call for call in calls if call["tool"] == "go"]
        expected_targets = {("linux", "amd64"), ("linux", "arm64"), ("windows", "amd64")}
        for package in ("./tests/e2e/policy", "./tests/e2e/managerapi"):
            package_builds = [call for call in builds if package in call["args"]]
            self.assertEqual({(call["goos"], call["goarch"]) for call in package_builds}, expected_targets)
        uploads = [call for call in calls if call["tool"] == "aws" and call["args"][:2] == ["s3", "cp"]]
        self.assertEqual(sum("e2e/policy-" in " ".join(call["args"]) for call in uploads), 3)
        self.assertEqual(sum("e2e/manager-api-" in " ".join(call["args"]) for call in uploads), 3)
        downloads = [call for call in calls if "--s3-download" in call["args"]]
        self.assertEqual(sum("policy-" in " ".join(call["args"]) for call in downloads), 3)
        self.assertEqual(sum("manager-api-" in " ".join(call["args"]) for call in downloads), 3)
        commands = [call["args"][call["args"].index("-c") + 1] for call in calls if call["tool"] == "python3" and "-c" in call["args"]]
        policy_commands = [command for command in commands if "policy-e2e" in command]
        manager_commands = [command for command in commands if "manager-api-e2e" in command]
        self.assertEqual(len(policy_commands), 3)
        self.assertEqual(len(manager_commands), 3)
        self.assertTrue(any("gantry-linux-arm64-current" in command for command in policy_commands))
        windows = next(command for command in policy_commands if "C:/gantry/policy-e2e.exe" in command)
        self.assertIn("C:/Owner''s Gantry/gantry-field.exe", windows)
        self.assertIn("exit $LASTEXITCODE", windows)
        self.assertTrue(all("-cli-only" not in command for command in policy_commands))
        self.assertTrue(all("-pull=false" in command for command in manager_commands))
        self.assertIn("AWS E2E VALIDATION PASSED", result.stdout)

    def test_policy_failure_fails_orchestrator_and_still_stops_instances(self):
        for platform in ("kvm", "whpx"):
            with self.subTest(platform=platform):
                self.log.unlink(missing_ok=True)
                result, calls = self.invoke(failure=platform)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("AWS E2E VALIDATION PASSED", result.stdout)
                stops = [call for call in calls if call["tool"] == "aws" and call["args"][:2] == ["ec2", "stop-instances"]]
                self.assertTrue(stops)
                self.assertTrue({"i-linux", "i-arm", "i-windows"}.issubset(stops[-1]["args"]))

    def test_keep_instances_preserves_all_hosts_after_failure(self):
        result, calls = self.invoke(failure="kvm", overrides={"GANTRY_KEEP_INSTANCES": "1"})
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(any(call["tool"] == "aws" and call["args"][:2] == ["ec2", "stop-instances"] for call in calls))
        self.assertIn("leaving instances running", result.stdout)

    def test_macos_policy_is_not_skipped_with_devcontainers_or_public_egress(self):
        result, calls = self.invoke("macos")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(any(call["tool"] == "aws" for call in calls))
        oauth_builds = [
            call
            for call in calls
            if call["tool"] == "go" and "./tests/e2e/oauthidp" in call["args"]
        ]
        self.assertEqual(
            {(call["goos"], call["goarch"]) for call in oauth_builds},
            {("darwin", "arm64")},
        )
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
