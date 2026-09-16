"""Host-only checks for the cross-platform E2E fixture; no VM or AWS needed."""

import argparse
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch
from urllib.error import HTTPError
from urllib.parse import parse_qs, urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

SPEC = importlib.util.spec_from_file_location(
    "oauth_custody_e2e", Path(__file__).with_name("oauth-custody-e2e.py")
)
e2e = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(e2e)


def shell_path(path):
    """Return a path consumable by the POSIX shell used by these tests."""
    if os.name != "nt":
        return str(path)
    return subprocess.run(
        ["cygpath", "-u", str(path)],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def bash_executable():
    """Find Git Bash on Windows without accidentally selecting WSL bash.exe."""
    if os.name != "nt":
        return shutil.which("bash") or "bash"
    sh = shutil.which("sh")
    if sh:
        candidate = Path(sh).with_name("bash.exe")
        if candidate.is_file():
            return str(candidate)
    raise RuntimeError("Git Bash is required for the shared shell-battery test")


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class FixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.build_dir = tempfile.TemporaryDirectory()
        suffix = ".exe" if os.name == "nt" else ""
        cls.idp_binary = str(Path(cls.build_dir.name) / ("oauth-idp" + suffix))
        subprocess.run(
            ["go", "build", "-o", cls.idp_binary, "./tests/e2e/oauthidp"],
            cwd=Path(__file__).resolve().parent.parent,
            check=True,
            capture_output=True,
            text=True,
        )

    @classmethod
    def tearDownClass(cls):
        cls.build_dir.cleanup()

    def setUp(self):
        self.fixture = e2e.LocalIDP(self.idp_binary)
        self.addCleanup(self.fixture.close)
        self.client = build_opener(ProxyHandler({}), NoRedirect())

    def request(self, path, body=None, headers=None):
        headers = dict(headers or {})
        data = None
        if body is not None:
            if path == "/mcp":
                data = json.dumps(body).encode()
                headers["Content-Type"] = "application/json"
            else:
                data = urlencode(body).encode()
                headers["Content-Type"] = "application/x-www-form-urlencoded"
        request = Request(self.fixture.origin + path, data=data, headers=headers)
        try:
            response = self.client.open(request, timeout=5)
        except HTTPError as response_error:
            response = response_error
        with response:
            raw = response.read()
            payload = (
                json.loads(raw)
                if raw
                and response.headers.get_content_type() == "application/json"
                else {}
            )
            return response.status, response.headers, payload

    def authorization(self, verifier="v" * 43):
        challenge = (
            base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
            .decode()
            .rstrip("=")
        )
        params = {
            "client_id": "e2e-public-client",
            "scope": "mcp offline_access",
            "resource": self.fixture.origin + "/mcp",
            "response_type": "code",
            "code_challenge_method": "S256",
            "code_challenge": challenge,
            "state": "test-state",
            "redirect_uri": "http://127.0.0.1:53693/callback",
        }
        status, headers, _ = self.request("/authorize?" + urlencode(params))
        self.assertEqual(status, 302)
        callback = parse_qs(urlsplit(headers["Location"]).query)
        self.assertEqual(callback["state"], [params["state"]])
        return {
            "grant_type": "authorization_code",
            "client_id": params["client_id"],
            "resource": params["resource"],
            "redirect_uri": params["redirect_uri"],
            "code": callback["code"][0],
            "code_verifier": verifier,
        }

    def test_github_device_pending_then_browser_approval(self):
        status, _, device = self.request(
            "/github/device",
            {"client_id": e2e.GH_CLIENT, "scope": "repo read:org gist"},
        )
        self.assertEqual(status, 200)
        grant = {
            "client_id": e2e.GH_CLIENT,
            "device_code": device["device_code"],
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
        }
        self.assertEqual(
            self.request("/github/token", grant)[2]["error"], "authorization_pending"
        )
        e2e.browser_get(
            device["verification_uri"]
            + "?"
            + urlencode({"user_code": device["user_code"]})
        )
        token = self.request("/github/token", grant)[2]
        self.assertEqual(token["access_token"], e2e.GH_ACCESS)
        self.assertNotIn("refresh_token", token)
        self.assertNotIn("expires_in", token)
        self.assertEqual(self.fixture.observation("pending"), 1)
        self.assertEqual(self.fixture.observation("github_issues"), 1)
        self.assertEqual(self.fixture.observation("errors"), [])

    def test_generic_pkce_rotation_mcp_and_revocation(self):
        status, _, token = self.request("/token", self.authorization())
        self.assertEqual(status, 200)
        for phase in (1, 2):
            status, _, token = self.request(
                "/token",
                {
                    "grant_type": "refresh_token",
                    "client_id": "e2e-public-client",
                    "resource": self.fixture.origin + "/mcp",
                    "refresh_token": token["refresh_token"],
                },
            )
            self.assertEqual(status, 200)
            self.assertEqual(token["refresh_token"], e2e.MCP_REFRESH + str(phase))
        status, _, response = self.request(
            "/mcp",
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"name": "probe"},
            },
            {"Authorization": "Bearer " + token["access_token"]},
        )
        self.assertEqual(status, 200)
        self.assertIn(token["access_token"], response["result"]["content"][0]["text"])
        self.assertEqual(self.fixture.observation("mcp_phases"), [2])
        self.fixture.revoke()
        status, _, error = self.request(
            "/token",
            {
                "grant_type": "refresh_token",
                "client_id": "e2e-public-client",
                "resource": self.fixture.origin + "/mcp",
                "refresh_token": token["refresh_token"],
            },
        )
        self.assertEqual(status, 200)
        self.assertEqual(error["error"], "invalid_grant")
        self.assertEqual(self.fixture.observation("rejections"), 1)
        self.assertEqual(self.fixture.observation("errors"), [])

    def test_fixture_rejects_wrong_pkce_resource_and_credential(self):
        grant = self.authorization()
        grant["code_verifier"] = "wrong"
        self.assertEqual(self.request("/token", grant)[0], 400)
        grant = self.authorization()
        grant["resource"] = "https://wrong.example/mcp"
        self.assertEqual(self.request("/token", grant)[0], 400)
        self.assertEqual(
            self.request("/mcp", {"id": 1, "method": "initialize"})[0], 400
        )
        self.assertEqual(len(self.fixture.observation("errors")), 3)

    def battery(self):
        battery = e2e.Battery(
            argparse.Namespace(
                gantry="/not-executed", kernel="kernel", rootfs="rootfs", image="image"
            ),
            self.fixture,
        )
        self.addCleanup(battery.close)
        return battery

    def test_forced_expiry_stops_before_touching_disk(self):
        battery = self.battery()
        token_file = battery.root / "sandboxes/mcp/oauth-tokens.json"
        token_file.parent.mkdir(parents=True)
        token_file.write_text(
            json.dumps(
                [
                    {
                        "provider": "company-mcp",
                        "expiry": "2099-01-01T00:00:00Z",
                        "registration": "hash",
                    }
                ]
            ),
            encoding="utf-8",
        )
        battery.command = Mock()
        battery.expire_stopped("mcp", "company-mcp")
        battery.command.assert_called_once_with("stop", "mcp")
        token = json.loads(token_file.read_text(encoding="utf-8"))[0]
        self.assertEqual(token["expiry"], "2000-01-01T00:00:00Z")
        self.assertEqual(token["registration"], "hash")
        mode = stat.S_IMODE(token_file.stat().st_mode)
        if os.name == "nt":
            self.assertTrue(mode & stat.S_IWRITE)
        else:
            self.assertEqual(mode, 0o600)

    def test_negative_credential_assertion_requires_a_working_exec(self):
        battery = self.battery()
        with patch.object(
            e2e.subprocess,
            "run",
            return_value=subprocess.CompletedProcess([], 1, "CREDENTIAL-CHECK-OK"),
        ):
            with self.assertRaises(AssertionError):
                battery.credential("gh", "evil.example")
        battery.guest = Mock()
        for expected in ("", e2e.GH_ACCESS):
            battery.guest.return_value = (
                ("username=x-access-token\npassword=" + expected + "\n")
                if expected
                else ""
            ) + "CREDENTIAL-CHECK-OK"
            battery.credential("gh", "github.com", expected)
            script = battery.guest.call_args[0][1]
            self.assertNotIn(e2e.GH_ACCESS, script)
            result = subprocess.run(
                ["sh", "-n", "-c", script], capture_output=True, text=True
            )
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_unconfigured_login_captures_guest_stderr_with_stdout_only_transport(self):
        battery = self.battery()
        helper = battery.root / "helper with spaces.py"
        helper.write_text(
            'import sys\nprint("gantry-guest: custody: unknown provider", file=sys.stderr)\nraise SystemExit(1)\n',
            encoding="utf-8",
        )
        helper_command = [sys.executable, str(helper)]
        real_run = subprocess.run

        # Match gantry's non-terminal transport: only guest stdout is forwarded.
        # Merging the *host* CLI's stderr cannot recover the guest's discarded fd 2.
        unwrapped = real_run(
            helper_command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True
        )
        self.assertEqual(unwrapped.returncode, 1)
        self.assertEqual(unwrapped.stdout, "")

        def stdout_only_gantry(argv, **kwargs):
            self.assertEqual(argv[:4], [battery.gantry, "exec", "mcp", "--"])
            return real_run(
                argv[4:],
                input=kwargs["input"],
                env=kwargs["env"],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=kwargs["timeout"],
            )

        with patch.object(e2e.subprocess, "run", side_effect=stdout_only_gantry):
            battery.reject_unconfigured_login("mcp", tuple(helper_command))
        self.assertIn(
            "unknown provider",
            battery.last_command_log.read_text(encoding="utf-8"),
        )

    def test_guest_exec_wrapper_preserves_argv_stdin_and_exit_status(self):
        battery = self.battery()
        marker = battery.root / "must-not-exist"
        argument = "literal with spaces; $(touch %s)" % marker
        argv = e2e.guest_exec_args(
            "mcp",
            "sh",
            "-c",
            'printf "<%s>\\n" "$1"; cat; printf "guest diagnostic\\n" >&2; exit 7',
            "probe",
            argument,
        )
        self.assertEqual(argv[:3], ("exec", "mcp", "--"))
        input_text = '{"jsonrpc":"2.0","id":1,"method":"ping"}\n'
        result = subprocess.run(
            argv[3:], input=input_text, capture_output=True, text=True
        )
        self.assertEqual(result.returncode, 7)
        self.assertEqual(
            result.stdout, "<" + argument + ">\n" + input_text + "guest diagnostic\n"
        )
        self.assertEqual(result.stderr, "")
        self.assertFalse(marker.exists())

    def test_unconfigured_login_keeps_both_rejection_requirements_and_diagnostics(self):
        battery = self.battery()
        battery.last_command_log = battery.root / "command-test.log"
        for status, output in (
            (0, "unknown provider"),
            (1, ""),
            (1, "broker unavailable"),
        ):
            with self.subTest(status=status, output=output):
                result = subprocess.CompletedProcess([], status, output)
                with patch.object(battery, "command", return_value=result):
                    with self.assertRaises(AssertionError) as failure:
                        battery.reject_unconfigured_login("mcp")
                self.assertIn("exit=%d" % status, str(failure.exception))
                self.assertIn(str(battery.last_command_log), str(failure.exception))

    def test_command_timeout_retains_partial_output_and_log_path(self):
        battery = self.battery()
        for partial, expected in (
            (
                b'before EOF\n{"id":1,"result":{}}\n\xff',
                'before EOF\n{"id":1,"result":{}}\n\ufffd',
            ),
            ("partial text", "partial text"),
            (None, ""),
        ):
            with self.subTest(partial=partial):
                error = subprocess.TimeoutExpired(
                    [battery.gantry, "exec"], 90, output=partial
                )
                with patch.object(e2e.subprocess, "run", side_effect=error):
                    with self.assertRaises(e2e.CommandTimeout) as failure:
                        battery.command(
                            *e2e.guest_exec_args("mcp", e2e.HELPER, "mcp-proxy")
                        )
                self.assertIsInstance(failure.exception, subprocess.TimeoutExpired)
                self.assertEqual(
                    battery.last_command_log.read_text(encoding="utf-8"), expected
                )
                self.assertEqual(battery.outputs[-1], expected)
                self.assertIn(str(battery.last_command_log), str(failure.exception))
                self.assertEqual(battery.passed, 0)

    def test_mcp_probe_requires_exit_success_even_with_all_replies(self):
        battery = self.battery()
        responses = [
            {"jsonrpc": "2.0", "id": 1, "result": {}},
            {"jsonrpc": "2.0", "id": 2, "result": {"tools": []}},
            {
                "jsonrpc": "2.0",
                "id": 3,
                "error": {"code": -32000, "message": "no access token"},
            },
        ]
        output = "".join(json.dumps(response) + "\n" for response in responses)
        for status in (0, 1, "timeout"):
            with self.subTest(status=status):
                before = battery.passed
                if status == "timeout":
                    run = Mock(
                        side_effect=subprocess.TimeoutExpired(
                            [battery.gantry, "exec"], 90, output=output.encode()
                        )
                    )
                else:
                    run = Mock(
                        return_value=subprocess.CompletedProcess([], status, output)
                    )
                with patch.object(e2e.subprocess, "run", run):
                    if status == 0:
                        battery.mcp_probe()
                        self.assertEqual(battery.passed, before + 3)
                    else:
                        with self.assertRaises(
                            (AssertionError, subprocess.TimeoutExpired)
                        ):
                            battery.mcp_probe()
                        self.assertEqual(battery.passed, before)
                self.assertEqual(
                    battery.last_command_log.read_text(encoding="utf-8"), output
                )

    def test_mcp_probe_missing_replies_reports_received_ids_and_log(self):
        battery = self.battery()
        result = subprocess.CompletedProcess(
            [], 0, '{"jsonrpc":"2.0","id":1,"result":{}}\n'
        )
        with patch.object(e2e.subprocess, "run", return_value=result):
            with self.assertRaises(AssertionError) as failure:
                battery.mcp_probe()
        self.assertIn("received IDs [1]", str(failure.exception))
        self.assertIn(str(battery.last_command_log), str(failure.exception))

    def test_ci_runs_all_non_vm_batteries_on_each_host_platform(self):
        workflow = Path(__file__).resolve().parent.parent.joinpath(
            ".github/workflows/ci.yml"
        ).read_text()
        start = workflow.index("  test:")
        end = workflow.index("\n  fuzz-virtqueue:", start)
        native_tests = workflow[start:end]
        self.assertNotIn("matrix.name != 'windows-amd64'", native_tests)
        self.assertNotIn("matrix.quality", native_tests)
        self.assertNotIn("matrix.race", native_tests)
        self.assertIn("go test -race -count=1 ./...", native_tests)
        self.assertIn("go build -o \"$RUNNER_TEMP/gantry-remotetui.exe\"", native_tests)
        self.assertIn("\"$RUNNER_TEMP/gantry-remotetui.exe\" -gantry", native_tests)
        self.assertIn("scripts/test-manager-api-e2e.sh -api-only", native_tests)
        fuzz_start = workflow.index("  fuzz-virtqueue:")
        fuzz_end = workflow.index("\n  # GitHub's Linux runner", fuzz_start)
        fuzz = workflow[fuzz_start:fuzz_end]
        self.assertIn("windows-latest", fuzz)
        self.assertIn("macos-latest", fuzz)
        conpty = Path(__file__).resolve().parent.parent.joinpath(
            "tests/e2e/remotetui/terminal_bridge_windows.go"
        ).read_text()
        self.assertIn("windows.CreatePseudoConsole", conpty)

    def test_linux_ci_runs_real_vm_manager_and_oauth_batteries(self):
        workflow = Path(__file__).resolve().parent.parent.joinpath(
            ".github/workflows/ci.yml"
        ).read_text()
        start = workflow.index("  native-smoke:")
        end = workflow.index("\n  build:", start)
        native = workflow[start:end]
        self.assertIn("needs: [build, guest-assets, kernels, guest-tools]", native)
        self.assertNotIn("!startsWith(github.ref, 'refs/tags/v')", native)
        self.assertIn("scripts/aws-e2e-validation.sh linux", native)
        self.assertIn("GANTRY_TEST_WORKLOAD_IMAGE", native)
        self.assertNotIn("-api-only", native)
        runner = Path(__file__).with_name("aws-e2e-validation.sh").read_text()
        start = runner.index("run_linux_validation()")
        end = runner.index('\ncase "$MODE"', start)
        linux = runner[start:end]
        self.assertIn("scripts/test-manager-api-e2e.sh", linux)
        self.assertIn("scripts/oauth-custody-e2e.py", linux)
        self.assertIn("./tests/e2e/oauthidp", linux)

    def test_linux_runner_stages_current_idp_binary(self):
        runner = (
            Path(__file__).with_name("aws-kvm").joinpath("run-tests.sh").read_text()
        )
        self.assertIn("./tests/e2e/oauthidp", runner)
        self.assertIn("gantry-oauth-idp-linux-amd64", runner)
        self.assertIn("GANTRY_TEST_OAUTH_IDP=/opt/gantry/", runner)

    def test_shared_runner_requires_exit_success_and_completion_marker(self):
        battery = self.battery()
        shared = (
            Path(__file__).with_name("aws-kvm").joinpath("test-battery.sh").read_text()
        )
        start = shared.index('echo "===== generic OAuth custody')
        end = shared.index('echo "===== MCP gateway', start)
        script = (
            "set +e\nok() { echo SHARED_OK; }\nbad() { echo SHARED_FAIL; }\n"
            + shared[start:end]
        )
        fixture = battery.root / "fixture with spaces.py"
        runner = battery.root / "shared runner with spaces.sh"
        runner.write_text(script, encoding="utf-8")
        env = dict(
            os.environ,
            GANTRY_TEST_OAUTH_E2E=shell_path(fixture),
            GANTRY_TEST_OAUTH_IDP=shell_path(battery.root / "oauth-idp"),
            SECRET_TMP=shell_path(battery.root),
            G="not-executed",
            KERNEL="kernel",
            ROOTFS="rootfs",
            CACHE_IMAGE="image",
        )
        for label, program, expected in (
            (
                "success",
                'import sys; assert "--idp" in sys.argv; print("OAuth E2E: 1 checks passed")',
                "SHARED_OK",
            ),
            ("empty script", "pass", "SHARED_FAIL"),
            (
                "failed cleanup",
                'import sys; print("OAuth E2E: 1 checks passed"); sys.exit(1)',
                "SHARED_FAIL",
            ),
        ):
            with self.subTest(label=label):
                fixture.write_text(program, encoding="utf-8")
                result = subprocess.run(
                    [bash_executable(), shell_path(runner)],
                    env=env,
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(
                    result.returncode,
                    0,
                    "stdout:\n%s\nstderr:\n%s" % (result.stdout, result.stderr),
                )
                self.assertIn(expected, result.stdout)
                self.assertNotIn(
                    "SHARED_FAIL" if expected == "SHARED_OK" else "SHARED_OK",
                    result.stdout,
                )


if __name__ == "__main__":
    unittest.main()
