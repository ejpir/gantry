#!/usr/bin/env python3
"""Real-VM OAuth custody checks shared by Linux KVM and macOS HVF.

A disposable Go authorization server implements the public-client grants and
protected MCP resource. Login, vsock, the credential helper, MCP worker,
refresh, and stop/resume all run through the current Gantry binaries. No
browser, public OAuth service, or real credential is needed.
"""

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import stat
import subprocess
import tempfile
import threading
import time
from urllib.error import HTTPError
from urllib.parse import parse_qs, urlencode, urlsplit
from urllib.request import ProxyHandler, Request, build_opener

GH_CLIENT = "Iv1.b507a08c87ecfe98"
GH_SCOPE = "repo read:org gist"
GH_ACCESS = "e2e-github-access-canary"
DEVICE_CODE = "e2e-private-device-canary"
USER_CODE = "E2E-TEST"
MCP_ACCESS = "e2e-mcp-access-canary-"
MCP_REFRESH = "e2e-mcp-refresh-canary-"
ERROR_CANARY = "e2e-token-error-body-canary"
HELPER = "/run/gantry/bin/gantry-guest"


def guest_exec_args(sandbox, *args):
    """Merge guest stderr before it crosses the stdout-only session transport.

    subprocess.STDOUT merges only the host CLI's stderr. The guest shell must
    redirect its own fd 2, and exec preserves the helper's exit status. Pass
    argv through positional parameters rather than interpolating shell text.
    """
    return (
        "exec",
        sandbox,
        "--",
        "sh",
        "-c",
        'exec "$@" 2>&1',
        "gantry-oauth-e2e",
        *args,
    )


def browser_get(url):
    """Ignore corporate proxy variables for our host-loopback browser stand-in."""
    with build_opener(ProxyHandler({})).open(url, timeout=10) as response:
        return response.read().decode()


def available_callback_uri():
    """Choose an explicit allowed callback while leaving Gantry to bind it."""
    for _ in range(20):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
        if 32768 <= port <= 65535:
            return "http://127.0.0.1:%d/callback" % port
    raise OSError("could not allocate an allowed OAuth callback port")


class LocalIDP:
    """Subprocess wrapper for Gantry's protocol-level Go OAuth fixture."""

    def __init__(self, executable):
        executable = str(Path(executable).resolve())
        if not os.access(executable, os.X_OK):
            raise ValueError("--idp must name an executable fixture binary")
        self.process = subprocess.Popen(
            [executable],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        ready = []

        def read_ready():
            ready.append(self.process.stdout.readline(4097))

        reader = threading.Thread(target=read_ready, daemon=True)
        reader.start()
        reader.join(timeout=10)
        line = ready[0] if ready else ""
        try:
            message = json.loads(line)
            parsed = urlsplit(message["origin"])
            if (
                len(line) > 4096
                or parsed.scheme != "http"
                or parsed.hostname != "127.0.0.1"
                or parsed.port is None
                or parsed.path
                or parsed.query
                or parsed.fragment
            ):
                raise ValueError("invalid fixture origin")
            expected = {
                "client_id": "e2e-public-client",
                "scope": "mcp offline_access",
                "github_client_id": GH_CLIENT,
                "github_scope": GH_SCOPE,
            }
            if any(message.get(key) != value for key, value in expected.items()):
                raise ValueError("fixture registration mismatch")
            if self.process.poll() is not None:
                raise ValueError("fixture exited after readiness")
            self.origin = message["origin"]
            self.client_id = message["client_id"]
            self.scope = message["scope"]
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
            self.close()
            raise ValueError("local OAuth IdP did not emit valid readiness") from error

    def close(self):
        process = getattr(self, "process", None)
        if process is None:
            return
        self.process = None
        if process.stdin:
            process.stdin.close()
        if process.poll() is None:
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
        if process.stdout:
            process.stdout.close()
        if process.stderr:
            process.stderr.close()

    def request(self, path, method="GET"):
        request = Request(
            self.origin + path,
            data=b"" if method == "POST" else None,
            method=method,
        )
        with build_opener(ProxyHandler({})).open(request, timeout=5) as response:
            raw = response.read()
        return json.loads(raw) if raw else {}

    def observation(self, field):
        return self.request("/test/observations")[field]

    def revoke(self):
        response = self.request("/test/revoke", "POST")
        if response.get("revoked") is not True:
            raise ValueError("local OAuth IdP did not revoke the fixture grant")


class CommandTimeout(subprocess.TimeoutExpired):
    """Keep the normal timeout cleanup path and point at retained partial output."""

    def __init__(self, error, log):
        super().__init__(
            error.cmd, error.timeout, output=error.output, stderr=error.stderr
        )
        self.log = log

    def __str__(self):
        return super().__str__() + " (partial output: %s)" % self.log


class Battery:
    def __init__(self, args, fixture):
        self.args = args
        self.fixture = fixture
        # Short, physical paths avoid Darwin's 104-byte AF_UNIX limit and
        # /tmp -> /private/tmp symlinks. Windows has no /tmp, so use its native
        # temporary directory; no VM is launched by the host-only unit tests.
        parent = "/tmp" if os.name != "nt" else None
        self.root = Path(tempfile.mkdtemp(prefix="g-oauth-", dir=parent)).resolve()
        self.env = dict(
            os.environ,
            GANTRY_HOME=str(self.root / "sandboxes"),
            GANTRY_OAUTH_DEVICE_URL_GITHUB=fixture.origin + "/github/device",
            GANTRY_OAUTH_TOKEN_URL_GITHUB=fixture.origin + "/github/token",
            GANTRY_OAUTH_CLIENT_ID_GITHUB=GH_CLIENT,
        )
        self.gantry = str(Path(args.gantry).resolve())
        self.names = []
        self.logins = []
        self.passed = 0
        self.commands = 0
        self.outputs = []
        self.last_command_log = None

    def check(self, condition, label, details=""):
        if not condition:
            raise AssertionError(label + (": " + details if details else ""))
        self.passed += 1
        print("PASS: oauth e2e: " + label, flush=True)

    def command(self, *args, input_text=None, successful=True, timeout=90):
        self.commands += 1
        log = self.root / ("command-%02d.log" % self.commands)
        self.last_command_log = log
        try:
            result = subprocess.run(
                [self.gantry, *args],
                input=input_text or "",
                env=self.env,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
            )
        except subprocess.TimeoutExpired as error:
            # TimeoutExpired can carry bytes even with text=True. Retain replies
            # already received so a transport/exit hang is distinguishable from
            # an unresponsive upstream; never treat partial replies as success.
            output = error.stdout or ""
            if isinstance(output, bytes):
                output = output.decode("utf-8", errors="replace")
            log.write_text(output, encoding="utf-8")
            self.outputs.append(output)
            raise CommandTimeout(error, log) from error
        log.write_text(result.stdout, encoding="utf-8")
        self.outputs.append(result.stdout)
        if successful and result.returncode != 0:
            raise AssertionError(
                "gantry %s exited %d (see %s)" % (args[0], result.returncode, log)
            )
        if result.returncode == 0 and args[0] in ("start", "resume"):
            # Older boot paths stage helpers asynchronously. Poll actual guest
            # readiness rather than assuming an AWS/macOS-specific sleep is enough.
            self.wait_for(
                lambda: self.command(
                    *guest_exec_args(
                        args[1],
                        "sh",
                        "-c",
                        "test -x /run/gantry/bin/gantry-guest && test -x /run/gantry/bin/credhelper",
                    ),
                    successful=False,
                    timeout=30,
                ).returncode
                == 0,
                "guest helper readiness for " + args[1],
                timeout=60,
            )
        self.last_command_log = log
        return result

    def start(self, name, *options, successful=True):
        self.names.append(name)
        return self.command(
            "start",
            name,
            "-kernel",
            self.args.kernel,
            "-rootfs",
            self.args.rootfs,
            "-image",
            self.args.image,
            *options,
            successful=successful,
            timeout=180,
        )

    def guest(self, name, script):
        return self.command(*guest_exec_args(name, "sh", "-c", script)).stdout

    def reject_unconfigured_login(self, sandbox, helper_command=(HELPER,)):
        result = self.command(
            *guest_exec_args(
                sandbox,
                *helper_command,
                "oauth",
                "login",
                "not-configured-e2e",
            ),
            successful=False,
        )
        self.check(
            result.returncode != 0 and "unknown provider" in result.stdout,
            "unconfigured login is refused",
            "exit=%d, expected 'unknown provider' in guest output; see %s"
            % (result.returncode, self.last_command_log),
        )

    @staticmethod
    def wait_for(predicate, label, timeout=45):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if predicate():
                return
            time.sleep(0.2)
        raise AssertionError("timed out: " + label)

    def login(self, sandbox, provider):
        log = self.root / (sandbox + "-login.log")
        with log.open("w", encoding="utf-8") as output:
            process = subprocess.Popen(
                [
                    self.gantry,
                    *guest_exec_args(sandbox, HELPER, "oauth", "login", provider),
                ],
                stdin=subprocess.DEVNULL,
                stdout=output,
                stderr=subprocess.STDOUT,
                env=self.env,
            )
        self.logins.append(process)
        self.wait_for(
            lambda: "Open this URL" in log.read_text(encoding="utf-8", errors="replace") or process.poll() is not None,
            "login instructions (" + str(log) + ")",
        )
        transcript = log.read_text(encoding="utf-8", errors="replace")
        urls = re.findall(re.escape(self.fixture.origin) + r"/[^\s\x1b]+", transcript)
        self.check(
            bool(urls) and process.poll() is None,
            provider + " prints local browser instructions",
        )
        return process, log, urls[0]

    def finish_login(self, process, log):
        status = process.wait(timeout=45)
        text = log.read_text(encoding="utf-8", errors="replace")
        self.outputs.append(text)
        self.check(
            status == 0 and "tokens held on host" in text,
            "guest login completes through the broker",
        )

    def tokens(self, sandbox):
        path = self.root / "sandboxes" / sandbox / "oauth-tokens.json"
        return json.loads(path.read_text(encoding="utf-8")) if path.exists() else []

    def token(self, sandbox, provider):
        return next(
            (token for token in self.tokens(sandbox) if token["provider"] == provider),
            {},
        )

    def expire_stopped(self, sandbox, provider):
        # Never edit a live registry's backing file: memory wins while running.
        # Shorten only our stopped fixture's expiry to test immediate refresh
        # on resume without waiting an hour or adding production test knobs.
        self.command("stop", sandbox)
        tokens = self.tokens(sandbox)
        token = next(token for token in tokens if token["provider"] == provider)
        token["expiry"] = "2000-01-01T00:00:00Z"
        path = self.root / "sandboxes" / sandbox / "oauth-tokens.json"
        temp = path.with_suffix(".tmp")
        temp.write_text(json.dumps(tokens), encoding="utf-8")
        temp.chmod(0o600)
        temp.replace(path)

    def credential(self, sandbox, host, expected=""):
        # A positive marker AND successful exec are required for negative
        # checks; a broken/missing helper must not count as an empty answer.
        # Compare on the host: putting an expected token in sh -c arguments
        # would itself plant the canary in exec/audit metadata.
        script = (
            'printf "protocol=https\\nhost=%s\\n\\n" | '
            "/run/gantry/bin/credhelper get || exit 1; echo CREDENTIAL-CHECK-OK"
        ) % host
        output = self.guest(sandbox, script)
        fields = dict(
            line.split("=", 1)
            for line in output.splitlines()
            if line.startswith(("username=", "password="))
        )
        wanted = (
            {"username": "x-access-token", "password": expected} if expected else {}
        )
        self.check(
            "CREDENTIAL-CHECK-OK" in output and fields == wanted,
            sandbox + " credential gate for " + host,
        )

    def no_guest_files(self, sandbox):
        script = (
            'test -z "${GITHUB_TOKEN:-}${GH_TOKEN:-}" && '
            'test ! -e "$HOME/.config/gh/hosts.yml" && '
            'test ! -e "$HOME/.claude/.credentials.json" && '
            'test ! -e "$HOME/.codex/auth.json" && echo NO-GUEST-AUTH-FILES'
        )
        self.check(
            "NO-GUEST-AUTH-FILES" in self.guest(sandbox, script),
            sandbox + " has no ambient GitHub token or CLI auth files",
        )

    def mcp_probe(self, expected_phase=None):
        transcript = [
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {"name": "oauth-e2e", "version": "1"},
                },
            },
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"name": "company__probe", "arguments": {}},
            },
        ]
        output = self.command(
            *guest_exec_args("mcp", HELPER, "mcp-proxy"),
            input_text="".join(json.dumps(r) + "\n" for r in transcript),
        ).stdout
        responses = {}
        for line in output.splitlines():
            try:
                response = json.loads(line)
            except ValueError:
                continue
            if isinstance(response, dict) and "id" in response:
                responses[response["id"]] = response
        self.check(
            all(rid in responses for rid in (1, 2, 3)),
            "MCP proxy returns all JSON-RPC responses",
            "received IDs %s; see %s" % (list(responses), self.last_command_log),
        )
        self.check(
            all(
                value not in output for value in (MCP_ACCESS, MCP_REFRESH, ERROR_CANARY)
            ),
            "MCP transcript contains no credential values",
        )
        call = responses[3]
        if expected_phase is None:
            self.check(
                "error" in call or call.get("result", {}).get("isError"),
                "MCP without a live custody token fails closed",
            )
        else:
            text = json.dumps(call.get("result", {}))
            self.check(
                "phase:%d" % expected_phase in text
                and "*" in text
                and not call.get("result", {}).get("isError"),
                "new MCP session receives phase %d access token and redacts its reflection"
                % expected_phase,
            )

    def run(self):
        self.start("gh", "-oauth-custody")
        # Detect a stale host binary with broken stdin EOF forwarding before
        # doing any login work: mcp-proxy cannot exit without this signal.
        self.check(
            "STDIN-EOF-OK"
            in self.command(
                *guest_exec_args(
                    "gh",
                    "sh",
                    "-c",
                    'test "$(cat)" = oauth-e2e-input && echo STDIN-EOF-OK',
                ),
                input_text="oauth-e2e-input\n",
                timeout=30,
            ).stdout,
            "exec forwards stdin EOF and preserves the reply",
        )
        self.credential("gh", "github.com")
        process, log, url = self.login("gh", "github")
        self.wait_for(
            lambda: "Enter this code: " + USER_CODE in log.read_text(encoding="utf-8", errors="replace"),
            "public device code instructions",
        )
        self.check(
            DEVICE_CODE not in log.read_text(encoding="utf-8", errors="replace"),
            "GitHub exposes only the public device code",
        )
        self.wait_for(
            lambda: self.fixture.observation("pending") > 0,
            "GitHub authorization_pending poll",
        )
        browser_get(url + "?" + urlencode({"user_code": USER_CODE}))
        self.finish_login(process, log)
        self.check(
            self.token("gh", "github").get("accessToken") == GH_ACCESS
            and not self.token("gh", "github").get("refreshToken"),
            "GitHub non-expiring token is held on host",
        )
        self.credential("gh", "github.com", GH_ACCESS)
        self.credential("gh", "github.com.evil.example")
        self.check(
            "/run/gantry/bin/credhelper"
            in self.guest("gh", 'printf "%s" "$GIT_CONFIG_VALUE_0"'),
            "git helper is wired without a bound secret",
        )
        self.no_guest_files("gh")
        policy = self.root / "deny-github.json"
        policy.write_text(
            json.dumps(
                {"default": "deny", "allowLocal": True, "allowDomains": ["example.com"]}
            ),
            encoding="utf-8",
        )
        self.command("net-policy", "set", "gh", str(policy))
        self.credential("gh", "github.com")
        self.command("net-policy", "default", "gh")
        self.credential("gh", "github.com", GH_ACCESS)
        self.command("stop", "gh")
        self.command("resume", "gh", timeout=180)
        self.credential("gh", "github.com", GH_ACCESS)
        self.check(
            self.fixture.observation("github_issues") == 1,
            "GitHub survives resume without reauthorization",
        )
        self.expire_stopped("gh", "github")
        self.command("resume", "gh", timeout=180)
        self.credential("gh", "github.com")
        self.check(
            not self.token("gh", "github"),
            "expired non-refreshable GitHub token is discarded",
        )
        self.command("stop", "gh")

        provider = self.root / "provider.json"
        configured_redirect = available_callback_uri()
        provider.write_text(
            json.dumps(
                {
                    "name": "company-mcp",
                    "authorize_url": self.fixture.origin + "/authorize",
                    "token_url": self.fixture.origin + "/token",
                    "client_id": self.fixture.client_id,
                    "redirect_uri": configured_redirect,
                    "scope": self.fixture.scope,
                    "resource": self.fixture.origin + "/mcp",
                }
            ),
            encoding="utf-8",
        )
        refusal = self.start("bad", "-oauth-provider", str(provider), successful=False)
        self.check(
            refusal.returncode != 0
            and "requires -oauth-custody" in refusal.stdout
            and not (self.root / "sandboxes/bad").exists()
            and not (self.root / "rwlayers/bad.ext4").exists(),
            "provider without custody is rejected before creating state",
        )
        refusal = self.start(
            "bad-ref",
            "-oauth-custody",
            "-mcp-remote",
            "name=bad,url=%s/mcp,auth=custody:not-configured-e2e,allow=probe"
            % self.fixture.origin,
            successful=False,
        )
        self.check(
            refusal.returncode != 0
            and "unknown custody provider" in refusal.stdout
            and not (self.root / "sandboxes/bad-ref").exists(),
            "unconfigured MCP custody reference is refused before boot",
        )
        self.start(
            "mcp",
            "-oauth-custody",
            "-oauth-provider",
            str(provider),
            "-mcp-fs-root",
            "/tmp",
            "-mcp-remote",
            "name=company,url=%s/mcp,auth=custody:company-mcp,allow=probe"
            % self.fixture.origin,
        )
        self.reject_unconfigured_login("mcp")
        self.mcp_probe()
        process, log, url = self.login("mcp", "company-mcp")
        redirect = parse_qs(urlsplit(url).query)["redirect_uri"][0]
        callback = urlsplit(redirect)
        self.check(
            callback.scheme == "http"
            and callback.hostname == "127.0.0.1"
            and callback.username is None
            and callback.password is None
            and redirect == configured_redirect
            and callback.port is not None
            and 32768 <= callback.port <= 65535
            and callback.path == "/callback"
            and not callback.query
            and not callback.fragment,
            "host honored the configured IPv4-loopback callback",
        )
        try:
            browser_get(redirect + "?state=wrong-e2e-state&code=wrong-e2e-code")
        except HTTPError as error:
            with error:
                self.check(error.code == 404, "callback with unknown state is rejected")
        else:
            raise AssertionError("callback with unknown state was accepted")
        self.check(
            "OAuth callback received" in browser_get(url),
            "generic PKCE callback is consumed on the host",
        )
        self.finish_login(process, log)
        self.wait_for(
            lambda: self.token("mcp", "company-mcp").get("accessToken")
            == MCP_ACCESS + "1",
            "initial generic refresh",
        )
        token = self.token("mcp", "company-mcp")
        self.check(
            token.get("refreshToken") == MCP_REFRESH + "1"
            and bool(token.get("registration")),
            "generic refresh rotates and persists context-bound tokens",
        )
        self.mcp_probe(1)
        self.no_guest_files("mcp")
        self.credential("mcp", "mcp.example")
        # Removing the original provider file proves resume uses its persisted
        # snapshot, not a launch-time path that could be changed by a guest.
        provider.unlink()
        self.command("stop", "mcp")
        self.command("resume", "mcp", timeout=180)
        self.mcp_probe(1)
        self.expire_stopped("mcp", "company-mcp")
        self.command("resume", "mcp", timeout=180)
        self.wait_for(
            lambda: self.token("mcp", "company-mcp").get("accessToken")
            == MCP_ACCESS + "2",
            "refresh after restart",
        )
        self.mcp_probe(2)
        self.check(
            self.fixture.observation("exchanges") == 1
            and self.fixture.observation("refreshes") == 2,
            "restart reuses rotated refresh material, with no new code exchange",
        )
        for sandbox in ("gh", "mcp"):
            path = self.root / "sandboxes" / sandbox / "oauth-tokens.json"
            self.check(
                stat.S_IMODE(path.stat().st_mode) == 0o600,
                sandbox + " token store is mode 0600",
            )
            audit = self.command("audit", sandbox).stdout
            config_text = (path.parent / "sandbox.json").read_text(encoding="utf-8")
            daemon_log = (path.parent / "daemon.log").read_text(
                encoding="utf-8", errors="replace"
            )
            self.check(
                all(
                    value not in audit + config_text + daemon_log
                    for value in (
                        GH_ACCESS,
                        DEVICE_CODE,
                        MCP_ACCESS,
                        MCP_REFRESH,
                        ERROR_CANARY,
                    )
                ),
                sandbox + " audit/config/logs contain no OAuth secrets",
            )
        self.expire_stopped("mcp", "company-mcp")
        self.fixture.revoke()
        self.command("resume", "mcp", timeout=180)
        self.wait_for(
            lambda: not self.token("mcp", "company-mcp"),
            "permanent invalid_grant revocation",
        )
        self.mcp_probe()
        self.check(
            self.fixture.observation("rejections") == 1,
            "permanent refresh failure revokes custody",
        )
        self.no_guest_files("mcp")
        audit = self.command("audit", "mcp").stdout
        daemon_log = (self.root / "sandboxes/mcp/daemon.log").read_text(
            encoding="utf-8", errors="replace"
        )
        self.check(
            ERROR_CANARY not in audit + daemon_log + "".join(self.outputs),
            "token endpoint error body is not exposed",
        )
        self.check(
            not self.fixture.observation("errors"),
            "local IdP verified PKCE, resource, refresh rotation, and upstream binding",
        )

    def close(self, keep=False):
        for process in self.logins:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
        stopped = True
        for name in reversed(self.names):
            sandbox = self.root / "sandboxes" / name
            if not sandbox.exists():
                continue
            if keep:
                for filename in ("daemon.log", "audit.log", "sandbox.json"):
                    source = sandbox / filename
                    if source.is_file():
                        try:
                            shutil.copyfile(source, self.root / (name + "-" + filename))
                        except OSError:
                            print(
                                "Could not copy diagnostic " + str(source), flush=True
                            )
            for operation in ("stop", "delete"):
                try:
                    self.command(operation, name, successful=False, timeout=45)
                except (OSError, subprocess.TimeoutExpired):
                    stopped = False
            if sandbox.exists():
                stopped = False
        if keep or not stopped:
            print("OAuth E2E logs retained at " + str(self.root), flush=True)
        else:
            shutil.rmtree(self.root)
        return stopped


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gantry", required=True)
    parser.add_argument("--kernel", required=True)
    parser.add_argument("--rootfs", required=True)
    parser.add_argument("--image", required=True)
    parser.add_argument(
        "--idp",
        default=os.environ.get("GANTRY_TEST_OAUTH_IDP", ""),
        help="path to the disposable Go OAuth IdP fixture",
    )
    parser.add_argument(
        "--keep",
        action="store_true",
        help="retain private fixture logs after a successful run",
    )
    args = parser.parse_args()
    if not os.access(args.gantry, os.X_OK):
        parser.error("--gantry must name an executable host binary")
    if not args.idp:
        parser.error("--idp is required (or set GANTRY_TEST_OAUTH_IDP)")
    os.umask(0o077)
    fixture = LocalIDP(args.idp)
    battery = Battery(args, fixture)
    success = False
    try:
        battery.run()
        success = True
        print("OAuth E2E: %d checks passed" % battery.passed, flush=True)
    except (AssertionError, OSError, ValueError, subprocess.TimeoutExpired) as error:
        print("FAIL: oauth e2e: " + str(error), flush=True)
    finally:
        try:
            cleanup_ok = battery.close(keep=args.keep or not success)
            if not cleanup_ok:
                print(
                    "FAIL: oauth e2e: fixture sandbox cleanup did not complete",
                    flush=True,
                )
        finally:
            fixture.close()
    return 0 if success and cleanup_ok else 1


if __name__ == "__main__":

    def interrupted(_signum, _frame):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGHUP, interrupted)
    raise SystemExit(main())
