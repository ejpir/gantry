#!/usr/bin/env python3
"""Real Gantry TUI driver. Native PTY/ConPTY plus a small screen reader."""

import codecs
import json
import os
from pathlib import Path
import queue
import re
import signal
import struct
import subprocess
import sys
import threading
import time
import unicodedata

if os.name != "nt":
    import fcntl
    import pty
    import select
    import termios


class Terminal:
    """Read cursor-addressed text, not historical matches from older dialogs."""

    width, height = 120, 54

    def __init__(self, fixture, name):
        self.fixture = fixture
        self.base = Path(fixture["root"]) / name
        self.base.mkdir(mode=0o700)
        self.env = dict(os.environ, HOME=str(self.base),
                        GANTRY_HOME=str(self.base / "sandboxes"),
                        GANTRY_REMOTE="must-not-be-used", TERM="xterm-256color",
                        COLORTERM="truecolor", GANTRY_E2E_BROWSER_URL=fixture["browser"])
        self.env["PATH"] = fixture["shim"] + os.pathsep + self.env.get("PATH", "")
        self.screen = [[" "] * self.width for _ in range(self.height)]
        self.row = self.col = 0
        self.pending = ""
        self.transcript = ""
        self.decoder = codecs.getincrementaldecoder("utf-8")("replace")
        self.status = None
        self.process = None
        self.fd = None
        self.read_queue = None
        if os.name == "nt":
            self.read_queue = queue.Queue()
            self.process = subprocess.Popen(
                [fixture["terminal_helper"], "-terminal-bridge", "-gantry", fixture["gantry"]],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                env=self.env,
            )
            self.pid = self.process.pid
            threading.Thread(target=self._read_windows, daemon=True).start()
        else:
            self.pid, self.fd = pty.fork()
            if self.pid == 0:
                os.execve(fixture["gantry"], [fixture["gantry"], "tui", "-remote="], self.env)
            fcntl.ioctl(self.fd, termios.TIOCSWINSZ, struct.pack("HHHH", self.height, self.width, 0, 0))
        self.wait_text("Press n to create one.")

    def text(self):
        return "\n".join("".join(row) for row in self.screen)

    def _read_windows(self):
        try:
            while True:
                data = os.read(self.process.stdout.fileno(), 65536)
                self.read_queue.put(data)
                if not data:
                    return
        except OSError:
            self.read_queue.put(b"")

    def send(self, value):
        data = value.encode()
        if self.process is not None:
            self.process.stdin.write(data)
            self.process.stdin.flush()
        else:
            os.write(self.fd, data)

    def pump(self, timeout=0.05):
        if self.process is not None:
            try:
                data = self.read_queue.get(timeout=timeout)
            except queue.Empty:
                return
            chunks = [data]
            while True:
                try:
                    chunks.append(self.read_queue.get_nowait())
                except queue.Empty:
                    break
            data = b"".join(chunks)
        else:
            if not select.select([self.fd], [], [], timeout)[0]:
                return
            try:
                data = os.read(self.fd, 65536)
            except OSError:
                return
        text = self.decoder.decode(data)
        self.transcript = (self.transcript + text)[-(4 << 20):]
        self.pending += text
        while self.pending:
            if self.pending.startswith("\x1b["):
                match = re.match(r"\x1b\[([0-?]*)([ -/]*)([@-~])", self.pending)
                if not match:
                    break
                self.csi(match[1], match[3])
                self.pending = self.pending[match.end():]
                continue
            if self.pending.startswith(("\x1b]", "\x1bP", "\x1b_")):
                match = re.match(r"\x1b[\]P_](.*?)(?:\x07|\x1b\\)", self.pending, re.S)
                if not match:
                    break
                if match[1] == "11;?":
                    self.send("\x1b]11;rgb:0000/0000/0000\x07")
                elif match[1] == "10;?":
                    self.send("\x1b]10;rgb:ffff/ffff/ffff\x07")
                self.pending = self.pending[match.end():]
                continue
            if self.pending[0] == "\x1b":
                if len(self.pending) < 2:
                    break
                length = 3 if self.pending[1] in "()" else 2
                if len(self.pending) < length:
                    break
                self.pending = self.pending[length:]
                continue
            char, self.pending = self.pending[0], self.pending[1:]
            if char == "\r":
                self.col = 0
            elif char == "\n":
                self.row += 1
                if self.row >= self.height:
                    self.screen.pop(0)
                    self.screen.append([" "] * self.width)
                    self.row = self.height - 1
            elif char == "\b":
                self.col = max(0, self.col - 1)
            elif char >= " " and not unicodedata.combining(char):
                if self.col >= self.width:
                    self.col, self.row = 0, min(self.height - 1, self.row + 1)
                self.screen[self.row][self.col] = char
                self.col += 2 if unicodedata.east_asian_width(char) in "WF" else 1

    def csi(self, raw, command):
        if raw.startswith(("?", ">", "<", "=")) or command == "m":
            return
        values = [int(v or 0) for v in raw.split(";")] if re.fullmatch(r"[0-9;]*", raw) else [0]
        first = values[0] or 1
        if command in "Hf":
            self.row = min(self.height - 1, first - 1)
            self.col = min(self.width - 1, (values[1] or 1) - 1) if len(values) > 1 else 0
        elif command in "ABCD":
            if command == "A": self.row = max(0, self.row - first)
            if command == "B": self.row = min(self.height - 1, self.row + first)
            if command == "C": self.col = min(self.width - 1, self.col + first)
            if command == "D": self.col = max(0, self.col - first)
        elif command == "G":
            self.col = min(self.width - 1, first - 1)
        elif command == "d":
            self.row = min(self.height - 1, first - 1)
        elif command == "J":
            if values[0] in (2, 3):
                self.screen = [[" "] * self.width for _ in range(self.height)]
            elif values[0] == 0:
                self.screen[self.row][self.col:] = [" "] * (self.width - self.col)
                for row in range(self.row + 1, self.height): self.screen[row] = [" "] * self.width
        elif command == "K":
            start, end = (0, self.width) if values[0] == 2 else ((0, self.col + 1) if values[0] == 1 else (self.col, self.width))
            self.screen[self.row][start:end] = [" "] * (end - start)
        elif command == "X":
            end = min(self.width, self.col + first)
            self.screen[self.row][self.col:end] = [" "] * (end - self.col)
        elif command == "P":
            row = self.screen[self.row]
            del row[self.col:self.col + first]
            row.extend([" "] * (self.width - len(row)))
        elif command == "n" and first == 6:
            self.send(f"\x1b[{self.row + 1};{self.col + 1}R")

    def poll(self):
        if self.status is not None:
            return True
        if self.process is not None:
            self.status = self.process.poll()
            return self.status is not None
        pid, status = os.waitpid(self.pid, os.WNOHANG)
        if pid:
            self.status = os.waitstatus_to_exitcode(status)
            return True
        return False

    def diagnostics(self):
        return self.text() + "\nterminal transcript tail: " + repr(self.transcript[-8192:])

    def wait(self, predicate, message, timeout=20):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            self.pump()
            if predicate():
                return
            if self.poll():
                raise AssertionError(
                    f"TUI exited {self.status} waiting for {message}\n{self.diagnostics()}"
                )
        raise AssertionError(f"timeout waiting for {message}\n{self.diagnostics()}")

    def wait_text(self, text):
        self.wait(lambda: text.lower() in self.text().lower(), text)

    def settle(self):
        end = time.monotonic() + 0.3
        while time.monotonic() < end:
            self.pump()

    def profiles(self):
        return read_json(self.base / "remotes.json").get("remotes") or []

    def fixture_state(self):
        return read_json(self.fixture["state"])

    def close(self):
        if self.process is not None:
            try:
                # Give the TUI and bridge a chance to unwind and close their
                # ConPTY handles before resorting to TerminateProcess.
                if self.process.poll() is None and self.process.stdin:
                    try:
                        self.process.stdin.write(b"q")
                        self.process.stdin.flush()
                    except OSError:
                        pass
                    try:
                        self.process.wait(timeout=1)
                    except subprocess.TimeoutExpired:
                        pass
                if self.process.stdin:
                    try:
                        self.process.stdin.close()
                    except OSError:
                        pass
                if self.process.poll() is None:
                    try:
                        self.process.wait(timeout=1)
                    except subprocess.TimeoutExpired:
                        self.process.terminate()
                        try:
                            self.process.wait(timeout=2)
                        except subprocess.TimeoutExpired:
                            self.process.kill()
                            self.process.wait(timeout=2)
                self.status = self.process.returncode
            finally:
                if self.process.stdout:
                    self.process.stdout.close()
            return
        try:
            if self.status is None:
                try:
                    os.kill(self.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                deadline = time.monotonic() + 2
                while self.status is None and time.monotonic() < deadline:
                    try:
                        pid, status = os.waitpid(self.pid, os.WNOHANG)
                    except ChildProcessError:
                        break
                    if pid:
                        self.status = os.waitstatus_to_exitcode(status)
                        break
                    time.sleep(0.02)
                if self.status is None:
                    try:
                        os.kill(self.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    try:
                        _, status = os.waitpid(self.pid, 0)
                        self.status = os.waitstatus_to_exitcode(status)
                    except ChildProcessError:
                        pass
        finally:
            try:
                os.close(self.fd)
            except OSError:
                pass

    def quit(self):
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and self.status is None:
            self.send("q")
            self.settle()
            self.poll()
        assert self.status == 0, "TUI did not quit cleanly"
        assert self.fixture["token"] not in self.transcript, "manager token appeared in terminal output"


def read_json(path):
    try:
        return json.loads(Path(path).read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def make_token_insecure(path):
    if os.name == "nt":
        result = subprocess.run(
            ["icacls", str(path), "/grant", "*S-1-1-0:(R)"],
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 0, "could not make fixture token ACL permissive"
    else:
        path.chmod(0o640)


def restore_token_security(path):
    if os.name == "nt":
        result = subprocess.run(
            ["icacls", str(path), "/remove:g", "*S-1-1-0"],
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 0, "could not restore fixture token ACL"
    else:
        path.chmod(0o600)


def enter_create(terminal, name, remote):
    terminal.wait_text("Location: Remote")
    terminal.send(name + "\talpine" + "\t" * 9 + "\r")
    terminal.wait(lambda: any(c["name"] == name for c in (terminal.fixture_state().get("creates") or [])), "remote create request")
    # The fixture records the request before the HTTP response is consumed.
    # Wait for the TUI to return to its list before sending another shortcut;
    # otherwise a loaded runner can deliver `q` into the still-open form and
    # strand cleanup until the outer watchdog kills the PTY driver.
    terminal.wait(
        lambda: "location: remote" not in terminal.text().lower()
        and ("remote: " + remote).lower() in terminal.text().lower(),
        "sandbox list after remote create",
    )
    terminal.settle()
    assert not (terminal.base / "sandboxes" / name).exists(), "remote creation created local state"


def standalone(fixture):
    terminal = Terminal(fixture, "standalone")
    try:
        terminal.send("n")
        terminal.wait_text("Where should this sandbox run?")
        terminal.send("l")
        terminal.wait_text("Location: Local")
        terminal.send("\x1b")
        terminal.settle()
        terminal.send("n")
        terminal.wait_text("Where should this sandbox run?")
        terminal.send("r")
        terminal.wait_text("Standalone remotes use")
        terminal.send("a")
        terminal.wait_text("Manager token")
        terminal.send("standalone\t" + fixture["manager"] + "\twrong-manager-token-123456\t" + fixture["ca"] + "\t\t\r")
        terminal.wait_text("access denied")
        assert not terminal.profiles(), "refused authentication still saved a profile"
        terminal.send("\x1b[Z" * 3 + fixture["token"] + "\t" * 3 + "\r")
        terminal.wait(lambda: len(terminal.profiles()) == 1, "standalone registration")
        assert fixture["token"] not in (terminal.base / "remotes.json").read_text(), "token stored in profile"
        token_path = terminal.base / "remotes" / "standalone.token"
        if os.name != "nt":
            assert token_path.stat().st_mode & 0o777 == 0o600, "token is not private"
        probe_args = [fixture["gantry"], "remote", "test", "standalone", "-remote="]
        private_probe = subprocess.run(probe_args, env=terminal.env, capture_output=True, text=True, timeout=20, check=False)
        assert private_probe.returncode == 0, "new token did not pass platform security validation"
        make_token_insecure(token_path)
        probe = subprocess.run(probe_args, env=terminal.env, capture_output=True, text=True, timeout=20, check=False)
        expected_acl_error = "insecure Windows ACL" if os.name == "nt" else "chmod 600"
        assert probe.returncode != 0 and expected_acl_error in probe.stderr, "readable token was accepted"
        restore_token_security(token_path)
        enter_create(terminal, "standalone-dev", "standalone")
        assert not list(terminal.base.glob("sandboxes-orgs/*.json")), "standalone flow required organization login"
        before = terminal.fixture_state()["health"]
        terminal.send("t")
        terminal.wait(lambda: terminal.fixture_state()["health"] > before, "TUI health test")
        terminal.settle()
        terminal.send("d")
        terminal.wait_text("Remove remote profile")
        terminal.send("y")
        terminal.wait(lambda: not terminal.profiles(), "profile removal")
        assert not token_path.exists(), "profile removal kept token"
        assert not terminal.fixture_state().get("unexpected"), "profile management sent a sandbox mutation"
        terminal.settle()
        terminal.quit()
        print("PASS standalone: add without org, auth refusal, private token, remote pull/create, TUI test/remove")
    finally:
        terminal.close()


def organization(fixture):
    terminal = Terminal(fixture, "organization")
    try:
        terminal.send("n")
        terminal.wait_text("Where should this sandbox run?")
        terminal.send("o")
        terminal.wait_text("Organization config file")
        terminal.send(fixture["config"] + "\tdeveloper\t\r")
        terminal.wait_text("example-org / org-team")
        receipts = list(terminal.base.glob("sandboxes-orgs/*.json"))
        assert len(receipts) == 1 and read_json(receipts[0]).get("remote_catalog"), "login did not save public discovery metadata"
        assert not terminal.profiles(), "discovery auto-added a remote or credential"
        terminal.send("\r")
        terminal.wait_text("Manager token")
        terminal.send(fixture["token"] + "\t" * 3 + "\r")
        terminal.wait(lambda: len(terminal.profiles()) == 1, "organization remote registration")
        enter_create(terminal, "organization-dev", "org-team")
        created = next(c for c in terminal.fixture_state()["creates"] if c["name"] == "organization-dev")
        assert created["organizationPolicy"]["profile"] == "developer", "organization selection lost its signed policy"
        terminal.quit()
        print("PASS organization: browser OIDC/PKCE, dynamic discovery, separate manager token, policy-bound create")
    finally:
        terminal.close()


def main():
    fixture = read_json(sys.argv[1])
    try:
        print("remote TUI E2E: starting standalone flow", flush=True)
        standalone(fixture)
        print("remote TUI E2E: starting organization flow", flush=True)
        organization(fixture)
    except Exception as exc:
        # Even a failed terminal assertion must not expose the write-only token.
        print(str(exc).replace(fixture["token"], "[redacted]"), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
