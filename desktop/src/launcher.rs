//! Launch only Gantry's race-safe default-local manager command. The Go side
//! owns detachment, instance locks, readiness, governance, and daemon lifetime.

use anyhow::{Context, Result, bail, ensure};
use serde::Deserialize;
use std::{
    io::Read,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

const START_TIMEOUT: Duration = Duration::from_secs(12);
const OUTPUT_LIMIT: u64 = 16 * 1024;

#[derive(Deserialize)]
struct Ready {
    socket: PathBuf,
    version: String,
}

pub fn executable(override_path: Option<&Path>) -> PathBuf {
    if let Some(path) = override_path {
        return path.to_owned();
    }
    if let Ok(current) = std::env::current_exe() {
        let name = if cfg!(windows) {
            "gantry.exe"
        } else {
            "gantry"
        };
        let sibling = current.with_file_name(name);
        if sibling.is_file() {
            return sibling;
        }
    }
    PathBuf::from("gantry")
}

pub fn ensure_local(socket: &Path, program: &Path) -> Result<()> {
    ensure_local_with_timeout(socket, program, START_TIMEOUT)
}

#[cfg(unix)]
fn ensure_local_with_timeout(socket: &Path, program: &Path, timeout: Duration) -> Result<()> {
    let deadline = Instant::now() + timeout;
    let mut command = Command::new(program);
    command
        .args(["serve", "--ensure", "--socket"])
        .arg(socket)
        .env("GANTRY_REMOTE", "")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // A concurrent fork can briefly inherit a writer's executable fd, even
    // with CLOEXEC. Retry only ETXTBSY before Gantry has executed, never a
    // running helper or an HTTP mutation. Stay within the readiness deadline.
    let mut busy_retries = 0;
    let mut child = loop {
        match command.spawn() {
            Err(error)
                if error.raw_os_error() == Some(libc::ETXTBSY)
                    && busy_retries < 5
                    && Instant::now() < deadline =>
            {
                busy_retries += 1;
                thread::sleep(Duration::from_millis(10));
            }
            result => break result,
        }
    }
    .with_context(|| {
        format!(
            "Cannot launch {}. Install an up-to-date Gantry CLI or pass --gantry PATH",
            program.display()
        )
    })?;
    let result = (|| {
        let mut out = child.stdout.take().context("Missing launcher stdout")?;
        let mut err = child.stderr.take().context("Missing launcher stderr")?;
        nonblocking(&out)?;
        nonblocking(&err)?;
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let status = loop {
            let out_closed = collect_output(&mut out, &mut stdout)?;
            let err_closed = collect_output(&mut err, &mut stderr)?;
            if let Some(status) = child
                .try_wait()
                .context("Waiting for local manager launcher")?
                && out_closed
                && err_closed
            {
                break status;
            }
            ensure!(
                Instant::now() < deadline,
                "Local manager startup timed out; retry or start gantry serve explicitly"
            );
            thread::sleep(Duration::from_millis(10));
        };
        if !status.success() {
            let diagnostic = String::from_utf8_lossy(&stderr);
            bail!("Local manager startup failed. {}", diagnostic.trim());
        }
        let ready: Ready = serde_json::from_slice(&stdout).context("Gantry did not return a readiness response; update the CLI to a version supporting serve --ensure")?;
        let absolute = |path: &Path| -> Result<PathBuf> {
            Ok(crate::options::clean_path(
                &std::env::current_dir()?.join(path),
            ))
        };
        ensure!(
            ready.version == "v1" && absolute(&ready.socket)? == absolute(socket)?,
            "Gantry returned a different socket or unsupported API version; no fallback was attempted"
        );
        Ok(())
    })();
    if result.is_err() {
        let _ = child.kill();
        let _ = child.wait();
    }
    result
}

#[cfg(not(unix))]
fn ensure_local_with_timeout(_: &Path, _: &Path, _: Duration) -> Result<()> {
    bail!("Automatic local manager startup currently requires Linux or macOS")
}

#[cfg(unix)]
pub(crate) fn nonblocking(pipe: &impl std::os::fd::AsRawFd) -> Result<()> {
    // SAFETY: this is a live, owned child pipe; fcntl changes only its status
    // flags. No pointers are passed and its existing flags are preserved.
    let result = unsafe {
        let flags = libc::fcntl(pipe.as_raw_fd(), libc::F_GETFL);
        if flags == -1 {
            -1
        } else {
            libc::fcntl(pipe.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK)
        }
    };
    if result == -1 {
        return Err(std::io::Error::last_os_error()).context("Configure launcher output pipe");
    }
    Ok(())
}

#[cfg(unix)]
pub(crate) fn collect_output(pipe: &mut impl Read, bytes: &mut Vec<u8>) -> Result<bool> {
    loop {
        let mut buffer = [0; 1024];
        match pipe.read(&mut buffer) {
            Ok(0) => return Ok(true),
            Ok(count) => {
                ensure!(
                    bytes.len() as u64 + count as u64 <= OUTPUT_LIMIT,
                    "Local manager launcher output exceeded its limit"
                );
                bytes.extend_from_slice(&buffer[..count]);
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return Ok(false),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error.into()),
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn helper(dir: &Path, script: &str) -> PathBuf {
        let path = dir.join("gantry");
        std::fs::write(&path, format!("#!/bin/sh\n{script}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        path
    }

    #[test]
    fn launcher_is_bounded_and_never_uses_a_shell_for_arguments() {
        let dir = tempfile::tempdir().unwrap();
        let program = helper(
            dir.path(),
            r#"[ "$1" = serve ] && [ "$2" = --ensure ] && [ "$3" = --socket ] && [ "$GANTRY_REMOTE" = '' ] || exit 4
printf '{"socket":"%s","version":"v1"}\n' "$4""#,
        );
        ensure_local(Path::new("/tmp/path with spaces.sock"), &program).unwrap();
        let program = helper(dir.path(), "exec sleep 30");
        let started = Instant::now();
        assert!(
            ensure_local_with_timeout(Path::new("/unused"), &program, Duration::from_millis(100))
                .unwrap_err()
                .to_string()
                .contains("timed out")
        );
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn launcher_rejects_wrong_target_and_failed_readiness() {
        let dir = tempfile::tempdir().unwrap();
        let program = helper(
            dir.path(),
            r#"printf '{"socket":"/other.sock","version":"v1"}'"#,
        );
        assert!(ensure_local(Path::new("/expected.sock"), &program).is_err());
        let program = helper(
            dir.path(),
            "printf 'another manager owns the state' >&2; exit 1",
        );
        assert!(
            ensure_local(Path::new("/expected.sock"), &program)
                .unwrap_err()
                .to_string()
                .contains("owns the state")
        );
    }
}
