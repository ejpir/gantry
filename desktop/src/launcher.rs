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

pub(crate) const EXECUTABLE: &str = if cfg!(windows) {
    "gantry.exe"
} else {
    "gantry"
};

/// No Gantry CLI exists anywhere the launcher looks. Unlike a CLI that fails
/// to start, this is the one condition where the desktop offers to install
/// the CLI that matches its own release.
#[derive(Debug)]
pub struct CliMissing {
    pub managed: Option<PathBuf>,
}

impl std::fmt::Display for CliMissing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "No Gantry CLI was found beside the desktop, on PATH")?;
        if let Some(path) = &self.managed {
            write!(f, ", or at {}", path.display())?;
        }
        write!(f, ". Install the Gantry CLI, or pass --gantry PATH.")
    }
}

impl std::error::Error for CliMissing {}

/// An explicit --gantry path, then a CLI shipped beside the desktop, then
/// PATH, then the desktop-managed install. The managed copy is only a
/// fallback, so any CLI the user installed themselves always wins.
pub fn executable(override_path: Option<&Path>, managed: Option<&Path>) -> Result<PathBuf> {
    locate(override_path, managed).ok_or_else(|| {
        CliMissing {
            managed: managed.map(Path::to_owned),
        }
        .into()
    })
}

pub fn locate(override_path: Option<&Path>, managed: Option<&Path>) -> Option<PathBuf> {
    let sibling = std::env::current_exe()
        .ok()
        .map(|current| current.with_file_name(EXECUTABLE));
    locate_in(
        override_path,
        sibling.as_deref(),
        std::env::var_os("PATH").as_deref(),
        managed,
    )
}

fn locate_in(
    override_path: Option<&Path>,
    sibling: Option<&Path>,
    search: Option<&std::ffi::OsStr>,
    managed: Option<&Path>,
) -> Option<PathBuf> {
    if let Some(path) = override_path {
        return Some(path.to_owned());
    }
    sibling
        .filter(|sibling| sibling.is_file())
        .map(Path::to_owned)
        .or_else(|| {
            std::env::split_paths(search?)
                // Relative entries would resolve against the working directory.
                .filter(|dir| dir.is_absolute())
                .map(|dir| dir.join(EXECUTABLE))
                .find(|candidate| runnable(candidate))
        })
        .or_else(|| {
            managed
                .filter(|path| managed_runnable(path))
                .map(Path::to_owned)
        })
}

#[cfg(unix)]
fn runnable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

#[cfg(not(unix))]
fn runnable(path: &Path) -> bool {
    path.is_file()
}

/// The managed copy is only trusted inside the private directory the
/// installer created; anything else is ignored rather than executed.
#[cfg(unix)]
fn managed_runnable(path: &Path) -> bool {
    runnable(path)
        && path
            .parent()
            .is_some_and(|dir| crate::security::private_directory(dir).is_ok())
}

#[cfg(not(unix))]
fn managed_runnable(_: &Path) -> bool {
    false
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

    #[test]
    fn user_installed_clis_win_over_the_desktop_managed_copy() {
        let dir = tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap();
        let bundled = dir.path().join("bundle");
        let on_path = dir.path().join("path");
        let managed = dir.path().join("bin");
        for directory in [&bundled, &on_path, &managed] {
            std::fs::create_dir(directory).unwrap();
            std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700)).unwrap();
            helper(directory, "exit 0");
        }
        let sibling = bundled.join("gantry");
        let managed = managed.join("gantry");
        let search = std::env::join_paths([Path::new("relative"), &on_path]).unwrap();
        let find = |sibling: &Path, search: &std::ffi::OsStr| {
            locate_in(None, Some(sibling), Some(search), Some(&managed))
        };
        assert_eq!(
            locate_in(Some(Path::new("/explicit")), Some(&sibling), None, None),
            Some("/explicit".into())
        );
        assert_eq!(find(&sibling, &search), Some(sibling.clone()));
        let missing = dir.path().join("missing");
        assert_eq!(find(&missing, &search), Some(on_path.join("gantry")));
        // Non-executable and relative PATH entries are not candidates.
        std::fs::set_permissions(
            on_path.join("gantry"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        assert_eq!(find(&missing, &search), Some(managed.clone()));
        // A managed copy outside a private directory is ignored, not run.
        std::fs::set_permissions(
            managed.parent().unwrap(),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        assert_eq!(find(&missing, &search), None);
        let message = CliMissing {
            managed: Some(managed.clone()),
        }
        .to_string();
        assert!(
            message.contains(&managed.display().to_string()),
            "{message}"
        );
    }
}
