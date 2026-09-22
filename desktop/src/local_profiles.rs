//! Profile writes stay with the Go CLI's verified registration and locked,
//! private credential store. This never invokes serve or forwards local profile
//! credentials to whichever manager happens to be selected in the UI.
use crate::forms::Intent;
use anyhow::{Result, bail};
use std::path::Path;

#[cfg(unix)]
pub fn apply(program: &Path, base: &Path, intent: &Intent) -> Result<String> {
    use anyhow::{Context, ensure};
    use std::{
        io::Write,
        process::{Command, Stdio},
        time::{Duration, Instant},
    };
    let mut command = Command::new(program);
    command
        .arg("remote")
        .env("GANTRY_REMOTE", "")
        .env("GANTRY_MANAGER_SOCKET", "")
        .env("GANTRY_HOME", base.join("sandboxes"));
    let token = match intent {
        Intent::RemoteAdd {
            name,
            url,
            ca,
            pin,
            token,
        } => {
            crate::profiles::RemoteProfile {
                name: name.clone(),
                url: url.clone(),
                fingerprint: pin.clone(),
                ca_cert: String::new(),
            }
            .validate()?;
            ensure!(
                (16..=256).contains(&token.expose().len())
                    && token.expose().bytes().all(|b| (0x21..=0x7e).contains(&b)),
                "Invalid bearer token"
            );
            command.args(["add", name, url, "--token-stdin"]);
            if !ca.is_empty() {
                command.arg("--ca").arg(ca);
            }
            if !pin.is_empty() {
                command.arg("--fingerprint").arg(pin);
            }
            Some(token.expose())
        }
        Intent::RemoteRemove(name) => {
            crate::profiles::validate_name(name)?;
            command.args(["rm", name]);
            None
        }
        _ => bail!("Not a client-local profile operation"),
    };
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("Cannot start Gantry profile helper; install the CLI or select --gantry PATH")?;
    let result = (|| {
        let mut stdin = child.stdin.take().context("Missing helper input")?;
        crate::launcher::nonblocking(&stdin)?;
        if let Some(token) = token {
            stdin.write_all(token.as_bytes())?;
            stdin.write_all(b"\n")?;
        }
        drop(stdin);
        let mut out = child.stdout.take().context("Missing helper output")?;
        let mut err = child.stderr.take().context("Missing helper diagnostic")?;
        crate::launcher::nonblocking(&out)?;
        crate::launcher::nonblocking(&err)?;
        let mut stdout = zeroize::Zeroizing::new(Vec::new());
        let mut stderr = zeroize::Zeroizing::new(Vec::new());
        let deadline = Instant::now() + Duration::from_secs(25);
        loop {
            let a = crate::launcher::collect_output(&mut out, &mut stdout)?;
            let b = crate::launcher::collect_output(&mut err, &mut stderr)?;
            if let Some(status) = child.try_wait()?
                && a
                && b
            {
                if !status.success() {
                    let mut message = String::from_utf8_lossy(&stderr).into_owned();
                    if let Some(token) = token {
                        message = message.replace(token, "[redacted]");
                    }
                    bail!(
                        "Profile operation failed: {}",
                        crate::workspace::text(&message)
                    );
                }
                return Ok(
                    "Client-local profile updated. The active manager was not changed.".into(),
                );
            }
            ensure!(
                Instant::now() < deadline,
                "Profile operation timed out. Refresh the catalog before retrying; it may have completed."
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    })();
    if result.is_err() {
        let _ = child.kill();
        let _ = child.wait();
    }
    result
}
#[cfg(not(unix))]
pub fn apply(_: &Path, _: &Path, _: &Intent) -> Result<String> {
    bail!("Protected profile writes are not supported on this platform")
}
