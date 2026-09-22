//! Share the Go CLI's remotes/store.lock. Without this, a remove/add could
//! pair an old server URL with the new server's token during replacement.

use anyhow::{Context, Result, ensure};
use std::{fs::File, path::Path};

#[cfg(unix)]
pub fn acquire(directory: &Path) -> Result<File> {
    use std::os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt},
    };
    let path = directory.join("store.lock");
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(&path)
        .context("Cannot open the remote profile lock; register profiles with gantry remote add")?;
    let metadata = file.metadata()?;
    // SAFETY: geteuid has no arguments; flock receives a live, owned file
    // descriptor. The advisory lock is released when the File is dropped.
    let uid = unsafe { libc::geteuid() };
    ensure!(
        metadata.is_file() && metadata.uid() == uid && metadata.mode() & 0o077 == 0,
        "Remote profile lock must be a private regular file owned by this user"
    );
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_SH | libc::LOCK_NB) } != 0 {
        return Err(std::io::Error::last_os_error())
            .context("Remote profiles are being updated; retry shortly");
    }
    Ok(file)
}

#[cfg(not(unix))]
pub fn acquire(_: &Path) -> Result<File> {
    anyhow::bail!("Remote profile locking is not implemented on this platform")
}
