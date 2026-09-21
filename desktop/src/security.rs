//! Local files and sockets are authentication boundaries, not just paths.

use anyhow::{Context, Result, ensure};
use std::{io::Read, path::Path};

#[cfg(unix)]
fn validate_owner(path: &Path, metadata: &std::fs::Metadata, private: bool) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    // SAFETY: geteuid has no pointer arguments or preconditions.
    let uid = unsafe { libc::geteuid() };
    ensure!(
        metadata.uid() == uid,
        "{} must be owned by the current user",
        path.display()
    );
    let forbidden = if private { 0o077 } else { 0o022 };
    ensure!(
        metadata.mode() & forbidden == 0,
        "{} has unsafe permissions; private credentials and sockets require owner-only access",
        path.display()
    );
    Ok(())
}

#[cfg(unix)]
pub fn private_directory(path: &Path) -> Result<()> {
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("Cannot inspect {}", path.display()))?;
    ensure!(
        metadata.is_dir() && !metadata.file_type().is_symlink(),
        "{} must be a real private directory, not a symlink",
        path.display()
    );
    validate_owner(path, &metadata, true)
}

#[cfg(unix)]
pub fn local_socket(path: &Path) -> Result<()> {
    use std::os::unix::fs::FileTypeExt;
    private_directory(
        path.parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or(Path::new(".")),
    )?;
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("Cannot inspect local manager socket {}", path.display()))?;
    ensure!(
        metadata.file_type().is_socket(),
        "The selected endpoint is not a Unix socket; it will not be replaced"
    );
    validate_owner(path, &metadata, true)
}

#[cfg(not(unix))]
pub fn local_socket(_: &Path) -> Result<()> {
    anyhow::bail!("Local socket connections currently require Linux or macOS")
}

/// O_NOFOLLOW and fstat validate the opened file, not an earlier path lookup.
/// O_NONBLOCK prevents a substituted FIFO from hanging the background worker.
#[cfg(unix)]
pub fn read_file(path: &Path, maximum: u64, private: bool) -> Result<Vec<u8>> {
    use std::os::unix::fs::OpenOptionsExt;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .with_context(|| format!("Cannot open {}", path.display()))?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file(),
        "{} must be a regular file",
        path.display()
    );
    validate_owner(path, &metadata, private)?;
    ensure!(
        metadata.len() <= maximum,
        "{} exceeds the allowed size",
        path.display()
    );
    let mut bytes = Vec::new();
    file.take(maximum + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= maximum,
        "{} exceeds the allowed size",
        path.display()
    );
    Ok(bytes)
}

// Fail closed until a Windows ACL implementation is provided. Unix mode bits
// are not a valid credential-security check on Windows.
#[cfg(not(unix))]
pub fn private_directory(_: &Path) -> Result<()> {
    anyhow::bail!(
        "Remote profile access requires a supported OS credential-permission check; Windows support is not implemented yet"
    )
}

#[cfg(not(unix))]
pub fn read_file(_: &Path, _: u64, _: bool) -> Result<Vec<u8>> {
    anyhow::bail!("Protected remote credential loading is not implemented on this platform")
}
