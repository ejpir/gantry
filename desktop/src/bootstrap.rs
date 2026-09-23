#![cfg_attr(not(unix), allow(dead_code))]
//! Explicit, user-approved installation of the Gantry CLI built from the same
//! release tag as this desktop. Nothing is downloaded without a click, and the
//! executable becomes visible (and runnable) only after its published SHA-256,
//! executable format, and on macOS its code signature have been verified.

use anyhow::{Context, Result, bail, ensure};
use sha2::{Digest, Sha256};
use std::{
    io::{Read, Write},
    path::{Path, PathBuf},
    time::Duration,
};

const RELEASE_BASE: &str = "https://github.com/ejpir/gantry/releases/download";
const MAX_CHECKSUM: u64 = 4 << 10;
const MAX_BINARY: u64 = 256 << 20;
const MAX_REDIRECTS: usize = 5;
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(15 * 60);

/// CI stamps the release tag into tagged builds. Anything else is a
/// development build: there is no published CLI it is guaranteed to match.
const STAMPED_RELEASE: Option<&str> = option_env!("GANTRY_DESKTOP_RELEASE");

/// The desktop-managed CLI under the Gantry root (`~/.gantry`, or the parent
/// of `GANTRY_HOME`). The launcher consults it after every user-provided CLI.
pub fn managed_path(base: &Path) -> PathBuf {
    base.join("bin").join(crate::launcher::EXECUTABLE)
}

/// A download this build can perform: the release asset matching the
/// desktop's own tag and platform, and where it would be installed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Offer {
    pub release: &'static str,
    pub asset: &'static str,
    pub destination: PathBuf,
}

/// None for development builds, platforms that cannot start a local manager,
/// and sessions without a Gantry root to install into.
pub fn offer(destination: Option<&Path>) -> Option<Offer> {
    offer_for(
        STAMPED_RELEASE,
        std::env::consts::OS,
        std::env::consts::ARCH,
        destination,
    )
}

fn offer_for(
    release: Option<&'static str>,
    os: &str,
    arch: &str,
    destination: Option<&Path>,
) -> Option<Offer> {
    Some(Offer {
        release: release.filter(|tag| valid_tag(tag))?,
        asset: platform_asset(os, arch)?,
        destination: destination?.to_owned(),
    })
}

/// Only Unix hosts can start a local manager, so only their CLIs are offered.
fn platform_asset(os: &str, arch: &str) -> Option<&'static str> {
    match (os, arch) {
        ("linux", "x86_64") => Some("gantry-linux-amd64"),
        ("linux", "aarch64") => Some("gantry-linux-arm64"),
        ("macos", "aarch64") => Some("gantry-darwin-arm64"),
        _ => None,
    }
}

/// The strict tag shape CI enforces before a tag reaches any build step:
/// `^v[0-9]+\.[0-9]+\.[0-9]+([-+][A-Za-z0-9._-]+)?$`. It becomes a URL path
/// segment, so a stamped value that does not match disables installation.
fn valid_tag(tag: &str) -> bool {
    let Some(rest) = tag.strip_prefix('v') else {
        return false;
    };
    let (core, suffix) = match rest.find(['-', '+']) {
        Some(index) => (&rest[..index], Some(&rest[index + 1..])),
        None => (rest, None),
    };
    let numbers = core.split('.').collect::<Vec<_>>();
    numbers.len() == 3
        && numbers
            .iter()
            .all(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
        && suffix.is_none_or(|s| {
            !s.is_empty()
                && s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        })
}

/// Where and how release assets are fetched; tests substitute a local server.
struct Channel {
    base: String,
    tls: rustls::ClientConfig,
    trusted: fn(&reqwest::Url) -> bool,
    system_proxy: bool,
}

impl Channel {
    fn github() -> Result<Self> {
        Ok(Self {
            base: RELEASE_BASE.into(),
            tls: crate::tls::public_configuration()?,
            trusted: github_host,
            // Like the CLI's own downloads, honor proxy variables: a CONNECT
            // tunnel keeps TLS end to end, and no credentials are sent.
            system_proxy: true,
        })
    }

    fn client(&self, release: &str) -> Result<reqwest::blocking::Client> {
        let trusted = self.trusted;
        let builder = reqwest::blocking::Client::builder()
            .https_only(true)
            .use_preconfigured_tls(self.tls.clone())
            .http1_only()
            .retry(reqwest::retry::never())
            .redirect(reqwest::redirect::Policy::custom(move |attempt| {
                if attempt.previous().len() > MAX_REDIRECTS {
                    attempt.error("too many redirects")
                } else if trusted(attempt.url()) {
                    attempt.follow()
                } else {
                    attempt.error("redirected outside the release download hosts")
                }
            }))
            .connect_timeout(Duration::from_secs(15))
            .timeout(DOWNLOAD_TIMEOUT)
            .user_agent(format!("gantry-desktop/{release}"));
        let builder = if self.system_proxy {
            builder
        } else {
            builder.no_proxy()
        };
        Ok(builder.build()?)
    }
}

/// GitHub serves release assets by redirecting to its download CDN.
fn github_host(url: &reqwest::Url) -> bool {
    url.scheme() == "https"
        && url.username().is_empty()
        && url.password().is_none()
        && url.port().is_none()
        && url
            .host_str()
            .is_some_and(|host| host == "github.com" || host.ends_with(".githubusercontent.com"))
}

/// Download, verify, and atomically install the offered CLI. Returns only
/// after the verified executable is durable at `offer.destination`. Runs
/// blocking network and file I/O: call it from a background thread.
pub fn install(offer: &Offer, progress: impl Fn(&str)) -> Result<()> {
    install_from(&Channel::github()?, offer, &progress)
}

#[cfg(unix)]
fn install_from(channel: &Channel, offer: &Offer, progress: &dyn Fn(&str)) -> Result<()> {
    ensure!(
        valid_tag(offer.release),
        "Invalid Gantry release {}",
        offer.release
    );
    let directory = offer
        .destination
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .context("Invalid Gantry CLI install location")?;
    prepare_directory(directory)?;
    let client = channel.client(offer.release)?;
    let url = format!(
        "{}/{}/{}",
        channel.base.trim_end_matches('/'),
        offer.release,
        offer.asset
    );
    progress(&format!("Fetching the {} checksum", offer.asset));
    let expected = fetch_checksum(&client, &format!("{url}.sha256"), offer)?;
    let (staged, mut file) = Staged::create(directory)?;
    let actual = download(&client, &url, offer, &mut file, progress)?;
    ensure!(
        actual == expected,
        "{} failed SHA-256 verification; nothing was installed",
        offer.asset
    );
    // Close the writer before anything can execute the file: Linux refuses
    // to run an executable that is still open for writing (ETXTBSY).
    file.sync_all()
        .context("Cannot persist the downloaded Gantry CLI")?;
    drop(file);
    verify_executable(&staged.path, std::env::consts::OS, std::env::consts::ARCH)?;
    progress(&format!("Verified {}; installing", offer.asset));
    staged.commit(&offer.destination)
}

#[cfg(not(unix))]
fn install_from(_: &Channel, _: &Offer, _: &dyn Fn(&str)) -> Result<()> {
    bail!("Installing the Gantry CLI from the desktop requires Linux or macOS")
}

/// Both the bin directory and the Gantry root must be private: anyone able
/// to rename either could substitute the executable the desktop later runs.
#[cfg(unix)]
fn prepare_directory(directory: &Path) -> Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(directory)
        .with_context(|| format!("Cannot create {}", directory.display()))?;
    if let Some(root) = directory
        .parent()
        .filter(|root| !root.as_os_str().is_empty())
    {
        crate::security::private_directory(root)?;
    }
    crate::security::private_directory(directory)
}

/// Receives each downloaded chunk with the running and advertised totals.
type Chunk<'a> = dyn FnMut(&[u8], u64, Option<u64>) -> Result<()> + 'a;

/// GET one release asset, handing each chunk to `chunk`. Anything but 200 OK,
/// or more than `maximum` bytes, fails before or while reading; a short body
/// is an error, not a success.
fn stream(
    client: &reqwest::blocking::Client,
    url: &str,
    offer: &Offer,
    maximum: u64,
    chunk: &mut Chunk,
) -> Result<()> {
    let name = url.rsplit('/').next().unwrap_or(offer.asset);
    let mut response = client
        .get(url)
        .send()
        .with_context(|| format!("Cannot download {name}"))?;
    let status = response.status();
    ensure!(
        status != reqwest::StatusCode::NOT_FOUND,
        "Gantry release {} does not publish {name}",
        offer.release
    );
    ensure!(
        status == reqwest::StatusCode::OK,
        "Downloading {name} failed with HTTP {}",
        status.as_u16()
    );
    let total = response.content_length();
    ensure!(
        total.is_none_or(|total| total <= maximum),
        "{name} exceeds the {maximum}-byte limit"
    );
    let mut buffer = vec![0; 64 << 10];
    let mut received = 0u64;
    loop {
        let count = match response.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => count,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => {
                return Err(error).with_context(|| format!("Downloading {name} failed"));
            }
        };
        received += count as u64;
        ensure!(
            received <= maximum,
            "{name} exceeds the {maximum}-byte limit"
        );
        chunk(&buffer[..count], received, total)?;
    }
    ensure!(
        total.is_none_or(|total| total == received),
        "Downloading {name} ended early"
    );
    Ok(())
}

fn fetch_checksum(
    client: &reqwest::blocking::Client,
    url: &str,
    offer: &Offer,
) -> Result<[u8; 32]> {
    let mut body = Vec::new();
    stream(client, url, offer, MAX_CHECKSUM, &mut |bytes, _, _| {
        body.extend_from_slice(bytes);
        Ok(())
    })?;
    parse_checksum(&body, offer.asset)
}

/// `sha256sum` output: a hex digest, optionally followed by the file it
/// hashed. A sidecar that names a different file is not a match.
fn parse_checksum(body: &[u8], asset: &str) -> Result<[u8; 32]> {
    let invalid = || format!("Invalid SHA-256 sidecar for {asset}");
    let mut fields = std::str::from_utf8(body)
        .ok()
        .into_iter()
        .flat_map(str::split_ascii_whitespace);
    let digest = fields
        .next()
        .filter(|digest| digest.len() == 64 && digest.bytes().all(|b| b.is_ascii_hexdigit()))
        .with_context(invalid)?;
    ensure!(
        fields
            .next()
            .is_none_or(|name| name.strip_prefix('*').unwrap_or(name) == asset),
        "The SHA-256 sidecar does not describe {asset}"
    );
    ensure!(fields.next().is_none(), invalid());
    let mut expected = [0; 32];
    for (byte, pair) in expected.iter_mut().zip(digest.as_bytes().chunks(2)) {
        *byte = u8::from_str_radix(std::str::from_utf8(pair)?, 16)?;
    }
    Ok(expected)
}

fn download(
    client: &reqwest::blocking::Client,
    url: &str,
    offer: &Offer,
    file: &mut std::fs::File,
    progress: &dyn Fn(&str),
) -> Result<[u8; 32]> {
    let mut hash = Sha256::new();
    let mut reported = None;
    stream(
        client,
        url,
        offer,
        MAX_BINARY,
        &mut |bytes, received, total| {
            hash.update(bytes);
            file.write_all(bytes)
                .context("Cannot write the downloaded Gantry CLI")?;
            // Report each whole percent, or every 4 MiB without a length.
            let (step, amount) = match total.filter(|&total| total > 0) {
                Some(total) => {
                    let percent = received * 100 / total;
                    (percent, format!("{percent}%"))
                }
                None => (received >> 22, format!("{} MiB", received >> 20)),
            };
            if reported.replace(step) != Some(step) {
                progress(&format!(
                    "Downloading {} {} · {amount}",
                    offer.asset, offer.release
                ));
            }
            Ok(())
        },
    )?;
    Ok(hash.finalize().into())
}

/// A private, exclusively created file beside the destination. Dropping it
/// before `commit` removes it, so no failure leaves a partial executable.
#[cfg(unix)]
struct Staged {
    path: PathBuf,
    committed: bool,
}

#[cfg(unix)]
impl Staged {
    fn create(directory: &Path) -> Result<(Self, std::fs::File)> {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| elapsed.as_nanos())
            .unwrap_or_default();
        for attempt in 0..16 {
            let path = directory.join(format!(
                ".gantry-install-{}-{nonce:x}-{attempt}",
                std::process::id()
            ));
            match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o700)
                .open(&path)
            {
                Ok(file) => {
                    let staged = Self {
                        path,
                        committed: false,
                    };
                    // Owner-only and executable regardless of the umask.
                    file.set_permissions(std::fs::Permissions::from_mode(0o700))?;
                    return Ok((staged, file));
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!("Cannot stage the Gantry CLI in {}", directory.display())
                    });
                }
            }
        }
        bail!("Cannot stage the Gantry CLI in {}", directory.display())
    }

    fn commit(mut self, destination: &Path) -> Result<()> {
        std::fs::rename(&self.path, destination)
            .with_context(|| format!("Cannot install {}", destination.display()))?;
        self.committed = true;
        // The executable is already visible; also persist its directory entry.
        destination
            .parent()
            .map_or(Ok(()), |parent| {
                std::fs::File::open(parent).and_then(|directory| directory.sync_all())
            })
            .with_context(|| {
                format!(
                    "Installed {}, but could not confirm it is durable",
                    destination.display()
                )
            })
    }
}

#[cfg(unix)]
impl Drop for Staged {
    fn drop(&mut self) {
        if !self.committed {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

fn verify_executable(path: &Path, os: &str, arch: &str) -> Result<()> {
    let mut header = Vec::with_capacity(64);
    std::fs::File::open(path)
        .and_then(|file| file.take(64).read_to_end(&mut header))
        .context("Cannot read the downloaded Gantry CLI")?;
    check_header(&header, os, arch)?;
    #[cfg(target_os = "macos")]
    macos::verify(path)?;
    Ok(())
}

/// The checksum proves what was published; the header proves it is a native
/// executable for this host rather than, say, another platform's asset.
fn check_header(header: &[u8], os: &str, arch: &str) -> Result<()> {
    match os {
        "linux" => {
            ensure!(
                header.len() >= 20
                    && header.starts_with(b"\x7fELF")
                    && header[4] == 2
                    && header[5] == 1,
                "The download is not a 64-bit little-endian ELF executable"
            );
            let machine = u16::from_le_bytes([header[18], header[19]]);
            let expected = match arch {
                "x86_64" => 62,
                "aarch64" => 183,
                _ => bail!("Unsupported CPU architecture {arch}"),
            };
            ensure!(
                machine == expected,
                "The download was built for a different CPU architecture"
            );
        }
        "macos" => ensure!(
            arch == "aarch64"
                && header.len() >= 8
                && header[..4] == 0xfeed_facf_u32.to_le_bytes()
                && header[4..8] == 0x0100_000c_u32.to_le_bytes(),
            "The download is not an arm64 Mach-O executable"
        ),
        _ => bail!("Installing the Gantry CLI is not supported on {os}"),
    }
    Ok(())
}

/// `<key>com.apple.security.hypervisor</key>` followed by `<true/>`, allowing
/// the same whitespace as the CLI updater's check.
#[cfg(any(target_os = "macos", test))]
fn hypervisor_entitled(plist: &[u8]) -> bool {
    let text = String::from_utf8_lossy(plist);
    let mut rest = &*text;
    while let Some(start) = rest.find("<key>") {
        rest = &rest[start + "<key>".len()..];
        let Some(end) = rest.find("</key>") else {
            return false;
        };
        let key = rest[..end].trim();
        rest = &rest[end + "</key>".len()..];
        if key == "com.apple.security.hypervisor"
            && rest
                .trim_start()
                .strip_prefix("<true")
                .is_some_and(|value| value.trim_start().starts_with("/>"))
        {
            return true;
        }
    }
    false
}

#[cfg(target_os = "macos")]
mod macos {
    use anyhow::{Context, Result, ensure};
    use std::{
        path::Path,
        process::{Command, Stdio},
    };

    const CODESIGN: &str = "/usr/bin/codesign";

    /// Mirrors the CLI updater: a valid signature carrying the Hypervisor
    /// entitlement the release build applies. Without it no VM can boot.
    pub fn verify(path: &Path) -> Result<()> {
        let status = Command::new(CODESIGN)
            .args(["--verify", "--strict"])
            .arg(path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .context("Cannot run codesign")?;
        ensure!(
            status.success(),
            "The downloaded Gantry CLI has an invalid macOS code signature"
        );
        let output = Command::new(CODESIGN)
            .args(["-d", "--entitlements", ":-"])
            .arg(path)
            .stdin(Stdio::null())
            .output()
            .context("Cannot run codesign")?;
        ensure!(
            output.status.success()
                && (super::hypervisor_entitled(&output.stdout)
                    || super::hypervisor_entitled(&output.stderr)),
            "The downloaded Gantry CLI lacks the macOS Hypervisor entitlement"
        );
        clear_quarantine(path)
    }

    /// Files this process writes are not quarantined today, but an app bundle
    /// that opts into LSFileQuarantineEnabled would tag them, and Gatekeeper
    /// refuses to run an ad-hoc signed CLI carrying the attribute. It is only
    /// removed after the checksum and signature checks above have passed.
    fn clear_quarantine(path: &Path) -> Result<()> {
        use std::os::unix::ffi::OsStrExt;
        let path = std::ffi::CString::new(path.as_os_str().as_bytes())?;
        // SAFETY: both arguments are NUL-terminated strings that outlive the
        // call; removexattr does not retain either pointer.
        let result = unsafe {
            libc::removexattr(
                path.as_ptr(),
                c"com.apple.quarantine".as_ptr(),
                libc::XATTR_NOFOLLOW,
            )
        };
        if result == -1 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::ENOATTR) {
                return Err(error).context("Cannot clear the download's quarantine attribute");
            }
        }
        Ok(())
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn tags_match_the_ci_release_pattern() {
        for tag in ["v0.0.24", "v1.2.3-rc.1", "v10.20.30+build_7", "v1.2.3-a-b"] {
            assert!(valid_tag(tag), "{tag}");
        }
        for tag in [
            "",
            "dev",
            "0.0.24",
            "v1.2",
            "v1.2.3.4",
            "v1..3",
            "v1.2.3-",
            "v1.2.3+",
            "v1.2.3-a+b",
            "v1.2.3/../x",
            "v1.2.3 ",
            "vx.2.3",
            "v1.2.3-ü",
        ] {
            assert!(!valid_tag(tag), "{tag}");
        }
    }

    #[test]
    fn only_tagged_builds_on_unix_hosts_that_run_managers_offer_an_install() {
        let destination = Path::new("/home/test/.gantry/bin/gantry");
        assert_eq!(managed_path(Path::new("/home/test/.gantry")), destination);
        assert_eq!(
            offer_for(Some("v0.0.24"), "linux", "x86_64", Some(destination)),
            Some(Offer {
                release: "v0.0.24",
                asset: "gantry-linux-amd64",
                destination: destination.into(),
            })
        );
        for (os, arch, asset) in [
            ("linux", "aarch64", "gantry-linux-arm64"),
            ("macos", "aarch64", "gantry-darwin-arm64"),
        ] {
            assert_eq!(
                offer_for(Some("v0.0.24"), os, arch, Some(destination))
                    .unwrap()
                    .asset,
                asset
            );
        }
        for (release, os, arch, destination) in [
            (None, "linux", "x86_64", Some(destination)),
            (Some(""), "linux", "x86_64", Some(destination)),
            (Some("dev"), "linux", "x86_64", Some(destination)),
            (Some("v0.0.24"), "windows", "x86_64", Some(destination)),
            (Some("v0.0.24"), "macos", "x86_64", Some(destination)),
            (Some("v0.0.24"), "linux", "x86_64", None),
        ] {
            assert!(offer_for(release, os, arch, destination).is_none());
        }
    }

    #[test]
    fn checksum_sidecars_must_describe_the_requested_asset() {
        let digest = "ab".repeat(32);
        let asset = "gantry-linux-amd64";
        for body in [
            format!("{digest}  {asset}\n"),
            format!("{digest} *{asset}"),
            format!("{}\n", digest.to_uppercase()),
        ] {
            assert_eq!(parse_checksum(body.as_bytes(), asset).unwrap(), [0xab; 32]);
        }
        for body in [
            String::new(),
            format!("{digest}  gantry-linux-arm64"),
            format!("{digest}  {asset}  extra"),
            digest[..62].to_owned(),
            format!("{}+1", &digest[..62]),
            format!("{}zz", &digest[..62]),
        ] {
            assert!(parse_checksum(body.as_bytes(), asset).is_err(), "{body}");
        }
    }

    #[test]
    fn redirects_stay_on_github_release_hosts() {
        for url in [
            "https://github.com/ejpir/gantry/releases/download/v1.2.3/gantry-linux-amd64",
            "https://objects.githubusercontent.com/github-production-release-asset/1",
            "https://release-assets.githubusercontent.com/github-production-release-asset/1",
        ] {
            assert!(github_host(&url.parse().unwrap()), "{url}");
        }
        for url in [
            "http://github.com/x",
            "https://github.com:8443/x",
            "https://user@github.com/x",
            "https://evilgithub.com/x",
            "https://github.com.evil.example/x",
            "https://githubusercontent.com.evil.example/x",
            "https://evil.example/objects.githubusercontent.com",
        ] {
            assert!(!github_host(&url.parse().unwrap()), "{url}");
        }
    }

    pub(super) fn elf(machine: u16) -> Vec<u8> {
        let mut header = vec![0; 64];
        header[..4].copy_from_slice(b"\x7fELF");
        header[4] = 2;
        header[5] = 1;
        header[18..20].copy_from_slice(&machine.to_le_bytes());
        header
    }

    #[test]
    fn executables_must_match_the_host_platform() {
        assert!(check_header(&elf(62), "linux", "x86_64").is_ok());
        assert!(check_header(&elf(183), "linux", "aarch64").is_ok());
        assert!(check_header(&elf(183), "linux", "x86_64").is_err());
        let mut big_endian = elf(62);
        big_endian[5] = 2;
        assert!(check_header(&big_endian, "linux", "x86_64").is_err());
        assert!(check_header(&elf(62)[..12], "linux", "x86_64").is_err());
        assert!(check_header(b"#!/bin/sh\nexit 0\n", "linux", "x86_64").is_err());
        let mut macho = 0xfeed_facf_u32.to_le_bytes().to_vec();
        macho.extend(0x0100_000c_u32.to_le_bytes());
        assert!(check_header(&macho, "macos", "aarch64").is_ok());
        assert!(check_header(&macho, "macos", "x86_64").is_err());
        assert!(check_header(&elf(183), "macos", "aarch64").is_err());
        assert!(check_header(&macho, "windows", "x86_64").is_err());
    }

    #[test]
    fn macos_downloads_require_the_hypervisor_entitlement() {
        assert!(hypervisor_entitled(
            b"<plist><dict><key>com.apple.security.hypervisor</key>\n\t<true/></dict></plist>"
        ));
        assert!(hypervisor_entitled(
            b"<key>a</key><true/><key> com.apple.security.hypervisor </key> <true />"
        ));
        assert!(!hypervisor_entitled(
            b"<key>com.apple.security.hypervisor</key><false/>"
        ));
        assert!(!hypervisor_entitled(
            b"<key>com.apple.security.network.client</key><true/>"
        ));
        assert!(!hypervisor_entitled(
            b"com.apple.security.hypervisor <true/>"
        ));
    }
}

/// End to end against a local HTTPS release server. Linux only: macOS would
/// also (correctly) require a real code signature on the fake executable.
#[cfg(all(test, target_os = "linux"))]
mod install_tests {
    use super::*;
    use rustls::{ServerConfig, ServerConnection, StreamOwned, pki_types::PrivatePkcs8KeyDer};
    use std::{
        cell::RefCell,
        net::TcpListener,
        os::unix::fs::PermissionsExt,
        sync::{
            Arc, Mutex,
            atomic::{AtomicBool, Ordering},
        },
        thread,
        time::Instant,
    };

    const RELEASE: &str = "v1.2.3";

    struct Route {
        path: String,
        status: u16,
        location: Option<String>,
        body: Vec<u8>,
    }

    fn route(path: &str, status: u16, body: impl Into<Vec<u8>>) -> Route {
        Route {
            path: path.into(),
            status,
            location: None,
            body: body.into(),
        }
    }

    struct Server {
        port: u16,
        tls: rustls::ClientConfig,
        requests: Arc<Mutex<Vec<String>>>,
        done: Arc<AtomicBool>,
        task: Option<thread::JoinHandle<()>>,
    }

    impl Server {
        fn start(routes: impl FnOnce(u16) -> Vec<Route>) -> Self {
            let key = rcgen::KeyPair::generate().unwrap();
            let cert = rcgen::CertificateParams::new(vec!["localhost".into()])
                .unwrap()
                .self_signed(&key)
                .unwrap();
            let provider = Arc::new(rustls::crypto::ring::default_provider());
            let server = Arc::new(
                ServerConfig::builder_with_provider(provider.clone())
                    .with_safe_default_protocol_versions()
                    .unwrap()
                    .with_no_client_auth()
                    .with_single_cert(
                        vec![cert.der().clone()],
                        PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
                    )
                    .unwrap(),
            );
            let mut roots = rustls::RootCertStore::empty();
            roots.add(cert.der().clone()).unwrap();
            let tls = rustls::ClientConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(roots)
                .with_no_client_auth();
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            listener.set_nonblocking(true).unwrap();
            let port = listener.local_addr().unwrap().port();
            let routes = routes(port);
            let requests = Arc::new(Mutex::new(Vec::new()));
            let done = Arc::new(AtomicBool::new(false));
            let (seen, stop) = (requests.clone(), done.clone());
            let task = thread::spawn(move || {
                let deadline = Instant::now() + Duration::from_secs(20);
                while !stop.load(Ordering::SeqCst) && Instant::now() < deadline {
                    let socket = match listener.accept() {
                        Ok((socket, _)) => socket,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(5));
                            continue;
                        }
                        Err(error) => panic!("release test listener: {error}"),
                    };
                    socket.set_nonblocking(false).unwrap();
                    socket
                        .set_read_timeout(Some(Duration::from_secs(2)))
                        .unwrap();
                    let mut stream =
                        StreamOwned::new(ServerConnection::new(server.clone()).unwrap(), socket);
                    let mut header = Vec::new();
                    while !header.ends_with(b"\r\n\r\n") && header.len() < 8192 {
                        let mut byte = [0];
                        if stream.read_exact(&mut byte).is_err() {
                            break;
                        }
                        header.push(byte[0]);
                    }
                    let header = String::from_utf8_lossy(&header);
                    let Some(path) = header
                        .strip_prefix("GET ")
                        .and_then(|r| r.split(' ').next())
                    else {
                        continue; // rejected handshake or no request
                    };
                    seen.lock().unwrap().push(path.to_owned());
                    let reply = routes.iter().find(|route| route.path == path);
                    let (status, location, body) = match reply {
                        Some(route) => (route.status, route.location.clone(), &route.body[..]),
                        None => (404, None, &b"missing"[..]),
                    };
                    let location = location
                        .map(|location| format!("Location: {location}\r\n"))
                        .unwrap_or_default();
                    let _ = stream.write_all(
                        format!(
                            "HTTP/1.1 {status} Test\r\nContent-Length: {}\r\n{location}Connection: close\r\n\r\n",
                            body.len()
                        )
                        .as_bytes(),
                    );
                    let _ = stream.write_all(body);
                    let _ = stream.flush();
                    stream.conn.send_close_notify();
                    let _ = stream.flush();
                }
            });
            Self {
                port,
                tls,
                requests,
                done,
                task: Some(task),
            }
        }

        fn channel(&self) -> Channel {
            Channel {
                base: format!("https://localhost:{}", self.port),
                tls: self.tls.clone(),
                trusted: |url| url.scheme() == "https" && url.host_str() == Some("localhost"),
                system_proxy: false,
            }
        }

        fn finish(mut self) -> Vec<String> {
            self.done.store(true, Ordering::SeqCst);
            self.task.take().unwrap().join().unwrap();
            std::mem::take(&mut self.requests.lock().unwrap())
        }
    }

    fn asset() -> &'static str {
        platform_asset(std::env::consts::OS, std::env::consts::ARCH).unwrap()
    }

    fn binary() -> Vec<u8> {
        let machine = if cfg!(target_arch = "aarch64") {
            183
        } else {
            62
        };
        let mut binary = super::tests::elf(machine);
        binary.resize(300_000, 0x5a);
        binary
    }

    fn sidecar(bytes: &[u8]) -> String {
        let digest = Sha256::digest(bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        format!("{digest}  {}\n", asset())
    }

    fn root() -> (tempfile::TempDir, Offer) {
        let dir = tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap();
        let offer = Offer {
            release: RELEASE,
            asset: asset(),
            destination: managed_path(dir.path()),
        };
        (dir, offer)
    }

    fn entries(directory: &Path) -> Vec<String> {
        let mut names = std::fs::read_dir(directory)
            .map(|entries| {
                entries
                    .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        names.sort();
        names
    }

    #[test]
    fn installs_a_verified_private_executable_through_a_release_redirect() {
        let binary = binary();
        let server = Server::start(|port| {
            vec![
                route(
                    &format!("/{RELEASE}/{}.sha256", asset()),
                    200,
                    sidecar(&binary),
                ),
                Route {
                    location: Some(format!("https://localhost:{port}/cdn/{}", asset())),
                    ..route(&format!("/{RELEASE}/{}", asset()), 302, "")
                },
                route(&format!("/cdn/{}", asset()), 200, binary.clone()),
            ]
        });
        let (dir, offer) = root();
        let messages = RefCell::new(Vec::new());
        install_from(&server.channel(), &offer, &|message| {
            messages.borrow_mut().push(message.to_owned())
        })
        .unwrap();
        assert_eq!(server.finish().len(), 3);
        assert_eq!(std::fs::read(&offer.destination).unwrap(), binary);
        let mode = |path: &Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode(&offer.destination), 0o700);
        assert_eq!(mode(&dir.path().join("bin")), 0o700);
        assert_eq!(entries(&dir.path().join("bin")), ["gantry"]);
        let messages = messages.into_inner();
        assert!(
            messages.iter().any(|m| m.ends_with("· 100%")),
            "{messages:?}"
        );
        assert!(messages.last().unwrap().starts_with("Verified"));
    }

    #[test]
    fn checksum_mismatches_install_nothing() {
        let binary = binary();
        let server = Server::start(|_| {
            vec![
                route(
                    &format!("/{RELEASE}/{}.sha256", asset()),
                    200,
                    sidecar(b"other"),
                ),
                route(&format!("/{RELEASE}/{}", asset()), 200, binary.clone()),
            ]
        });
        let (dir, offer) = root();
        let error = install_from(&server.channel(), &offer, &|_| {}).unwrap_err();
        assert!(format!("{error:#}").contains("SHA-256"), "{error:#}");
        server.finish();
        assert!(!offer.destination.exists());
        assert!(entries(&dir.path().join("bin")).is_empty());
    }

    #[test]
    fn a_wrong_platform_executable_installs_nothing() {
        let mut binary = binary();
        binary[18..20].copy_from_slice(
            &(if cfg!(target_arch = "aarch64") {
                62u16
            } else {
                183
            })
            .to_le_bytes(),
        );
        let server = Server::start(|_| {
            vec![
                route(
                    &format!("/{RELEASE}/{}.sha256", asset()),
                    200,
                    sidecar(&binary),
                ),
                route(&format!("/{RELEASE}/{}", asset()), 200, binary.clone()),
            ]
        });
        let (dir, offer) = root();
        let error = install_from(&server.channel(), &offer, &|_| {}).unwrap_err();
        assert!(error.to_string().contains("architecture"), "{error:#}");
        server.finish();
        assert!(entries(&dir.path().join("bin")).is_empty());
    }

    #[test]
    fn untrusted_redirects_and_missing_assets_are_refused() {
        let binary = binary();
        let server = Server::start(|port| {
            vec![
                route(
                    &format!("/{RELEASE}/{}.sha256", asset()),
                    200,
                    sidecar(&binary),
                ),
                Route {
                    // Same server, but not a trusted release host name.
                    location: Some(format!("https://127.0.0.1:{port}/cdn/{}", asset())),
                    ..route(&format!("/{RELEASE}/{}", asset()), 302, "")
                },
                route(&format!("/cdn/{}", asset()), 200, binary.clone()),
            ]
        });
        let (dir, offer) = root();
        let error = install_from(&server.channel(), &offer, &|_| {}).unwrap_err();
        assert!(
            format!("{error:#}").contains("redirected outside"),
            "{error:#}"
        );
        let missing = Offer {
            release: "v9.9.9",
            ..offer.clone()
        };
        let error = install_from(&server.channel(), &missing, &|_| {}).unwrap_err();
        assert!(error.to_string().contains("does not publish"), "{error:#}");
        let requests = server.finish();
        assert!(
            !requests.iter().any(|path| path.starts_with("/cdn/")),
            "{requests:?}"
        );
        assert!(
            !requests
                .iter()
                .any(|path| path == &format!("/v9.9.9/{}", asset()))
        );
        assert!(entries(&dir.path().join("bin")).is_empty());
    }

    #[test]
    fn a_shared_gantry_root_is_refused_before_any_download() {
        let server = Server::start(|_| vec![]);
        let (dir, offer) = root();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        let error = install_from(&server.channel(), &offer, &|_| {}).unwrap_err();
        assert!(
            error.to_string().contains("unsafe permissions"),
            "{error:#}"
        );
        assert!(server.finish().is_empty());
        assert!(!offer.destination.exists());
    }
}
