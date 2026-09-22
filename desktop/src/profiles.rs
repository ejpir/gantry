//! Credential-free metadata uses the existing gantry remote profile format.
//! Tokens are loaded separately and never included in Debug output or UI state.

use anyhow::{Context, Result, bail, ensure};
use serde::Deserialize;
use std::{io::Cursor, path::Path};
use zeroize::Zeroizing;

use crate::security;

#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RemoteProfile {
    pub name: String,
    pub url: String,
    #[serde(default)]
    pub ca_cert: String,
    #[serde(default)]
    pub fingerprint: String,
}

pub struct BearerToken(Zeroizing<String>);

impl BearerToken {
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for BearerToken {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("BearerToken([redacted])")
    }
}

#[derive(Deserialize)]
struct Store {
    #[serde(deserialize_with = "crate::wire::null_vec")]
    remotes: Vec<RemoteProfile>,
}

pub fn validate_name(name: &str) -> Result<()> {
    ensure!(
        !name.is_empty()
            && name.len() <= 64
            && name
                .bytes()
                .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, b'_' | b'-')),
        "Remote name must be a single label of letters, digits, underscores, or hyphens"
    );
    Ok(())
}

impl RemoteProfile {
    pub fn validate(&self) -> Result<()> {
        validate_name(&self.name)?;
        ensure!(
            self.url.len() <= 2048
                && self.url.starts_with("https://")
                && !self
                    .url
                    .chars()
                    .any(|ch| ch.is_whitespace() || ch.is_control() || ch == '\\'),
            "Remote URL must use https://HOST[:PORT]"
        );
        // Check the original path as well: URL parsers normalize /.. to /.
        let authority = self.url.strip_prefix("https://").unwrap_or_default();
        let end = authority.find(['/', '?', '#']).unwrap_or(authority.len());
        ensure!(
            !authority[..end].contains('@') && matches!(&authority[end..], "" | "/"),
            "Remote URL must contain only an HTTPS origin, without credentials, paths, queries, or fragments"
        );
        let url = reqwest::Url::parse(&self.url).context("Invalid remote URL")?;
        ensure!(
            url.host_str().is_some() && url.scheme() == "https",
            "Remote URL has no HTTPS host"
        );
        self.pin()?;
        let mut roots = rustls::RootCertStore::empty();
        for certificate in self.certificates()? {
            roots
                .add(certificate)
                .context("Invalid remote CA certificate")?;
        }
        Ok(())
    }

    pub fn pin(&self) -> Result<Option<[u8; 32]>> {
        if self.fingerprint.is_empty() {
            return Ok(None);
        }
        let Some(hex) = self.fingerprint.strip_prefix("sha256:") else {
            bail!("Remote fingerprint must be sha256:<64 lowercase hex characters>");
        };
        ensure!(
            hex.len() == 64
                && hex
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
            "Remote fingerprint must be sha256:<64 lowercase hex characters>"
        );
        let mut digest = [0; 32];
        for (index, byte) in digest.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16)?;
        }
        Ok(Some(digest))
    }

    pub fn certificates(&self) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>> {
        ensure!(
            self.ca_cert.len() <= 64 * 1024,
            "Remote CA bundle exceeds 64 KiB"
        );
        if self.ca_cert.is_empty() {
            return Ok(Vec::new());
        }
        let mut remaining = self.ca_cert.trim();
        let mut certificates = Vec::new();
        while !remaining.is_empty() {
            ensure!(
                remaining.starts_with("-----BEGIN CERTIFICATE-----"),
                "Remote CA bundle must contain only public PEM certificates"
            );
            let end = remaining
                .find("-----END CERTIFICATE-----")
                .context("Incomplete remote CA certificate")?
                + "-----END CERTIFICATE-----".len();
            let mut cursor = Cursor::new(&remaining.as_bytes()[..end]);
            match rustls_pemfile::read_one(&mut cursor).context("Invalid remote CA certificate")? {
                Some(rustls_pemfile::Item::X509Certificate(cert)) => certificates.push(cert),
                _ => bail!("Invalid remote CA certificate"),
            }
            remaining = remaining[end..].trim();
        }
        ensure!(
            !certificates.is_empty(),
            "Remote CA bundle has no certificates"
        );
        Ok(certificates)
    }
}

/// Read the client-local catalog without loading any bearer values.
pub fn list(base: &Path) -> Result<Vec<RemoteProfile>> {
    match std::fs::symlink_metadata(base.join("remotes.json")) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e.into()),
        Ok(_) => {}
    }
    security::private_directory(base)?;
    let tokens = base.join("remotes");
    security::private_directory(&tokens)?;
    let _lock = crate::profile_lock::acquire(&tokens)?;
    let bytes = security::read_file(&base.join("remotes.json"), 1024 * 1024, false)?;
    let store: Store = serde_json::from_slice(&bytes).context("Invalid remote profile store")?;
    let mut names = std::collections::HashSet::new();
    for profile in &store.remotes {
        profile.validate()?;
        ensure!(names.insert(&profile.name), "Duplicate remote profile name");
    }
    Ok(store.remotes)
}

pub fn load(base: &Path, name: &str) -> Result<(RemoteProfile, BearerToken)> {
    validate_name(name)?;
    security::private_directory(base)?;
    let tokens = base.join("remotes");
    security::private_directory(&tokens)?;
    let _store_lock = crate::profile_lock::acquire(&tokens)?;
    let bytes = security::read_file(&base.join("remotes.json"), 1024 * 1024, false).context(
        "Cannot load remote profiles; configure one with gantry remote add NAME https://HOST:PORT",
    )?;
    let store: Store = serde_json::from_slice(&bytes).context("Invalid remote profile store")?;
    let mut names = std::collections::HashSet::new();
    for profile in &store.remotes {
        profile.validate()?;
        ensure!(
            names.insert(profile.name.as_str()),
            "Duplicate remote profile name"
        );
    }
    let profile = store
        .remotes
        .into_iter()
        .find(|profile| profile.name == name)
        .context("Remote profile not found; configure it with gantry remote add")?;
    let bytes = Zeroizing::new(security::read_file(
        &tokens.join(format!("{name}.token")),
        258,
        true,
    )?);
    let text = std::str::from_utf8(&bytes).context("Remote token is not valid text")?;
    let token = text.trim_end_matches(['\r', '\n']);
    ensure!(
        (16..=256).contains(&token.len()) && token.bytes().all(|ch| (0x21..=0x7e).contains(&ch)),
        "Remote token must contain 16–256 printable ASCII characters without spaces"
    );
    Ok((profile, BearerToken(Zeroizing::new(token.to_owned()))))
}
