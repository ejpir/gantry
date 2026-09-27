//! One manager wire client over a private Unix socket or verified HTTPS.
//! Endpoint selection never changes request/response semantics. Startup and
//! credential-file handling live outside the protocol client.

use std::path::Path;

use anyhow::Result;
use serde::{Deserialize, Deserializer};

use crate::inventory::Sandbox;

#[derive(Debug)]
pub struct Snapshot {
    pub version: String,
    pub sandboxes: Vec<Sandbox>,
    pub capabilities: Vec<String>,
}

#[derive(Deserialize)]
struct Health {
    ok: bool,
    version: String,
    #[serde(default)]
    capabilities: Vec<String>,
}

#[derive(Deserialize)]
struct SandboxList {
    // Go can encode a nil slice as null. A missing field, however, is a
    // malformed response, not a successful empty inventory.
    #[serde(deserialize_with = "null_sandboxes")]
    sandboxes: Vec<Sandbox>,
}

fn null_sandboxes<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<Sandbox>, D::Error> {
    Ok(Option::<Vec<Sandbox>>::deserialize(deserializer)?.unwrap_or_default())
}

pub struct ManagerClient {
    http: reqwest::blocking::Client,
    base: String,
    bearer: crate::wire::SecretInput,
}

impl ManagerClient {
    /// Construct on a background thread: the blocking HTTP runtime and TLS
    /// certificate store must never be initialized during GPUI rendering.
    #[cfg(unix)]
    pub fn local(socket: &Path) -> Result<Self> {
        crate::security::local_socket(socket)?;
        Ok(Self {
            http: builder().unix_socket(socket).build()?,
            base: "http://gantry.local".into(),
            bearer: Default::default(),
        })
    }

    #[cfg(not(unix))]
    pub fn local(_: &Path) -> Result<Self> {
        anyhow::bail!("Local socket connections currently require Linux or macOS")
    }

    pub fn remote(profile: &crate::profiles::RemoteProfile, token: &str) -> Result<Self> {
        use reqwest::header::{AUTHORIZATION, HeaderMap, HeaderValue};
        anyhow::ensure!(
            (16..=256).contains(&token.len())
                && token.bytes().all(|ch| (0x21..=0x7e).contains(&ch)),
            "Invalid remote bearer token"
        );
        let tls = crate::tls::configuration(profile)?;
        let mut authorization = HeaderValue::from_str(&format!("Bearer {token}"))?;
        authorization.set_sensitive(true);
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, authorization);
        Ok(Self {
            http: builder()
                .https_only(true)
                .use_preconfigured_tls(tls)
                .default_headers(headers)
                .build()?,
            base: profile.url.trim_end_matches('/').to_owned(),
            bearer: crate::wire::SecretInput::new(token.to_owned()),
        })
    }

    pub(crate) fn require_control(&self) -> Result<()> {
        let health: Health = get_json(self, "/v1/health")?;
        anyhow::ensure!(
            health.ok
                && health.version == "v1"
                && health
                    .capabilities
                    .iter()
                    .any(|c| c == "dashboard-control-v1"),
            "This manager does not advertise safe dashboard control. Upgrade and restart it; no write was sent."
        );
        Ok(())
    }

    pub fn dashboard(&self) -> Result<crate::dashboard_wire::HostSnapshot> {
        self.request::<_, ()>(
            "GET",
            "/v1/dashboard",
            None,
            std::time::Duration::from_secs(15),
            &[],
        )
    }

    pub fn safe_message(&self, message: &str, secrets: &[&str]) -> String {
        let mut text = message.to_owned();
        for secret in std::iter::once(self.bearer.expose())
            .chain(secrets.iter().copied())
            .filter(|s| !s.is_empty())
        {
            text = text.replace(secret, "[redacted]");
        }
        text.chars()
            .filter(|c| !c.is_control())
            .take(1024)
            .collect()
    }

    pub(crate) fn request<T: serde::de::DeserializeOwned, B: serde::Serialize>(
        &self,
        method: &str,
        route: &str,
        body: Option<&B>,
        timeout: std::time::Duration,
        secrets: &[&str],
    ) -> Result<T> {
        use std::io::Read;
        let mut request = self
            .http
            .request(
                reqwest::Method::from_bytes(method.as_bytes())?,
                format!("{}{route}", self.base),
            )
            .timeout(timeout)
            .header(reqwest::header::ACCEPT, "application/json");
        if let Some(body) = body {
            let bytes = serde_json::to_vec(body)?;
            anyhow::ensure!(
                bytes.len() <= 1024 * 1024,
                "Request exceeds the 1 MiB limit"
            );
            request = request
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(bytes);
        }
        let response = request.send().map_err(|_| {
            anyhow::anyhow!(if method == "GET" {
                "Cannot read the selected manager"
            } else {
                "Write outcome unknown. Refresh before retrying; the request was not replayed."
            })
        })?;
        let status = response.status();
        let mut bytes = Vec::new();
        response
            .take(4 * 1024 * 1024 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| {
                anyhow::anyhow!(
                    "Response incomplete. Refresh before retrying a write; it may have completed."
                )
            })?;
        anyhow::ensure!(
            bytes.len() <= 4 * 1024 * 1024,
            "Manager response exceeds the 4 MiB limit"
        );
        if !matches!(status.as_u16(), 200..=202) {
            // Secret-bearing errors are intentionally opaque, including encoded
            // reflections that a substring redactor could not recognize.
            let detail = if !secrets.is_empty() {
                "Secret-bearing request rejected. Check the input and sandbox state.".into()
            } else {
                serde_json::from_slice::<serde_json::Value>(&bytes)
                    .ok()
                    .and_then(|body| {
                        body.get("error")
                            .and_then(|v| v.as_str())
                            .map(str::to_owned)
                    })
                    .unwrap_or_default()
            };
            return Err(ManagerError {
                status: status.as_u16(),
                message: format!(
                    "Manager returned HTTP {status}. {}",
                    self.safe_message(&detail, secrets)
                ),
            }
            .into());
        }
        serde_json::from_slice(&bytes).map_err(|_| {
            anyhow::anyhow!("Invalid manager response; refresh before retrying a write")
        })
    }

    /// The endpoint's API version and capabilities. A policy service answers
    /// with the manager's shape and its own capability.
    pub fn health(&self) -> Result<(String, Vec<String>)> {
        let health: Health = get_json(self, "/v1/health")?;
        anyhow::ensure!(health.ok, "The endpoint reports that it is not ready");
        anyhow::ensure!(
            health.version == "v1",
            "Unsupported API version; the endpoint was not replaced"
        );
        Ok((health.version, health.capabilities))
    }

    /// A bounded non-JSON response, such as a signed bundle.
    pub(crate) fn get_bytes(&self, route: &str, limit: usize) -> Result<Vec<u8>> {
        use std::io::Read;
        let response = self
            .http
            .get(format!("{}{route}", self.base))
            .timeout(std::time::Duration::from_secs(30))
            .send()
            .map_err(|_| anyhow::anyhow!("Cannot read the selected service"))?;
        let status = response.status();
        let mut bytes = Vec::new();
        response
            .take(limit as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| anyhow::anyhow!("Response incomplete"))?;
        anyhow::ensure!(
            bytes.len() <= limit,
            "Response exceeds {} KiB",
            limit / 1024
        );
        if !status.is_success() {
            let detail = serde_json::from_slice::<serde_json::Value>(&bytes)
                .ok()
                .and_then(|body| {
                    body.get("error")
                        .and_then(|v| v.as_str())
                        .map(str::to_owned)
                })
                .unwrap_or_default();
            return Err(ManagerError {
                status: status.as_u16(),
                message: format!(
                    "Service returned HTTP {status}. {}",
                    self.safe_message(&detail, &[])
                ),
            }
            .into());
        }
        Ok(bytes)
    }

    pub fn snapshot(&self) -> Result<Snapshot> {
        let health: Health = get_json(self, "/v1/health")?;
        anyhow::ensure!(health.ok, "The manager reports that it is not ready");
        anyhow::ensure!(
            health.version == "v1",
            "Unsupported manager API version; the endpoint was not replaced"
        );
        self.inventory(health.version, health.capabilities)
    }

    /// The sandbox list, completing a snapshot whose health was just read.
    pub fn inventory(&self, version: String, capabilities: Vec<String>) -> Result<Snapshot> {
        let list: SandboxList = get_json(self, "/v1/sandboxes")?;
        Ok(Snapshot {
            version,
            sandboxes: list.sandboxes,
            capabilities,
        })
    }
}

#[derive(Debug)]
pub struct ManagerError {
    pub status: u16,
    pub message: String,
}
impl std::fmt::Display for ManagerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}
impl std::error::Error for ManagerError {}

fn builder() -> reqwest::blocking::ClientBuilder {
    use std::time::Duration;
    reqwest::blocking::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .http1_only()
        .connect_timeout(Duration::from_secs(2))
        .timeout(Duration::from_secs(5))
}

/// Existing callers can select a socket without invoking any launcher.
pub fn snapshot(socket: &Path) -> Result<Snapshot> {
    ManagerClient::local(socket)?.snapshot()
}

pub fn is_absent(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause.downcast_ref::<std::io::Error>().is_some_and(|error| {
            matches!(
                error.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
            )
        })
    })
}

fn get_json<T: serde::de::DeserializeOwned>(client: &ManagerClient, route: &str) -> Result<T> {
    use anyhow::{Context, bail, ensure};
    use std::io::Read;

    const MAX_RESPONSE_BYTES: u64 = 4 * 1024 * 1024;
    let response = client
        .http
        .get(format!("{}{route}", client.base))
        .header(reqwest::header::ACCEPT, "application/json")
        .send()
        .context(
            "Cannot reach the selected manager; check its availability and TLS trust settings",
        )?;
    let status = response.status();
    let mut bytes = Vec::new();
    response
        .take(MAX_RESPONSE_BYTES + 1)
        .read_to_end(&mut bytes)
        .context("Could not read the manager response")?;
    ensure!(
        bytes.len() as u64 <= MAX_RESPONSE_BYTES,
        "Manager response exceeds the 4 MiB limit"
    );
    if status != reqwest::StatusCode::OK {
        // Do not surface arbitrary response bodies (or redirects) in the UI.
        bail!("Manager returned HTTP {status} for {route}");
    }
    // A hostile server can reflect its bearer into an invalid JSON value.
    // Do not retain serde's value-bearing diagnostic in the error chain.
    serde_json::from_slice(&bytes)
        .map_err(|_| anyhow::anyhow!("Invalid manager response for {route}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_empty_go_slices_but_not_missing_inventory() {
        for json in [r#"{"sandboxes":null}"#, r#"{"sandboxes":[]}"#] {
            assert!(
                serde_json::from_str::<SandboxList>(json)
                    .unwrap()
                    .sandboxes
                    .is_empty()
            );
        }
        assert!(serde_json::from_str::<SandboxList>("{}").is_err());
    }

    #[cfg(unix)]
    mod socket {
        use super::*;
        use std::{
            fs,
            io::{Read, Write},
            os::unix::{
                fs::{DirBuilderExt, PermissionsExt},
                net::UnixListener,
            },
            path::PathBuf,
            sync::atomic::{AtomicUsize, Ordering},
            thread::{self, JoinHandle},
            time::{Duration, Instant},
        };

        struct MockManager {
            dir: PathBuf,
            path: PathBuf,
            task: Option<JoinHandle<()>>,
        }

        impl MockManager {
            fn new(replies: Vec<(&'static str, String)>) -> Self {
                static SEQUENCE: AtomicUsize = AtomicUsize::new(0);
                let dir = std::env::temp_dir().join(format!(
                    "gantry-ui-{}-{}",
                    std::process::id(),
                    SEQUENCE.fetch_add(1, Ordering::Relaxed)
                ));
                fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
                let path = dir.join("manager.sock");
                let listener = UnixListener::bind(&path).unwrap();
                fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
                listener.set_nonblocking(true).unwrap();
                let task = thread::spawn(move || {
                    for (route, reply) in replies {
                        let deadline = Instant::now() + Duration::from_secs(5);
                        let mut stream = loop {
                            match listener.accept() {
                                Ok((stream, _)) => break stream,
                                Err(err)
                                    if err.kind() == std::io::ErrorKind::WouldBlock
                                        && Instant::now() < deadline =>
                                {
                                    thread::sleep(Duration::from_millis(5))
                                }
                                Err(err) => panic!("mock manager did not receive request: {err}"),
                            }
                        };
                        stream
                            .set_read_timeout(Some(Duration::from_secs(2)))
                            .unwrap();
                        stream
                            .set_write_timeout(Some(Duration::from_secs(2)))
                            .unwrap();
                        let mut header = Vec::new();
                        while !header.ends_with(b"\r\n\r\n") {
                            let mut byte = [0];
                            stream.read_exact(&mut byte).unwrap();
                            header.push(byte[0]);
                            assert!(header.len() < 8192);
                        }
                        let header = String::from_utf8(header).unwrap();
                        assert!(
                            header.starts_with(&format!("GET {route} HTTP/1.1\r\n")),
                            "{header}"
                        );
                        assert!(!header.to_ascii_lowercase().contains("authorization:"));
                        // The oversize-response test may close after its byte limit.
                        let _ = stream.write_all(reply.as_bytes());
                    }
                });
                Self {
                    dir,
                    path,
                    task: Some(task),
                }
            }

            fn finish(mut self) {
                self.task.take().unwrap().join().unwrap();
            }
        }

        impl Drop for MockManager {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.dir);
            }
        }

        fn response(body: &str) -> String {
            format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
        }

        fn health() -> (&'static str, String) {
            ("/v1/health", response(r#"{"ok":true,"version":"v1"}"#))
        }

        #[test]
        fn reads_real_wire_format_over_a_private_socket() {
            let body = format!(
                "{{\"sandboxes\":{}}}",
                include_str!("../fixtures/sandboxes.json")
            );
            let manager = MockManager::new(vec![health(), ("/v1/sandboxes", response(&body))]);
            let result = snapshot(&manager.path).unwrap();
            assert_eq!(result.version, "v1");
            assert_eq!(result.sandboxes.len(), 4);
            assert_eq!(result.sandboxes[0].desired.memory_mib, 4096);
            manager.finish();
        }

        #[test]
        fn does_not_follow_redirects_or_fall_back_to_tcp() {
            let manager = MockManager::new(vec![("/v1/health", "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:9/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".into())]);
            let err = snapshot(&manager.path).unwrap_err().to_string();
            assert!(err.contains("HTTP 302"), "{err}");
            manager.finish();
        }

        #[test]
        fn rejects_unhealthy_and_malformed_managers() {
            let manager = MockManager::new(vec![(
                "/v1/health",
                response(r#"{"ok":false,"version":"test"}"#),
            )]);
            assert!(
                snapshot(&manager.path)
                    .unwrap_err()
                    .to_string()
                    .contains("not ready")
            );
            manager.finish();
            let manager = MockManager::new(vec![health(), ("/v1/sandboxes", response("not json"))]);
            assert!(
                snapshot(&manager.path)
                    .unwrap_err()
                    .to_string()
                    .contains("Invalid manager response")
            );
            manager.finish();
        }

        #[test]
        fn bounds_response_size() {
            let manager = MockManager::new(vec![(
                "/v1/health",
                response(&"x".repeat(4 * 1024 * 1024 + 1)),
            )]);
            assert!(
                snapshot(&manager.path)
                    .unwrap_err()
                    .to_string()
                    .contains("4 MiB limit")
            );
            manager.finish();
        }
    }
}
