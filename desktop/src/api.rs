//! The only manager operations in this preview are GET /v1/health and
//! GET /v1/sandboxes. No CLI subprocesses, state-file reads, or TCP fallback.

use std::path::Path;

use anyhow::Result;
use serde::{Deserialize, Deserializer};

use crate::inventory::Sandbox;

#[derive(Debug)]
pub struct Snapshot {
    pub version: String,
    pub sandboxes: Vec<Sandbox>,
}

#[derive(Deserialize)]
struct Health {
    ok: bool,
    version: String,
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

/// Blocking and bounded; callers must run this off the GPUI foreground thread.
#[cfg(unix)]
pub fn snapshot(socket: &Path) -> Result<Snapshot> {
    use anyhow::{Context, ensure};
    use std::time::Duration;

    let client = reqwest::blocking::Client::builder()
        .unix_socket(socket)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .http1_only()
        .connect_timeout(Duration::from_secs(2))
        .timeout(Duration::from_secs(5))
        .build()
        .context("Could not initialize the local manager client")?;

    let health: Health = get_json(&client, "/v1/health")?;
    ensure!(health.ok, "The manager reports that it is not ready");
    let list: SandboxList = get_json(&client, "/v1/sandboxes")?;
    Ok(Snapshot {
        version: health.version,
        sandboxes: list.sandboxes,
    })
}

#[cfg(not(unix))]
pub fn snapshot(_: &Path) -> Result<Snapshot> {
    anyhow::bail!(
        "Local socket connections currently require Linux or macOS. Use --demo to preview the UI on this platform."
    )
}

#[cfg(unix)]
fn get_json<T: serde::de::DeserializeOwned>(
    client: &reqwest::blocking::Client,
    route: &str,
) -> Result<T> {
    use anyhow::{Context, bail, ensure};
    use std::io::Read;

    const MAX_RESPONSE_BYTES: u64 = 4 * 1024 * 1024;
    let response = client
        .get(format!("http://gantry.local{route}"))
        .header(reqwest::header::ACCEPT, "application/json")
        .send()
        .context("Cannot reach the selected manager socket")?;
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
    serde_json::from_slice(&bytes).with_context(|| format!("Invalid manager response for {route}"))
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
            os::unix::{fs::DirBuilderExt, net::UnixListener},
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
            (
                "/v1/health",
                response(r#"{"ok":true,"version":"test-manager"}"#),
            )
        }

        #[test]
        fn reads_real_wire_format_over_a_private_socket() {
            let body = format!(
                "{{\"sandboxes\":{}}}",
                include_str!("../fixtures/sandboxes.json")
            );
            let manager = MockManager::new(vec![health(), ("/v1/sandboxes", response(&body))]);
            let result = snapshot(&manager.path).unwrap();
            assert_eq!(result.version, "test-manager");
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
