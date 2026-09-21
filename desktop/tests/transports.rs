use gantry_desktop::{api::ManagerClient, profiles::RemoteProfile};
use rustls::{ServerConfig, ServerConnection, StreamOwned, pki_types::PrivatePkcs8KeyDer};
use sha2::{Digest, Sha256};
use std::{
    io::{Read, Write},
    net::TcpListener,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

const TOKEN: &str = "test-bearer-never-log-this-value";

fn response(status: u16, body: &str) -> String {
    format!(
        "HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nLocation: http://127.0.0.1:9/\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

fn inventory_responses() -> Vec<String> {
    vec![
        response(200, r#"{"ok":true,"version":"v1"}"#),
        response(
            200,
            &format!(
                "{{\"sandboxes\":{}}}",
                include_str!("../fixtures/sandboxes.json")
            ),
        ),
    ]
}

fn exchange(
    mut stream: impl Read + Write,
    reply: &str,
    index: usize,
    authenticated: bool,
    requests: &AtomicUsize,
) {
    let mut header = Vec::new();
    while !header.ends_with(b"\r\n\r\n") {
        let mut byte = [0];
        if stream.read_exact(&mut byte).is_err() {
            return;
        } // rejected TLS handshake
        header.push(byte[0]);
        assert!(header.len() <= 8192);
    }
    requests.fetch_add(1, Ordering::SeqCst);
    let header = String::from_utf8(header).unwrap();
    let path = if index == 0 {
        "/v1/health"
    } else {
        "/v1/sandboxes"
    };
    assert!(header.starts_with(&format!("GET {path} HTTP/1.1\r\n")));
    let authorization = header
        .lines()
        .find(|line| line.to_ascii_lowercase().starts_with("authorization:"));
    if authenticated {
        assert_eq!(
            authorization.unwrap().split_once(':').unwrap().1.trim(),
            format!("Bearer {TOKEN}")
        );
    } else {
        assert!(authorization.is_none());
    }
    let _ = stream.write_all(reply.as_bytes());
    let _ = stream.flush();
}

fn conformance(client: ManagerClient) {
    let snapshot = client.snapshot().unwrap();
    assert_eq!(snapshot.version, "v1");
    assert_eq!(snapshot.sandboxes.len(), 4);
    let dev = snapshot
        .sandboxes
        .iter()
        .find(|row| row.name == "dev")
        .unwrap();
    assert!(dev.restart_required);
    assert_eq!(dev.desired.memory_mib, 4096);
    assert_eq!(dev.displayed_resources().unwrap().memory_mib, 2048);
}

struct TlsManager {
    profile: RemoteProfile,
    task: JoinHandle<()>,
    requests: Arc<AtomicUsize>,
}

impl TlsManager {
    fn new(responses: Vec<String>, expired: bool) -> Self {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap();
        if expired {
            params.not_before = rcgen::date_time_ymd(1999, 1, 1);
            params.not_after = rcgen::date_time_ymd(2000, 1, 1);
        }
        let cert = params.self_signed(&key).unwrap();
        let config =
            ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(
                    vec![cert.der().clone()],
                    PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
                )
                .unwrap();
        let config = Arc::new(config);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let profile = RemoteProfile {
            name: "test".into(),
            url: format!(
                "https://localhost:{}",
                listener.local_addr().unwrap().port()
            ),
            ca_cert: cert.pem(),
            fingerprint: format!("sha256:{:x}", Sha256::digest(cert.der().as_ref())),
        };
        let requests = Arc::new(AtomicUsize::new(0));
        let count = requests.clone();
        let task = thread::spawn(move || {
            for (index, reply) in responses.into_iter().enumerate() {
                let deadline = Instant::now() + Duration::from_secs(5);
                let socket = loop {
                    match listener.accept() {
                        Ok((socket, _)) => break socket,
                        Err(error)
                            if error.kind() == std::io::ErrorKind::WouldBlock
                                && Instant::now() < deadline =>
                        {
                            thread::sleep(Duration::from_millis(5))
                        }
                        Err(error) => panic!("TLS test listener: {error}"),
                    }
                };
                socket
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                socket
                    .set_write_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let tls = StreamOwned::new(ServerConnection::new(config.clone()).unwrap(), socket);
                exchange(tls, &reply, index, true, &count);
            }
        });
        Self {
            profile,
            task,
            requests,
        }
    }

    fn finish(self) -> usize {
        self.task.join().unwrap();
        self.requests.load(Ordering::SeqCst)
    }
}

#[test]
fn https_uses_the_same_wire_contract_with_verified_ca_and_pin() {
    let server = TlsManager::new(inventory_responses(), false);
    conformance(ManagerClient::remote(&server.profile, TOKEN).unwrap());
    assert_eq!(server.finish(), 2);
}

#[test]
fn https_also_verifies_certificates_without_an_optional_pin() {
    let mut server = TlsManager::new(inventory_responses(), false);
    server.profile.fingerprint.clear();
    conformance(ManagerClient::remote(&server.profile, TOKEN).unwrap());
    assert_eq!(server.finish(), 2);
}

#[cfg(unix)]
#[test]
fn unix_uses_the_same_wire_contract_without_bearer_credentials() {
    use std::os::unix::{fs::PermissionsExt, net::UnixListener};
    let dir = tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()
        .unwrap();
    let path = dir.path().join("manager.sock");
    let listener = UnixListener::bind(&path).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let task = thread::spawn(move || {
        for (index, reply) in inventory_responses().iter().enumerate() {
            let (socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            exchange(socket, reply, index, false, &AtomicUsize::new(0));
        }
    });
    conformance(ManagerClient::local(&path).unwrap());
    task.join().unwrap();
}

#[test]
fn wrong_pin_is_rejected_before_sending_any_http_or_bearer() {
    let mut server = TlsManager::new(vec![response(200, "{}")], false);
    server.profile.fingerprint = format!("sha256:{}", "00".repeat(32));
    let error = ManagerClient::remote(&server.profile, TOKEN)
        .unwrap()
        .snapshot()
        .unwrap_err();
    assert!(!error.to_string().contains(TOKEN));
    assert_eq!(server.finish(), 0);
}

#[test]
fn a_matching_pin_does_not_bypass_hostname_ca_or_expiry_checks() {
    for problem in ["hostname", "ca", "expiry"] {
        let mut server = TlsManager::new(vec![response(200, "{}")], problem == "expiry");
        match problem {
            "hostname" => server.profile.url = server.profile.url.replace("localhost", "127.0.0.1"),
            "ca" => server.profile.ca_cert.clear(),
            _ => {}
        }
        assert!(
            ManagerClient::remote(&server.profile, TOKEN)
                .unwrap()
                .snapshot()
                .is_err(),
            "{problem}"
        );
        assert_eq!(
            server.finish(),
            0,
            "{problem} sent HTTP before verification"
        );
    }
}

#[test]
fn remote_redirects_and_reflected_errors_never_leak_credentials() {
    for status in [302, 403, 500] {
        let server = TlsManager::new(
            vec![response(status, &format!(r#"{{"error":"{TOKEN}"}}"#))],
            false,
        );
        let error = ManagerClient::remote(&server.profile, TOKEN)
            .unwrap()
            .snapshot()
            .unwrap_err();
        assert!(error.to_string().contains(&format!("HTTP {status}")));
        assert!(!format!("{error:#}").contains(TOKEN));
        assert_eq!(server.finish(), 1);
    }
}

#[test]
fn malformed_success_responses_cannot_reflect_bearers_into_error_chains() {
    let server = TlsManager::new(
        vec![response(
            200,
            &format!(r#"{{"ok":"{TOKEN}","version":"v1"}}"#),
        )],
        false,
    );
    let error = ManagerClient::remote(&server.profile, TOKEN)
        .unwrap()
        .snapshot()
        .unwrap_err();
    assert!(error.to_string().contains("Invalid manager response"));
    assert!(!format!("{error:#}").contains(TOKEN));
    assert_eq!(server.finish(), 1);
}

#[cfg(unix)]
#[test]
fn missing_and_refused_sockets_are_distinct_from_protocol_errors() {
    use std::os::unix::{fs::PermissionsExt, net::UnixListener};
    let dir = tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()
        .unwrap();
    let path = dir.path().join("manager.sock");
    let error = gantry_desktop::api::snapshot(&path).unwrap_err();
    assert!(gantry_desktop::api::is_absent(&error));
    let listener = UnixListener::bind(&path).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    drop(listener);
    let error = gantry_desktop::api::snapshot(&path).unwrap_err();
    assert!(gantry_desktop::api::is_absent(&error), "{error:#}");
    std::fs::remove_file(&path).unwrap();
    let listener = UnixListener::bind(&path).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let task = thread::spawn(move || {
        let (socket, _) = listener.accept().unwrap();
        exchange(
            socket,
            &response(200, r#"{"ok":true,"version":"v2"}"#),
            0,
            false,
            &AtomicUsize::new(0),
        );
    });
    let error = gantry_desktop::api::snapshot(&path).unwrap_err();
    assert!(!gantry_desktop::api::is_absent(&error));
    assert!(error.to_string().contains("Unsupported manager API"));
    task.join().unwrap();
}
