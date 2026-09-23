#![cfg(unix)]
use gantry_desktop::{
    api::ManagerClient,
    commands::Command,
    connector::{Connector, Target},
    dashboard_wire::*,
    options::{Appearance, Options, Source},
    profiles::RemoteProfile,
    wire::SecretInput,
};
use rustls::{ServerConfig, ServerConnection, StreamOwned, pki_types::PrivatePkcs8KeyDer};
use serde_json::{Value, json};
use std::{
    io::{Read, Write},
    net::TcpListener,
    os::unix::{fs::PermissionsExt, net::UnixListener},
    sync::Arc,
    thread,
    time::{Duration, Instant},
};

const BEARER: &str = "synthetic-manager-bearer-credential";
struct Call {
    method: &'static str,
    path: &'static str,
    body: Value,
    status: u16,
    reply: Option<Value>,
}
trait Stream: Read + Write {}
impl<T: Read + Write> Stream for T {}
enum Listener {
    Unix(UnixListener),
    Tls(TcpListener, Arc<ServerConfig>),
}
struct Server {
    client: ManagerClient,
    task: thread::JoinHandle<()>,
    _dir: tempfile::TempDir,
}
impl Server {
    fn new(tls: bool, mut calls: Vec<Call>) -> Self {
        if !calls.first().is_some_and(|call| call.path == "/v1/health") {
            calls.insert(
                0,
                Call {
                    method: "GET",
                    path: "/v1/health",
                    body: Value::Null,
                    status: 200,
                    reply: Some(
                        json!({"ok":true,"version":"v1","capabilities":["dashboard-control-v1"]}),
                    ),
                },
            );
        }
        Self::exact(tls, calls)
    }
    /// Serve exactly these calls, with no leading health check.
    fn exact(tls: bool, calls: Vec<Call>) -> Self {
        let dir = tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap();
        let (listener, client) = if tls {
            let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
            let config = ServerConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.cert.der().clone()],
                PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()).into(),
            )
            .unwrap();
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            listener.set_nonblocking(true).unwrap();
            let profile = RemoteProfile {
                name: "fixture".into(),
                url: format!(
                    "https://localhost:{}",
                    listener.local_addr().unwrap().port()
                ),
                ca_cert: cert.cert.pem(),
                fingerprint: String::new(),
            };
            (
                Listener::Tls(listener, Arc::new(config)),
                ManagerClient::remote(&profile, BEARER).unwrap(),
            )
        } else {
            let path = dir.path().join("manager.sock");
            let listener = UnixListener::bind(&path).unwrap();
            listener.set_nonblocking(true).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
            (
                Listener::Unix(listener),
                ManagerClient::local(&path).unwrap(),
            )
        };
        let task = thread::spawn(move || {
            for call in calls {
                let deadline = Instant::now() + Duration::from_secs(5);
                let mut stream: Box<dyn Stream> = loop {
                    let accepted: std::io::Result<Box<dyn Stream>> = match &listener {
                        Listener::Unix(l) => l.accept().map(|(s, _)| {
                            s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
                            Box::new(s) as Box<dyn Stream>
                        }),
                        Listener::Tls(l, config) => l.accept().map(|(s, _)| {
                            s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
                            Box::new(StreamOwned::new(
                                ServerConnection::new(config.clone()).unwrap(),
                                s,
                            )) as Box<dyn Stream>
                        }),
                    };
                    match accepted {
                        Ok(s) => break s,
                        Err(e)
                            if e.kind() == std::io::ErrorKind::WouldBlock
                                && Instant::now() < deadline =>
                        {
                            thread::sleep(Duration::from_millis(5))
                        }
                        Err(e) => panic!("fixture listener: {e}"),
                    }
                };
                let mut header = Vec::new();
                while !header.ends_with(b"\r\n\r\n") {
                    let mut b = [0];
                    stream.read_exact(&mut b).unwrap();
                    header.push(b[0]);
                    assert!(header.len() < 16384);
                }
                let header = String::from_utf8(header).unwrap();
                assert!(header.starts_with(&format!("{} {} HTTP/1.1\r\n", call.method, call.path)));
                let lower = header.to_ascii_lowercase();
                assert_eq!(lower.contains("authorization: bearer"), tls);
                if tls {
                    assert!(header.contains(BEARER));
                }
                let length = lower
                    .lines()
                    .find_map(|line| line.strip_prefix("content-length:"))
                    .map(|n| n.trim().parse::<usize>().unwrap())
                    .unwrap_or(0);
                assert!(length <= 1024 * 1024);
                let mut body = vec![0; length];
                stream.read_exact(&mut body).unwrap();
                let body = if body.is_empty() {
                    Value::Null
                } else {
                    serde_json::from_slice(&body).unwrap()
                };
                assert_eq!(body, call.body);
                if let Some(reply) = call.reply {
                    let body = serde_json::to_string(&reply).unwrap();
                    let response = format!(
                        "HTTP/1.1 {} Test\r\nContent-Length: {}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{}",
                        call.status,
                        body.len(),
                        body
                    );
                    stream.write_all(response.as_bytes()).unwrap();
                    stream.flush().unwrap();
                }
            }
            // No write may be automatically replayed after the scripted reply
            // or an ambiguous disconnect. Keep listening briefly to catch it.
            let deadline = Instant::now() + Duration::from_millis(120);
            while Instant::now() < deadline {
                let extra = match &listener {
                    Listener::Unix(l) => l.accept().is_ok(),
                    Listener::Tls(l, _) => l.accept().is_ok(),
                };
                assert!(!extra, "unexpected retry or extra mutation");
                thread::sleep(Duration::from_millis(5));
            }
        });
        Self {
            client,
            task,
            _dir: dir,
        }
    }
    fn finish(self) {
        self.task.join().unwrap();
    }
}
#[test]
fn live_packet_reads_follow_the_cursor_without_a_control_check() {
    use gantry_desktop::capture;
    let packet = |sequence: u64| {
        json!({"sequence":sequence,"timestamp":"2026-09-23T08:00:00Z","direction":"tx",
               "allowed":true,"length":60,"data":"AAEC"})
    };
    for tls in [false, true] {
        let server = Server::exact(
            tls,
            vec![
                Call {
                    method: "POST",
                    path: "/v1/dashboard/packets/dev",
                    body: json!({"max_packets":256,"max_bytes":262144}),
                    status: 200,
                    reply: Some(
                        json!({"active":true,"packets":[packet(1),packet(2)],"next":2,"latest":3}),
                    ),
                },
                Call {
                    method: "POST",
                    path: "/v1/dashboard/packets/dev",
                    body: json!({"after":2,"max_packets":256,"max_bytes":262144}),
                    status: 200,
                    reply: Some(json!({"active":true,"packets":[packet(3)],"next":3,"latest":3})),
                },
            ],
        );
        let mut held = server.client.read_packets("dev", 0).unwrap();
        assert!(capture::behind(&held));
        let after = held.next;
        let read = server.client.read_packets("dev", after).unwrap();
        capture::merge(&mut held, read, after);
        let sequences: Vec<u64> = held.packets.iter().map(|p| p.sequence).collect();
        assert_eq!(sequences, [1, 2, 3]);
        assert!(held.active && !capture::behind(&held));
        server.finish();
    }
}
#[test]
fn configure_and_operation_progress_have_identical_unix_and_tls_semantics() {
    for tls in [false, true] {
        let server = Server::new(
            tls,
            vec![Call {
                method: "PATCH",
                path: "/v1/sandboxes/dev",
                body: json!({"memoryMiB":1024,"cpus":2,"processIsolation":"auto","ssh":false,"devContainers":false}),
                status: 200,
                reply: Some(
                    json!({"id":"op-1","state":"succeeded","configure":{"restartRequired":true}}),
                ),
            }],
        );
        let outcome = server
            .client
            .execute(&Command::Configure(SandboxConfigRequest {
                name: "dev".into(),
                mem_mb: 1024,
                vcpus: 2,
                process_isolation: "auto".into(),
                ssh: false,
                dev_containers: false,
            }))
            .unwrap();
        assert!(outcome.message.contains("Restart required"));
        server.finish();
        let server = Server::new(
            tls,
            vec![
                Call {
                    method: "POST",
                    path: "/v1/images/pull",
                    body: json!({"ref":"example:cached"}),
                    status: 202,
                    reply: Some(
                        json!({"id":"op-2","state":"running","progress":"Downloading test layer"}),
                    ),
                },
                Call {
                    method: "GET",
                    path: "/v1/operations/op-2",
                    body: Value::Null,
                    status: 200,
                    reply: Some(json!({"id":"op-2","state":"succeeded"})),
                },
            ],
        );
        let progress = std::sync::Mutex::new(Vec::new());
        server
            .client
            .execute_with_progress(&Command::PullImage("example:cached".into()), |s| {
                progress.lock().unwrap().push(s.to_owned())
            })
            .unwrap();
        assert!(
            progress
                .lock()
                .unwrap()
                .iter()
                .any(|s| s.contains("Downloading test layer"))
        );
        server.finish();
    }
}
#[test]
fn secret_requests_are_write_only_even_when_errors_reflect_encoded_values() {
    for tls in [false, true] {
        let server = Server::new(
            tls,
            vec![Call {
                method: "POST",
                path: "/v1/dashboard/actions",
                body: json!({"action":"add-secret","secret":{"Sandbox":"dev","Name":"TOKEN","Value":"private\nvalue"}}),
                status: 400,
                reply: Some(json!({"error":format!("private\\nvalue + {BEARER}")})),
            }],
        );
        let command = Command::Dashboard(Box::new(ActionRequest {
            action: "add-secret".into(),
            secret: Some(SecretRequest {
                sandbox: "dev".into(),
                name: "TOKEN".into(),
                value: SecretInput::new("private\nvalue".into()),
            }),
            ..Default::default()
        }));
        let error = server.client.execute(&command).unwrap_err();
        assert!(!format!("{error:#}").contains("private"));
        assert!(!format!("{error:#}").contains(BEARER));
        server.finish();
    }
}
#[test]
fn disconnect_after_a_write_is_reported_as_unknown_and_never_replayed() {
    for tls in [false, true] {
        let server = Server::new(
            tls,
            vec![Call {
                method: "POST",
                path: "/v1/sandboxes/dev/start",
                body: Value::Null,
                status: 200,
                reply: None,
            }],
        );
        let error = server
            .client
            .execute(&Command::Start("dev".into()))
            .unwrap_err();
        assert!(error.to_string().contains("outcome unknown"));
        server.finish();
    }
}
#[test]
fn share_plans_cannot_retarget_the_following_write() {
    let request = ShareRequest {
        sandbox: "dev".into(),
        tag: "src".into(),
        path: "/private/workspace".into(),
        read_only: true,
        ..Default::default()
    };
    let server = Server::new(
        false,
        vec![Call {
            method: "POST",
            path: "/v1/dashboard/actions",
            body: serde_json::to_value(ActionRequest {
                action: "plan-share".into(),
                share: Some(request.clone()),
                ..Default::default()
            })
            .unwrap(),
            status: 200,
            reply: Some(
                json!({"sharePlan":{"Sandbox":"other","Tag":"src","Spec":"src=/private/workspace"}}),
            ),
        }],
    );
    assert!(
        server
            .client
            .execute(&Command::Share(request))
            .unwrap_err()
            .to_string()
            .contains("different share target")
    );
    server.finish();
}
#[test]
fn replaced_remote_profile_invalidates_an_open_action_before_any_connection() {
    let dir = tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()
        .unwrap();
    let tokens = dir.path().join("remotes");
    std::fs::create_dir(&tokens).unwrap();
    std::fs::set_permissions(&tokens, std::fs::Permissions::from_mode(0o700)).unwrap();
    for (path, content) in [
        (
            "remotes.json",
            r#"{"remotes":[{"name":"team","url":"https://new.example"}]}"#,
        ),
        ("remotes/store.lock", ""),
        ("remotes/team.token", BEARER),
    ] {
        let path = dir.path().join(path);
        std::fs::write(&path, content).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let source = Source::Remote {
        name: "team".into(),
        config_dir: dir.path().into(),
    };
    let options = Options {
        source: source.clone(),
        appearance: Appearance::System,
        auto_start: false,
        gantry: None,
        managed_gantry: None,
    };
    let target = Target {
        source,
        profile: Some(RemoteProfile {
            name: "team".into(),
            url: "https://old.example".into(),
            ca_cert: String::new(),
            fingerprint: String::new(),
        }),
    };
    let error = Connector::new(&options)
        .execute(&target, &Command::Delete("dev".into()))
        .unwrap_err();
    assert!(error.to_string().contains("connection changed"));
}
