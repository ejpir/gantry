//! The desktop against a real `gantry policy-service`: registration through
//! the CLI's profile store, workspace detection, and every administrator
//! write the Organization screens send, including signing with the CLI.
//!
//! Needs a Gantry executable built from this checkout:
//!   GANTRY_TEST_GANTRY=/path/to/gantry cargo test --test org_service
//! Without it the test is skipped. scripts/test-desktop-policy-service.sh
//! builds one and runs this.
#![cfg(unix)]

use gantry_desktop::{
    commands::Command,
    connector::Connector,
    options::{Appearance, Options, Source},
    org::{self, Edit, NetworkRule, OrgCommand, OrgSnapshot, Publish},
};
use std::{
    io::Write,
    net::TcpListener,
    path::{Path, PathBuf},
    process::{Child, Command as Process, Stdio},
    time::{Duration, Instant},
};

struct Service(Child);
impl Drop for Service {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn gantry(program: &Path, base: &Path, args: &[&str]) -> String {
    let output = Process::new(program)
        .args(args)
        .env("GANTRY_HOME", base.join("sandboxes"))
        .env("GANTRY_REMOTE", "")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "gantry {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

fn snapshot(connector: &mut Connector) -> OrgSnapshot {
    connector
        .workspace(false)
        .expect("workspace")
        .organization
        .expect("the connection is a policy service")
}

#[test]
fn desktop_administers_a_real_policy_service() {
    let Some(program) = std::env::var_os("GANTRY_TEST_GANTRY").map(PathBuf::from) else {
        eprintln!(
            "skipped: set GANTRY_TEST_GANTRY to a gantry executable built from this checkout"
        );
        return;
    };
    let work = tempfile::tempdir().unwrap();
    let base = work.path().join("client");
    std::fs::create_dir(&base).unwrap();
    // Like ~/.gantry: the client store must be private.
    std::fs::set_permissions(&base, std::os::unix::fs::PermissionsExt::from_mode(0o700)).unwrap();
    let path = |name: &str| work.path().join(name);
    let text = |p: &Path| p.to_str().unwrap().to_owned();

    gantry(
        &program,
        &base,
        &[
            "policy",
            "keygen",
            "-out",
            &text(&path("key")),
            "-bits",
            "2048",
        ],
    );
    gantry(
        &program,
        &base,
        &[
            "policy",
            "keygen",
            "-out",
            &text(&path("stranger")),
            "-bits",
            "2048",
        ],
    );
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let url = format!("https://127.0.0.1:{port}");
    let service_dir = text(&path("service"));
    gantry(
        &program,
        &base,
        &[
            "policy-service",
            "init",
            "-dir",
            &service_dir,
            "-organization",
            "acme",
            "-url",
            &url,
            "-public-key",
            &text(&path("key").join("public.pem")),
        ],
    );
    let token = gantry(
        &program,
        &base,
        &[
            "policy-service",
            "admin",
            "add",
            "-dir",
            &service_dir,
            "-name",
            "desktop-admin",
        ],
    );
    let _service = Service(
        Process::new(&program)
            .args([
                "policy-service",
                "serve",
                "-dir",
                &service_dir,
                "-listen",
                &format!("127.0.0.1:{port}"),
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );

    // Register it exactly as the docs say: a remote profile with its CA.
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let mut add = Process::new(&program)
            .args([
                "remote",
                "add",
                "acme",
                &url,
                "--ca",
                &format!("{service_dir}/ca.pem"),
                "--token-stdin",
            ])
            .env("GANTRY_HOME", base.join("sandboxes"))
            .env("GANTRY_REMOTE", "")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        add.stdin
            .take()
            .unwrap()
            .write_all(token.as_bytes())
            .unwrap();
        let output = add.wait_with_output().unwrap();
        if output.status.success() {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "remote add: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        std::thread::sleep(Duration::from_millis(100));
    }

    let options = Options {
        source: Source::Remote {
            name: "acme".into(),
            config_dir: base.clone(),
        },
        appearance: Appearance::System,
        auto_start: false,
        gantry: Some(program.clone()),
        managed_gantry: None,
    };
    let mut connector = Connector::new(&options);
    let workspace = connector.workspace(false).unwrap();
    assert!(workspace.inventory.sandboxes.is_empty());
    assert!(
        workspace
            .inventory
            .capabilities
            .iter()
            .any(|c| c == org::CAPABILITY)
    );
    let target = workspace.target;
    let first = workspace.organization.unwrap();
    assert_eq!(
        (
            first.overview.organization.as_str(),
            first.overview.admin.as_str()
        ),
        ("acme", "desktop-admin")
    );
    assert_eq!(first.overview.latest, 0);
    assert_eq!(first.profiles(), ["developer"]);
    let run = |connector: &Connector, command: OrgCommand| {
        connector
            .execute(&target, &Command::Org(command))
            .map(|outcome| outcome.message)
    };

    // Enroll a host from its own request; the files land in a new folder.
    gantry(
        &program,
        &base,
        &[
            "policy",
            "feed-request",
            "-out",
            &text(&path("host")),
            "-host",
            "dev-mac-031",
        ],
    );
    run(
        &connector,
        OrgCommand::Enroll {
            name: "dev-mac-031".into(),
            profile: "developer".into(),
            ring: "canary".into(),
            request: path("host").join("host.csr"),
            save_to: path("enrolled"),
        },
    )
    .unwrap();
    for file in ["feed.json", "host.pem", "ca.pem", "org-public.pem"] {
        assert!(
            path("enrolled").join(file).is_file(),
            "{file} was not saved"
        );
    }
    assert!(
        run(
            &connector,
            OrgCommand::Enroll {
                name: "dev-mac-032".into(),
                profile: "developer".into(),
                ring: "canary".into(),
                request: path("host").join("host.csr"),
                save_to: path("enrolled"),
            }
        )
        .unwrap_err()
        .to_string()
        .contains("not empty")
    );

    // Edit the draft; the service validates it and reports the change.
    let document = first.document.clone().unwrap();
    let edit = Edit::Network {
        rule: NetworkRule {
            id: "https".into(),
            effect: "allow".into(),
            cidr: "0.0.0.0/0".into(),
            protocol: "tcp".into(),
            ports: vec![443],
        },
        replacing: None,
    };
    let edited = org::apply_edit(&document, "developer", &edit).unwrap();
    run(
        &connector,
        OrgCommand::SaveDraft {
            base: first.draft.base,
            document: edited.clone(),
            summary: edit.summary("developer"),
        },
    )
    .unwrap();
    let drafted = snapshot(&mut connector);
    assert!(drafted.draft.saved);
    // Before the first publication a draft is a whole new profile.
    assert!(drafted.draft.changes.iter().any(|c| c.kind == "profile"
        && c.profile == "developer"
        && c.summary.contains("1 network rules")));

    // A key hosts do not pin is refused before anything is uploaded.
    let publish = |document: &org::Document, key: &Path, revision: &str| {
        let mut document = document.clone();
        document.revision = revision.into();
        document.expires_at =
            gantry_desktop::clock::format(gantry_desktop::clock::now() + 30 * 86_400);
        OrgCommand::Publish(Box::new(Publish {
            base: drafted.draft.base,
            document,
            signing_key: key.to_owned(),
            first_ring: String::new(),
            key_fingerprint: drafted.overview.public_key_fingerprint.clone(),
            gantry: Some(program.clone()),
            managed: None,
        }))
    };
    let refused = run(
        &connector,
        publish(&edited, &path("stranger").join("signing-key.pem"), "r1"),
    )
    .unwrap_err();
    assert!(
        refused.to_string().contains("not the organization key"),
        "{refused}"
    );
    assert_eq!(snapshot(&mut connector).overview.latest, 0);

    // Signed here with the real key, published, and the draft is cleared.
    run(
        &connector,
        publish(&edited, &path("key").join("signing-key.pem"), "r1"),
    )
    .unwrap();
    let published = snapshot(&mut connector);
    assert_eq!(published.overview.latest, 1);
    assert!(!published.draft.saved);
    assert_eq!(published.generations[0].revision, "r1");
    assert_eq!(published.generations[0].published_by, "desktop-admin");
    assert_eq!(published.overview.rings[0].generation, 1);
    assert_eq!(published.overview.rings[2].generation, 0);

    // Once published, drafts are compared rule by rule with their base.
    let tightened = org::apply_edit(
        &edited,
        "developer",
        &Edit::Remove {
            kind: org::ItemKind::Network,
            id: "https".into(),
        },
    )
    .unwrap();
    run(
        &connector,
        OrgCommand::SaveDraft {
            base: 1,
            document: tightened,
            summary: "developer · remove https".into(),
        },
    )
    .unwrap();
    let changes = snapshot(&mut connector).draft.changes;
    assert_eq!(changes.len(), 1, "{changes:?}");
    assert_eq!(
        (
            changes[0].kind.as_str(),
            changes[0].change.as_str(),
            changes[0].effect.as_str()
        ),
        ("network", "removed", "tightens")
    );
    run(&connector, OrgCommand::DiscardDraft).unwrap();
    assert!(!snapshot(&mut connector).draft.saved);
    run(
        &connector,
        OrgCommand::Promote {
            generation: 1,
            ring: "everyone".into(),
        },
    )
    .unwrap();
    assert!(
        snapshot(&mut connector)
            .overview
            .rings
            .iter()
            .all(|r| r.generation == 1)
    );

    let second = org::apply_edit(&edited, "developer", &Edit::AddDns("github.com".into())).unwrap();
    run(
        &connector,
        publish(&second, &path("key").join("signing-key.pem"), "r2"),
    )
    .unwrap();
    run(
        &connector,
        OrgCommand::Republish {
            generation: 1,
            first_ring: "everyone".into(),
        },
    )
    .unwrap();
    let history = snapshot(&mut connector);
    assert_eq!(history.overview.latest, 3);
    assert_eq!(history.generations[0].republish_of, 1);
    assert_eq!(
        history.generations[0].bundle_sha256,
        history.generations[2].bundle_sha256
    );

    std::fs::create_dir(path("downloads")).unwrap();
    run(
        &connector,
        OrgCommand::Download {
            generation: 3,
            save_to: path("downloads"),
        },
    )
    .unwrap();
    let saved = std::fs::metadata(path("downloads").join("g3-bundle.tar.gz")).unwrap();
    assert_eq!(saved.len(), history.generations[0].size);

    run(
        &connector,
        OrgCommand::MoveHost {
            name: "dev-mac-031".into(),
            ring: "early".into(),
        },
    )
    .unwrap();
    run(
        &connector,
        OrgCommand::Revoke {
            name: "dev-mac-031".into(),
        },
    )
    .unwrap();
    let hosts = snapshot(&mut connector).hosts;
    assert_eq!(
        (
            hosts[0].ring.as_str(),
            hosts[0].revoked,
            hosts[0].status.as_str()
        ),
        ("early", true, "revoked")
    );
}
