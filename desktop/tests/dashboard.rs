use gantry_desktop::{
    commands::{Command, name_path},
    dashboard_wire::*,
    forms::{Intent, Kind, Spec, Values},
    org,
    wire::SecretInput,
    workspace::{self, Page},
};

fn values(spec: &Spec) -> Values {
    spec.fields
        .iter()
        .map(|f| (f.key.to_string(), zeroize::Zeroizing::new(f.value.clone())))
        .collect()
}
fn set(values: &mut Values, key: &str, value: &str) {
    values.insert(key.into(), zeroize::Zeroizing::new(value.into()));
}

#[test]
fn dashboard_top_level_is_required_and_go_nil_slices_are_supported() {
    assert!(serde_json::from_str::<HostSnapshot>("{}").is_err());
    let snapshot: HostSnapshot = serde_json::from_str(
        r#"{"snapshot":{"Sandboxes":null,"Traffic":null},"resourceLimits":{"MaxVCPUs":8}}"#,
    )
    .unwrap();
    assert!(snapshot.snapshot.sandboxes.is_empty());
    assert_eq!(snapshot.resource_limits.max_vcpus, 8);
}
#[test]
fn every_tui_page_has_a_native_projection_and_stable_row_ids() {
    let host = workspace::demo();
    assert_eq!(Page::ALL.len(), 17);
    for page in Page::ALL {
        let rows = workspace::rows(page, &host, &[], &PacketSnapshot::default());
        assert!(!page.is_organization() || rows.is_empty());
        for row in rows {
            assert_eq!(row.cells.len(), page.columns().len());
            assert!(!row.key.is_empty());
            assert!(!row.record.details().is_empty());
        }
    }
    // Organization pages project the policy service's snapshot instead.
    let organization = org::demo();
    for (page, rows) in [
        (Page::OrgHosts, org::host_rows(&organization, false)),
        (Page::OrgRollouts, org::host_rows(&organization, false)),
        (Page::OrgEnrollment, org::host_rows(&organization, true)),
        (Page::OrgHistory, org::generation_rows(&organization)),
        (
            Page::OrgPolicy,
            org::policy_rows(&organization, "developer"),
        ),
    ] {
        assert!(!rows.is_empty(), "{page:?} has no demo rows");
        let mut keys = std::collections::HashSet::new();
        for row in rows {
            assert_eq!(row.cells.len(), page.columns().len());
            assert!(keys.insert(row.key.clone()), "duplicate key on {page:?}");
            assert!(!row.record.details().is_empty());
        }
    }
    let before = workspace::rows(Page::Traffic, &host, &[], &PacketSnapshot::default());
    let mut after = host.clone();
    after.snapshot.traffic[0].tx_bytes += 1234;
    assert_eq!(
        before[0].key,
        workspace::rows(Page::Traffic, &after, &[], &PacketSnapshot::default())[0].key
    );
}
#[test]
fn overview_never_substitutes_saved_resources_for_unknown_active_allocation() {
    let mut host = workspace::demo();
    let s = &mut host.snapshot.sandboxes[0];
    s.state = "running".into();
    s.active_available = false;
    s.mem_mb = 8192;
    let rows = workspace::rows(Page::Overview, &host, &[], &PacketSnapshot::default());
    assert_eq!(rows[0].cells[3], "Unknown active allocation");
}
#[test]
fn create_and_edit_preserve_false_and_use_saved_not_active_settings() {
    let host = workspace::demo();
    let spec = Spec::new(Kind::Create, &host, "");
    let mut v = values(&spec);
    set(&mut v, "name", "unit-vm");
    set(&mut v, "image", "test:cached");
    set(&mut v, "rw", "false");
    set(&mut v, "net", "false");
    let Intent::Manager(Command::Create(request)) = spec.build(&v, &host).unwrap() else {
        panic!("not create")
    };
    let wire = serde_json::to_value(request).unwrap();
    assert_eq!(wire["rw"], false);
    assert_eq!(wire["net"], false);
    assert_eq!(wire["cpus"], 1);
    let spec = Spec::new(
        Kind::Configure(SandboxConfigRequest {
            name: "dev".into(),
            mem_mb: 4096,
            vcpus: 2,
            process_isolation: "auto".into(),
            ssh: false,
            dev_containers: false,
        }),
        &host,
        "other",
    );
    let v = values(&spec);
    let Intent::Manager(Command::Configure(request)) = spec.build(&v, &host).unwrap() else {
        panic!()
    };
    assert_eq!(request.name, "dev");
    assert_eq!(request.mem_mb, 4096);
    assert!(!request.ssh);
}
#[test]
fn native_validation_rejects_traversal_invalid_resources_and_invalid_json() {
    for name in ["../dev", ".", "..", "x/y", "x?host=y", "x#y", ""] {
        assert!(name_path(name).is_err());
    }
    let host = workspace::demo();
    let spec = Spec::new(Kind::Create, &host, "");
    let mut v = values(&spec);
    set(&mut v, "name", "dev");
    set(&mut v, "image", "test:cached");
    set(&mut v, "cpus", "-1");
    assert!(spec.build(&v, &host).is_err());
    set(&mut v, "cpus", "1");
    set(&mut v, "devcontainers", "true");
    assert!(spec.build(&v, &host).is_err());
    let spec = Spec::new(Kind::NetworkPolicy, &host, "dev");
    let v = values(&spec);
    assert!(spec.build(&v, &host).is_err());
}
#[test]
fn secret_intents_redact_debug_and_use_the_go_write_only_field_names() {
    let host = workspace::demo();
    let spec = Spec::new(Kind::Secret, &host, "dev");
    let mut v = values(&spec);
    set(&mut v, "name", "SERVICE_TOKEN");
    set(&mut v, "value", "synthetic-secret-value");
    let Intent::Manager(command) = spec.build(&v, &host).unwrap() else {
        panic!()
    };
    assert!(!format!("{command:?}").contains("synthetic-secret-value"));
    let Command::Dashboard(request) = command else {
        panic!()
    };
    let wire = serde_json::to_value(request).unwrap();
    assert_eq!(wire["secret"]["Value"], "synthetic-secret-value");
    assert_eq!(wire["secret"]["Sandbox"], "dev");
    assert_eq!(wire.as_object().unwrap().len(), 2);
    assert_eq!(
        format!("{:?}", SecretInput::new("never-log".into())),
        "[redacted]"
    );
}
#[test]
fn no_auth_mcp_uses_empty_kind_and_mount_edits_keep_current_guest() {
    let host = workspace::demo();
    let spec = Spec::new(Kind::Mcp(None), &host, "dev");
    let mut v = values(&spec);
    set(&mut v, "name", "docs");
    set(&mut v, "url", "https://docs.example.test/mcp");
    let Intent::Manager(Command::Dashboard(request)) = spec.build(&v, &host).unwrap() else {
        panic!()
    };
    assert_eq!(request.mcp_remote.unwrap().auth_kind, "");
    let spec = Spec::new(Kind::Share(None), &host, "dev");
    let mut v = values(&spec);
    set(&mut v, "tag", "src");
    set(&mut v, "path", "/demo/new");
    let Intent::Manager(Command::Share(request)) = spec.build(&v, &host).unwrap() else {
        panic!()
    };
    assert_eq!(request.current_guest, "/workspace");
    assert!(request.read_only);
}
#[test]
fn sandbox_fields_pick_from_the_manager_sandboxes() {
    use gantry_desktop::forms::FieldKind;
    let host = workspace::demo();
    let sandbox = |spec: &Spec| {
        let field = spec.fields.iter().find(|f| f.key == "sandbox").unwrap();
        let FieldKind::Select(options) = &field.kind else {
            panic!("the sandbox field is a dropdown")
        };
        (field.value.clone(), options.clone())
    };
    let names = ["agent", "build", "dev", "scratch"]
        .map(String::from)
        .to_vec();
    for kind in [
        Kind::Port,
        Kind::Secret,
        Kind::Filesystem,
        Kind::NetworkPolicy,
        Kind::Capture,
        Kind::Rule(None),
        Kind::Share(None),
        Kind::Mcp(None),
    ] {
        assert_eq!(
            sandbox(&Spec::new(kind, &host, "dev")),
            ("dev".into(), names.clone())
        );
    }
    // Without a selected sandbox the first one is chosen.
    assert_eq!(sandbox(&Spec::new(Kind::Secret, &host, "")).0, "agent");
    // An edit of a sandbox the snapshot no longer lists keeps its target.
    let rule = RuleRequest {
        sandbox: "gone".into(),
        ..Default::default()
    };
    let (value, options) = sandbox(&Spec::new(Kind::Rule(Some(rule)), &host, "dev"));
    assert_eq!((value.as_str(), options[0].as_str()), ("gone", "gone"));
    // With no sandboxes there is nothing to pick, and Go gets no request.
    let spec = Spec::new(Kind::Secret, &HostSnapshot::default(), "");
    assert_eq!(sandbox(&spec), (String::new(), vec![]));
    let mut v = values(&spec);
    set(&mut v, "name", "TOKEN");
    set(&mut v, "value", "x");
    assert!(spec.build(&v, &HostSnapshot::default()).is_err());
}
#[test]
fn destructive_confirmation_names_the_actual_subject() {
    let spec = Spec::new(
        Kind::Confirm(Command::Delete("important-vm".into())),
        &HostSnapshot::default(),
        "other",
    );
    assert!(spec.help.contains("important-vm"));
    assert!(!spec.help.contains("other"));
}
#[test]
fn traffic_reads_largest_first_and_segments_split_decisions() {
    let host = workspace::demo();
    let rows = workspace::rows(Page::Traffic, &host, &[], &PacketSnapshot::default());
    let bytes = |row: &workspace::Row| match &row.record {
        workspace::Record::Traffic(r) => r.tx_bytes + r.rx_bytes,
        _ => unreachable!(),
    };
    assert!(
        rows.windows(2)
            .all(|pair| bytes(&pair[0]) >= bytes(&pair[1]))
    );
    assert_eq!(Page::Traffic.segments(), ["All", "Allowed", "Denied"]);
    let count = |segment| {
        rows.iter()
            .filter(|row| workspace::segment_matches(Page::Traffic, segment, &row.record))
            .count()
    };
    assert_eq!(count(0), rows.len());
    assert_eq!(count(1) + count(2), rows.len());
    assert_eq!(count(2), 2);
    assert!(Page::Overview.segments().is_empty());
}
