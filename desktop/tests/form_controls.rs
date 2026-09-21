use gantry_desktop::{
    commands::Command,
    dashboard_wire::{HostSnapshot, SandboxConfigRequest},
    forms::{FieldKind, Intent, Kind, PathKind, Spec, Values},
    options::Source,
    workspace,
};

fn values(spec: &Spec) -> Values {
    spec.fields
        .iter()
        .map(|f| (f.key.into(), zeroize::Zeroizing::new(f.value.clone())))
        .collect()
}

#[test]
fn resource_sliders_use_manager_bounds_without_rewriting_saved_values() {
    let mut host = workspace::demo();
    host.resource_limits.min_memory_mb = 130;
    host.resource_limits.max_memory_mb = 999;
    host.resource_limits.max_vcpus = 3;
    let spec = Spec::new(
        Kind::Configure(SandboxConfigRequest {
            name: "dev".into(),
            mem_mb: 513,
            vcpus: 2,
            process_isolation: "auto".into(),
            ..Default::default()
        }),
        &host,
        "other",
    );
    let FieldKind::Resource(memory) = spec.fields[0].kind else {
        panic!()
    };
    let FieldKind::Resource(cpus) = spec.fields[1].kind else {
        panic!()
    };
    assert_eq!((memory.min, memory.max, memory.step), (130, 999, 128));
    assert_eq!((cpus.min, cpus.max, cpus.step), (1, 3, 1));
    assert_eq!(memory.slider_value(128.), 130);
    assert_eq!(memory.slider_value(1024.), 999);
    let mut draft = values(&spec);
    let Intent::Manager(Command::Configure(request)) = spec.build(&draft, &host).unwrap() else {
        panic!()
    };
    assert_eq!((request.mem_mb, request.vcpus), (513, 2));
    draft.insert("memory".into(), zeroize::Zeroizing::new("1000".into()));
    assert!(spec.build(&draft, &host).is_err());
    // The latest limits are still checked on submission, not only at form creation.
    host.resource_limits.max_memory_mb = 256;
    assert!(spec.build(&values(&spec), &host).is_err());
    assert_eq!(spec.fields[0].value, "513");
}

#[test]
fn unknown_and_degenerate_resource_bounds_are_safe() {
    let mut host = HostSnapshot::default();
    let spec = Spec::new(Kind::Create, &host, "");
    let FieldKind::Resource(memory) = spec.fields[4].kind else {
        panic!()
    };
    assert!(memory.min > 0 && memory.max > memory.min);
    host.resource_limits.min_memory_mb = 1024;
    host.resource_limits.max_memory_mb = 1024;
    host.resource_limits.max_vcpus = 1;
    let spec = Spec::new(Kind::Create, &host, "");
    assert_eq!(spec.fields[4].value, "1024");
    let FieldKind::Resource(memory) = spec.fields[4].kind else {
        panic!()
    };
    assert_eq!(memory.slider_value(5000.), 1024);
    host.resource_limits.max_memory_mb = 100;
    let spec = Spec::new(Kind::Create, &host, "");
    let FieldKind::Resource(memory) = spec.fields[4].kind else {
        panic!()
    };
    assert!(memory.max < memory.min); // The UI disables an inconsistent range.
    assert_eq!(memory.slider_value(0.), 1024); // No clamp panic.
}

#[test]
fn chosen_paths_are_not_silently_trimmed_or_retargeted() {
    let host = workspace::demo();
    let spec = Spec::new(Kind::Share(None), &host, "dev");
    let mut draft = values(&spec);
    draft.insert("tag".into(), zeroize::Zeroizing::new("src".into()));
    draft.insert(
        "path".into(),
        zeroize::Zeroizing::new("/tmp/a project with spaces".into()),
    );
    let Intent::Manager(Command::Share(request)) = spec.build(&draft, &host).unwrap() else {
        panic!()
    };
    assert_eq!(request.path, "/tmp/a project with spaces");
    for path in ["/tmp/project ", " /tmp/project", "/tmp/project\n"] {
        draft.insert("path".into(), zeroize::Zeroizing::new(path.into()));
        assert!(spec.build(&draft, &host).is_err());
    }
}

#[test]
fn path_semantics_distinguish_desktop_manager_and_guest() {
    let local = Source::Local("/private/manager.sock".into());
    let remote = Source::Remote {
        name: "build".into(),
        config_dir: "/private/client".into(),
    };
    let host = HostSnapshot::default();
    for (kind, index, expected) in [
        (Kind::Create, 2, PathKind::ManagerFile),
        (Kind::Share(None), 2, PathKind::ManagerDirectory),
        (Kind::Share(None), 3, PathKind::GuestDirectory),
        (Kind::Filesystem, 1, PathKind::GuestDirectory),
        (Kind::RemoteAdd, 2, PathKind::DesktopFile),
    ] {
        let spec = Spec::new(kind, &host, "dev");
        let FieldKind::Path(path) = spec.fields[index].kind else {
            panic!()
        };
        assert_eq!(path, expected);
        assert_eq!(path.can_browse(&local), path != PathKind::GuestDirectory);
        assert_eq!(path.can_browse(&remote), path == PathKind::DesktopFile);
        assert!(!path.can_browse(&Source::Demo));
    }
}
