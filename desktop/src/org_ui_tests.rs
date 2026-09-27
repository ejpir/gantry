use crate::{
    app::{Connection, Desktop},
    ui_tests::{desktop, desktop_at},
};
use gantry_desktop::{
    commands::Command,
    connector::Target,
    forms::{Intent, Kind, Values},
    options::Source,
    org::{self, OrgCommand, OrgRecord},
    workspace::{Page, Record},
};
use gpui_kit::test::TestWindowExt;
use gpui_kit::{AppContext, Context, TestAppContext, px};

/// A verified remote connection to a policy service with fresh data.
fn organization(this: &mut Desktop, cx: &mut Context<Desktop>) {
    let source = Source::Remote {
        name: "acme".into(),
        config_dir: "/private/client".into(),
    };
    this.options.source = source.clone();
    this.target = Some(Target {
        source,
        profile: None,
    });
    this.connection = Connection::Connected("v1".into());
    this.control_available = true;
    this.set_organization(Some(org::demo()), cx);
    this.sync_pages(cx);
}

#[gpui_kit::test]
fn demo_organization_opens_every_page_at_the_minimum_window_size(cx: &mut TestAppContext) {
    let (handle, desktop) = desktop_at(cx, 1040., 640.);
    cx.update_window(handle.into(), |_, window, cx| {
        window.render_frame(cx);
        window.click("connection-demo-organization", cx);
        window.render_frame(cx);
        let this = desktop.read(cx);
        assert!(this.org_mode && this.organization.is_some());
        assert_eq!(this.page, Page::OrgHosts);
        // The manager's workspace pages are gone from the sidebar.
        assert!(
            window
                .try_find(("page-nav", Page::Traffic.index()))
                .is_none()
        );
    })
    .unwrap();
    for page in Page::ORGANIZATION {
        cx.update_window(handle.into(), |_, window, cx| {
            window.click(("page-nav", page.index()), cx);
            window.render_frame(cx);
            assert_eq!(desktop.read(cx).page, page);
            let bounds = window.find(("page-table", page.index())).bounds();
            assert!(bounds.right() <= px(1040.));
            assert!(bounds.size.height > px(60.), "{page:?} list collapsed");
            for segment in 0..page.segments().len() {
                window.click(("segment", segment), cx);
                window.render_frame(cx);
            }
            window.click(("segment", 0usize), cx);
            window.render_frame(cx);
        })
        .unwrap();
    }
}

#[gpui_kit::test]
fn organization_rows_select_inspect_and_the_policy_page_starts_on_publish(cx: &mut TestAppContext) {
    let (handle, desktop) = desktop(cx);
    cx.update_window(handle.into(), |_, window, cx| {
        window.render_frame(cx);
        window.click("connection-demo-organization", cx);
        window.render_frame(cx);
        // Hosts select their first row; the inspector shows it.
        let selected = desktop.update(cx, |this, cx| this.selected_record(cx));
        assert!(matches!(selected, Some(Record::Org(OrgRecord::Host(_)))));
        window.click(("page-nav", Page::OrgPolicy.index()), cx);
        window.render_frame(cx);
        assert!(
            desktop
                .update(cx, |this, cx| this.selected_record(cx))
                .is_none()
        );
        assert!(window.try_find("org-publish-panel").is_some());
        window.click(("org-row", 0usize), cx);
    })
    .unwrap();
    cx.update_window(handle.into(), |_, window, cx| {
        window.render_frame(cx);
        let Some(Record::Org(OrgRecord::Item(item))) =
            desktop.update(cx, |this, cx| this.selected_record(cx))
        else {
            panic!("policy row did not select an item")
        };
        assert_eq!(item.profile, "developer");
        // A second click clears the selection back to the publish panel.
        window.click(("org-row", 0usize), cx);
    })
    .unwrap();
    cx.update_window(handle.into(), |_, window, cx| {
        window.render_frame(cx);
        assert!(
            desktop
                .update(cx, |this, cx| this.selected_record(cx))
                .is_none()
        );
        // Reviewing changes shows the data.json diff tree against the base.
        window.click(("segment", 1usize), cx);
        window.render_frame(cx);
        assert!(window.try_find("org-diff").is_some());
        window.click(("segment", 0usize), cx);
        window.render_frame(cx);
        window.click(("org-profile", 0usize), cx);
        window.render_frame(cx);
        assert_eq!(desktop.read(cx).org_profile, "ci");
        // The rollout charts how hosts acknowledged the newest generation.
        window.click(("page-nav", Page::OrgRollouts.index()), cx);
        window.render_frame(cx);
        assert!(window.find("org-ack-chart").bounds().size.height > px(60.));
    })
    .unwrap();
}

#[gpui_kit::test]
fn demo_organization_is_read_only_and_leaving_restores_the_manager(cx: &mut TestAppContext) {
    let (handle, desktop) = desktop(cx);
    cx.update_window(handle.into(), |_, window, cx| {
        window.render_frame(cx);
        window.click("connection-demo-organization", cx);
        window.render_frame(cx);
        assert!(!desktop.read(cx).can_write());
        window.click("org-enroll", cx);
        assert!(desktop.read(cx).form.is_none());
        window.click("connection-local", cx);
        window.render_frame(cx);
        let this = desktop.read(cx);
        assert!(!this.org_mode && this.organization.is_none());
        assert_eq!(this.page, Page::Sandboxes);
        assert!(
            window
                .try_find(("page-nav", Page::Traffic.index()))
                .is_some()
        );
    })
    .unwrap();
}

#[gpui_kit::test]
fn a_live_organization_opens_forms_scoped_to_its_draft_and_rings(cx: &mut TestAppContext) {
    let (handle, desktop) = desktop(cx);
    cx.update_window(handle.into(), |_, window, cx| {
        desktop.update(cx, organization);
        window.render_frame(cx);
        assert!(desktop.read(cx).can_write());
        window.click("org-enroll", cx);
        window.render_frame(cx);
        let this = desktop.read(cx);
        let form = this.form.as_ref().expect("enroll form");
        let Kind::OrgEnroll { profiles, rings } = &form.spec.kind else {
            panic!("not the enrollment form")
        };
        assert_eq!(profiles, &["ci", "contractor", "developer"]);
        assert_eq!(rings, &["canary", "early", "everyone"]);
        desktop.update(cx, |this, cx| this.close_form(window, cx));
        window.click(("page-nav", Page::OrgPolicy.index()), cx);
        window.render_frame(cx);
        window.click("org-add-network", cx);
        window.render_frame(cx);
        let Kind::OrgRule(form) = &desktop.read(cx).form.as_ref().expect("rule form").spec.kind
        else {
            panic!("not the rule form")
        };
        assert!(form.network && form.existing.is_none());
        assert_eq!(form.draft.profile, "developer");
        desktop.update(cx, |this, cx| this.close_form(window, cx));
        window.click(("page-nav", Page::OrgRollouts.index()), cx);
        window.render_frame(cx);
        window.click("org-promote", cx);
        window.render_frame(cx);
        let spec = &desktop
            .read(cx)
            .form
            .as_ref()
            .expect("promote confirmation")
            .spec;
        assert!(spec.help.contains("everyone"), "{}", spec.help);
    })
    .unwrap();
}

#[gpui_kit::test]
fn managed_remote_enrollment_selects_a_registered_manager(cx: &mut TestAppContext) {
    let (handle, desktop) = desktop(cx);
    cx.update_window(handle.into(), |_, window, cx| {
        desktop.update(cx, |this, cx| {
            organization(this, cx);
            this.config_dir = Some("/private/client".into());
            this.profiles = vec![gantry_desktop::profiles::RemoteProfile {
                name: "managed-host".into(),
                url: "https://managed.example.test:8443".into(),
                ca_cert: String::new(),
                fingerprint: String::new(),
            }];
        });
        window.render_frame(cx);
        window.click("org-enroll-managed", cx);
        window.render_frame(cx);
        let form = desktop.read(cx);
        let spec = &form.form.as_ref().expect("managed enrollment form").spec;
        let Kind::OrgManagedEnroll { remotes, .. } = &spec.kind else {
            panic!("wrong form")
        };
        assert_eq!(remotes[0].name, "managed-host");
        assert!(
            spec.help
                .contains("Enrollment alone does not enforce policy")
        );
        let values: Values = spec
            .fields
            .iter()
            .map(|f| (f.key.to_owned(), zeroize::Zeroizing::new(f.value.clone())))
            .collect();
        let Intent::Manager(Command::Org(OrgCommand::EnrollManaged {
            name, remote, ring, ..
        })) = spec.build(&values, &form.host).expect("managed intent")
        else {
            panic!("wrong enrollment intent")
        };
        assert_eq!(
            (name.as_str(), remote.name.as_str(), ring.as_str()),
            ("managed-host", "managed-host", "canary")
        );
    })
    .unwrap();
}

#[gpui_kit::test]
fn managed_activation_selects_a_registered_manager(cx: &mut TestAppContext) {
    let (handle, desktop) = desktop(cx);
    cx.update_window(handle.into(), |_, window, cx| {
        desktop.update(cx, |this, cx| {
            organization(this, cx);
            this.config_dir = Some("/private/client".into());
            this.profiles = vec![gantry_desktop::profiles::RemoteProfile {
                name: "managed-host".into(),
                url: "https://managed.example.test:8443".into(),
                ca_cert: String::new(),
                fingerprint: String::new(),
            }];
        });
        window.render_frame(cx);
        window.click("org-activate-feed", cx);
        window.render_frame(cx);
        let form = desktop.read(cx);
        let spec = &form.form.as_ref().expect("activate feed form").spec;
        let Kind::OrgActivateFeed { remotes, .. } = &spec.kind else {
            panic!("wrong form")
        };
        assert_eq!(remotes[0].name, "managed-host");
        assert!(spec.help.contains("published, signed generation"));
        let values: Values = spec
            .fields
            .iter()
            .map(|field| {
                (
                    field.key.to_owned(),
                    zeroize::Zeroizing::new(field.value.clone()),
                )
            })
            .collect();
        let Intent::Manager(Command::Org(OrgCommand::ActivateManaged { remote, .. })) =
            spec.build(&values, &form.host).expect("activation intent")
        else {
            panic!("wrong activation intent")
        };
        assert_eq!(remote.name, "managed-host");
    })
    .unwrap();
}

#[gpui_kit::test]
fn an_offline_organization_keeps_its_workspace_and_disables_writes(cx: &mut TestAppContext) {
    let (handle, desktop) = desktop(cx);
    cx.update_window(handle.into(), |_, window, cx| {
        desktop.update(cx, organization);
        desktop.update(cx, |this, cx| {
            this.connection = Connection::Offline("policy service unreachable".into());
            this.organization = None;
            this.sync_pages(cx);
        });
        window.render_frame(cx);
        let this = desktop.read(cx);
        assert!(this.org_mode && this.page.is_organization());
        assert!(!this.can_write());
        assert!(
            window
                .try_find(("page-nav", Page::OrgHosts.index()))
                .is_some()
        );
    })
    .unwrap();
}
