use crate::{
    app::Connection,
    ui_tests::{desktop, desktop_at},
};
use gantry_desktop::{
    connector::Target, forms::Kind, inventory::Filter, options::Source, workspace::Page,
};
use gpui_kit::test::TestWindowExt;
use gpui_kit::{AppContext, ClipboardItem, TestAppContext, px};

#[gpui_kit::test]
fn every_dashboard_page_renders_at_the_minimum_window_size(cx: &mut TestAppContext) {
    let (handle, desktop) = desktop_at(cx, 1040., 640.);
    // Organization pages belong to policy-service connections (org_ui_tests).
    for page in Page::ALL.into_iter().filter(|page| !page.is_organization()) {
        cx.update_window(handle.into(), |_, window, cx| {
            window.render_frame(cx);
            if page == Page::Overview {
                desktop.update(cx, |this, cx| this.switch_page(page, window, cx));
            } else {
                let bounds = window.find(("page-nav", page.index())).bounds();
                let sidebar = window.find("sidebar-region").bounds();
                if page != Page::Remotes
                    && (bounds.bottom() > sidebar.bottom() || bounds.top() < sidebar.top())
                {
                    let dy = sidebar.top() + px(30.) - bounds.top();
                    window.scroll(
                        "sidebar-region",
                        gpui_kit::ScrollDelta::Pixels(gpui_kit::point(px(0.), dy)),
                        cx,
                    );
                    window.render_frame(cx);
                }
                window.click(("page-nav", page.index()), cx);
            }
            window.render_frame(cx);
            assert_eq!(desktop.read(cx).page, page);
            if page != Page::Sandboxes {
                let bounds = window.find(("page-table", page.index())).bounds();
                assert!(bounds.right() <= px(1040.));
                assert!(bounds.size.height > px(60.));
            }
        })
        .unwrap();
    }
}
#[gpui_kit::test]
fn page_queries_and_explicit_deselection_survive_navigation_and_refresh(cx: &mut TestAppContext) {
    let (handle, desktop) = desktop(cx);
    cx.update_window(handle.into(), |_, window, cx| {
        window.click(("page-nav", Page::Traffic.index()), cx);
        window.click("dashboard-search", cx);
        window.input("registry", cx);
    })
    .unwrap();
    cx.update_window(handle.into(), |_, window, cx| {
        assert_eq!(
            desktop.read(cx).pages[Page::Traffic.index()].query,
            "registry"
        );
        desktop.update(cx, |this, cx| {
            this.pages[Page::Traffic.index()].selected = None;
            this.sync_pages(cx);
            assert!(this.pages[Page::Traffic.index()].selected.is_none());
        });
        window.click(("page-nav", Page::Rules.index()), cx);
    })
    .unwrap();
    cx.update_window(handle.into(), |_, window, cx| {
        assert_eq!(window.find("dashboard-search").value(), Some(""));
        window.click(("page-nav", Page::Traffic.index()), cx);
    })
    .unwrap();
    cx.update_window(handle.into(), |_, window, cx| {
        assert_eq!(window.find("dashboard-search").value(), Some("registry"));
        assert!(
            desktop.read(cx).pages[Page::Traffic.index()]
                .selected
                .is_none()
        );
    })
    .unwrap();
}
#[gpui_kit::test]
fn demo_and_offline_modes_do_not_open_write_forms(cx: &mut TestAppContext) {
    let (handle, desktop) = desktop(cx);
    cx.update_window(handle.into(), |_, window, cx| {
        window.click("sandbox-create", cx);
        assert!(desktop.read(cx).form.is_none());
        assert!(!desktop.read(cx).can_write());
        window.click(("page-nav", Page::Secrets.index()), cx);
        window.click("secret-add", cx);
        assert!(desktop.read(cx).form.is_none());
        desktop.update(cx, |this, cx| {
            this.connection = Connection::Offline("test".into());
            this.open_form(Kind::Secret, window, cx);
        });
        assert!(desktop.read(cx).form.is_none());
    })
    .unwrap();
}
#[gpui_kit::test]
fn editing_keeps_its_original_sandbox_and_shows_its_source(cx: &mut TestAppContext) {
    let (handle, desktop) = desktop(cx);
    cx.update_window(handle.into(), |_, window, cx| {
        desktop.update(cx, |this, cx| {
            let source = Source::Local("/private/test/manager.sock".into());
            this.options.source = source.clone();
            this.target = Some(Target {
                source,
                profile: None,
            });
            this.connection = Connection::Connected("v1".into());
            cx.notify();
        });
        window.click("sandbox-edit", cx);
    })
    .unwrap();
    cx.update_window(handle.into(), |_, window, cx| {
        desktop.update(cx, |this, cx| {
            this.inventory.select("build");
            this.cycle_theme(window, cx);
        });
        let form = desktop.read(cx).form.as_ref().unwrap();
        let Kind::Configure(request) = &form.spec.kind else {
            panic!()
        };
        assert_eq!(request.name, "dev");
        assert!(form.scope.contains("/private/test/manager.sock"));
        window.render_frame(cx);
        let bounds = window.find("action-form").bounds();
        assert!(bounds.right() <= px(1280.));
        assert!(bounds.bottom() <= px(800.));
        window.click("form-cancel", cx);
        assert!(desktop.read(cx).form.is_none());
        assert!(!desktop.read(cx).writing);
    })
    .unwrap();
}
#[gpui_kit::test]
fn secret_inputs_are_masked_not_copyable_and_dropped_on_cancel(cx: &mut TestAppContext) {
    let (handle, desktop) = desktop(cx);
    cx.update_window(handle.into(), |_, window, cx| {
        desktop.update(cx, |this, cx| {
            let source = Source::Local("/private/test/manager.sock".into());
            this.options.source = source.clone();
            this.target = Some(Target {
                source,
                profile: None,
            });
            this.connection = Connection::Connected("v1".into());
            this.open_form(Kind::Secret, window, cx);
        });
        window.click(("form-input", 2usize), cx);
        window.input("synthetic-secret-for-ui-test", cx);
        cx.write_to_clipboard(ClipboardItem::new_string("unchanged".into()));
        window.press(
            if cfg!(target_os = "macos") {
                "cmd-a"
            } else {
                "ctrl-a"
            },
            cx,
        );
        window.press(
            if cfg!(target_os = "macos") {
                "cmd-c"
            } else {
                "ctrl-c"
            },
            cx,
        );
    })
    .unwrap();
    cx.update_window(handle.into(), |_, window, cx| {
        assert_eq!(
            desktop.read(cx).form.as_ref().unwrap().inputs[2]
                .value(cx)
                .as_ref(),
            "synthetic-secret-for-ui-test"
        );
        assert!(
            !window
                .find(("form-input", 2usize))
                .value()
                .is_some_and(|value| value.contains("synthetic-secret"))
        );
        assert_eq!(
            cx.read_from_clipboard().unwrap().text().as_deref(),
            Some("unchanged")
        );
        window.press("escape", cx);
    })
    .unwrap();
    cx.update_window(handle.into(), |_, _, cx| {
        assert!(desktop.read(cx).form.is_none());
        assert!(!desktop.read(cx).writing);
    })
    .unwrap();
}
#[gpui_kit::test]
fn confirmation_does_not_submit_when_connection_identity_changes(cx: &mut TestAppContext) {
    let (handle, desktop) = desktop(cx);
    cx.update_window(handle.into(), |_, window, cx| {
        desktop.update(cx, |this, cx| {
            let source = Source::Local("/private/test/manager.sock".into());
            this.options.source = source.clone();
            this.target = Some(Target {
                source,
                profile: None,
            });
            this.connection = Connection::Connected("v1".into());
            this.set_filter(Filter::Stopped, cx);
        });
        window.click(("inspector-tab", 1usize), cx);
        window.click("sandbox-delete", cx);
        assert!(
            desktop
                .read(cx)
                .form
                .as_ref()
                .unwrap()
                .spec
                .help
                .contains("build")
        );
        desktop.update(cx, |this, cx| {
            this.target = None;
            this.submit_form(window, cx);
        });
        assert!(!desktop.read(cx).writing);
        assert!(desktop.read(cx).form.as_ref().unwrap().error.is_some());
    })
    .unwrap();
}

#[gpui_kit::test]
fn traffic_segments_filter_flows_and_the_inspector_offers_rules(cx: &mut TestAppContext) {
    let (handle, desktop) = desktop(cx);
    let rows = |desktop: &gpui_kit::Entity<crate::app::Desktop>, cx: &gpui_kit::App| {
        desktop.read(cx).pages[Page::Traffic.index()]
            .table
            .read(cx)
            .delegate()
            .rows
            .iter()
            .map(|row| match &row.record {
                gantry_desktop::workspace::Record::Traffic(flow) => flow.allowed,
                _ => unreachable!(),
            })
            .collect::<Vec<_>>()
    };
    cx.update_window(handle.into(), |_, window, cx| {
        window.click(("page-nav", Page::Traffic.index()), cx);
    })
    .unwrap();
    cx.update_window(handle.into(), |_, window, cx| {
        window.render_frame(cx);
        assert_eq!(rows(&desktop, cx).len(), 8);
        // The largest flow is selected and inspected, with rule actions.
        assert!(window.try_find("inspector-pane").is_some());
        assert!(window.try_find("inspector-allow").is_some());
        assert!(window.try_find("traffic-allow").is_none());
        window.click(("segment", 2usize), cx);
    })
    .unwrap();
    cx.update_window(handle.into(), |_, window, cx| {
        window.render_frame(cx);
        assert_eq!(rows(&desktop, cx), [false, false]);
        window.click("inspector-toggle", cx);
    })
    .unwrap();
    cx.update_window(handle.into(), |_, window, cx| {
        window.render_frame(cx);
        // Without the inspector, the rule actions return to the toolbar.
        assert!(window.try_find("inspector-pane").is_none());
        assert!(window.try_find("traffic-allow").is_some());
        assert!(window.try_find("inspector-allow").is_none());
    })
    .unwrap();
}

#[gpui_kit::test]
fn rules_group_by_sandbox_with_a_policy_card_each(cx: &mut TestAppContext) {
    let (handle, desktop) = desktop(cx);
    cx.update_window(handle.into(), |_, window, cx| {
        window.click(("page-nav", Page::Rules.index()), cx);
    })
    .unwrap();
    cx.update_window(handle.into(), |_, window, cx| {
        window.render_frame(cx);
        // agent, build, dev, scratch: one policy card per sandbox.
        assert!(window.try_find(("policy-card", 3usize)).is_some());
        assert!(window.try_find(("policy-card", 4usize)).is_none());
        assert!(window.try_find("inspector-remove-rule").is_some());
        let sandboxes: Vec<String> = desktop.read(cx).pages[Page::Rules.index()]
            .table
            .read(cx)
            .delegate()
            .rows
            .iter()
            .map(|row| row.cells[0].clone())
            .collect();
        let mut grouped = sandboxes.clone();
        grouped.sort();
        assert_eq!(sandboxes, grouped, "rules stay grouped by sandbox");
        window.click(("segment", 2usize), cx);
    })
    .unwrap();
    cx.update_window(handle.into(), |_, _, cx| {
        let actions: Vec<String> = desktop.read(cx).pages[Page::Rules.index()]
            .table
            .read(cx)
            .delegate()
            .rows
            .iter()
            .map(|row| row.cells[1].clone())
            .collect();
        assert!(!actions.is_empty() && actions.iter().all(|a| a == "deny"));
    })
    .unwrap();
}

#[gpui_kit::test]
fn ports_draw_connections_and_select_by_card(cx: &mut TestAppContext) {
    let (handle, desktop) = desktop(cx);
    cx.update_window(handle.into(), |_, window, cx| {
        window.click(("page-nav", Page::Ports.index()), cx);
    })
    .unwrap();
    cx.update_window(handle.into(), |_, window, cx| {
        window.render_frame(cx);
        assert!(window.try_find(("port-card", 3usize)).is_some());
        assert!(window.try_find(("port-card", 4usize)).is_none());
        window.click(("port-card", 2usize), cx);
    })
    .unwrap();
    cx.update_window(handle.into(), |_, window, cx| {
        window.render_frame(cx);
        let record = desktop.update(cx, |this, cx| this.selected_record(cx));
        let Some(gantry_desktop::workspace::Record::Port(port)) = record else {
            panic!("a port is selected")
        };
        assert_eq!(port.bind, "0.0.0.0:5173");
        assert!(window.try_find("port-copy").is_some());
    })
    .unwrap();
}

#[gpui_kit::test]
fn packet_capture_reads_newest_first_and_decodes_the_selected_frame(cx: &mut TestAppContext) {
    let (handle, desktop) = desktop(cx);
    cx.update_window(handle.into(), |_, window, cx| {
        window.click(("page-nav", Page::Packets.index()), cx);
    })
    .unwrap();
    cx.update_window(handle.into(), |_, window, cx| {
        window.render_frame(cx);
        assert!(window.try_find("packet-histogram").is_some());
        assert!(window.try_find("packet-hex").is_some());
        let record = desktop.update(cx, |this, cx| this.selected_record(cx));
        let Some(gantry_desktop::workspace::Record::Packet(packet)) = record else {
            panic!("a packet is selected")
        };
        assert_eq!(packet.sequence, desktop.read(cx).packets.latest);
    })
    .unwrap();
}

#[gpui_kit::test]
fn packet_capture_reads_live_pauses_and_reports_failed_reads_quietly(cx: &mut TestAppContext) {
    let (handle, desktop) = desktop(cx);
    cx.update_window(handle.into(), |_, window, cx| {
        window.click(("page-nav", Page::Packets.index()), cx);
    })
    .unwrap();
    cx.update_window(handle.into(), |_, window, cx| {
        window.render_frame(cx);
        // Frames arrive on their own; there is no batch button to press.
        assert!(window.try_find("capture-read").is_none());
        window.click("capture-pause", cx);
    })
    .unwrap();
    desktop.update(cx, |this, cx| {
        assert!(this.packets_paused);
        assert!(this.packets_status().starts_with("Paused · dev"));
        // Paused, nothing is read.
        this.read_packets(cx);
        assert!(!this.packets_reading);
        this.packets_paused = false;
        let activity = this.activity.len();
        this.options.source = Source::Local("/nonexistent/gantry-live-read.sock".into());
        this.connector = std::sync::Arc::new(std::sync::Mutex::new(
            gantry_desktop::connector::Connector::new(&this.options),
        ));
        this.target = Some(Target {
            source: this.options.source.clone(),
            profile: None,
        });
        this.connection = Connection::Connected("v1".into());
        this.read_packets(cx);
        assert!(this.packets_reading);
        assert_eq!(this.activity.len(), activity);
    });
    cx.run_until_parked();
    desktop.update(cx, |this, cx| {
        assert!(!this.packets_reading);
        assert!(this.packet_error.is_some());
        assert!(this.packets_status().starts_with("Reading dev failed"));
        // The frames already read stay on screen.
        assert!(!this.packets.packets.is_empty());
        // Another page stops reading.
        this.page = Page::Traffic;
        this.read_packets(cx);
        assert!(!this.packets_reading);
    });
}

#[gpui_kit::test]
fn mounts_group_mappings_by_sandbox_and_filter_by_access(cx: &mut TestAppContext) {
    let (handle, desktop) = desktop(cx);
    cx.update_window(handle.into(), |_, window, cx| {
        window.click(("page-nav", Page::Mounts.index()), cx);
    })
    .unwrap();
    cx.update_window(handle.into(), |_, window, cx| {
        window.render_frame(cx);
        assert!(window.try_find(("mount-card", 4usize)).is_some());
        assert!(window.try_find("mount-add-zone").is_some());
        window.click(("mount-card", 2usize), cx);
    })
    .unwrap();
    cx.update_window(handle.into(), |_, window, cx| {
        window.render_frame(cx);
        let record = desktop.update(cx, |this, cx| this.selected_record(cx));
        let Some(gantry_desktop::workspace::Record::Mount(mount)) = record else {
            panic!("a mount is selected")
        };
        assert_eq!(mount.sandbox, "build");
        assert!(window.try_find("mount-remove").is_some());
        window.click(("segment", 1usize), cx);
    })
    .unwrap();
    cx.update_window(handle.into(), |_, window, cx| {
        window.render_frame(cx);
        // Two read-only shares remain, both dev's.
        assert!(window.try_find(("mount-card", 1usize)).is_some());
        assert!(window.try_find(("mount-card", 2usize)).is_none());
        let _ = desktop;
    })
    .unwrap();
}

#[gpui_kit::test]
fn secrets_show_names_and_bindings_never_values(cx: &mut TestAppContext) {
    let (handle, desktop) = desktop(cx);
    cx.update_window(handle.into(), |_, window, cx| {
        window.click(("page-nav", Page::Secrets.index()), cx);
    })
    .unwrap();
    cx.update_window(handle.into(), |_, window, cx| {
        window.render_frame(cx);
        assert!(window.try_find(("secret-card", 4usize)).is_some());
        window.click(("secret-card", 2usize), cx);
    })
    .unwrap();
    cx.update_window(handle.into(), |_, window, cx| {
        window.render_frame(cx);
        let record = desktop.update(cx, |this, cx| this.selected_record(cx));
        let Some(gantry_desktop::workspace::Record::Secret(secret)) = record else {
            panic!("a secret is selected")
        };
        assert_eq!(secret.name, "GOPROXY_TOKEN@proxy.golang.org");
        assert!(window.try_find("secret-set").is_some());
        window.click(("segment", 2usize), cx);
    })
    .unwrap();
    cx.update_window(handle.into(), |_, window, cx| {
        window.render_frame(cx);
        // Only build's secret waits for the next start.
        assert!(window.try_find(("secret-card", 0usize)).is_some());
        assert!(window.try_find(("secret-card", 1usize)).is_none());
    })
    .unwrap();
}

#[gpui_kit::test]
fn mcp_cards_show_guardrails_and_the_inspector_owns_record_actions(cx: &mut TestAppContext) {
    let (handle, desktop) = desktop(cx);
    cx.update_window(handle.into(), |_, window, cx| {
        window.click(("page-nav", Page::Mcp.index()), cx);
    })
    .unwrap();
    cx.update_window(handle.into(), |_, window, cx| {
        window.render_frame(cx);
        assert!(window.try_find(("mcp-card", 3usize)).is_some());
        // Per-record actions live in the inspector while it is open.
        assert!(window.try_find("row-remove").is_none());
        assert!(window.try_find("mcp-remove").is_some());
        window.click(("segment", 2usize), cx);
    })
    .unwrap();
    cx.update_window(handle.into(), |_, window, cx| {
        window.render_frame(cx);
        let record = desktop.update(cx, |this, cx| this.selected_record(cx));
        let Some(gantry_desktop::workspace::Record::Mcp(server)) = record else {
            panic!("an MCP server is selected")
        };
        assert_eq!(server.name, "github");
        assert!(window.try_find(("mcp-card", 1usize)).is_none());
    })
    .unwrap();
}

#[gpui_kit::test]
fn audit_reads_as_one_timeline_newest_first(cx: &mut TestAppContext) {
    let (handle, desktop) = desktop(cx);
    cx.update_window(handle.into(), |_, window, cx| {
        window.click(("page-nav", Page::Audit.index()), cx);
    })
    .unwrap();
    cx.update_window(handle.into(), |_, window, cx| {
        window.render_frame(cx);
        let times: Vec<i64> = desktop.read(cx).pages[Page::Audit.index()]
            .table
            .read(cx)
            .delegate()
            .rows
            .iter()
            .filter_map(|row| match &row.record {
                gantry_desktop::workspace::Record::Audit(event) => {
                    gantry_desktop::clock::parse(&event.time)
                }
                _ => None,
            })
            .collect();
        assert_eq!(times.len(), 11, "every demo event carries a time");
        assert!(times.windows(2).all(|pair| pair[0] >= pair[1]));
        assert!(window.try_find("audit-raw").is_some());
        window.click(("segment", 2usize), cx);
    })
    .unwrap();
    cx.update_window(handle.into(), |_, window, cx| {
        window.render_frame(cx);
        assert!(window.try_find(("audit-event", 4usize)).is_some());
        assert!(window.try_find(("audit-event", 5usize)).is_none());
    })
    .unwrap();
}

#[gpui_kit::test]
fn local_images_show_usage_and_filter_by_it(cx: &mut TestAppContext) {
    let (handle, desktop) = desktop(cx);
    cx.update_window(handle.into(), |_, window, cx| {
        window.click(("page-nav", Page::Images.index()), cx);
    })
    .unwrap();
    cx.update_window(handle.into(), |_, window, cx| {
        window.render_frame(cx);
        assert!(window.try_find(("image-card", 5usize)).is_some());
        window.click(("segment", 2usize), cx);
    })
    .unwrap();
    cx.update_window(handle.into(), |_, window, cx| {
        window.render_frame(cx);
        // ghcr.io/acme/api:1.8 and python:3.12 are unused.
        assert!(window.try_find(("image-card", 1usize)).is_some());
        assert!(window.try_find(("image-card", 2usize)).is_none());
        let record = desktop.update(cx, |this, cx| this.selected_record(cx));
        let Some(gantry_desktop::workspace::Record::Image(image)) = record else {
            panic!("an image is selected")
        };
        assert!(!image.in_use && image.used_by.is_empty());
    })
    .unwrap();
}

#[gpui_kit::test]
fn registries_show_logins_their_sources_and_images(cx: &mut TestAppContext) {
    let (handle, desktop) = desktop(cx);
    cx.update_window(handle.into(), |_, window, cx| {
        window.click(("page-nav", Page::Images.index()), cx);
        window.click(("segment", 2usize), cx);
        window.click("registries-nav", cx);
    })
    .unwrap();
    let selected = |cx: &mut TestAppContext| {
        desktop.update(cx, |this, cx| match this.selected_record(cx) {
            Some(gantry_desktop::workspace::Record::Registry(r)) => r,
            other => panic!("a registry is selected, not {other:?}"),
        })
    };
    cx.update_window(handle.into(), |_, window, cx| {
        window.render_frame(cx);
        // The image segment does not carry over; logins come first.
        assert_eq!(desktop.read(cx).pages[Page::Images.index()].segment, 0);
        assert!(window.try_find(("image-card", 0usize)).is_none());
        assert!(window.try_find(("registry-card", 4usize)).is_some());
        assert!(window.try_find("registry-login-zone").is_some());
    })
    .unwrap();
    // docker.io is held by Docker's helper: logging out is offered.
    let docker = selected(cx);
    assert_eq!(docker.registry, "docker.io");
    cx.update_window(handle.into(), |_, window, cx| {
        window.render_frame(cx);
        assert!(window.try_find(("registry-image", 4usize)).is_some());
        window.click(("registry-card", 2usize), cx);
    })
    .unwrap();
    // registry.gitlab.com comes from Podman: the manager cannot erase it.
    assert_eq!(selected(cx).registry, "registry.gitlab.com");
    cx.update_window(handle.into(), |_, window, cx| {
        window.render_frame(cx);
        assert!(window.try_find(("registry-image", 0usize)).is_none());
        window.click(("segment", 2usize), cx);
    })
    .unwrap();
    cx.update_window(handle.into(), |_, window, cx| {
        window.render_frame(cx);
        // quay.io and gcr.io pull anonymously.
        assert!(window.try_find(("registry-card", 1usize)).is_some());
        assert!(window.try_find(("registry-card", 2usize)).is_none());
        window.click(("segment", 0usize), cx);
    })
    .unwrap();
    cx.update_window(handle.into(), |_, window, cx| {
        window.render_frame(cx);
        window.click(("registry-card", 1usize), cx);
    })
    .unwrap();
    assert_eq!(selected(cx).registry, "ghcr.io");
    cx.update_window(handle.into(), |_, window, cx| {
        window.render_frame(cx);
        window.click(("registry-image", 0usize), cx);
    })
    .unwrap();
    // An image in the inspector opens it in Local Images.
    cx.update_window(handle.into(), |_, window, cx| {
        window.render_frame(cx);
        assert!(!desktop.read(cx).images_registries);
        assert!(window.try_find(("image-card", 0usize)).is_some());
        let record = desktop.update(cx, |this, cx| this.selected_record(cx));
        let Some(gantry_desktop::workspace::Record::Image(image)) = record else {
            panic!("an image is selected")
        };
        assert_eq!(image.r#ref, "ghcr.io/acme/api:1.8");
    })
    .unwrap();
}
