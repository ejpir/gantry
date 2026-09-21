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
    for page in Page::ALL {
        cx.update_window(handle.into(), |_, window, cx| {
            window.click(("page-nav", page.index()), cx);
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
