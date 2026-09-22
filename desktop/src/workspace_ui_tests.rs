use crate::{
    app::{Connection, Desktop},
    row_actions::RowAction,
    ui_tests::desktop_at,
};
use gantry_desktop::{connector::Target, forms::Kind, options::Source, workspace::Page};
use gpui_kit::component::ActiveTheme;
use gpui_kit::test::{TestAppContextExt, TestWindowExt};
use gpui_kit::{App, AppContext, Entity, TestAppContext, px, rgb};
use std::time::Duration;

fn connect(view: &Entity<Desktop>, cx: &mut App) {
    view.update(cx, |this, cx| {
        let source = Source::Local("/private/test/manager.sock".into());
        this.options.source = source.clone();
        this.target = Some(Target {
            source,
            profile: None,
        });
        this.connection = Connection::Connected("v1".into());
        this.set_filter(gantry_desktop::inventory::Filter::All, cx);
        cx.notify();
    });
}
#[gpui_kit::test]
fn design_dimensions_palette_and_pane_toggles(cx: &mut TestAppContext) {
    let (handle, desktop) = desktop_at(cx, 1344., 740.);
    cx.update_window(handle.into(), |_, window, cx| {
        window.render_frame(cx);
        assert_eq!(cx.theme().background, gpui_kit::Hsla::from(rgb(0x222429)));
        assert_eq!(cx.theme().table_active, gpui_kit::Hsla::from(rgb(0x315b89)));
        let list = window.find("inventory-pane").bounds();
        let inspector = window.find("inspector-pane").bounds();
        assert_eq!(list.top(), px(52.));
        assert_eq!(list.left(), px(208.));
        assert_eq!(inspector.size.width, px(328.));
        window.click("activity-toggle", cx);
        assert!(!desktop.read(cx).activity_open);
        window.click("inspector-toggle", cx);
        assert!(!desktop.read(cx).inspector_open);
        window.render_frame(cx);
        assert!(window.try_find("inspector-pane").is_none());
        assert_eq!(window.find("inventory-pane").bounds().right(), px(1344.));
    })
    .unwrap();
}
#[gpui_kit::test]
fn inline_settings_fit_inspector_and_never_retarget_to_a_new_selection(cx: &mut TestAppContext) {
    let (handle, desktop) = desktop_at(cx, 1040., 640.);
    cx.update_window(handle.into(), |_, window, cx| {
        connect(&desktop, cx);
        window.click("sandbox-edit", cx);
        window.render_frame(cx);
        assert!(desktop.read(cx).inline_form());
        assert!(window.try_find("form-overlay").is_none());
        let form = window.find("action-form").bounds();
        let pane = window.find("inspector-pane").bounds();
        assert!(form.left() >= pane.left() && form.right() <= pane.right());
        assert!(form.bottom() <= pane.bottom());
        // Changing the table selection cannot rewrite an already-open edit.
        desktop.update(cx, |this, cx| {
            this.inventory.select("build");
            this.set_filter(gantry_desktop::inventory::Filter::All, cx);
        });
        let Kind::Configure(request) = &desktop.read(cx).form.as_ref().unwrap().spec.kind else {
            panic!()
        };
        assert_eq!(request.name, "dev");
        window.click("form-cancel", cx);
        assert!(desktop.read(cx).form.is_none());
        assert!(!desktop.read(cx).writing);
    })
    .unwrap();
}
#[gpui_kit::test]
fn captured_context_action_rechecks_source_and_current_state(cx: &mut TestAppContext) {
    let (handle, desktop) = desktop_at(cx, 1344., 740.);
    cx.update_window(handle.into(), |_, window, cx| {
        connect(&desktop, cx);
        let target = desktop.read(cx).target.clone();
        desktop.update(cx, |this, cx| {
            this.inventory.select("agent");
            this.row_action("build", target.as_ref(), RowAction::Edit, window, cx);
            let Kind::Configure(request) = &this.form.as_ref().unwrap().spec.kind else {
                panic!()
            };
            assert_eq!(request.name, "build");
            this.close_form(window, cx);
            this.row_action("build", target.as_ref(), RowAction::Stop, window, cx);
            assert!(this.form.is_none(), "cannot stop a stopped sandbox");
            this.target = None;
            this.row_action("build", target.as_ref(), RowAction::Delete, window, cx);
            assert!(this.form.is_none());
            assert!(!this.writing);
        });
    })
    .unwrap();
}
#[gpui_kit::test]
async fn right_click_opens_a_scoped_menu_and_edits_that_row(cx: &mut TestAppContext) {
    let (handle, desktop) = desktop_at(cx, 1344., 740.);
    cx.update_window(handle.into(), |_, window, cx| {
        connect(&desktop, cx);
        window.right_click(("row", 1usize), cx); // build, not the previously selected dev
    })
    .unwrap();
    cx.wait_for(handle.into(), Duration::from_secs(1), |window, _| {
        window.try_find("popup-menu").is_some()
    })
    .await;
    cx.update_window(handle.into(), |_, window, cx| {
        assert_eq!(
            window.within("popup-menu").find(5usize).label(),
            Some("Edit Settings…")
        );
        desktop.update(cx, |this, cx| {
            this.inventory.select("agent");
            this.sync_table(cx);
        });
        window.within("popup-menu").click(5usize, cx);
    })
    .unwrap();
    cx.wait_for(handle.into(), Duration::from_secs(1), |_, cx| {
        desktop.read(cx).form.is_some()
    })
    .await;
    cx.update_window(handle.into(), |_, window, cx| {
        window.render_frame(cx);
        assert!(desktop.read(cx).context_menu.is_none());
        assert_eq!(window.find(("form-input", 0usize)).focused(), Some(true));
        let Kind::Configure(request) = &desktop.read(cx).form.as_ref().unwrap().spec.kind else {
            panic!()
        };
        assert_eq!(request.name, "build");
        assert!(
            desktop
                .read(cx)
                .form
                .as_ref()
                .unwrap()
                .scope
                .contains("/private/test/manager.sock")
        );
    })
    .unwrap();
}
#[gpui_kit::test]
async fn application_menu_reaches_overview_without_a_dashboard_sidebar_item(
    cx: &mut TestAppContext,
) {
    let (handle, desktop) = desktop_at(cx, 1040., 640.);
    cx.update_window(handle.into(), |_, window, cx| window.click("app-menu", cx))
        .unwrap();
    cx.wait_for(handle.into(), Duration::from_secs(1), |window, _| {
        window.try_find("popup-menu").is_some()
    })
    .await;
    cx.update_window(handle.into(), |_, window, cx| {
        window.within("popup-menu").click(0usize, cx)
    })
    .unwrap();
    cx.wait_for(handle.into(), Duration::from_secs(1), |_, cx| {
        desktop.read(cx).page == Page::Overview
    })
    .await;
}
