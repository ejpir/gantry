//! Interaction checks use GPUI's test windows, not a mock of our event handlers.
//! Native rendering, platform integration, and accessibility still need review.

use gantry_desktop::{
    inventory::Filter,
    options::{Appearance, Options, Source},
};
use gpui_kit::component::{ActiveTheme, Root};
use gpui_kit::test::TestWindowExt;
use gpui_kit::{AppContext, Entity, TestAppContext, WindowHandle, px, size};

use crate::{
    app::{Connection, Desktop},
    bind_keys,
};

pub(crate) fn desktop(cx: &mut TestAppContext) -> (WindowHandle<Root>, Entity<Desktop>) {
    desktop_at(cx, 1280., 800.)
}

pub(crate) fn desktop_at(
    cx: &mut TestAppContext,
    width: f32,
    height: f32,
) -> (WindowHandle<Root>, Entity<Desktop>) {
    cx.update(|cx| {
        gpui_kit::init(cx);
        bind_keys(cx);
    });
    let mut desktop = None;
    let window = cx.open_window(size(px(width), px(height)), |window, cx| {
        let view = cx.new(|cx| {
            Desktop::new(
                Options {
                    source: Source::Demo,
                    appearance: Appearance::Dark,
                    auto_start: false,
                    gantry: None,
                    managed_gantry: None,
                },
                window,
                cx,
            )
        });
        desktop = Some(view.clone());
        Root::new(view, window, cx)
    });
    (window, desktop.unwrap())
}

#[gpui_kit::test]
fn search_keeps_its_state_and_subscription_across_theme_redraws(cx: &mut TestAppContext) {
    let (handle, desktop) = desktop(cx);
    cx.update_window(handle.into(), |_, window, cx| {
        window.click("sandbox-search", cx);
        window.input("debi", cx);
    })
    .unwrap();
    // GPUI delivers emitted Input/Table events at the end of the app update.
    // Assert in the next update, as a user sees them on the next frame.
    cx.update_window(handle.into(), |_, window, cx| {
        assert_eq!(desktop.read(cx).inventory.visible().len(), 1);
        assert_eq!(desktop.read(cx).inventory.selected().unwrap().name, "dev");
        window.click("appearance", cx);
        assert!(!cx.theme().is_dark());
        window.click("sandbox-search", cx);
        window.input("an", cx);
    })
    .unwrap();
    cx.update_window(handle.into(), |_, window, cx| {
        window.render_frame(cx);
        assert_eq!(window.find("sandbox-search").value(), Some("debian"));
        assert_eq!(desktop.read(cx).inventory.query, "debian");
        assert_eq!(desktop.read(cx).inventory.visible().len(), 1);
        assert_eq!(desktop.read(cx).options.appearance, Appearance::Light);
    })
    .unwrap();
}

#[gpui_kit::test]
fn row_click_and_arrow_keys_update_the_inspector(cx: &mut TestAppContext) {
    let (handle, desktop) = desktop(cx);
    cx.update_window(handle.into(), |_, window, cx| {
        window.click(("row", 1usize), cx);
    })
    .unwrap();
    cx.update_window(handle.into(), |_, window, cx| {
        assert_eq!(desktop.read(cx).inventory.selected().unwrap().name, "build");
        window.press("down", cx);
    })
    .unwrap();
    cx.update_window(handle.into(), |_, window, cx| {
        assert_eq!(desktop.read(cx).inventory.selected().unwrap().name, "dev");
        window.press("up", cx);
    })
    .unwrap();
    cx.update_window(handle.into(), |_, window, cx| {
        assert_eq!(desktop.read(cx).inventory.selected().unwrap().name, "build");
        window.press("/", cx);
        assert_eq!(window.find("sandbox-search").focused(), Some(true));
        window.input("alpine", cx);
    })
    .unwrap();
    cx.update_window(handle.into(), |_, window, cx| {
        window.press("enter", cx);
    })
    .unwrap();
    cx.update_window(handle.into(), |_, window, cx| {
        window.render_frame(cx);
        assert_eq!(desktop.read(cx).inventory.selected().unwrap().name, "agent");
        assert_eq!(window.find(("row", 0usize)).selected(), Some(true));
    })
    .unwrap();
}

#[gpui_kit::test]
fn status_filter_reconciles_rows_and_selection(cx: &mut TestAppContext) {
    let (handle, desktop) = desktop(cx);
    cx.update_window(handle.into(), |_, window, cx| {
        window.click(("filter", 2usize), cx);
        assert_eq!(desktop.read(cx).inventory.filter, Filter::Stopped);
        assert_eq!(desktop.read(cx).inventory.visible().len(), 1);
        assert_eq!(desktop.read(cx).inventory.selected().unwrap().name, "build");
        window.click(("filter", 0usize), cx);
        assert_eq!(desktop.read(cx).inventory.visible().len(), 4);
        assert_eq!(desktop.read(cx).inventory.selected().unwrap().name, "build");
    })
    .unwrap();
}

#[gpui_kit::test]
fn inspector_fits_beside_the_sidebar_and_inventory(cx: &mut TestAppContext) {
    let (handle, _) = desktop(cx);
    cx.update_window(handle.into(), |_, window, cx| {
        window.render_frame(cx);
        let inventory = window.find("inventory-pane").bounds();
        let inspector = window.find("inspector-pane").bounds();
        assert!(inventory.left() >= px(184.));
        assert!(inventory.size.width >= px(420.));
        assert!(inspector.size.width >= px(280.));
        assert!(inventory.right() <= inspector.left());
        assert!(inspector.right() <= px(1280.));
    })
    .unwrap();
}

#[gpui_kit::test]
fn minimum_window_size_keeps_the_inspector_visible(cx: &mut TestAppContext) {
    let (handle, _) = desktop_at(cx, 1040., 640.);
    cx.update_window(handle.into(), |_, window, cx| {
        window.render_frame(cx);
        assert!(window.find("inspector-pane").bounds().right() <= px(1040.));
        assert!(window.find("inspector-pane").bounds().size.width >= px(280.));
        assert!(window.find("inventory-pane").bounds().size.width >= px(420.));
    })
    .unwrap();
}

#[gpui_kit::test]
fn a_missing_cli_explains_itself_and_offers_only_a_matching_install(cx: &mut TestAppContext) {
    let (handle, desktop) = desktop(cx);
    cx.update_window(handle.into(), |_, window, cx| {
        desktop.update(cx, |this, cx| {
            this.options.managed_gantry = Some("/home/test/.gantry/bin/gantry".into());
            this.connection = Connection::Offline("No Gantry CLI was found.".into());
            this.cli_missing = true;
            cx.notify();
        });
        window.render_frame(cx);
        assert!(window.try_find("retry-connection").is_some());
        // Untagged (development) test builds have no release to match. Never
        // click it here: that would start a real download.
        let offer = desktop.read(cx).cli_offer();
        assert_eq!(window.try_find("install-cli").is_some(), offer.is_some());
        if let Some(offer) = offer {
            let install = window.find("install-cli");
            let label = format!("Install Gantry CLI {}", offer.release);
            assert_eq!(install.label(), Some(label.as_str()));
        }
        desktop.update(cx, |this, cx| {
            this.cli_missing = false;
            cx.notify();
        });
        window.render_frame(cx);
        assert!(window.try_find("install-cli").is_none());
        assert!(window.try_find("retry-connection").is_some());
    })
    .unwrap();
}

#[gpui_kit::test]
fn sandbox_detail_follows_the_selection_and_its_tabs(cx: &mut TestAppContext) {
    let (handle, desktop) = desktop(cx);
    cx.update_window(handle.into(), |_, window, cx| {
        window.render_frame(cx);
        // The list is only as tall as its rows; the detail pane gets the rest.
        let list = window.find("sandbox-list").bounds();
        assert_eq!(list.size.height, px(28. + 34. * 4. + 2.));
        let detail = window.find("sandbox-detail").bounds();
        assert!(detail.top() >= list.bottom());
        assert!(detail.size.height > list.size.height);
        // Demo selects dev: live tiles and its six destinations, largest first.
        assert!(window.try_find("detail-download").is_some());
        assert!(window.try_find("detail-upload").is_some());
        assert!(window.try_find(("destination", 5usize)).is_some());
        assert!(window.try_find(("destination", 6usize)).is_none());
        window.click(("detail-tab", 1usize), cx);
    })
    .unwrap();
    cx.update_window(handle.into(), |_, window, cx| {
        window.render_frame(cx);
        assert_eq!(
            desktop.read(cx).detail_tab,
            gantry_desktop::detail::Tab::Ports
        );
        assert!(window.try_find("detail-download").is_none());
        window.click(("detail-tab", 0usize), cx);
        window.click(("row", 0usize), cx);
    })
    .unwrap();
    cx.update_window(handle.into(), |_, window, cx| {
        window.render_frame(cx);
        assert_eq!(desktop.read(cx).inventory.selected().unwrap().name, "agent");
        // agent has one allowed and one denied destination.
        assert!(window.try_find(("destination", 1usize)).is_some());
        assert!(window.try_find(("destination", 2usize)).is_none());
    })
    .unwrap();
}

#[gpui_kit::test]
fn collapsed_activity_still_shows_the_newest_entry(cx: &mut TestAppContext) {
    let (handle, desktop) = desktop(cx);
    cx.update_window(handle.into(), |_, window, cx| {
        window.render_frame(cx);
        assert!(window.try_find("activity-latest").is_none());
        desktop.update(cx, |this, cx| {
            this.begin_activity(7, None, "Settings saved · dev".into());
            this.activity_open = false;
            cx.notify();
        });
        window.render_frame(cx);
        assert!(window.try_find("activity-latest").is_some());
        window.click("activity-toggle", cx);
        window.render_frame(cx);
        assert!(window.try_find("activity-latest").is_none());
    })
    .unwrap();
}
