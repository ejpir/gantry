//! Interaction checks use GPUI's test windows, not a mock of our event handlers.
//! Native rendering, platform integration, and accessibility still need review.

use gantry_desktop::{
    inventory::Filter,
    options::{Appearance, Options, Source},
};
use gpui_kit::component::{ActiveTheme, Root};
use gpui_kit::test::TestWindowExt;
use gpui_kit::{AppContext, Entity, TestAppContext, WindowHandle, px, size};

use crate::{app::Desktop, bind_keys};

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
