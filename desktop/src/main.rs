mod activity;
mod app;
mod chrome;
mod dashboard_table;
mod row_actions;
mod sandbox_table;
mod theme;
mod ui_forms;
mod views;
mod workbench;

#[cfg(all(test, feature = "ui-tests"))]
mod activity_tests;
#[cfg(all(test, feature = "ui-tests"))]
mod dashboard_ui_tests;
#[cfg(all(test, feature = "ui-tests"))]
mod ui_tests;
#[cfg(all(test, feature = "ui-tests"))]
mod workspace_ui_tests;

use gantry_desktop::options::{HELP, Options, SocketDefaults};
use gpui_kit::component::{
    Root, TitleBar,
    input::{Copy, Cut, Paste, Redo, SelectAll, Undo},
};
use gpui_kit::{
    App, AppContext, Bounds, KeyBinding, Menu, MenuItem, OsAction, TitlebarOptions, WindowBounds,
    WindowOptions, point, px, size,
};

use app::*;

fn main() -> anyhow::Result<()> {
    let Some(options) = Options::parse(std::env::args_os().skip(1), SocketDefaults::from_env())?
    else {
        print!("{HELP}");
        return Ok(());
    };
    gpui_kit::application()
        .with_assets(gpui_kit::assets::AllAssets)
        .run(move |cx| {
            gpui_kit::init(cx);
            bind_keys(cx);
            cx.on_action(|_: &Quit, cx| cx.quit());
            cx.set_menus(vec![
                Menu::new("Gantry").items([
                    MenuItem::action("Appearance", CycleAppearance),
                    MenuItem::separator(),
                    MenuItem::action("Quit Gantry", Quit),
                ]),
                Menu::new("File").items([
                    MenuItem::action("New Sandbox…", NewSandbox),
                    MenuItem::action("Connections…", ShowConnections),
                ]),
                Menu::new("Edit").items([
                    MenuItem::os_action("Undo", Undo, OsAction::Undo),
                    MenuItem::os_action("Redo", Redo, OsAction::Redo),
                    MenuItem::separator(),
                    MenuItem::os_action("Cut", Cut, OsAction::Cut),
                    MenuItem::os_action("Copy", Copy, OsAction::Copy),
                    MenuItem::os_action("Paste", Paste, OsAction::Paste),
                    MenuItem::os_action("Select All", SelectAll, OsAction::SelectAll),
                ]),
                Menu::new("Sandbox").items([
                    MenuItem::action("Start…", StartSandbox),
                    MenuItem::action("Stop…", StopSandbox),
                    MenuItem::separator(),
                    MenuItem::action("Edit Settings…", EditSandbox),
                    MenuItem::action("Delete…", DeleteSandbox),
                ]),
                Menu::new("View").items([
                    MenuItem::action("Sandboxes", FocusInventory),
                    MenuItem::action("Overview", ShowOverview),
                    MenuItem::action("Images", ShowImages),
                    MenuItem::separator(),
                    MenuItem::action("Search", FocusSearch),
                    MenuItem::action("Refresh", Refresh),
                    MenuItem::action("Toggle Inspector", ToggleInspector),
                    MenuItem::action("Toggle Activity", ToggleActivity),
                ]),
                Menu::new("Window").items([
                    MenuItem::action("Minimize", MinimizeWindow),
                    MenuItem::action("Zoom", ZoomWindow),
                    MenuItem::action("Toggle Full Screen", FullScreen),
                ]),
                Menu::new("Help").items([MenuItem::action("Gantry Manual", ShowManual)]),
            ]);
            cx.on_window_closed(|cx, _| {
                if cx.windows().is_empty() {
                    cx.quit();
                }
            })
            .detach();
            let bounds = Bounds::centered(None, size(px(1344.), px(740.)), cx);
            cx.spawn(async move |cx| {
                if let Err(err) = cx.open_window(
                    WindowOptions {
                        window_bounds: Some(WindowBounds::Windowed(bounds)),
                        window_min_size: Some(size(px(1040.), px(640.))),
                        titlebar: Some(TitlebarOptions {
                            title: Some("Gantry".into()),
                            appears_transparent: true,
                            traffic_light_position: Some(point(px(16.), px(19.))),
                        }),
                        app_id: Some("com.gantry.desktop".into()),
                        ..TitleBar::window_options()
                    },
                    |window, cx| {
                        let desktop = cx.new(|cx| Desktop::new(options, window, cx));
                        cx.new(|cx| Root::new(desktop, window, cx))
                    },
                ) {
                    eprintln!("Could not open Gantry Desktop: {err:#}");
                    cx.update(|cx| cx.quit());
                    return;
                }
                cx.update(|cx| cx.activate(true));
            })
            .detach();
        });
    Ok(())
}

fn bind_keys(cx: &mut App) {
    let modifier = if cfg!(target_os = "macos") {
        "cmd"
    } else {
        "ctrl"
    };
    cx.bind_keys([
        KeyBinding::new(&format!("{modifier}-q"), Quit, None),
        KeyBinding::new(&format!("{modifier}-r"), Refresh, Some("GantryDesktop")),
        KeyBinding::new(&format!("{modifier}-f"), FocusSearch, Some("GantryDesktop")),
        KeyBinding::new(
            &format!("{modifier}-1"),
            FocusInventory,
            Some("GantryDesktop"),
        ),
        KeyBinding::new(&format!("{modifier}-n"), NewSandbox, Some("GantryDesktop")),
        KeyBinding::new(&format!("{modifier}-i"), EditSandbox, Some("GantryDesktop")),
        KeyBinding::new(
            &format!("{modifier}-shift-i"),
            ToggleInspector,
            Some("GantryDesktop"),
        ),
        KeyBinding::new(
            &format!("{modifier}-j"),
            ToggleActivity,
            Some("GantryDesktop"),
        ),
        KeyBinding::new(
            &format!("{modifier}-m"),
            MinimizeWindow,
            Some("GantryDesktop"),
        ),
        KeyBinding::new("/", FocusSearch, Some("DataTable")),
        KeyBinding::new("escape", CloseForm, Some("GantryDesktop")),
    ]);
}
