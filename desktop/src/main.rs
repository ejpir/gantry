mod app;
mod dashboard_table;
mod sandbox_table;
mod theme;
mod ui_forms;
mod views;
mod workbench;

#[cfg(all(test, feature = "ui-tests"))]
mod dashboard_ui_tests;
#[cfg(all(test, feature = "ui-tests"))]
mod ui_tests;

use gantry_desktop::options::{HELP, Options, SocketDefaults};
use gpui_kit::component::Root;
use gpui_kit::{
    App, AppContext, Bounds, KeyBinding, Menu, MenuItem, TitlebarOptions, WindowBounds,
    WindowOptions, px, size,
};

use app::{CloseForm, Desktop, FocusInventory, FocusSearch, Quit, Refresh};

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
            cx.set_menus(vec![Menu {
                name: "Gantry".into(),
                items: vec![MenuItem::action("Quit Gantry", Quit)],
                disabled: false,
            }]);
            cx.on_window_closed(|cx, _| {
                if cx.windows().is_empty() {
                    cx.quit();
                }
            })
            .detach();
            let bounds = Bounds::centered(None, size(px(1280.), px(800.)), cx);
            cx.spawn(async move |cx| {
                if let Err(err) = cx.open_window(
                    WindowOptions {
                        window_bounds: Some(WindowBounds::Windowed(bounds)),
                        window_min_size: Some(size(px(1040.), px(640.))),
                        titlebar: Some(TitlebarOptions {
                            title: Some("Gantry Desktop".into()),
                            ..Default::default()
                        }),
                        app_id: Some("com.gantry.desktop".into()),
                        ..Default::default()
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
        KeyBinding::new("/", FocusSearch, Some("DataTable")),
        KeyBinding::new("escape", CloseForm, Some("GantryDesktop")),
    ]);
}
