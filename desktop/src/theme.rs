use gantry_desktop::options::Appearance;
use gpui_kit::component::{ActiveTheme, Theme, ThemeColor, ThemeMode};
use gpui_kit::{App, Hsla, Window, px, rgb};

pub const SIDEBAR_WIDTH: f32 = 208.;
pub const INSPECTOR_WIDTH: f32 = 328.;
pub const TOOLBAR_HEIGHT: f32 = 52.;
pub const STATUS_HEIGHT: f32 = 24.;

pub fn selected_control(cx: &App) -> Hsla {
    rgb(if cx.theme().is_dark() {
        0x50555d
    } else {
        0xffffff
    })
    .into()
}

fn pick(cx: &App, dark: u32, light: u32) -> Hsla {
    rgb(if cx.theme().is_dark() { dark } else { light }).into()
}

/// Chart series from desktop/design/desktop-detail-study.svg.
pub fn download(cx: &App) -> Hsla {
    pick(cx, 0x7aa7e0, 0x2f6db5)
}

pub fn upload(cx: &App) -> Hsla {
    pick(cx, 0x6fc1c9, 0x1f8a93)
}

/// Bars and tracks on panel surfaces.
pub fn bar(cx: &App) -> Hsla {
    pick(cx, 0x5f8fc9, 0x4a7fc0)
}

pub fn track(cx: &App) -> Hsla {
    pick(cx, 0x30333a, 0xe3e5ea)
}

/// Cards on the middle pane (tiles, grouped rows).
pub fn card(cx: &App) -> Hsla {
    pick(cx, 0x2a2c31, 0xf7f7f9)
}

pub fn card_border(cx: &App) -> Hsla {
    pick(cx, 0x383b42, 0xdfe1e6)
}

/// A translucent pill behind a status label, readable on selected rows too.
pub fn tint(color: Hsla, cx: &App) -> Hsla {
    color.opacity(if cx.theme().is_dark() { 0.18 } else { 0.14 })
}

/// Distinguishes sandboxes in legends and shares, in a stable order.
pub fn series(cx: &App, slot: usize) -> Hsla {
    const DARK: [u32; 6] = [0x7aa7e0, 0x6fc1c9, 0x9a8fd6, 0xc9a86a, 0xd08bb0, 0x8fc48a];
    const LIGHT: [u32; 6] = [0x2f6db5, 0x1f8a93, 0x6a5cc2, 0x9a7328, 0xb0457f, 0x3f7f3b];
    let index = slot % DARK.len();
    pick(cx, DARK[index], LIGHT[index])
}

/// The checked-in desktop/design/desktop-workspace.svg is the dark-mode spec.
/// Keep custom chrome and toolkit components on the same semantic palette.
pub fn apply(appearance: Appearance, window: &mut Window, cx: &mut App) {
    let mode = match appearance {
        Appearance::System => ThemeMode::from(window.appearance()),
        Appearance::Dark => ThemeMode::Dark,
        Appearance::Light => ThemeMode::Light,
    };
    Theme::change(mode, None, cx);
    let color = |value| -> Hsla { rgb(value).into() };
    let (
        bg,
        panel,
        sidebar,
        toolbar,
        selected,
        raised,
        text,
        muted,
        border,
        accent,
        success,
        warning,
        error,
    ) = if mode.is_dark() {
        (
            0x222429, 0x2b2d32, 0x2e3035, 0x33353a, 0x315b89, 0x41444b, 0xe3e5e8, 0xa9b4c4,
            0x42454a, 0xa7c8f4, 0x90c47c, 0xddc58f, 0xefb3b3,
        )
    } else {
        (
            0xffffff, 0xf5f5f7, 0xececf0, 0xe6e6e9, 0xcde2fa, 0xdcdde2, 0x232730, 0x586273,
            0xd0d2d8, 0x245d9b, 0x38743c, 0x87651d, 0xa8363d,
        )
    };
    let theme = Theme::global_mut(cx);
    theme.colors = ThemeColor {
        background: color(bg),
        foreground: color(text),
        border: color(border),
        input: color(border),
        ring: color(accent),
        primary: color(accent),
        primary_foreground: color(bg),
        primary_hover: color(accent),
        primary_active: color(accent),
        accent: color(raised),
        accent_foreground: color(text),
        muted: color(raised),
        muted_foreground: color(muted),
        secondary: color(panel),
        secondary_foreground: color(text),
        secondary_hover: color(raised),
        secondary_active: color(selected),
        button: color(raised),
        button_foreground: color(text),
        button_hover: color(toolbar),
        button_active: color(selected),
        button_primary: color(selected),
        button_primary_foreground: color(text),
        button_primary_hover: color(selected),
        button_primary_active: color(selected),
        button_secondary: color(raised),
        button_secondary_foreground: color(text),
        button_secondary_hover: color(toolbar),
        button_secondary_active: color(selected),
        sidebar: color(sidebar),
        sidebar_foreground: color(text),
        sidebar_border: color(border),
        sidebar_accent: color(raised),
        sidebar_accent_foreground: color(text),
        popover: color(toolbar),
        popover_foreground: color(text),
        group_box: color(panel),
        group_box_foreground: color(text),
        list: color(bg),
        list_hover: color(panel),
        list_active: color(selected),
        list_active_border: color(selected),
        table: color(bg),
        table_head: color(panel),
        table_head_foreground: color(muted),
        table_hover: color(raised),
        table_active: color(selected),
        table_active_border: color(selected),
        table_row_border: color(bg),
        table_even: color(if mode.is_dark() { 0x292b30 } else { 0xf5f5f7 }),
        selection: color(selected),
        caret: color(accent),
        success: color(success),
        warning: color(warning),
        danger: color(error),
        scrollbar: color(bg).opacity(0.),
        scrollbar_thumb: color(muted).opacity(0.35),
        scrollbar_thumb_hover: color(muted).opacity(0.65),
        title_bar: color(toolbar),
        title_bar_border: color(border),
        status_bar: color(panel),
        status_bar_border: color(border),
        ..theme.colors
    };
    #[cfg(target_os = "linux")]
    {
        theme.font_family = "Adwaita Sans".into();
    }
    theme.tokens = (&theme.colors).into();
    // Toolkit small controls use 0.875rem; 15px yields the spec's ~13px
    // controls. Workspace text and pane geometry use explicit pixel sizes.
    theme.font_size = px(15.);
    theme.mono_font_size = px(12.);
    theme.radius = px(5.);
    theme.radius_lg = px(8.);
    Theme::sync_base(cx);
    window.refresh();
}
