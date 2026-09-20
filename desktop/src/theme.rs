use gantry_desktop::options::Appearance;
use gpui_kit::component::{Theme, ThemeColor, ThemeMode};
use gpui_kit::{App, Hsla, Window, px, rgb};

/// Keep this palette aligned with internal/dashboard/theme.go and the website.
/// Application views consume semantic tokens, never literal colors.
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
        selected,
        raised,
        text,
        muted,
        border,
        accent,
        accent_text,
        success,
        warning,
        error,
    ) = if mode.is_dark() {
        (
            0x101210, 0x171a17, 0x1c2419, 0x1e221d, 0xf0f1e9, 0xa6aca0, 0x30352e, 0xc2f36b,
            0x101210, 0xa8d58a, 0xe6c073, 0xeaa59b,
        )
    } else {
        (
            0xf7f8f3, 0xeef1e8, 0xe8eddf, 0xe6ebdd, 0x202819, 0x57634d, 0xd2dac7, 0x365b19,
            0xffffff, 0x3f6b28, 0x855513, 0x9f342e,
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
        primary_foreground: color(accent_text),
        primary_hover: color(accent),
        primary_active: color(accent),
        accent: color(selected),
        accent_foreground: color(text),
        muted: color(raised),
        muted_foreground: color(muted),
        secondary: color(panel),
        secondary_foreground: color(text),
        secondary_hover: color(raised),
        secondary_active: color(selected),
        button: color(panel),
        button_foreground: color(text),
        button_hover: color(raised),
        button_active: color(selected),
        button_primary: color(accent),
        button_primary_foreground: color(accent_text),
        button_primary_hover: color(accent),
        button_primary_active: color(accent),
        button_secondary: color(selected),
        button_secondary_foreground: color(text),
        button_secondary_hover: color(raised),
        button_secondary_active: color(selected),
        sidebar: color(panel),
        sidebar_foreground: color(text),
        sidebar_border: color(border),
        sidebar_accent: color(selected),
        sidebar_accent_foreground: color(text),
        popover: color(panel),
        popover_foreground: color(text),
        group_box: color(panel),
        group_box_foreground: color(text),
        list: color(bg),
        list_hover: color(panel),
        list_active: color(selected),
        list_active_border: color(accent),
        table: color(bg),
        table_head: color(panel),
        table_head_foreground: color(muted),
        table_hover: color(panel),
        table_active: color(selected),
        table_active_border: color(accent),
        table_row_border: color(border),
        table_even: color(bg),
        selection: color(accent).opacity(0.2),
        caret: color(accent),
        success: color(success),
        warning: color(warning),
        danger: color(error),
        scrollbar: color(bg).opacity(0.),
        scrollbar_thumb: color(muted).opacity(0.35),
        scrollbar_thumb_hover: color(muted).opacity(0.65),
        title_bar: color(panel),
        title_bar_border: color(border),
        status_bar: color(panel),
        status_bar_border: color(border),
        ..theme.colors
    };
    // Styled components read resolved fill tokens; Base owns resize handles and
    // scrollbars. Keep both in sync with our solid-color theme.
    theme.tokens = (&theme.colors).into();
    theme.font_size = px(14.);
    theme.mono_font_size = px(12.);
    theme.radius = px(6.);
    theme.radius_lg = px(8.);
    Theme::sync_base(cx);
    window.refresh();
}
