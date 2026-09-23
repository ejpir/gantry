//! Shared building blocks for the dashboard screens, matching the design
//! studies in desktop/design: cards and summary tiles, pills and chips, and
//! the inspector's header, sections, and property rows.

use crate::{charts, theme, views::eyebrow};
use gantry_desktop::workspace::text;
use gpui_kit::assets::IconName;
use gpui_kit::component::{ActiveTheme, Icon};
use gpui_kit::{
    App, Div, FontWeight, Hsla, IntoElement, ParentElement, Styled, div, prelude::FluentBuilder, px,
};

pub fn card(cx: &App) -> Div {
    div()
        .flex()
        .flex_col()
        .p(px(12.))
        .rounded(px(8.))
        .bg(theme::card(cx))
        .border_1()
        .border_color(theme::card_border(cx))
}

/// Optional visual in the top-right corner of a summary tile.
pub enum TileAccent {
    None,
    /// Share of a whole, for example allowed out of all flows.
    Ratio(f32, Hsla),
    /// Tints the value, for counts that need attention.
    Tint(Hsla),
    Series(Vec<f32>, Hsla),
}

pub fn tile(label: &str, value: String, detail: String, accent: TileAccent, cx: &App) -> Div {
    let value_color = match &accent {
        TileAccent::Tint(color) => *color,
        _ => cx.theme().foreground,
    };
    let corner = match accent {
        TileAccent::Ratio(fraction, color) => Some(div().w(px(56.)).child(charts::meter(
            fraction,
            color,
            theme::track(cx),
        ))),
        TileAccent::Series(values, color) => Some(
            div()
                .w(px(60.))
                .h(px(22.))
                .child(charts::sparkline(values, color, false).size_full()),
        ),
        _ => None,
    };
    card(cx)
        .flex_1()
        .min_w(px(0.))
        .gap(px(3.))
        .py(px(10.))
        .child(eyebrow(label, cx))
        .child(
            div()
                .flex()
                .items_center()
                .gap_2()
                .child(
                    div()
                        .flex_1()
                        .min_w(px(0.))
                        .truncate()
                        .text_size(px(20.))
                        .font_weight(FontWeight::SEMIBOLD)
                        .text_color(value_color)
                        .child(value),
                )
                .children(corner),
        )
        .child(
            div()
                .truncate()
                .text_size(px(10.))
                .text_color(cx.theme().muted_foreground)
                .child(detail),
        )
}

pub fn tiles(items: impl IntoIterator<Item = Div>) -> Div {
    div().flex().gap(px(12.)).children(items)
}

pub fn note(message: &str, cx: &App) -> Div {
    div()
        .py(px(6.))
        .text_size(px(12.))
        .text_color(cx.theme().muted_foreground)
        .child(message.to_owned())
}

pub fn mono(value: &str, cx: &App) -> Div {
    div()
        .min_w(px(0.))
        .truncate()
        .font_family(cx.theme().mono_font_family.clone())
        .text_size(px(12.))
        .child(text(value))
}

pub fn chip(label: &str, color: Hsla, cx: &App) -> Div {
    div()
        .flex_shrink_0()
        .px(px(7.))
        .py(px(1.))
        .rounded(px(4.))
        .bg(theme::tint(color, cx))
        .text_size(px(10.))
        .text_color(color)
        .child(text(label))
}

pub fn pill(label: &str, color: Hsla, cx: &App) -> Div {
    div()
        .flex()
        .flex_shrink_0()
        .items_center()
        .gap(px(5.))
        .h(px(18.))
        .px(px(7.))
        .rounded_full()
        .bg(theme::tint(color, cx))
        .text_size(px(10.))
        .child(div().size(px(5.)).rounded_full().bg(color))
        .child(text(label))
}

pub fn decision(allowed: bool, cx: &App) -> Div {
    let color = if allowed {
        cx.theme().success
    } else {
        cx.theme().danger
    };
    pill(if allowed { "allowed" } else { "denied" }, color, cx)
}

/// A policy action as a coloured uppercase chip.
pub fn action_chip(action: &str, cx: &App) -> Div {
    let color = match action {
        "allow" => cx.theme().success,
        "deny" | "error" => cx.theme().danger,
        "resolve" => cx.theme().primary,
        _ => cx.theme().muted_foreground,
    };
    chip(&action.to_uppercase(), color, cx)
}

/// Manager state strings are shown as reported; an error wins over state.
pub fn state_label(state: &str, error: &str, cx: &App) -> Div {
    let error = !error.is_empty();
    let color = if error {
        cx.theme().danger
    } else if matches!(state, "active" | "live" | "running" | "mounted" | "bound") {
        cx.theme().success
    } else if state == "restart" {
        cx.theme().warning
    } else {
        cx.theme().muted_foreground
    };
    pill(if error { "error" } else { state }, color, cx)
}

pub fn section_title(label: &str, detail: String, cx: &App) -> Div {
    div()
        .flex()
        .items_center()
        .child(eyebrow(label, cx))
        .child(div().flex_1())
        .child(
            div()
                .text_size(px(10.))
                .text_color(cx.theme().muted_foreground)
                .child(detail),
        )
}

/// A horizontal bar split into coloured shares, each at least a sliver.
pub fn stacked_bar(parts: &[(f32, Hsla)], cx: &App) -> Div {
    let total: f32 = parts.iter().map(|(value, _)| value).sum();
    div()
        .flex()
        .gap(px(2.))
        .h(px(12.))
        .w_full()
        .rounded(px(3.))
        .overflow_hidden()
        .bg(theme::track(cx))
        .children(
            parts
                .iter()
                .filter(|(value, _)| *value > 0.)
                .map(|(value, color)| {
                    div()
                        .h_full()
                        .min_w(px(4.))
                        .flex_grow(0.)
                        .flex_shrink(1.)
                        .flex_basis(gpui_kit::relative(value / total.max(f32::EPSILON)))
                        .bg(*color)
                }),
        )
}

/// Stacked columns of (allowed, denied) counts, denied on top in red.
pub fn histogram(buckets: &[(u32, u32)], cx: &App) -> Div {
    let max = buckets
        .iter()
        .map(|(allowed, denied)| allowed + denied)
        .max()
        .unwrap_or(0)
        .max(1) as f32;
    div()
        .flex()
        .items_end()
        .gap(px(2.))
        .h(px(56.))
        .w_full()
        .children(buckets.iter().map(|&(allowed, denied)| {
            let bar = |count: u32, color: Hsla| {
                div()
                    .w_full()
                    .h(gpui_kit::relative(count as f32 / max))
                    .when(count > 0, |d| d.min_h(px(2.)))
                    .bg(color)
            };
            div()
                .flex()
                .flex_col()
                .justify_end()
                .flex_1()
                .h_full()
                .gap(px(1.))
                .child(bar(denied, cx.theme().danger))
                .child(bar(allowed, theme::bar(cx)))
        }))
}

pub fn legend(items: impl IntoIterator<Item = (String, String, Hsla)>, cx: &App) -> Div {
    div()
        .flex()
        .flex_wrap()
        .gap_x(px(18.))
        .gap_y(px(4.))
        .text_size(px(11.))
        .children(items.into_iter().map(|(name, value, color)| {
            div()
                .flex()
                .items_center()
                .gap(px(6.))
                .child(div().size(px(8.)).rounded_full().bg(color))
                .child(text(&name))
                .child(div().text_color(cx.theme().muted_foreground).child(value))
        }))
}

// ---------------------------------------------------------------- inspector

pub fn inspector_header(
    icon: IconName,
    title: &str,
    status: Option<(&str, Hsla)>,
    source: String,
    cx: &App,
) -> Div {
    div()
        .flex()
        .flex_col()
        .gap(px(8.))
        .px(px(20.))
        .pt(px(20.))
        .pb(px(14.))
        .child(
            div()
                .flex()
                .items_center()
                .gap_3()
                .child(
                    Icon::new(icon)
                        .size(px(22.))
                        .text_color(cx.theme().muted_foreground),
                )
                .child(
                    div()
                        .min_w(px(0.))
                        .truncate()
                        .text_size(px(if title.chars().count() > 16 { 17. } else { 20. }))
                        .font_weight(FontWeight::SEMIBOLD)
                        .child(text(title)),
                ),
        )
        .child(
            div()
                .flex()
                .items_center()
                .justify_between()
                .text_size(px(12.))
                .when_some(status, |d, (label, color)| {
                    d.child(
                        div()
                            .flex()
                            .items_center()
                            .gap_2()
                            .child(div().size(px(6.)).rounded_full().bg(color))
                            .child(text(label)),
                    )
                })
                .child(
                    div()
                        .text_size(px(11.))
                        .text_color(cx.theme().muted_foreground)
                        .child(source),
                ),
        )
}

pub fn inspector_section(label: &str, rows: Vec<(&str, String, bool)>, cx: &App) -> Div {
    div()
        .flex()
        .flex_col()
        .gap(px(12.))
        .child(eyebrow(label, cx))
        .children(rows.into_iter().map(|(name, value, mono)| {
            div()
                .flex()
                .w_full()
                .items_center()
                .gap_3()
                .text_size(px(12.))
                .child(
                    div()
                        .flex_shrink_0()
                        .text_color(cx.theme().muted_foreground)
                        .child(name.to_owned()),
                )
                .child(
                    div()
                        .flex_1()
                        .min_w(px(0.))
                        .text_right()
                        .truncate()
                        .when(mono, |d| d.font_family(cx.theme().mono_font_family.clone()))
                        .child(text(&value)),
                )
        }))
}

pub fn inspector_note(icon: IconName, color: Hsla, title: &str, detail: &str, cx: &App) -> Div {
    div()
        .flex()
        .items_start()
        .gap_2()
        .child(Icon::new(icon).size(px(15.)).text_color(color))
        .child(
            div()
                .flex()
                .flex_col()
                .flex_1()
                .min_w(px(0.))
                .gap_1()
                .child(
                    div()
                        .text_size(px(12.))
                        .text_color(color)
                        .child(title.to_owned()),
                )
                .child(
                    div()
                        .text_size(px(11.))
                        .text_color(cx.theme().muted_foreground)
                        .child(detail.to_owned()),
                ),
        )
}

pub fn separator(cx: &App) -> impl IntoElement {
    div().h(px(1.)).w_full().bg(cx.theme().border)
}
