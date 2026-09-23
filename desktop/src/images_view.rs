//! Local Images: where the disk space goes. Size bars, the sandboxes that use
//! each image, and what pruning unused images would reclaim.

use crate::{
    app::*,
    screens::InspectorView,
    theme,
    widgets::{self, TileAccent},
};
use gantry_desktop::{
    clock,
    dashboard_wire::Image,
    detail::split_image,
    forms::Kind,
    summary,
    telemetry::bytes_label,
    workspace::{Page, Record, text},
};
use gpui_kit::assets::IconName;
use gpui_kit::component::{ActiveTheme, Disableable, Icon, Sizable, button::Button};
use gpui_kit::{
    App, Context, Div, FontWeight, InteractiveElement, ParentElement, Styled, TestSupportExt, div,
    prelude::FluentBuilder, px,
};

impl Desktop {
    pub fn images_status(&self) -> String {
        let summary = summary::images(&self.host);
        format!(
            "{} image{} · {} on disk",
            summary.images,
            if summary.images == 1 { "" } else { "s" },
            bytes_label(summary.bytes)
        )
    }

    pub fn images_summary(&self, cx: &mut Context<Self>) -> Div {
        let summary = summary::images(&self.host);
        let share = if summary.bytes == 0 {
            0.
        } else {
            1. - summary.reclaimable as f32 / summary.bytes as f32
        };
        let tiles = widgets::tiles([
            widgets::tile(
                "IMAGES",
                summary.images.to_string(),
                "cached on this manager".into(),
                TileAccent::None,
                cx,
            ),
            widgets::tile(
                "ON DISK",
                bytes_label(summary.bytes),
                format!("{:.0}% used by sandboxes", share * 100.),
                TileAccent::Ratio(share, theme::bar(cx)),
                cx,
            ),
            widgets::tile(
                "IN USE",
                summary.in_use.to_string(),
                format!(
                    "by {} sandbox{}",
                    summary.sandboxes,
                    if summary.sandboxes == 1 { "" } else { "es" }
                ),
                TileAccent::None,
                cx,
            ),
            widgets::tile(
                "RECLAIMABLE",
                bytes_label(summary.reclaimable),
                format!(
                    "{} unused image{}",
                    summary.unused,
                    if summary.unused == 1 { "" } else { "s" }
                ),
                if summary.reclaimable > 0 {
                    TileAccent::Tint(cx.theme().warning)
                } else {
                    TileAccent::None
                },
                cx,
            ),
        ]);
        div().px_4().pt(px(12.)).pb(px(14.)).child(tiles)
    }

    pub fn images_list(&self, cx: &mut Context<Self>) -> Div {
        let state = &self.pages[Page::Images.index()];
        let rows = state.table.read(cx).delegate().rows.clone();
        let largest = self
            .host
            .snapshot
            .images
            .iter()
            .map(|i| i.size.max(0))
            .max()
            .unwrap_or(0)
            .max(1) as f32;
        let now = clock::now();
        let list = div().flex().flex_col().gap(px(6.)).px_4().pb(px(14.));
        if rows.is_empty() {
            return list.child(widgets::note(
                "No cached images. Pull one to get started.",
                cx,
            ));
        }
        let summary = summary::images(&self.host);
        list.children(rows.iter().enumerate().filter_map(|(index, row)| {
            let Record::Image(image) = &row.record else {
                return None;
            };
            let selected = state.selected.as_deref() == Some(row.key.as_str());
            let key = row.key.clone();
            Some(
                image_card(image, selected, image.size.max(0) as f32 / largest, now, cx)
                    .id(("image-card", index))
                    .test_support()
                    .cursor_pointer()
                    .on_mouse_down(
                        gpui_kit::MouseButton::Left,
                        cx.listener(move |this, _, _, cx| this.select_page_row(key.clone(), cx)),
                    ),
            )
        }))
        .when(summary.unused > 0, |d| {
            d.child(
                div()
                    .mt(px(6.))
                    .text_size(px(11.))
                    .text_color(cx.theme().muted_foreground)
                    .child(format!(
                        "Prune removes only images no sandbox references ({} · {}).",
                        summary.unused,
                        bytes_label(summary.reclaimable)
                    )),
            )
        })
    }

    pub fn image_inspector(&self, image: &Image, cx: &mut Context<Self>) -> InspectorView {
        let created = clock::parse(&image.created)
            .map(|then| format!("{} ago", clock::age(then, clock::now())))
            .unwrap_or_else(|| {
                if image.created.is_empty() {
                    "—".into()
                } else {
                    image.created.clone()
                }
            });
        let list = |items: &[String]| {
            if items.is_empty() {
                "—".to_owned()
            } else {
                items.join(" ")
            }
        };
        let (status, color) = if image.in_use {
            (
                format!("In use · {}", image.used_by.join(", ")),
                cx.theme().success,
            )
        } else {
            ("Unused".to_owned(), cx.theme().warning)
        };
        let body = div()
            .flex()
            .flex_col()
            .gap(px(14.))
            .child(widgets::inspector_section(
                "IMAGE",
                vec![
                    ("Digest", image.digest.clone(), true),
                    ("Architecture", image.arch.clone(), false),
                    ("Size", bytes_label(image.size.max(0) as u64), false),
                    ("Created", created, false),
                ],
                cx,
            ))
            .child(widgets::separator(cx))
            .child(widgets::inspector_section(
                "RUNTIME CONFIG",
                vec![
                    (
                        "User",
                        if image.user.is_empty() {
                            "root".into()
                        } else {
                            image.user.clone()
                        },
                        true,
                    ),
                    (
                        "Working dir",
                        if image.working_dir.is_empty() {
                            "/".into()
                        } else {
                            image.working_dir.clone()
                        },
                        true,
                    ),
                    ("Entrypoint", list(&image.entrypoint), true),
                    ("Command", list(&image.cmd), true),
                    (
                        "Environment",
                        format!(
                            "{} variable{}",
                            image.env_count,
                            if image.env_count == 1 { "" } else { "s" }
                        ),
                        false,
                    ),
                ],
                cx,
            ))
            .child(widgets::separator(cx))
            .child(if image.in_use {
                div()
                    .flex()
                    .flex_col()
                    .gap(px(10.))
                    .child(crate::views::eyebrow("USED BY", cx))
                    .child(
                        div()
                            .flex()
                            .flex_wrap()
                            .gap(px(6.))
                            .children(image.used_by.iter().map(|name| sandbox_chip(name, cx))),
                    )
            } else {
                widgets::inspector_note(
                    IconName::Trash,
                    cx.theme().warning,
                    "No sandbox uses this image.",
                    "Prune unused images, or remove this one, to reclaim its space.",
                    cx,
                )
            })
            .child(
                div()
                    .flex()
                    .flex_wrap()
                    .gap_2()
                    .child(self.form_button("image-new-sandbox", "New Sandbox…", Kind::Create, cx))
                    .child(
                        Button::new("image-remove")
                            .small()
                            .label("Remove…")
                            .when(self.can_write() && !image.in_use, |b| {
                                b.text_color(cx.theme().danger)
                            })
                            // Removing an image a sandbox still boots from is refused.
                            .disabled(!self.can_write() || image.in_use)
                            .on_click(
                                cx.listener(|this, _, window, cx| this.remove_selected(window, cx)),
                            ),
                    ),
            );
        InspectorView {
            header: widgets::inspector_header(
                IconName::Layers,
                &image.r#ref,
                Some((&status, color)),
                self.source_name(),
                cx,
            ),
            body,
            footer: format!("Inspecting an image on {}", self.source_name()),
        }
    }
}

fn sandbox_chip(name: &str, cx: &App) -> Div {
    div()
        .flex()
        .items_center()
        .gap(px(4.))
        .px(px(7.))
        .py(px(2.))
        .rounded(px(4.))
        .bg(theme::tint(cx.theme().success, cx))
        .text_size(px(11.))
        .child(
            Icon::new(IconName::Box)
                .size(px(12.))
                .text_color(cx.theme().success),
        )
        .child(text(name))
}

fn image_card(image: &Image, selected: bool, fraction: f32, now: i64, cx: &App) -> Div {
    let (prefix, name) = split_image(&image.r#ref);
    let digest = image
        .digest
        .strip_prefix("sha256:")
        .map(|hex| format!("sha256:{}", &hex[..hex.len().min(12)]))
        .unwrap_or_else(|| image.digest.clone());
    let age = clock::parse(&image.created)
        .map(|then| format!(" · {} old", clock::age(then, now)))
        .unwrap_or_default();
    div()
        .flex()
        .items_center()
        .gap(px(12.))
        .px(px(12.))
        .py(px(8.))
        .rounded(px(7.))
        .bg(if selected {
            theme::tint(cx.theme().primary, cx)
        } else {
            theme::card(cx)
        })
        .border_1()
        .border_color(if selected {
            cx.theme().primary
        } else {
            theme::card_border(cx)
        })
        .child(
            Icon::new(IconName::Layers)
                .size(px(17.))
                .text_color(cx.theme().muted_foreground),
        )
        .child(
            div()
                .flex()
                .flex_col()
                .gap(px(3.))
                .w(px(250.))
                .flex_shrink_0()
                .min_w(px(0.))
                .child(
                    div()
                        .flex()
                        .min_w(px(0.))
                        .font_family(cx.theme().mono_font_family.clone())
                        .text_size(px(12.))
                        .font_weight(FontWeight::MEDIUM)
                        .when(!prefix.is_empty(), |d| {
                            d.child(
                                div()
                                    .truncate()
                                    .text_color(cx.theme().muted_foreground)
                                    .child(text(prefix)),
                            )
                        })
                        .child(div().flex_shrink_0().child(text(name))),
                )
                .child(
                    div()
                        .truncate()
                        .font_family(cx.theme().mono_font_family.clone())
                        .text_size(px(10.))
                        .text_color(cx.theme().muted_foreground)
                        .child(format!("{digest}{age}")),
                ),
        )
        .child(widgets::chip(&image.arch, cx.theme().muted_foreground, cx))
        .child(div().flex_1().min_w(px(60.)).child(crate::charts::meter(
            fraction,
            if image.in_use {
                theme::bar(cx)
            } else {
                cx.theme().warning
            },
            theme::track(cx),
        )))
        .child(
            div()
                .w(px(64.))
                .flex_shrink_0()
                .text_right()
                .text_size(px(12.))
                .child(bytes_label(image.size.max(0) as u64)),
        )
        .child(
            div()
                .flex()
                .flex_wrap()
                .gap(px(4.))
                .w(px(130.))
                .flex_shrink_0()
                .children(if image.in_use {
                    image
                        .used_by
                        .iter()
                        .map(|name| sandbox_chip(name, cx))
                        .collect()
                } else {
                    vec![widgets::chip("unused", cx.theme().warning, cx)]
                }),
        )
}
