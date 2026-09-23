//! Secrets: names, never values. Masked cards grouped by sandbox, showing
//! whether each is loaded and, for `NAME@host`, the one host it is brokered to.

use crate::{
    app::*,
    screens::InspectorView,
    theme,
    widgets::{self, TileAccent},
};
use gantry_desktop::{
    dashboard_wire::Secret,
    forms::Kind,
    summary::{self, split_secret},
    workspace::{Page, Record, text},
};
use gpui_kit::assets::IconName;
use gpui_kit::component::{ActiveTheme, Disableable, Icon, Sizable, button::Button};
use gpui_kit::{
    App, Context, Div, FontWeight, InteractiveElement, ParentElement, Styled, TestSupportExt, div,
    prelude::FluentBuilder, px,
};

impl Desktop {
    pub fn secrets_summary(&self, cx: &mut Context<Self>) -> Div {
        let summary = summary::secrets(&self.host);
        let tiles = widgets::tiles([
            widgets::tile(
                "SECRETS",
                summary.secrets.to_string(),
                format!(
                    "for {} sandbox{}",
                    summary.sandboxes,
                    if summary.sandboxes == 1 { "" } else { "es" }
                ),
                TileAccent::None,
                cx,
            ),
            widgets::tile(
                "LOADED",
                summary.loaded.to_string(),
                "available to running sandboxes".into(),
                TileAccent::Ratio(
                    if summary.secrets == 0 {
                        0.
                    } else {
                        summary.loaded as f32 / summary.secrets as f32
                    },
                    cx.theme().success,
                ),
                cx,
            ),
            widgets::tile(
                "NEXT START",
                summary.pending.to_string(),
                "loads when it boots".into(),
                if summary.pending > 0 {
                    TileAccent::Tint(cx.theme().warning)
                } else {
                    TileAccent::None
                },
                cx,
            ),
            widgets::tile(
                "HOST-BOUND",
                summary.host_bound.to_string(),
                "served only for one host".into(),
                TileAccent::None,
                cx,
            ),
        ]);
        div().px_4().pt(px(12.)).pb(px(14.)).child(tiles)
    }

    pub fn secrets_list(&self, cx: &mut Context<Self>) -> Div {
        let state = &self.pages[Page::Secrets.index()];
        let rows = state.table.read(cx).delegate().rows.clone();
        let mut list = div().flex().flex_col().gap(px(8.)).px_4().pb(px(14.));
        let mut group: Option<(String, Div)> = None;
        let mut groups = Vec::new();
        for (index, row) in rows.iter().enumerate() {
            let Record::Secret(secret) = &row.record else {
                continue;
            };
            if group.as_ref().map(|(name, _)| name.as_str()) != Some(secret.sandbox.as_str()) {
                groups.extend(group.take());
                group = Some((
                    secret.sandbox.clone(),
                    div().flex().flex_wrap().gap(px(10.)),
                ));
            }
            let selected = state.selected.as_deref() == Some(row.key.as_str());
            let key = row.key.clone();
            let card = secret_card(secret, selected, cx)
                .id(("secret-card", index))
                .test_support()
                .cursor_pointer()
                .on_mouse_down(
                    gpui_kit::MouseButton::Left,
                    cx.listener(move |this, _, _, cx| this.select_page_row(key.clone(), cx)),
                );
            if let Some((_, cards)) = group.take() {
                group = Some((secret.sandbox.clone(), cards.child(card)));
            }
        }
        groups.extend(group);
        for (index, (sandbox, cards)) in groups.into_iter().enumerate() {
            list = list
                .child(
                    div()
                        .flex()
                        .items_center()
                        .gap(px(7.))
                        .when(index > 0, |d| d.mt(px(8.)))
                        .child(
                            Icon::new(IconName::Box)
                                .size(px(13.))
                                .text_color(cx.theme().success.opacity(0.85)),
                        )
                        .child(
                            div()
                                .text_size(px(12.))
                                .font_weight(FontWeight::SEMIBOLD)
                                .child(text(&sandbox)),
                        ),
                )
                .child(cards);
        }
        if rows.is_empty() {
            list = list.child(widgets::note("No secrets configured.", cx));
        }
        list.child(
            div()
                .mt(px(10.))
                .flex()
                .items_center()
                .gap(px(14.))
                .px(px(18.))
                .py(px(14.))
                .rounded(px(8.))
                .bg(theme::card(cx))
                .border_1()
                .border_color(theme::card_border(cx))
                .child(
                    Icon::new(IconName::ShieldCheck)
                        .size(px(20.))
                        .text_color(cx.theme().success),
                )
                .child(
                    div()
                        .flex()
                        .flex_col()
                        .gap(px(3.))
                        .child(
                            div()
                                .text_size(px(12.))
                                .font_weight(FontWeight::MEDIUM)
                                .child("This desktop never receives secret values."),
                        )
                        .child(
                            div()
                                .text_size(px(11.))
                                .text_color(cx.theme().muted_foreground)
                                .child(
                                    "The manager reports names and state only. New values are sent once, masked, and the form is discarded.",
                                ),
                        ),
                ),
        )
    }

    pub fn secret_inspector(&self, secret: &Secret, cx: &mut Context<Self>) -> InspectorView {
        let (name, host) = split_secret(&secret.name);
        let loaded = secret.state == "loaded";
        let (status, color) = if loaded {
            ("Loaded", cx.theme().success)
        } else {
            ("Next start", cx.theme().warning)
        };
        let body = div()
            .flex()
            .flex_col()
            .gap(px(14.))
            .child(widgets::inspector_section(
                "SECRET",
                vec![
                    ("Name", name.to_owned(), true),
                    (
                        "Delivered to",
                        host.map(str::to_owned)
                            .unwrap_or_else(|| "the sandbox environment".into()),
                        host.is_some(),
                    ),
                    ("Sandbox", secret.sandbox.clone(), false),
                    ("State", secret.state.clone(), false),
                ],
                cx,
            ))
            .child(widgets::separator(cx))
            .child(widgets::inspector_section(
                "VALUE",
                vec![("Stored value", "••••••••••••".into(), true)],
                cx,
            ))
            .child(widgets::inspector_note(
                IconName::ShieldCheck,
                cx.theme().success,
                "Write-only.",
                "Setting a new value never shows the old one; this window never receives it.",
                cx,
            ))
            .when_some(host, |d, host| {
                d.child(widgets::inspector_note(
                    IconName::Waypoints,
                    cx.theme().primary,
                    &format!("Brokered to {host}."),
                    "The credential broker hands it out only for this host, and only while the network policy allows that host.",
                    cx,
                ))
            })
            .when(!loaded, |d| {
                d.child(widgets::inspector_note(
                    IconName::RefreshCw,
                    cx.theme().warning,
                    "Loaded at the next start.",
                    "The sandbox is not running, so the secret is not in use yet.",
                    cx,
                ))
            })
            .child(
                div()
                    .flex()
                    .flex_wrap()
                    .gap_2()
                    .child(self.form_button(
                        "secret-set",
                        "Set value…",
                        Kind::Secret,
                        cx,
                    ))
                    .child(
                        Button::new("secret-remove")
                            .small()
                            .label("Remove…")
                            .when(self.can_write(), |b| b.text_color(cx.theme().danger))
                            .disabled(!self.can_write())
                            .on_click(cx.listener(|this, _, window, cx| {
                                this.remove_selected(window, cx)
                            })),
                    ),
            );
        InspectorView {
            header: widgets::inspector_header(
                IconName::KeyRound,
                name,
                Some((&format!("{status} · {}", secret.sandbox), color)),
                self.source_name(),
                cx,
            ),
            body,
            footer: format!(
                "Inspecting a secret of {} on {}",
                secret.sandbox,
                self.source_name()
            ),
        }
    }
}

fn secret_card(secret: &Secret, selected: bool, cx: &App) -> Div {
    let (name, host) = split_secret(&secret.name);
    let loaded = secret.state == "loaded";
    div()
        .flex()
        .flex_col()
        .gap(px(6.))
        .w(px(236.))
        .px(px(14.))
        .py(px(11.))
        .rounded(px(8.))
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
            div()
                .flex()
                .items_center()
                .gap(px(8.))
                .child(
                    Icon::new(IconName::KeyRound)
                        .size(px(14.))
                        .text_color(if loaded {
                            cx.theme().warning
                        } else {
                            cx.theme().muted_foreground
                        }),
                )
                .child(
                    widgets::mono(name, cx)
                        .flex_1()
                        .font_weight(FontWeight::SEMIBOLD),
                ),
        )
        .child(
            div()
                .flex()
                .items_center()
                .gap(px(8.))
                .child(
                    widgets::mono("••••••••••", cx)
                        .flex_1()
                        .text_color(cx.theme().muted_foreground),
                )
                .child(widgets::pill(
                    if loaded { "loaded" } else { "next start" },
                    if loaded {
                        cx.theme().success
                    } else {
                        cx.theme().warning
                    },
                    cx,
                )),
        )
        .when_some(host, |d, host| {
            d.child(
                div()
                    .flex()
                    .items_center()
                    .gap(px(5.))
                    .text_size(px(10.))
                    .text_color(cx.theme().primary)
                    .child(Icon::new(IconName::Waypoints).size(px(11.)))
                    .child(
                        div()
                            .truncate()
                            .child(format!("brokered to {}", text(host))),
                    ),
            )
        })
}
