//! Ports: each published port drawn as a connection from a host endpoint to a
//! sandbox endpoint, so a port that is not bound, or is reachable from the
//! network, is obvious at a glance.

use crate::{
    app::*,
    screens::InspectorView,
    theme,
    widgets::{self, TileAccent},
};
use gantry_desktop::{
    dashboard_wire::Port,
    options::Source,
    summary::{self, BindScope},
    workspace::{Page, Record, text},
};
use gpui_kit::assets::IconName;
use gpui_kit::component::{
    ActiveTheme, Disableable, Icon, Sizable,
    button::{Button, ButtonVariants},
};
use gpui_kit::{
    App, ClipboardItem, Context, Div, FontWeight, InteractiveElement, ParentElement, Styled,
    TestSupportExt, div, prelude::FluentBuilder, px,
};

impl Desktop {
    pub fn ports_summary(&self, cx: &mut Context<Self>) -> Div {
        let summary = summary::ports(&self.host);
        let bound = if summary.published == 0 {
            0.
        } else {
            summary.bound as f32 / summary.published as f32
        };
        let tiles = widgets::tiles([
            widgets::tile(
                "PUBLISHED",
                summary.published.to_string(),
                format!(
                    "for {} sandbox{}",
                    summary.sandboxes,
                    if summary.sandboxes == 1 { "" } else { "es" }
                ),
                TileAccent::None,
                cx,
            ),
            widgets::tile(
                "BOUND",
                summary.bound.to_string(),
                "accepting connections".into(),
                TileAccent::Ratio(bound, cx.theme().success),
                cx,
            ),
            widgets::tile(
                "LOOPBACK ONLY",
                format!("{} of {}", summary.loopback, summary.published),
                if summary.network == 0 {
                    "nothing reachable from the network".into()
                } else {
                    format!("{} reachable from the network", summary.network)
                },
                if summary.network > 0 {
                    TileAccent::Tint(cx.theme().warning)
                } else {
                    TileAccent::None
                },
                cx,
            ),
            widgets::tile(
                "ERRORS",
                summary.errors.to_string(),
                if summary.errors == 0 {
                    "every port listed".into()
                } else {
                    "a sandbox could not list its ports".into()
                },
                if summary.errors > 0 {
                    TileAccent::Tint(cx.theme().danger)
                } else {
                    TileAccent::None
                },
                cx,
            ),
        ]);
        div().px_4().pt(px(12.)).pb(px(14.)).child(tiles)
    }

    pub fn ports_list(&self, cx: &mut Context<Self>) -> Div {
        let state = &self.pages[Page::Ports.index()];
        let rows = state.table.read(cx).delegate().rows.clone();
        if rows.is_empty() {
            return widgets::note(
                "No published ports. Publish one to reach a sandbox service from this host.",
                cx,
            )
            .px_4();
        }
        let host_label = match self.options.source {
            Source::Remote { .. } => "MANAGER HOST".to_owned(),
            _ => self.source_name().to_uppercase(),
        };
        div()
            .flex()
            .flex_col()
            .gap(px(10.))
            .px_4()
            .pb(px(14.))
            .child(
                div()
                    .flex()
                    .child(
                        div()
                            .w(px(250.))
                            .child(crate::views::eyebrow(&host_label, cx)),
                    )
                    .child(div().flex_1())
                    .child(
                        div()
                            .w(px(300.))
                            .child(crate::views::eyebrow("SANDBOX", cx)),
                    ),
            )
            .children(rows.into_iter().enumerate().filter_map(|(index, row)| {
                let Record::Port(port) = &row.record else {
                    return None;
                };
                let selected = state.selected.as_deref() == Some(row.key.as_str());
                let key = row.key.clone();
                Some(
                    port_card(port, selected, cx)
                        .id(("port-card", index))
                        .test_support()
                        .cursor_pointer()
                        .on_mouse_down(
                            gpui_kit::MouseButton::Left,
                            cx.listener(move |this, _, _, cx| {
                                this.select_page_row(key.clone(), cx)
                            }),
                        ),
                )
            }))
    }

    pub fn port_inspector(&self, port: &Port, cx: &mut Context<Self>) -> InspectorView {
        let scope = summary::bind_scope(&port.bind);
        let (host, host_port) = port
            .bind
            .rsplit_once(':')
            .map(|(host, port)| (host.to_owned(), port.to_owned()))
            .unwrap_or_else(|| (port.bind.clone(), "—".into()));
        let bound = port.state == "bound";
        let local = matches!(self.options.source, Source::Local(_));
        let remote = matches!(self.options.source, Source::Remote { .. });
        let address = port.bind.clone();
        let url = format!("http://{}", port.bind);
        let (status, color) = if !port.error.is_empty() {
            ("Error".to_owned(), cx.theme().danger)
        } else if bound {
            ("Bound".to_owned(), cx.theme().success)
        } else {
            (capitalized(&port.state), cx.theme().muted_foreground)
        };
        let body = div()
            .flex()
            .flex_col()
            .gap(px(14.))
            .child(widgets::inspector_section(
                "MAPPING",
                vec![
                    ("Host address", host.trim_matches(['[', ']']).to_owned(), true),
                    ("Host port", host_port, false),
                    ("Sandbox", port.sandbox.clone(), false),
                    ("Guest port", port.guest.to_string(), false),
                    ("Protocol", port.proto.to_uppercase(), false),
                    ("State", port.state.clone(), false),
                ],
                cx,
            ))
            .child(widgets::separator(cx))
            .when(!port.error.is_empty(), |d| {
                d.child(widgets::inspector_note(
                    IconName::CircleAlert,
                    cx.theme().danger,
                    "The manager reported an error.",
                    &text(&port.error),
                    cx,
                ))
            })
            .child(match scope {
                BindScope::Network => widgets::inspector_note(
                    IconName::TriangleAlert,
                    cx.theme().warning,
                    "Reachable from the network.",
                    "Other machines that can route to this host can connect. Bind to 127.0.0.1 to keep it local.",
                    cx,
                ),
                BindScope::Loopback => widgets::inspector_note(
                    IconName::ShieldCheck,
                    cx.theme().success,
                    "Loopback only.",
                    if !remote {
                        "Only programs on this machine can connect."
                    } else {
                        "Only programs on the manager's host can connect, not this desktop."
                    },
                    cx,
                ),
                BindScope::Unknown => div(),
            })
            .child(
                div()
                    .flex()
                    .flex_wrap()
                    .gap_2()
                    .child(
                        // Opening a remote manager's loopback address here would
                        // reach this machine instead, so only local ports open.
                        Button::new("port-open")
                            .small()
                            .primary()
                            .label("Open in Browser")
                            .disabled(!(local && bound && port.proto == "tcp"))
                            .on_click(move |_, _, cx| cx.open_url(&url)),
                    )
                    .child(
                        Button::new("port-copy")
                            .small()
                            .label("Copy Address")
                            .on_click(move |_, _, cx| {
                                cx.write_to_clipboard(ClipboardItem::new_string(address.clone()))
                            }),
                    )
                    .child(
                        Button::new("port-unpublish")
                            .small()
                            .label("Unpublish…")
                            .when(self.can_write(), |b| b.text_color(cx.theme().danger))
                            .disabled(!self.can_write())
                            .on_click(cx.listener(|this, _, window, cx| {
                                this.remove_selected(window, cx)
                            })),
                    ),
            );
        InspectorView {
            header: widgets::inspector_header(
                IconName::Network,
                &port.bind,
                Some((&format!("{status} · {}", port.sandbox), color)),
                self.source_name(),
                cx,
            ),
            body,
            footer: format!(
                "Inspecting a port of {} on {}",
                port.sandbox,
                self.source_name()
            ),
        }
    }
}

fn capitalized(value: &str) -> String {
    let mut chars = value.chars();
    chars
        .next()
        .map(|first| first.to_uppercase().chain(chars).collect())
        .unwrap_or_default()
}

fn port_card(port: &Port, selected: bool, cx: &App) -> Div {
    let failed = !port.error.is_empty();
    let bound = port.state == "bound";
    let link = if failed {
        cx.theme().danger
    } else if bound {
        theme::download(cx)
    } else {
        cx.theme().muted_foreground
    };
    let border = if selected {
        cx.theme().primary
    } else if failed {
        cx.theme().danger.opacity(0.5)
    } else {
        theme::card_border(cx)
    };
    let background = if selected {
        theme::tint(cx.theme().primary, cx)
    } else {
        theme::card(cx)
    };
    let endpoint = |width: f32| {
        div()
            .flex()
            .items_center()
            .gap(px(10.))
            .w(px(width))
            .flex_shrink_0()
            .h(px(58.))
            .px(px(12.))
            .rounded(px(8.))
            .bg(background)
            .border_1()
            .border_color(border)
    };
    let scope = summary::bind_scope(&port.bind);
    let host = endpoint(250.)
        .child(
            Icon::new(IconName::Monitor)
                .size(px(16.))
                .text_color(cx.theme().muted_foreground),
        )
        .child(
            div()
                .flex()
                .flex_col()
                .min_w(px(0.))
                .gap(px(3.))
                .child(
                    widgets::mono(&port.bind, cx)
                        .text_size(px(13.))
                        .font_weight(FontWeight::MEDIUM),
                )
                .child(
                    div()
                        .truncate()
                        .text_size(px(10.))
                        .text_color(if failed {
                            cx.theme().danger
                        } else if scope == BindScope::Network {
                            cx.theme().warning
                        } else {
                            cx.theme().muted_foreground
                        })
                        .child(if failed {
                            text(&port.error)
                        } else {
                            match scope {
                                BindScope::Loopback => "loopback only".into(),
                                BindScope::Network => "reachable from the network".into(),
                                BindScope::Unknown => "no host address".into(),
                            }
                        }),
                ),
        );
    let connection = div()
        .flex()
        .items_center()
        .flex_1()
        .min_w(px(80.))
        .px(px(4.))
        .child(
            div()
                .flex_1()
                .h(px(2.))
                .bg(link.opacity(if bound { 0.9 } else { 0.4 })),
        )
        .child(widgets::chip(&port.proto, link, cx))
        .child(
            div()
                .flex_1()
                .h(px(2.))
                .bg(link.opacity(if bound { 0.9 } else { 0.4 })),
        )
        .child(
            Icon::new(IconName::ChevronRight)
                .size(px(14.))
                .text_color(link),
        );
    let sandbox = endpoint(300.)
        .child(Icon::new(IconName::Box).size(px(16.)).text_color(if bound {
            cx.theme().success
        } else {
            cx.theme().muted_foreground
        }))
        .child(
            div()
                .flex()
                .flex_col()
                .flex_1()
                .min_w(px(0.))
                .gap(px(3.))
                .child(
                    div()
                        .truncate()
                        .text_size(px(13.))
                        .font_weight(FontWeight::SEMIBOLD)
                        .child(text(&port.sandbox)),
                )
                .child(
                    widgets::mono(&format!(":{} inside the sandbox", port.guest), cx)
                        .text_size(px(10.))
                        .text_color(cx.theme().muted_foreground),
                ),
        )
        .child(widgets::state_label(&port.state, &port.error, cx));
    div()
        .flex()
        .items_center()
        .child(host)
        .child(connection)
        .child(sandbox)
}
