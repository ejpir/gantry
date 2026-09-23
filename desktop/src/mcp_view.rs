//! MCP: servers with their guardrails. Each card shows where the server
//! points, how it authenticates (by reference, never a value), and which tools
//! the gateway allows, denies, or redacts.

use crate::{
    app::*,
    screens::InspectorView,
    theme,
    widgets::{self, TileAccent},
    workbench::mcp_edit,
};
use gantry_desktop::{
    dashboard_wire::MCPServer,
    summary::{self, mcp_auth},
    workspace::{Page, Record, text},
};
use gpui_kit::assets::IconName;
use gpui_kit::component::{ActiveTheme, Disableable, Icon, Sizable, button::Button};
use gpui_kit::{
    App, Context, Div, FontWeight, InteractiveElement, ParentElement, Styled, TestSupportExt, div,
    prelude::FluentBuilder, px,
};

impl Desktop {
    pub fn mcp_summary(&self, cx: &mut Context<Self>) -> Div {
        let summary = summary::mcp(&self.host);
        let tiles = widgets::tiles([
            widgets::tile(
                "SERVERS",
                summary.servers.to_string(),
                format!(
                    "for {} sandbox{}",
                    summary.sandboxes,
                    if summary.sandboxes == 1 { "" } else { "es" }
                ),
                TileAccent::None,
                cx,
            ),
            widgets::tile(
                "ACTIVE",
                summary.active.to_string(),
                "reachable through the gateway".into(),
                TileAccent::Ratio(
                    if summary.servers == 0 {
                        0.
                    } else {
                        summary.active as f32 / summary.servers as f32
                    },
                    cx.theme().success,
                ),
                cx,
            ),
            widgets::tile(
                "TOOL FILTERS",
                summary.filters.to_string(),
                "allow · deny · redact entries".into(),
                TileAccent::None,
                cx,
            ),
            widgets::tile(
                "ERRORS",
                summary.errors.to_string(),
                if summary.errors == 0 {
                    "every server configured".into()
                } else {
                    "a server needs attention".into()
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

    pub fn mcp_list(&self, cx: &mut Context<Self>) -> Div {
        let state = &self.pages[Page::Mcp.index()];
        let rows = state.table.read(cx).delegate().rows.clone();
        if rows.is_empty() {
            return widgets::note("No MCP servers configured.", cx).px_4();
        }
        div()
            .flex()
            .flex_col()
            .gap(px(10.))
            .px_4()
            .pb(px(14.))
            .children(rows.into_iter().enumerate().filter_map(|(index, row)| {
                let Record::Mcp(server) = &row.record else {
                    return None;
                };
                let selected = state.selected.as_deref() == Some(row.key.as_str());
                let key = row.key.clone();
                Some(
                    server_card(server, selected, cx)
                        .id(("mcp-card", index))
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

    pub fn mcp_inspector(&self, server: &MCPServer, cx: &mut Context<Self>) -> InspectorView {
        let (status, color) = status(server, cx);
        let local = server.r#type == "local";
        let mut details = vec![(
            "Kind",
            if local { "Local filesystem" } else { "Remote" }.to_owned(),
            false,
        )];
        if local {
            details.push(("Root", server.root.clone(), true));
            details.push(("User", server.user.clone(), true));
        } else {
            details.push(("URL", server.url.clone(), true));
            details.push(("Auth", mcp_auth(server), false));
        }
        details.push(("Sandbox", server.sandbox.clone(), false));
        details.push(("State", server.state.clone(), false));
        let body = div()
            .flex()
            .flex_col()
            .gap(px(14.))
            .child(widgets::inspector_section("SERVER", details, cx))
            .child(widgets::separator(cx))
            .when(!server.error.is_empty(), |d| {
                d.child(widgets::inspector_note(
                    IconName::CircleAlert,
                    cx.theme().danger,
                    "The server reported an error.",
                    &text(&server.error),
                    cx,
                ))
            })
            .when(server.state == "restart", |d| {
                d.child(widgets::inspector_note(
                    IconName::RefreshCw,
                    cx.theme().warning,
                    "Changes apply at the next start.",
                    "The running sandbox still uses the previous MCP configuration.",
                    cx,
                ))
            })
            .when(!local, |d| {
                d.child(crate::views::eyebrow("TOOL FILTERS", cx)).child(
                    if server.allow.is_empty() && server.deny.is_empty() && server.redact.is_empty()
                    {
                        widgets::note("No filters: the gateway passes every tool through.", cx)
                    } else {
                        filters(server, cx)
                    },
                )
            })
            .child(
                div()
                    .flex()
                    .flex_wrap()
                    .gap_2()
                    .when_some(mcp_edit(server), |d, kind| {
                        d.child(self.form_button("mcp-inspector-edit", "Edit filters…", kind, cx))
                    })
                    .child(
                        Button::new("mcp-remove")
                            .small()
                            .label("Remove…")
                            .when(self.can_write(), |b| b.text_color(cx.theme().danger))
                            .disabled(!self.can_write())
                            .on_click(
                                cx.listener(|this, _, window, cx| this.remove_selected(window, cx)),
                            ),
                    ),
            );
        InspectorView {
            header: widgets::inspector_header(
                IconName::Plug,
                &server.name,
                Some((&format!("{status} · {}", server.sandbox), color)),
                self.source_name(),
                cx,
            ),
            body,
            footer: format!(
                "Inspecting an MCP server of {} on {}",
                server.sandbox,
                self.source_name()
            ),
        }
    }
}

fn status(server: &MCPServer, cx: &App) -> (&'static str, gpui_kit::Hsla) {
    if !server.error.is_empty() {
        ("Error", cx.theme().danger)
    } else {
        match server.state.as_str() {
            "active" => ("Active", cx.theme().success),
            "restart" => ("Restart needed", cx.theme().warning),
            _ => ("Saved", cx.theme().muted_foreground),
        }
    }
}

fn filters(server: &MCPServer, cx: &App) -> Div {
    let row = |label: &'static str, items: &[String], color: gpui_kit::Hsla| {
        div()
            .flex()
            .items_start()
            .gap(px(10.))
            .child(
                div()
                    .w(px(44.))
                    .flex_shrink_0()
                    .pt(px(2.))
                    .text_size(px(10.))
                    .font_weight(FontWeight::SEMIBOLD)
                    .text_color(cx.theme().muted_foreground)
                    .child(label),
            )
            .child(
                div()
                    .flex()
                    .flex_wrap()
                    .gap(px(5.))
                    .children(items.iter().map(|item| widgets::chip(item, color, cx))),
            )
    };
    div()
        .flex()
        .flex_col()
        .gap(px(6.))
        .when(!server.allow.is_empty(), |d| {
            d.child(row("allow", &server.allow, cx.theme().success))
        })
        .when(!server.deny.is_empty(), |d| {
            d.child(row("deny", &server.deny, cx.theme().danger))
        })
        .when(!server.redact.is_empty(), |d| {
            d.child(row("redact", &server.redact, cx.theme().warning))
        })
}

fn server_card(server: &MCPServer, selected: bool, cx: &App) -> Div {
    let (status, color) = status(server, cx);
    let local = server.r#type == "local";
    let target = if local {
        format!("{} as {}", server.root, server.user)
    } else {
        server.url.clone()
    };
    div()
        .flex()
        .flex_col()
        .gap(px(7.))
        .px(px(16.))
        .py(px(12.))
        .rounded(px(8.))
        .bg(if selected {
            theme::tint(cx.theme().primary, cx)
        } else {
            theme::card(cx)
        })
        .border_1()
        .border_color(if selected {
            cx.theme().primary
        } else if !server.error.is_empty() {
            cx.theme().danger.opacity(0.5)
        } else {
            theme::card_border(cx)
        })
        .child(
            div()
                .flex()
                .items_center()
                .gap(px(8.))
                .child(
                    Icon::new(IconName::Plug)
                        .size(px(16.))
                        .text_color(cx.theme().muted_foreground),
                )
                .child(
                    div()
                        .text_size(px(14.))
                        .font_weight(FontWeight::SEMIBOLD)
                        .child(text(&server.name)),
                )
                .child(widgets::chip(
                    &server.r#type,
                    if local {
                        cx.theme().muted_foreground
                    } else {
                        cx.theme().primary
                    },
                    cx,
                ))
                .child(
                    div()
                        .flex()
                        .items_center()
                        .gap(px(4.))
                        .text_size(px(11.))
                        .text_color(cx.theme().muted_foreground)
                        .child(Icon::new(IconName::Box).size(px(12.)))
                        .child(text(&server.sandbox)),
                )
                .child(div().flex_1())
                .child(widgets::pill(status, color, cx)),
        )
        .child(widgets::mono(&target, cx).text_color(cx.theme().foreground.opacity(0.85)))
        .child(
            div()
                .text_size(px(11.))
                .text_color(cx.theme().muted_foreground)
                .child(text(&mcp_auth(server))),
        )
        .when(!server.error.is_empty(), |d| {
            d.child(
                div()
                    .flex()
                    .items_center()
                    .gap(px(6.))
                    .text_size(px(11.))
                    .text_color(cx.theme().danger)
                    .child(Icon::new(IconName::TriangleAlert).size(px(13.)))
                    .child(text(&server.error)),
            )
        })
        .when(
            !server.allow.is_empty() || !server.deny.is_empty() || !server.redact.is_empty(),
            |d| d.child(filters(server, cx)),
        )
}
