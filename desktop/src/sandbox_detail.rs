//! The selected sandbox, in the middle pane under the list: live network
//! throughput and destinations, plus the sandbox's ports, mounts, secrets, MCP
//! servers, and audit events. Everything is read from the dashboard snapshot.

use crate::{
    app::*,
    charts, theme,
    views::eyebrow,
    widgets::{card, chip, decision, mono, note, state_label},
};
use gantry_desktop::{
    dashboard_wire::Sandbox as DashboardSandbox,
    detail::{self, Tab},
    options::Source,
    telemetry::{bytes_label, rate_label},
    workspace::text,
};
use gpui_kit::assets::IconName;
use gpui_kit::component::{
    ActiveTheme, Icon, Selectable, Sizable,
    button::{Button, ButtonVariants},
    scroll::ScrollableElement,
};
use gpui_kit::{
    App, Context, Div, FontWeight, Hsla, InteractiveElement, IntoElement, ParentElement, Styled,
    TestSupportExt, div, prelude::FluentBuilder, px,
};

impl Desktop {
    pub fn sandbox_detail(&self, cx: &mut Context<Self>) -> Div {
        let pane = div()
            .id("sandbox-detail")
            .test_support()
            .flex()
            .flex_col()
            .flex_1()
            .min_h(px(0.))
            .border_t_1()
            .border_color(cx.theme().border);
        let Some(row) = self.inventory.selected() else {
            return div().flex().flex_col().flex_1().min_h(px(0.)).child(
                pane.items_center().justify_center().child(
                    div()
                        .text_size(px(12.))
                        .text_color(cx.theme().muted_foreground)
                        .child("Select a sandbox to see its traffic, ports, mounts, and more."),
                ),
            );
        };
        let name = row.name.clone();
        let sandbox = self.host.snapshot.sandboxes.iter().find(|s| s.name == name);
        let header = div()
            .flex()
            .items_center()
            .gap_3()
            .h(px(42.))
            .flex_shrink_0()
            .px(px(16.))
            .bg(cx.theme().secondary)
            .border_b_1()
            .border_color(cx.theme().border)
            .child(Icon::new(IconName::Box).size(px(16.)))
            .child(
                div()
                    .max_w(px(160.))
                    .truncate()
                    .text_size(px(13.))
                    .font_weight(FontWeight::SEMIBOLD)
                    .child(name.clone()),
            )
            .child(self.detail_tabs(&name, cx))
            .child(div().flex_1())
            .child(
                div()
                    .flex_shrink_0()
                    .text_size(px(10.))
                    .text_color(cx.theme().muted_foreground)
                    .child(if self.options.source == Source::Demo {
                        "Demo · sample traffic"
                    } else {
                        "3 s samples · this window"
                    }),
            );
        let body = match self.detail_tab {
            Tab::Network => self.network_tab(&name, sandbox, cx),
            Tab::Ports => self.ports_tab(&name, cx),
            Tab::Mounts => self.mounts_tab(&name, cx),
            Tab::Secrets => self.secrets_tab(&name, cx),
            Tab::Mcp => self.mcp_tab(&name, cx),
            Tab::Audit => self.audit_tab(&name, cx),
        };
        div().flex().flex_col().flex_1().min_h(px(0.)).child(
            pane.child(header).child(
                div()
                    .id("detail-scroll")
                    .flex_1()
                    .min_h(px(0.))
                    .overflow_y_scrollbar()
                    .child(div().px(px(20.)).py(px(14.)).child(body)),
            ),
        )
    }

    fn detail_tabs(&self, sandbox: &str, cx: &mut Context<Self>) -> Div {
        div()
            .flex()
            .flex_shrink_0()
            .p(px(2.))
            .rounded(px(5.))
            .bg(cx.theme().background)
            .border_1()
            .border_color(cx.theme().border)
            .children(Tab::ALL.into_iter().enumerate().map(|(index, tab)| {
                let label = match tab.count(&self.host, sandbox) {
                    Some(count) => format!("{}  {count}", tab.label()),
                    None => tab.label().to_owned(),
                };
                let selected = self.detail_tab == tab;
                Button::new(("detail-tab", index))
                    .ghost()
                    .xsmall()
                    .h(px(21.))
                    .px_3()
                    .label(label)
                    .selected(selected)
                    .when(selected, |b| b.bg(theme::selected_control(cx)))
                    .on_click(cx.listener(move |this, _, _, cx| {
                        this.detail_tab = tab;
                        cx.notify();
                    }))
            }))
    }

    fn network_tab(&self, name: &str, sandbox: Option<&DashboardSandbox>, cx: &App) -> Div {
        let Some(sandbox) = sandbox else {
            return note(
                "This manager does not report traffic. Upgrade it to see network activity.",
                cx,
            );
        };
        let rates = self.throughput.rates(name);
        let peak = self.throughput.peak(name);
        let latest = self.throughput.latest(name);
        let status = if sandbox.state != "running" {
            Some("Not running")
        } else if !sandbox.traffic_available {
            Some("Not reported by the manager")
        } else if rates.len() < 2 {
            Some("Measuring…")
        } else {
            None
        };
        let tile = |id: &'static str,
                    label: &str,
                    value: Option<f64>,
                    peak: f64,
                    color: Hsla,
                    series: Vec<f32>| {
            card(cx)
                .id(id)
                .test_support()
                .flex_1()
                .min_w(px(0.))
                .gap(px(4.))
                .child(
                    div()
                        .flex()
                        .items_center()
                        .child(eyebrow(label, cx))
                        .child(div().flex_1())
                        .when(status.is_none(), |d| {
                            d.child(
                                div()
                                    .text_size(px(10.))
                                    .text_color(cx.theme().muted_foreground)
                                    .child(format!("peak {}", rate_label(peak))),
                            )
                        }),
                )
                .child(
                    div()
                        .text_size(px(18.))
                        .font_weight(FontWeight::SEMIBOLD)
                        .child(match (status, value) {
                            (None, Some(value)) => rate_label(value),
                            _ => "—".into(),
                        }),
                )
                .child(match status {
                    None => div()
                        .h(px(34.))
                        .child(charts::sparkline(series, color, true).size_full()),
                    Some(status) => div()
                        .h(px(34.))
                        .flex()
                        .items_end()
                        .text_size(px(11.))
                        .text_color(cx.theme().muted_foreground)
                        .child(status),
                })
        };
        let dropped = card(cx)
            .id("detail-dropped")
            .test_support()
            .w(px(128.))
            .flex_shrink_0()
            .gap(px(4.))
            .child(eyebrow("DROPPED", cx))
            .child(
                div()
                    .text_size(px(18.))
                    .font_weight(FontWeight::SEMIBOLD)
                    .child(if sandbox.traffic_available {
                        sandbox.dropped_packets.to_string()
                    } else {
                        "—".into()
                    }),
            )
            .child(
                div()
                    .text_size(px(11.))
                    .text_color(cx.theme().muted_foreground)
                    .child("packets"),
            );
        let tiles = div()
            .flex()
            .gap(px(12.))
            .child(tile(
                "detail-download",
                "DOWNLOAD",
                latest.map(|r| r.down),
                peak.down,
                theme::download(cx),
                rates.iter().map(|r| r.down as f32).collect(),
            ))
            .child(tile(
                "detail-upload",
                "UPLOAD",
                latest.map(|r| r.up),
                peak.up,
                theme::upload(cx),
                rates.iter().map(|r| r.up as f32).collect(),
            ))
            .child(dropped);
        let destinations = detail::destinations(&self.host, name);
        let max = destinations
            .iter()
            .map(|d| d.bytes)
            .max()
            .unwrap_or(0)
            .max(1) as f32;
        let list = div()
            .flex()
            .flex_col()
            .children(destinations.iter().enumerate().map(|(i, d)| {
                div()
                    .id(("destination", i))
                    .test_support()
                    .flex()
                    .items_center()
                    .gap(px(14.))
                    .h(px(28.))
                    .px(px(8.))
                    .rounded(px(4.))
                    .when(i % 2 == 1, |row| row.bg(cx.theme().table_even))
                    .child(
                        div()
                            .w(px(230.))
                            .flex_shrink_0()
                            .truncate()
                            .font_family(cx.theme().mono_font_family.clone())
                            .text_size(px(12.))
                            .text_color(if d.allowed {
                                cx.theme().foreground
                            } else {
                                cx.theme().danger
                            })
                            .child(text(&format!("{}:{}", d.label, d.port))),
                    )
                    .child(div().flex_1().min_w(px(40.)).child(charts::meter(
                        (d.bytes as f32 / max).sqrt(),
                        if d.allowed {
                            theme::bar(cx)
                        } else {
                            cx.theme().danger
                        },
                        theme::track(cx),
                    )))
                    .child(
                        div()
                            .w(px(64.))
                            .flex_shrink_0()
                            .text_right()
                            .text_size(px(12.))
                            .child(bytes_label(d.bytes)),
                    )
                    .child(
                        div()
                            .w(px(76.))
                            .flex_shrink_0()
                            .child(decision(d.allowed, cx)),
                    )
            }));
        div()
            .flex()
            .flex_col()
            .gap(px(14.))
            .child(tiles)
            .child(
                div()
                    .flex()
                    .items_center()
                    .child(eyebrow("DESTINATIONS", cx))
                    .child(div().flex_1())
                    .child(
                        div()
                            .text_size(px(10.))
                            .text_color(cx.theme().muted_foreground)
                            .child(format!(
                                "{} · by bytes · bars are square-root scaled",
                                plural(destinations.len(), "destination")
                            )),
                    ),
            )
            .child(if destinations.is_empty() {
                note("No traffic observed for this sandbox yet.", cx)
            } else {
                list
            })
    }

    fn ports_tab(&self, name: &str, cx: &App) -> Div {
        let ports: Vec<_> = self
            .host
            .snapshot
            .ports
            .iter()
            .filter(|p| p.sandbox == name)
            .collect();
        if ports.is_empty() {
            return note("No published ports. Publish one from the Ports screen.", cx);
        }
        rows(ports.iter().map(|port| {
            line(cx)
                .child(mono(&port.bind, cx).w(px(180.)))
                .child(arrow(cx))
                .child(mono(&format!(":{} {}", port.guest, port.proto), cx).flex_1())
                .child(state_label(&port.state, &port.error, cx))
        }))
    }

    fn mounts_tab(&self, name: &str, cx: &App) -> Div {
        let mounts: Vec<_> = self
            .host
            .snapshot
            .mounts
            .iter()
            .filter(|m| m.sandbox == name)
            .collect();
        if mounts.is_empty() {
            return note("No shared folders. Add one from the Mounts screen.", cx);
        }
        rows(mounts.iter().map(|mount| {
            line(cx)
                .child(
                    Icon::new(IconName::Folder)
                        .size(px(14.))
                        .text_color(cx.theme().muted_foreground),
                )
                .child(mono(&mount.host, cx).flex_1())
                .child(arrow(cx))
                .child(mono(&mount.guest, cx).flex_1())
                .child(chip(
                    if mount.read_only {
                        "read-only"
                    } else {
                        "read-write"
                    },
                    if mount.read_only {
                        cx.theme().muted_foreground
                    } else {
                        cx.theme().warning
                    },
                    cx,
                ))
                .child(state_label(&mount.state, &mount.error, cx))
        }))
    }

    fn secrets_tab(&self, name: &str, cx: &App) -> Div {
        let secrets: Vec<_> = self
            .host
            .snapshot
            .secrets
            .iter()
            .filter(|s| s.sandbox == name)
            .collect();
        if secrets.is_empty() {
            return note(
                "No secrets. Values are never shown here; add them from Secrets.",
                cx,
            );
        }
        rows(secrets.iter().map(|secret| {
            line(cx)
                .child(
                    Icon::new(IconName::KeyRound)
                        .size(px(14.))
                        .text_color(cx.theme().warning),
                )
                .child(mono(&secret.name, cx).w(px(260.)))
                .child(
                    mono("••••••••••", cx)
                        .flex_1()
                        .text_color(cx.theme().muted_foreground),
                )
                .child(state_label(&secret.state, "", cx))
        }))
    }

    fn mcp_tab(&self, name: &str, cx: &App) -> Div {
        let servers: Vec<_> = self
            .host
            .snapshot
            .mcp_servers
            .iter()
            .filter(|s| s.sandbox == name)
            .collect();
        if servers.is_empty() {
            return note("No MCP servers configured for this sandbox.", cx);
        }
        rows(servers.iter().map(|server| {
            let target = if server.url.is_empty() {
                &server.root
            } else {
                &server.url
            };
            line(cx)
                .child(
                    Icon::new(IconName::Plug)
                        .size(px(14.))
                        .text_color(cx.theme().muted_foreground),
                )
                .child(
                    div()
                        .w(px(120.))
                        .truncate()
                        .text_size(px(12.))
                        .font_weight(FontWeight::MEDIUM)
                        .child(text(&server.name)),
                )
                .child(chip(&server.r#type, cx.theme().primary, cx))
                .child(
                    mono(target, cx)
                        .flex_1()
                        .text_color(cx.theme().muted_foreground),
                )
                .child(state_label(&server.state, &server.error, cx))
        }))
    }

    fn audit_tab(&self, name: &str, cx: &App) -> Div {
        let events: Vec<_> = self
            .host
            .snapshot
            .audit
            .iter()
            .filter(|e| e.sandbox == name)
            .collect();
        if events.is_empty() {
            return note("No audit events recorded for this sandbox.", cx);
        }
        rows(events.iter().rev().map(|event| {
            let denied = event
                .decision
                .as_ref()
                .map(|d| d.effect == "deny")
                .unwrap_or_else(|| event.line.contains("denied"));
            line(cx)
                .child(
                    div()
                        .size(px(7.))
                        .flex_shrink_0()
                        .rounded_full()
                        .bg(if denied {
                            cx.theme().danger
                        } else {
                            cx.theme().success
                        }),
                )
                .child(mono(&event.line, cx).flex_1())
                .when(event.occurrence > 1, |d| {
                    d.child(
                        div()
                            .text_size(px(11.))
                            .text_color(cx.theme().muted_foreground)
                            .child(format!("×{}", event.occurrence)),
                    )
                })
        }))
    }
}

fn plural(n: usize, noun: &str) -> String {
    format!("{n} {noun}{}", if n == 1 { "" } else { "s" })
}

fn rows(items: impl Iterator<Item = Div>) -> Div {
    div().flex().flex_col().gap(px(6.)).children(items)
}

fn line(cx: &App) -> Div {
    div()
        .flex()
        .items_center()
        .gap(px(12.))
        .h(px(36.))
        .px(px(12.))
        .rounded(px(6.))
        .bg(theme::card(cx))
        .border_1()
        .border_color(theme::card_border(cx))
}

fn arrow(cx: &App) -> impl IntoElement {
    Icon::new(IconName::MoveRight)
        .size(px(16.))
        .text_color(theme::download(cx))
}
