//! Traffic: who each sandbox talks to. Summary tiles, the share of bytes per
//! sandbox, and an inspector that turns an observed flow into a rule.

use crate::{
    app::*,
    dashboard_table::sandbox_slots,
    screens::InspectorView,
    theme,
    widgets::{self, TileAccent},
};
use gantry_desktop::{
    clock,
    dashboard_wire::Traffic,
    summary,
    telemetry::{bytes_label, count_label},
};
use gpui_kit::assets::IconName;
use gpui_kit::component::ActiveTheme;
use gpui_kit::{Context, Div, ParentElement, Styled, div, prelude::FluentBuilder, px};

impl Desktop {
    pub fn traffic_summary(&self, cx: &mut Context<Self>) -> Div {
        let summary = summary::traffic(&self.host);
        let slots = sandbox_slots(&self.host);
        let share = if summary.flows == 0 {
            0.
        } else {
            summary.allowed as f32 / summary.flows as f32
        };
        let total = summary.sent.saturating_add(summary.received);
        let trend = self.combined_throughput();
        let tiles = widgets::tiles([
            widgets::tile(
                "FLOWS",
                summary.flows.to_string(),
                format!(
                    "{} · {}",
                    plural(summary.sandboxes, "sandbox", "sandboxes"),
                    plural(summary.hosts, "host", "hosts")
                ),
                TileAccent::None,
                cx,
            ),
            widgets::tile(
                "ALLOWED",
                summary.allowed.to_string(),
                format!("{:.0}% of flows", share * 100.),
                TileAccent::Ratio(share, cx.theme().success),
                cx,
            ),
            widgets::tile(
                "DENIED",
                summary.denied.to_string(),
                "blocked by network policy".into(),
                if summary.denied > 0 {
                    TileAccent::Tint(cx.theme().danger)
                } else {
                    TileAccent::None
                },
                cx,
            ),
            widgets::tile(
                "TRANSFERRED",
                bytes_label(total),
                format!(
                    "↓ {} · ↑ {}",
                    bytes_label(summary.received),
                    bytes_label(summary.sent)
                ),
                if trend.len() >= 2 {
                    TileAccent::Series(trend, theme::download(cx))
                } else {
                    TileAccent::None
                },
                cx,
            ),
        ]);
        let parts: Vec<_> = summary
            .by_sandbox
            .iter()
            .map(|(name, bytes)| {
                (
                    *bytes as f32,
                    theme::series(cx, slots.get(name).copied().unwrap_or(0)),
                )
            })
            .collect();
        div()
            .flex()
            .flex_col()
            .gap(px(10.))
            .px_4()
            .pt(px(12.))
            .pb(px(14.))
            .child(tiles)
            .when(total > 0, |d| {
                d.child(widgets::section_title(
                    "BYTES BY SANDBOX",
                    format!("{} total", bytes_label(total)),
                    cx,
                ))
                .child(widgets::stacked_bar(&parts, cx))
                .child(widgets::legend(
                    summary.by_sandbox.iter().map(|(name, bytes)| {
                        (
                            name.clone(),
                            bytes_label(*bytes),
                            theme::series(cx, slots.get(name).copied().unwrap_or(0)),
                        )
                    }),
                    cx,
                ))
            })
    }

    /// All sandboxes' throughput added up, aligned on the newest sample.
    fn combined_throughput(&self) -> Vec<f32> {
        let mut total: Vec<f32> = Vec::new();
        for sandbox in &self.host.snapshot.sandboxes {
            let rates = self.throughput.rates(&sandbox.name);
            if rates.len() > total.len() {
                let mut padded = vec![0.; rates.len() - total.len()];
                padded.extend(total);
                total = padded;
            }
            let offset = total.len() - rates.len();
            for (slot, rate) in total[offset..].iter_mut().zip(rates) {
                *slot += (rate.down + rate.up) as f32;
            }
        }
        total
    }

    pub fn traffic_inspector(&self, flow: &Traffic, cx: &mut Context<Self>) -> InspectorView {
        let title = if flow.host.is_empty() {
            &flow.address
        } else {
            &flow.host
        };
        let (status, color) = if flow.allowed {
            ("Allowed", cx.theme().success)
        } else {
            ("Denied", cx.theme().danger)
        };
        let now = clock::now();
        let seen = |value: &str| match clock::parse(value) {
            Some(then) => format!("{} UTC · {} ago", clock::clock(then), clock::age(then, now)),
            None => "—".into(),
        };
        let mut connection = vec![("Sandbox", flow.sandbox.clone(), false)];
        if !flow.host.is_empty() && !flow.address.is_empty() {
            connection.push(("Address", flow.address.clone(), true));
        }
        connection.push(("Protocol", flow.protocol.to_uppercase(), false));
        connection.push(("Port", flow.port.to_string(), false));
        let body = div()
            .flex()
            .flex_col()
            .gap(px(14.))
            .child(widgets::inspector_section("CONNECTION", connection, cx))
            .child(widgets::separator(cx))
            .child(widgets::inspector_section(
                "VOLUME",
                vec![
                    (
                        "Sent",
                        format!(
                            "{} · {}",
                            bytes_label(flow.tx_bytes),
                            packets(flow.tx_packets)
                        ),
                        false,
                    ),
                    (
                        "Received",
                        format!(
                            "{} · {}",
                            bytes_label(flow.rx_bytes),
                            packets(flow.rx_packets)
                        ),
                        false,
                    ),
                    ("First seen", seen(&flow.first_seen), false),
                    ("Last seen", seen(&flow.last_seen), false),
                ],
                cx,
            ))
            .child(widgets::separator(cx))
            .when(!flow.allowed, |d| {
                d.child(widgets::inspector_note(
                    IconName::ShieldAlert,
                    cx.theme().danger,
                    &format!("Denied by {}'s network policy.", flow.sandbox),
                    "Allow it below to add a rule, or review Network Rules.",
                    cx,
                ))
            })
            .child(
                div()
                    .flex()
                    .flex_wrap()
                    .gap_2()
                    .child(self.traffic_rule_button(
                        "inspector-allow",
                        "Allow destination…",
                        flow,
                        "allow",
                        cx,
                    ))
                    .child(self.traffic_rule_button(
                        "inspector-deny",
                        "Deny destination…",
                        flow,
                        "deny",
                        cx,
                    )),
            );
        InspectorView {
            header: widgets::inspector_header(
                IconName::ArrowLeftRight,
                title,
                Some((&format!("{status} · {}", flow.sandbox), color)),
                self.source_name(),
                cx,
            ),
            body,
            footer: format!(
                "Inspecting a flow from {} on {}",
                flow.sandbox,
                self.source_name()
            ),
        }
    }
}

fn plural(n: usize, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

fn packets(n: u64) -> String {
    format!("{} packet{}", count_label(n), if n == 1 { "" } else { "s" })
}
