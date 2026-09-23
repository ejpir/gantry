use crate::{charts, theme, widgets};
use gantry_desktop::{
    clock,
    dashboard_wire::{HostSnapshot, Rule, Traffic},
    summary::{self, RuleOrigin},
    workspace::{Page, Record, Row},
};
use gpui_kit::assets::IconName;
use gpui_kit::component::{
    ActiveTheme, Icon,
    table::{Column, TableDelegate, TableState},
};
use gpui_kit::{
    App, Context, Div, InteractiveElement, IntoElement, ParentElement, Styled, Window, div, px,
};
use std::collections::HashMap;

/// Page-wide values a row needs to draw itself relative to its peers.
#[derive(Clone, Debug, Default)]
pub struct TableScale {
    /// Largest per-row volume, for proportional bars.
    pub max_bytes: u64,
    /// Colour slot per sandbox, shared with the page's legend.
    pub slots: HashMap<String, usize>,
    /// Captured once per refresh so every row's age agrees.
    pub now: i64,
}

impl TableScale {
    pub fn new(page: Page, host: &HostSnapshot) -> Self {
        match page {
            Page::Traffic => Self {
                max_bytes: host
                    .snapshot
                    .traffic
                    .iter()
                    .map(|r| r.tx_bytes.saturating_add(r.rx_bytes))
                    .max()
                    .unwrap_or(0),
                slots: sandbox_slots(host),
                now: clock::now(),
            },
            _ => Self::default(),
        }
    }
}

/// Largest-traffic sandbox first, then the rest by name, so colours are stable.
pub fn sandbox_slots(host: &HostSnapshot) -> HashMap<String, usize> {
    let mut names: Vec<String> = summary::traffic(host)
        .by_sandbox
        .into_iter()
        .map(|(name, _)| name)
        .collect();
    let mut others: Vec<&str> = host
        .snapshot
        .sandboxes
        .iter()
        .map(|s| s.name.as_str())
        .filter(|name| !names.iter().any(|n| n == name))
        .collect();
    others.sort();
    names.extend(others.into_iter().map(str::to_owned));
    names
        .into_iter()
        .enumerate()
        .map(|(i, name)| (name, i))
        .collect()
}

pub struct DashboardTable {
    pub rows: Vec<Row>,
    pub scale: TableScale,
    page: Page,
    columns: Vec<Column>,
}
impl DashboardTable {
    pub fn new(page: Page) -> Self {
        let widths: &[f32] = match page {
            Page::Traffic => &[104., 196., 76., 128., 70., 66., 56., 92.],
            Page::Rules => &[112., 88., 260., 132., 160.],
            Page::Packets => &[64., 104., 88., 96., 80., 360.],
            _ => &[],
        };
        Self {
            rows: vec![],
            scale: TableScale::default(),
            page,
            columns: page
                .columns()
                .iter()
                .enumerate()
                .map(|(i, label)| {
                    let default = if i == 1 { 260. } else { 170. };
                    Column::new(format!("column-{i}"), *label)
                        .width(widths.get(i).copied().unwrap_or(default))
                        .movable(false)
                })
                .collect(),
        }
    }

    /// Numeric columns read right-aligned, header included.
    fn right_aligned(&self, column: usize) -> bool {
        matches!(
            (self.page, column),
            (Page::Traffic, 4..=6) | (Page::Packets, 4)
        )
    }
}
impl TableDelegate for DashboardTable {
    fn columns_count(&self, _: &App) -> usize {
        self.columns.len()
    }
    fn rows_count(&self, _: &App) -> usize {
        self.rows.len()
    }
    fn column(&self, index: usize, _: &App) -> Column {
        self.columns[index].clone()
    }
    fn render_header(
        &mut self,
        _: &mut Window,
        _: &mut Context<TableState<Self>>,
    ) -> gpui_kit::Stateful<gpui_kit::Div> {
        div().id("header").h(px(28.)).overflow_hidden()
    }
    fn render_th(
        &mut self,
        column: usize,
        _: &mut Window,
        cx: &mut Context<TableState<Self>>,
    ) -> impl IntoElement {
        let cell = div()
            .flex()
            .items_center()
            .size_full()
            .text_size(px(11.))
            .child(self.column(column, cx).name.clone());
        if self.right_aligned(column) {
            cell.justify_end().pr(px(10.))
        } else {
            cell
        }
    }
    fn render_tr(
        &mut self,
        row: usize,
        _: &mut Window,
        cx: &mut Context<TableState<Self>>,
    ) -> gpui_kit::Stateful<gpui_kit::Div> {
        div().id(("row", row)).bg(if row % 2 == 1 {
            cx.theme().table_even
        } else {
            cx.theme().table
        })
    }
    fn render_td(
        &mut self,
        row: usize,
        column: usize,
        _: &mut Window,
        cx: &mut Context<TableState<Self>>,
    ) -> impl IntoElement {
        let cell = div()
            .flex()
            .items_center()
            .size_full()
            .overflow_hidden()
            .text_size(px(12.))
            .text_color(cx.theme().foreground);
        let previous = row.checked_sub(1).and_then(|i| self.rows.get(i));
        let row = &self.rows[row];
        match &row.record {
            Record::Traffic(flow) => return traffic_cell(cell, flow, column, &self.scale, cx),
            Record::Packet(packet) => {
                let cells = &row.cells;
                return packet_cell(
                    cell,
                    packet.allowed,
                    packet.direction == "tx",
                    cells,
                    column,
                    cx,
                );
            }
            Record::Rule(rule) => {
                // Rules arrive grouped by sandbox; name each group once.
                let first = !matches!(previous.map(|p| &p.record), Some(Record::Rule(p)) if p.sandbox == rule.sandbox);
                return rule_cell(cell, rule, first, column, cx);
            }
            _ => {}
        }
        cell.child(
            div()
                .truncate()
                .child(row.cells.get(column).cloned().unwrap_or_default()),
        )
    }
}

fn traffic_cell(cell: Div, flow: &Traffic, column: usize, scale: &TableScale, cx: &App) -> Div {
    let muted = cx.theme().muted_foreground;
    let bytes = flow.tx_bytes.saturating_add(flow.rx_bytes);
    match column {
        0 => cell
            .gap(px(7.))
            .child(
                div()
                    .size(px(7.))
                    .flex_shrink_0()
                    .rounded_full()
                    .bg(theme::series(
                        cx,
                        scale.slots.get(&flow.sandbox).copied().unwrap_or(0),
                    )),
            )
            .child(div().truncate().child(flow.sandbox.clone())),
        1 => cell.child(
            widgets::mono(
                if flow.host.is_empty() {
                    &flow.address
                } else {
                    &flow.host
                },
                cx,
            )
            .text_color(if flow.allowed {
                cx.theme().foreground
            } else {
                cx.theme().danger
            }),
        ),
        2 => cell.child(
            widgets::mono(&format!("{} {}", flow.protocol, flow.port), cx)
                .text_size(px(11.))
                .text_color(muted),
        ),
        3 => cell.pr(px(12.)).child(charts::meter(
            (bytes as f32 / scale.max_bytes.max(1) as f32).sqrt(),
            if flow.allowed {
                theme::bar(cx)
            } else {
                cx.theme().danger
            },
            theme::track(cx),
        )),
        4 => cell
            .justify_end()
            .pr(px(10.))
            .child(gantry_desktop::telemetry::bytes_label(bytes)),
        5 => cell.justify_end().pr(px(10.)).text_color(muted).child(
            gantry_desktop::telemetry::count_label(flow.tx_packets.saturating_add(flow.rx_packets)),
        ),
        6 => cell.justify_end().pr(px(10.)).text_color(muted).child(
            clock::parse(&flow.last_seen)
                .map(|then| clock::age(then, scale.now))
                .unwrap_or_else(|| "—".into()),
        ),
        _ => cell.child(widgets::decision(flow.allowed, cx)),
    }
}

fn rule_cell(cell: Div, rule: &Rule, first: bool, column: usize, cx: &App) -> Div {
    let muted = cx.theme().muted_foreground;
    match column {
        0 if first => cell
            .gap(px(7.))
            .font_weight(gpui_kit::FontWeight::MEDIUM)
            .child(Icon::new(IconName::Box).size(px(13.)).text_color(muted))
            .child(div().truncate().child(rule.sandbox.clone())),
        0 => cell,
        1 => cell.child(widgets::action_chip(&rule.action, cx)),
        2 => cell.child(widgets::mono(&rule.target, cx).text_color(if rule.error {
            cx.theme().danger
        } else {
            cx.theme().foreground
        })),
        3 => cell.child(
            widgets::mono(
                &if rule.ports.is_empty() {
                    rule.proto.clone()
                } else {
                    format!("{} {}", rule.proto, rule.ports)
                },
                cx,
            )
            .text_size(px(11.))
            .text_color(muted),
        ),
        _ => {
            let origin = RuleOrigin::of(rule);
            match &origin {
                RuleOrigin::Organization { .. } => cell.gap(px(6.)).child(
                    div()
                        .flex()
                        .items_center()
                        .gap(px(4.))
                        .child(
                            Icon::new(IconName::ShieldCheck)
                                .size(px(12.))
                                .text_color(cx.theme().warning),
                        )
                        .child(widgets::chip(&origin.label(), cx.theme().warning, cx)),
                ),
                RuleOrigin::Policy(_) | RuleOrigin::Domain => {
                    cell.child(widgets::chip(&origin.label(), cx.theme().primary, cx))
                }
                RuleOrigin::Managed(label) => cell
                    .text_size(px(11.))
                    .text_color(muted)
                    .child(label.clone()),
            }
        }
    }
}

/// Packet cells reuse the projected text (time, sizes, preview) and add colour.
fn packet_cell(
    cell: Div,
    allowed: bool,
    outbound: bool,
    cells: &[String],
    column: usize,
    cx: &App,
) -> Div {
    let text = cells.get(column).cloned().unwrap_or_default();
    let muted = cx.theme().muted_foreground;
    match column {
        0 => cell.child(widgets::mono(&text, cx)),
        1 => cell.child(
            widgets::mono(&text, cx)
                .text_size(px(11.))
                .text_color(muted),
        ),
        2 => cell
            .gap(px(5.))
            .text_color(if outbound {
                theme::download(cx)
            } else {
                theme::upload(cx)
            })
            .child(
                Icon::new(if outbound {
                    IconName::ArrowUp
                } else {
                    IconName::ArrowDown
                })
                .size(px(13.)),
            )
            .child(text),
        3 => cell.child(widgets::decision(allowed, cx)),
        4 => cell.justify_end().pr(px(10.)).child(text),
        _ => cell.child(
            widgets::mono(&text, cx)
                .text_size(px(11.))
                .text_color(muted),
        ),
    }
}
