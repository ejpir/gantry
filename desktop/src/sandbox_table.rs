use crate::{charts, theme};
use gantry_desktop::{
    connector::Target,
    detail::{Feature, split_image},
    inventory::{Sandbox, memory_label},
    telemetry::{Rate, rate_label},
};
use gpui_kit::assets::IconName;
use gpui_kit::component::{
    ActiveTheme, ElementExt, Icon, Sizable,
    table::{Column, TableDelegate, TableState},
};
use gpui_kit::{
    App, Context, Div, FontWeight, InteractiveElement, IntoElement, ParentElement, Styled, Window,
    div, prelude::FluentBuilder, px,
};
use std::collections::HashMap;

#[derive(Clone)]
pub struct PaintedRow {
    pub bounds: gpui_kit::Bounds<gpui_kit::Pixels>,
    pub row: Sandbox,
    pub target: Option<Target>,
}

/// What the dashboard snapshot adds to an inventory row.
#[derive(Clone, Debug, Default, PartialEq)]
pub enum TrafficTrend {
    /// Running with manager-reported counters; history may still be empty.
    Tracked { rates: Vec<Rate> },
    /// Running, but the manager does not report this sandbox's traffic.
    Unreported,
    #[default]
    Idle,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct RowExtras {
    pub features: Vec<Feature>,
    pub traffic: TrafficTrend,
}

pub struct SandboxTable {
    pub rows: Vec<Sandbox>,
    columns: Vec<Column>,
    pub target: Option<Target>,
    pub painted_rows: Vec<PaintedRow>,
    pub extras: HashMap<String, RowExtras>,
}

impl SandboxTable {
    pub fn new() -> Self {
        Self {
            rows: Vec::new(),
            target: None,
            painted_rows: vec![],
            extras: HashMap::new(),
            columns: vec![
                // Sums to the design's 808px middle pane at the default size.
                Column::new("name", "Name").width(132.).movable(false),
                Column::new("state", "State").width(96.).movable(false),
                Column::new("allocation", "Allocation")
                    .width(124.)
                    .movable(false),
                Column::new("network", "Network").width(150.).movable(false),
                Column::new("features", "Features")
                    .width(132.)
                    .movable(false),
                Column::new("image", "Image").width(174.).movable(false),
            ],
        }
    }
}

impl TableDelegate for SandboxTable {
    fn columns_count(&self, _: &App) -> usize {
        self.columns.len()
    }
    fn rows_count(&self, _: &App) -> usize {
        self.rows.len()
    }
    fn column(&self, index: usize, _: &App) -> Column {
        self.columns[index].clone()
    }

    fn render_tr(
        &mut self,
        row: usize,
        _: &mut Window,
        cx: &mut Context<TableState<Self>>,
    ) -> gpui_kit::Stateful<Div> {
        let state = cx.entity().downgrade();
        let painted = self
            .rows
            .get(row)
            .cloned()
            .map(|row| (row, self.target.clone()));
        div()
            .id(("row", row))
            .bg(if row % 2 == 1 {
                cx.theme().table_even
            } else {
                cx.theme().table
            })
            .on_prepaint(move |bounds, _, cx| {
                if let Some((row, target)) = &painted {
                    let _ = state.update(cx, |table, _| {
                        table.delegate_mut().painted_rows.push(PaintedRow {
                            bounds,
                            row: row.clone(),
                            target: target.clone(),
                        })
                    });
                }
            })
    }
    fn render_header(
        &mut self,
        _: &mut Window,
        _: &mut Context<TableState<Self>>,
    ) -> gpui_kit::Stateful<Div> {
        self.painted_rows.clear();
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
            .gap_2()
            .text_size(px(11.))
            .child(self.column(column, cx).name.clone());
        match column {
            0 => cell
                .pl(px(16.))
                .child(Icon::new(IconName::ChevronUp).size(px(12.))),
            _ => cell.pl(px(8.)),
        }
    }
    fn render_td(
        &mut self,
        row: usize,
        column: usize,
        _: &mut Window,
        cx: &mut Context<TableState<Self>>,
    ) -> impl IntoElement {
        let row = &self.rows[row];
        let extras = self.extras.get(&row.name);
        let cell = div()
            .text_size(px(13.))
            .flex()
            .items_center()
            .size_full()
            .gap_2()
            .overflow_hidden();
        match column {
            0 => cell
                .pl(px(16.))
                .font_weight(FontWeight::MEDIUM)
                .child(
                    Icon::new(IconName::Box)
                        .small()
                        .text_color(if row.state == "running" {
                            cx.theme().success.opacity(0.85)
                        } else {
                            cx.theme().muted_foreground
                        }),
                )
                .child(div().truncate().child(row.name.clone())),
            1 => cell.pl(px(8.)).child(state_pill(row, cx)),
            2 => cell.pl(px(8.)).child(allocation(row, cx)),
            3 => cell.pl(px(8.)).pr(px(8.)).child(trend(
                extras.map(|e| &e.traffic).unwrap_or(&TrafficTrend::Idle),
                cx,
            )),
            4 => cell.pl(px(8.)).gap(px(5.)).children(
                extras
                    .into_iter()
                    .flat_map(|e| e.features.iter())
                    .map(|feature| feature_badge(*feature, cx)),
            ),
            _ => cell.pl(px(8.)).child(image(row.image_label(), cx)),
        }
    }
}

/// State label with its colour, as a pill that stays legible on a selected row.
pub fn state_pill(row: &Sandbox, cx: &App) -> Div {
    let color = state_color(row, cx);
    div()
        .flex()
        .items_center()
        .gap(px(6.))
        .h(px(19.))
        .px(px(8.))
        .rounded_full()
        .bg(theme::tint(color, cx))
        .text_size(px(11.))
        .child(div().size(px(6.)).rounded_full().bg(color))
        .child(row.state_label().to_owned())
}

pub fn status(row: &Sandbox, cx: &App) -> Div {
    div()
        .flex()
        .items_center()
        .gap_2()
        .text_size(px(12.))
        .child(div().size(px(6.)).rounded_full().bg(state_color(row, cx)))
        .child(row.state_label().to_owned())
}

fn state_color(row: &Sandbox, cx: &App) -> gpui_kit::Hsla {
    match row.state.as_str() {
        "running" => cx.theme().success,
        "starting" => cx.theme().warning,
        _ => cx.theme().muted_foreground,
    }
}

/// Running allocation only: stopped VMs show a dash, as their saved
/// allocation belongs to Next Boot in the inspector.
fn allocation(row: &Sandbox, cx: &App) -> Div {
    let active = (row.state == "running")
        .then_some(row.active.as_ref())
        .flatten();
    div()
        .flex()
        .items_center()
        .gap(px(6.))
        .text_size(px(12.))
        .child(match active {
            Some(settings) => format!(
                "{} vCPU · {}",
                settings.cpus,
                memory_label(settings.memory_mib)
            ),
            None => "—".into(),
        })
        .when(row.restart_required, |d| {
            d.child(
                Icon::new(IconName::TriangleAlert)
                    .size(px(13.))
                    .text_color(cx.theme().warning),
            )
        })
}

fn trend(traffic: &TrafficTrend, cx: &App) -> Div {
    let muted = cx.theme().muted_foreground;
    let cell = div()
        .flex()
        .items_center()
        .gap(px(8.))
        .w_full()
        .text_size(px(11.))
        .text_color(muted);
    match traffic {
        TrafficTrend::Tracked { rates } if rates.len() >= 2 => {
            let totals: Vec<f32> = rates.iter().map(|r| (r.down + r.up) as f32).collect();
            let latest = rates.last().map(|r| r.down + r.up).unwrap_or_default();
            cell.child(
                charts::sparkline(totals, theme::download(cx), false)
                    .w(px(52.))
                    .h(px(18.))
                    .flex_shrink_0(),
            )
            .child(
                div()
                    .flex_1()
                    .flex_shrink_0()
                    .text_right()
                    .whitespace_nowrap()
                    .child(rate_label(latest)),
            )
        }
        TrafficTrend::Tracked { .. } => cell.child("Measuring…"),
        TrafficTrend::Unreported => cell.child("Not reported"),
        TrafficTrend::Idle => cell.child(
            charts::idle_line(muted.opacity(0.6))
                .w(px(52.))
                .h(px(18.))
                .flex_shrink_0(),
        ),
    }
}

pub fn feature_icon(feature: Feature) -> IconName {
    match feature {
        Feature::Ssh => IconName::SquareTerminal,
        Feature::DevContainers => IconName::Braces,
        Feature::Ports(_) => IconName::EthernetPort,
        Feature::Secrets(_) => IconName::KeyRound,
        Feature::Shares(_) => IconName::Folder,
        Feature::NoNetwork => IconName::WifiOff,
        Feature::ProxyEnforced => IconName::ShieldCheck,
    }
}

fn feature_badge(feature: Feature, cx: &App) -> Div {
    div()
        .flex()
        .items_center()
        .gap(px(3.))
        .text_size(px(11.))
        .text_color(cx.theme().muted_foreground)
        .child(Icon::new(feature_icon(feature)).size(px(13.)))
        .children(feature.count().map(|n| n.to_string()))
}

/// Registry and namespace dimmed, repository and tag at full contrast.
pub fn image(reference: &str, cx: &App) -> Div {
    let (prefix, name) = split_image(reference);
    div()
        .flex()
        .min_w_0()
        .overflow_hidden()
        .font_family(cx.theme().mono_font_family.clone())
        .text_size(px(12.))
        .when(!prefix.is_empty(), |d| {
            d.child(
                div()
                    .flex_shrink(1.)
                    .min_w_0()
                    .truncate()
                    .text_color(cx.theme().muted_foreground.opacity(0.7))
                    .child(prefix.to_owned()),
            )
        })
        .child(
            div()
                .flex_shrink_0()
                .text_color(cx.theme().foreground.opacity(0.85))
                .child(name.to_owned()),
        )
}
