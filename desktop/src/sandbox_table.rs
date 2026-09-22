use gantry_desktop::{
    connector::Target,
    inventory::{Sandbox, memory_label},
};
use gpui_kit::assets::IconName;
use gpui_kit::component::{
    ActiveTheme, ElementExt, Icon, Sizable,
    table::{Column, TableDelegate, TableState},
};
use gpui_kit::{
    App, Context, Div, FontWeight, InteractiveElement, IntoElement, ParentElement, Styled, Window,
    div, px,
};

#[derive(Clone)]
pub struct PaintedRow {
    pub bounds: gpui_kit::Bounds<gpui_kit::Pixels>,
    pub row: Sandbox,
    pub target: Option<Target>,
}
pub struct SandboxTable {
    pub rows: Vec<Sandbox>,
    columns: Vec<Column>,
    pub target: Option<Target>,
    pub painted_rows: Vec<PaintedRow>,
}

impl SandboxTable {
    pub fn new() -> Self {
        Self {
            rows: Vec::new(),
            target: None,
            painted_rows: vec![],
            columns: vec![
                Column::new("name", "Name").width(240.).movable(false),
                Column::new("state", "State").width(144.).movable(false),
                Column::new("cpu", "CPU").width(64.).movable(false),
                Column::new("memory", "Memory").width(96.).movable(false),
                Column::new("image", "Image").width(264.).movable(false),
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
            1 => cell.pl(px(16.)),
            2 | 3 => cell.justify_end().pr(px(4.)),
            _ => cell.pl(px(4.)),
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
        let active = (row.state == "running")
            .then_some(row.active.as_ref())
            .flatten();
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
                        .text_color(cx.theme().muted_foreground),
                )
                .child(div().truncate().child(row.name.clone())),
            1 => cell.pl(px(16.)).child(status(row, cx)),
            2 => cell.justify_end().pr(px(4.)).child(
                active
                    .map(|settings| settings.cpus.to_string())
                    .unwrap_or_else(|| "—".into()),
            ),
            3 => cell.justify_end().pr(px(4.)).child(
                active
                    .map(|settings| memory_label(settings.memory_mib))
                    .unwrap_or_else(|| "—".into()),
            ),
            _ => cell
                .pl(px(4.))
                .font_family(cx.theme().mono_font_family.clone())
                .text_size(px(12.))
                .text_color(cx.theme().muted_foreground)
                .child(div().truncate().child(row.image_label().to_owned())),
        }
    }
}

pub fn status(row: &Sandbox, cx: &App) -> Div {
    let color = match row.state.as_str() {
        "running" => cx.theme().success,
        "starting" => cx.theme().warning,
        _ => cx.theme().muted_foreground,
    };
    div()
        .flex()
        .items_center()
        .gap_2()
        .text_size(px(12.))
        .child(div().size(px(6.)).rounded_full().bg(color))
        .child(row.state_label().to_owned())
}
