use gantry_desktop::workspace::{Page, Row};
use gpui_kit::component::{
    ActiveTheme,
    table::{Column, TableDelegate, TableState},
};
use gpui_kit::{
    App, Context, InteractiveElement, IntoElement, ParentElement, Styled, Window, div, px,
};

pub struct DashboardTable {
    pub rows: Vec<Row>,
    columns: Vec<Column>,
}
impl DashboardTable {
    pub fn new(page: Page) -> Self {
        Self {
            rows: vec![],
            columns: page
                .columns()
                .iter()
                .enumerate()
                .map(|(i, label)| {
                    Column::new(format!("column-{i}"), *label)
                        .width(if i == 1 { 260. } else { 170. })
                        .movable(false)
                })
                .collect(),
        }
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
        div()
            .size_full()
            .text_size(px(11.))
            .child(self.column(column, cx).name.clone())
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
        div()
            .flex()
            .items_center()
            .size_full()
            .overflow_hidden()
            .text_size(px(12.))
            .text_color(cx.theme().foreground)
            .child(
                div().truncate().child(
                    self.rows[row]
                        .cells
                        .get(column)
                        .cloned()
                        .unwrap_or_default(),
                ),
            )
    }
}
