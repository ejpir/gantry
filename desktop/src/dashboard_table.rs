use gantry_desktop::workspace::{Page, Row};
use gpui_kit::component::{
    ActiveTheme,
    table::{Column, TableDelegate, TableState},
};
use gpui_kit::{App, Context, IntoElement, ParentElement, Styled, Window, div, px};

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
