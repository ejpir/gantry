use gantry_desktop::inventory::{Sandbox, memory_label};
use gpui_kit::assets::IconName;
use gpui_kit::component::{
    ActiveTheme, Icon, Sizable,
    table::{Column, TableDelegate, TableState},
};
use gpui_kit::{
    App, Context, Div, FontWeight, IntoElement, ParentElement, Styled, Window, div, px,
};

pub struct SandboxTable {
    pub rows: Vec<Sandbox>,
    columns: Vec<Column>,
}

impl SandboxTable {
    pub fn new() -> Self {
        Self {
            rows: Vec::new(),
            columns: vec![
                Column::new("name", "Name").width(170.).movable(false),
                Column::new("state", "Status").width(110.).movable(false),
                Column::new("cpu", "vCPU").width(64.).movable(false),
                Column::new("memory", "Memory").width(100.).movable(false),
                Column::new("image", "Image").width(210.).movable(false),
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

    fn render_td(
        &mut self,
        row: usize,
        column: usize,
        _: &mut Window,
        cx: &mut Context<TableState<Self>>,
    ) -> impl IntoElement {
        let row = &self.rows[row];
        let cell = div()
            .flex()
            .items_center()
            .size_full()
            .gap_2()
            .overflow_hidden();
        match column {
            0 => cell
                .font_weight(FontWeight::MEDIUM)
                .child(
                    Icon::new(IconName::Box)
                        .small()
                        .text_color(cx.theme().muted_foreground),
                )
                .child(div().truncate().child(row.name.clone())),
            1 => cell.child(status(row, cx)),
            2 => cell.child(
                row.displayed_resources()
                    .map(|settings| settings.cpus.to_string())
                    .unwrap_or_else(|| "—".into()),
            ),
            3 => cell.child(
                row.displayed_resources()
                    .map(|settings| memory_label(settings.memory_mib))
                    .unwrap_or_else(|| "—".into()),
            ),
            _ => cell
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
