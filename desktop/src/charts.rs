//! Small charts drawn with GPUI paths: row sparklines, the detail pane's
//! throughput areas, and proportion bars. Callers label every value.

use gpui_kit::{
    Canvas, Div, Hsla, ParentElement, PathBuilder, Pixels, Point, Styled, canvas, div,
    linear_color_stop, linear_gradient, point, px, relative,
};

/// A line through `values`, scaled to the largest value, optionally with a
/// fading area fill beneath it. Fewer than two values draw nothing.
pub fn sparkline(values: Vec<f32>, color: Hsla, filled: bool) -> Canvas<()> {
    canvas(
        |_, _, _| {},
        move |bounds, _, window, _| {
            if values.len() < 2 {
                return;
            }
            let max = values.iter().copied().fold(0.0_f32, f32::max);
            let max = if max > 0.0 { max } else { 1.0 };
            let inset = px(1.5);
            let width = bounds.size.width - inset * 2.;
            let height = bounds.size.height - inset * 2.;
            let step = width / (values.len() - 1) as f32;
            let points: Vec<Point<Pixels>> = values
                .iter()
                .enumerate()
                .map(|(i, value)| {
                    point(
                        bounds.origin.x + inset + step * i as f32,
                        bounds.origin.y + inset + height * (1.0 - (value / max).clamp(0.0, 1.0)),
                    )
                })
                .collect();
            if filled {
                let bottom = bounds.origin.y + bounds.size.height;
                let mut area = PathBuilder::fill();
                area.move_to(point(points[0].x, bottom));
                for point in &points {
                    area.line_to(*point);
                }
                area.line_to(point(points[points.len() - 1].x, bottom));
                area.close();
                if let Ok(path) = area.build() {
                    window.paint_path(
                        path,
                        linear_gradient(
                            180.,
                            linear_color_stop(color.opacity(0.32), 0.),
                            linear_color_stop(color.opacity(0.), 1.),
                        ),
                    );
                }
            }
            let mut line = PathBuilder::stroke(px(1.5));
            line.move_to(points[0]);
            for point in &points[1..] {
                line.line_to(*point);
            }
            if let Ok(path) = line.build() {
                window.paint_path(path, color);
            }
        },
    )
}

/// A dotted baseline for rows with nothing to chart (for example stopped VMs).
pub fn idle_line(color: Hsla) -> Canvas<()> {
    canvas(
        |_, _, _| {},
        move |bounds, _, window, _| {
            let y = bounds.origin.y + bounds.size.height - px(4.);
            let mut line = PathBuilder::stroke(px(1.2)).dash_array(&[px(1.5), px(3.5)]);
            line.move_to(point(bounds.origin.x, y));
            line.line_to(point(bounds.origin.x + bounds.size.width, y));
            if let Ok(path) = line.build() {
                window.paint_path(path, color);
            }
        },
    )
}

/// A horizontal proportion bar. Non-zero values stay visible at a few pixels.
pub fn meter(fraction: f32, color: Hsla, track: Hsla) -> Div {
    let fraction = fraction.clamp(0.0, 1.0);
    div().h(px(6.)).w_full().rounded_full().bg(track).child(
        div()
            .h_full()
            .rounded_full()
            .bg(color)
            .w(relative(fraction))
            .min_w(if fraction > 0.0 { px(3.) } else { px(0.) }),
    )
}
