//! The integrated terminal: a sandbox's shell in the detail pane, drawn from
//! alacritty's screen grid, with keyboard input, paste, selection and
//! scrollback. The shell runs through the Gantry CLI (`gantry exec NAME`, or
//! `gantry ssh NAME -remote PROFILE` for a remote manager) in a local PTY.

use alacritty_terminal::{
    event::Event,
    grid::{Dimensions, Scroll},
    index::{Column, Line, Point as GridPoint, Side},
    selection::{Selection, SelectionType},
    term::{TermMode, cell::Flags},
    vte::ansi::{Color, CursorShape, NamedColor, Rgb},
};
use gantry_desktop::{
    detail::Tab,
    launcher,
    options::Source,
    terminal::{
        GridSize, Modifiers, Session, SessionCommand, color_rgb, key_input, paste_input,
        session_command,
    },
    workspace::text,
};
use gpui_kit::assets::IconName;
use gpui_kit::component::{
    ActiveTheme, Disableable, Icon, Sizable,
    button::{Button, ButtonVariants},
};
use gpui_kit::{
    AnyElement, App, AppContext, Bounds, ClipboardItem, Context, CursorStyle, Div, FocusHandle,
    Focusable, FontStyle, FontWeight, Hsla, InteractiveElement, IntoElement, KeyDownEvent,
    MouseButton, MouseDownEvent, MouseMoveEvent, ParentElement, Pixels, Render, Rgba, ScrollDelta,
    ScrollWheelEvent, StrikethroughStyle, Styled, StyledText, Task, TestSupportExt, TextRun,
    UnderlineStyle, Window, canvas, div, font, prelude::FluentBuilder, px,
};
use std::{cell::Cell, rc::Rc};

const FONT_SIZE: f32 = 13.;
const LINE_HEIGHT: f32 = 1.35;
/// Space between the grid and the pane's edge.
const INSET: f32 = 8.;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TerminalState {
    Running,
    /// The command ended, with its exit code when it had one.
    Exited(Option<i32>),
    /// The CLI could not be started at all.
    Failed(String),
}

pub struct TerminalView {
    command: SessionCommand,
    session: Option<Session>,
    pub state: TerminalState,
    /// The title the shell set (OSC 0/2), if any.
    pub title: Option<String>,
    focus: FocusHandle,
    /// Cell width and height, from the monospace font.
    cell: (f32, f32),
    /// Where the grid was painted last frame, in window coordinates.
    bounds: Rc<Cell<Option<Bounds<Pixels>>>>,
    /// Pixel scrolling not yet worth a whole line.
    scroll_remainder: f32,
    exit_code: Option<i32>,
    _events: Option<Task<()>>,
}

impl TerminalView {
    pub fn new(command: SessionCommand, window: &mut Window, cx: &mut Context<Self>) -> Self {
        let family = cx.theme().mono_font_family.clone();
        let text_system = window.text_system();
        let font_id = text_system.resolve_font(&font(family));
        let width = text_system
            .advance(font_id, px(FONT_SIZE), 'm')
            .map(|size| f32::from(size.width))
            .unwrap_or(FONT_SIZE * 0.6);
        let mut view = Self {
            command,
            session: None,
            state: TerminalState::Running,
            title: None,
            focus: cx.focus_handle(),
            cell: (width.max(1.), (FONT_SIZE * LINE_HEIGHT).round()),
            bounds: Rc::new(Cell::new(None)),
            scroll_remainder: 0.,
            exit_code: None,
            _events: None,
        };
        view.start(cx);
        view
    }

    fn start(&mut self, cx: &mut Context<Self>) {
        let size = self.bounds.get().map_or(
            GridSize {
                columns: 100,
                lines: 30,
            },
            |bounds| self.fit(bounds),
        );
        self.title = None;
        self.exit_code = None;
        match Session::spawn(&self.command, size, self.cell.0, self.cell.1) {
            Ok((session, events)) => {
                self.session = Some(session);
                self.state = TerminalState::Running;
                self._events = Some(cx.spawn(async move |this, cx| {
                    while let Ok(event) = events.recv().await {
                        // Output arrives in bursts; draw once per burst.
                        let mut batch = vec![event];
                        while let Ok(more) = events.try_recv() {
                            batch.push(more);
                        }
                        if this.update(cx, |this, cx| this.handle(batch, cx)).is_err() {
                            break;
                        }
                    }
                }));
            }
            Err(error) => {
                self.session = None;
                self.state = TerminalState::Failed(format!("{error:#}"));
            }
        }
        cx.notify();
    }

    /// Start the command again after it ended, in the same pane.
    pub fn restart(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        self._events = None;
        self.session = None;
        self.start(cx);
        self.focus.focus(window, cx);
    }

    pub fn running(&self) -> bool {
        self.state == TerminalState::Running
    }

    fn write(&self, bytes: Vec<u8>) {
        if let Some(session) = &self.session {
            session.write(bytes);
        }
    }

    fn handle(&mut self, events: Vec<Event>, cx: &mut Context<Self>) {
        for event in events {
            match event {
                Event::Title(title) => self.title = Some(text(&title)),
                Event::ResetTitle => self.title = None,
                // Replies the program asked for: cursor position, device
                // attributes, colours and size.
                Event::PtyWrite(reply) => self.write(reply.into_bytes()),
                Event::ColorRequest(index, format) => {
                    let color = self.palette(index, cx.theme().is_dark());
                    self.write(format(color).into_bytes());
                }
                Event::TextAreaSizeRequest(format) => {
                    if let Some(session) = &self.session {
                        self.write(format(session.window_size()).into_bytes());
                    }
                }
                // OSC 52 copy; pasting from the clipboard stays with the user.
                Event::ClipboardStore(_, value) => {
                    cx.write_to_clipboard(ClipboardItem::new_string(value))
                }
                Event::ChildExit(status) => self.exit_code = status.code(),
                Event::Exit => self.state = TerminalState::Exited(self.exit_code),
                _ => {}
            }
        }
        cx.notify();
    }

    fn palette(&self, index: usize, dark: bool) -> Rgb {
        let (foreground, background) = defaults(dark);
        let color = match index {
            0..=255 => Color::Indexed(index as u8),
            257 => Color::Named(NamedColor::Background),
            _ => Color::Named(NamedColor::Foreground),
        };
        match &self.session {
            Some(session) => color_rgb(
                color,
                session.term.lock().colors(),
                dark,
                foreground,
                background,
            ),
            None => foreground,
        }
    }

    #[cfg(test)]
    pub fn grid_columns(&self) -> usize {
        self.session.as_ref().map_or(0, |s| s.size().columns)
    }

    /// The visible screen as text, one trimmed line per row.
    #[cfg(test)]
    pub fn screen_text(&self) -> String {
        let Some(session) = &self.session else {
            return String::new();
        };
        let term = session.term.lock();
        let grid = term.grid();
        (0..term.screen_lines() as i32)
            .map(|line| {
                let row = &grid[Line(line)];
                (0..term.columns())
                    .map(|column| row[Column(column)].c)
                    .collect::<String>()
                    .trim_end()
                    .to_owned()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn fit(&self, bounds: Bounds<Pixels>) -> GridSize {
        GridSize::fitting(
            f32::from(bounds.size.width),
            f32::from(bounds.size.height),
            self.cell.0,
            self.cell.1,
        )
    }

    /// The grid cell under a window position, and which half of it.
    fn grid_point(&self, position: gpui_kit::Point<Pixels>) -> Option<(GridPoint, Side)> {
        let bounds = self.bounds.get()?;
        let session = self.session.as_ref()?;
        let size = session.size();
        let x = f32::from(position.x - bounds.origin.x).max(0.);
        let y = f32::from(position.y - bounds.origin.y).max(0.);
        let column = ((x / self.cell.0) as usize).min(size.columns - 1);
        let row = ((y / self.cell.1) as usize).min(size.lines - 1);
        let side = if x % self.cell.0 > self.cell.0 / 2. {
            Side::Right
        } else {
            Side::Left
        };
        let offset = session.term.lock().grid().display_offset() as i32;
        Some((
            GridPoint::new(Line(row as i32 - offset), Column(column)),
            side,
        ))
    }

    fn key_down(&mut self, event: &KeyDownEvent, window: &mut Window, cx: &mut Context<Self>) {
        let keystroke = &event.keystroke;
        let held = &keystroke.modifiers;
        // Copy and paste: Command on macOS, Ctrl+Shift elsewhere, so Ctrl+C
        // still interrupts.
        let clipboard = if cfg!(target_os = "macos") {
            held.platform && !held.control && !held.alt
        } else {
            held.control && held.shift && !held.alt && !held.platform
        };
        if clipboard && keystroke.key == "c" {
            self.copy(cx);
            cx.stop_propagation();
            return;
        }
        if clipboard && keystroke.key == "v" {
            self.paste(cx);
            cx.stop_propagation();
            return;
        }
        if !self.running() {
            if keystroke.key == "enter" && !held.platform {
                self.restart(window, cx);
                cx.stop_propagation();
            }
            return;
        }
        let Some(session) = &self.session else {
            return;
        };
        let mode = *session.term.lock().mode();
        let mods = Modifiers {
            control: held.control,
            alt: held.alt,
            shift: held.shift,
            platform: held.platform,
        };
        let Some(bytes) = key_input(
            &keystroke.key,
            keystroke.key_char.as_deref(),
            mods,
            mode,
            !cfg!(target_os = "macos"),
        ) else {
            return;
        };
        {
            // Typing returns to the live screen and ends a selection.
            let mut term = session.term.lock();
            term.scroll_display(Scroll::Bottom);
            term.selection = None;
        }
        session.write(bytes);
        cx.stop_propagation();
        cx.notify();
    }

    fn copy(&self, cx: &mut Context<Self>) {
        if let Some(value) = self
            .session
            .as_ref()
            .and_then(|s| s.term.lock().selection_to_string())
        {
            cx.write_to_clipboard(ClipboardItem::new_string(value));
        }
    }

    fn paste(&self, cx: &mut Context<Self>) {
        let (Some(session), Some(value)) = (
            self.session.as_ref().filter(|_| self.running()),
            cx.read_from_clipboard().and_then(|item| item.text()),
        ) else {
            return;
        };
        let mode = *session.term.lock().mode();
        session.term.lock().scroll_display(Scroll::Bottom);
        session.write(paste_input(&value, mode));
    }

    fn mouse_down(&mut self, event: &MouseDownEvent, window: &mut Window, cx: &mut Context<Self>) {
        self.focus.focus(window, cx);
        let Some((point, side)) = self.grid_point(event.position) else {
            return;
        };
        let kind = match event.click_count {
            2 => SelectionType::Semantic,
            3 => SelectionType::Lines,
            _ => SelectionType::Simple,
        };
        if let Some(session) = &self.session {
            session.term.lock().selection = Some(Selection::new(kind, point, side));
        }
        cx.notify();
    }

    fn mouse_move(&mut self, event: &MouseMoveEvent, _: &mut Window, cx: &mut Context<Self>) {
        if event.pressed_button != Some(MouseButton::Left) {
            return;
        }
        let Some((point, side)) = self.grid_point(event.position) else {
            return;
        };
        if let Some(session) = &self.session
            && let Some(selection) = session.term.lock().selection.as_mut()
        {
            selection.update(point, side);
        }
        cx.notify();
    }

    fn scroll(&mut self, event: &ScrollWheelEvent, _: &mut Window, cx: &mut Context<Self>) {
        let Some(session) = &self.session else {
            return;
        };
        let lines = match event.delta {
            ScrollDelta::Lines(delta) => delta.y,
            ScrollDelta::Pixels(delta) => f32::from(delta.y) / self.cell.1,
        } + self.scroll_remainder;
        let whole = lines.trunc();
        self.scroll_remainder = lines - whole;
        if whole == 0. {
            return;
        }
        let mode = *session.term.lock().mode();
        if mode.contains(TermMode::ALT_SCREEN | TermMode::ALTERNATE_SCROLL) {
            // Full-screen programs (less, vim) scroll with arrow keys.
            let key = if whole > 0. { "up" } else { "down" };
            let arrow = key_input(key, None, Modifiers::default(), mode, true).unwrap_or_default();
            for _ in 0..whole.abs() as usize {
                session.write(arrow.clone());
            }
        } else {
            session
                .term
                .lock()
                .scroll_display(Scroll::Delta(whole as i32));
        }
        cx.notify();
    }

    /// Each screen line as styled text, and the cursor.
    fn screen(&self, dark: bool, focused: bool, cx: &App) -> (Vec<Div>, Option<Div>) {
        let Some(session) = &self.session else {
            return (vec![], None);
        };
        let (foreground, background) = defaults(dark);
        let mono = cx.theme().mono_font_family.clone();
        let selection_color = cx.theme().primary.opacity(0.35);
        let term = session.term.lock();
        let content = term.renderable_content();
        let offset = content.display_offset as i32;
        let lines = term.screen_lines();
        let mut rows: Vec<(String, Vec<TextRun>)> = vec![(String::new(), vec![]); lines];
        for indexed in content.display_iter {
            let cell = indexed.cell;
            if cell
                .flags
                .intersects(Flags::WIDE_CHAR_SPACER | Flags::LEADING_WIDE_CHAR_SPACER)
            {
                continue;
            }
            let row = indexed.point.line.0 + offset;
            let Some((line, runs)) = usize::try_from(row).ok().and_then(|r| rows.get_mut(r)) else {
                continue;
            };
            let resolve = |color| color_rgb(color, content.colors, dark, foreground, background);
            let (mut fg, mut bg) = (resolve(cell.fg), resolve(cell.bg));
            if cell.flags.contains(Flags::INVERSE) {
                std::mem::swap(&mut fg, &mut bg);
            }
            let mut fg = hsla(fg);
            if cell.flags.contains(Flags::DIM) {
                fg = fg.opacity(0.66);
            }
            if cell.flags.contains(Flags::HIDDEN) {
                fg = hsla(bg);
            }
            let selected = content
                .selection
                .is_some_and(|range| range.contains(indexed.point));
            let background_color = if selected {
                Some(selection_color)
            } else if bg != background {
                Some(hsla(bg))
            } else {
                None
            };
            let start = line.len();
            line.push(if cell.c == '\0' { ' ' } else { cell.c });
            for extra in cell.zerowidth().unwrap_or_default() {
                line.push(*extra);
            }
            let mut face = font(mono.clone());
            if cell.flags.contains(Flags::BOLD) {
                face.weight = FontWeight::BOLD;
            }
            if cell.flags.contains(Flags::ITALIC) {
                face.style = FontStyle::Italic;
            }
            let run = TextRun {
                len: line.len() - start,
                font: face,
                color: fg,
                background_color,
                underline: cell
                    .flags
                    .intersects(Flags::ALL_UNDERLINES)
                    .then_some(UnderlineStyle {
                        thickness: px(1.),
                        color: Some(fg),
                        wavy: cell.flags.contains(Flags::UNDERCURL),
                    }),
                strikethrough: cell.flags.contains(Flags::STRIKEOUT).then_some(
                    StrikethroughStyle {
                        thickness: px(1.),
                        color: Some(fg),
                    },
                ),
            };
            // Neighbouring cells in the same style share a run.
            match runs.last_mut() {
                Some(last) if same_style(last, &run) => last.len += run.len,
                _ => runs.push(run),
            }
        }
        let cursor_point = content.cursor.point;
        let cursor_row = cursor_point.line.0 + offset;
        let cursor = (content.cursor.shape != CursorShape::Hidden
            && (0..lines as i32).contains(&cursor_row))
        .then(|| {
            let color = hsla(foreground);
            let (width, height) = self.cell;
            let left = px(cursor_point.column.0 as f32 * width);
            let top = px(cursor_row as f32 * height);
            let base = div().absolute().left(left).top(top);
            match (focused, content.cursor.shape) {
                (false, _) | (_, CursorShape::HollowBlock) => base
                    .w(px(width))
                    .h(px(height))
                    .border_1()
                    .border_color(color),
                (_, CursorShape::Beam) => base.w(px(2.)).h(px(height)).bg(color),
                (_, CursorShape::Underline) => base
                    .top(top + px(height - 2.))
                    .w(px(width))
                    .h(px(2.))
                    .bg(color),
                _ => base.w(px(width)).h(px(height)).bg(color.opacity(0.55)),
            }
        });
        let height = px(self.cell.1);
        let rows = rows
            .into_iter()
            .map(|(line, runs)| {
                div()
                    .h(height)
                    .line_height(height)
                    .whitespace_nowrap()
                    .overflow_hidden()
                    .child(StyledText::new(line).with_runs(runs))
            })
            .collect();
        (rows, cursor)
    }
}

fn same_style(a: &TextRun, b: &TextRun) -> bool {
    a.font == b.font
        && a.color == b.color
        && a.background_color == b.background_color
        && a.underline == b.underline
        && a.strikethrough == b.strikethrough
}

/// The terminal's own foreground and background, a shade apart from the
/// app's surfaces so the shell reads as its own space.
fn defaults(dark: bool) -> (Rgb, Rgb) {
    if dark {
        (
            Rgb {
                r: 0xd7,
                g: 0xdb,
                b: 0xe1,
            },
            Rgb {
                r: 0x15,
                g: 0x17,
                b: 0x1b,
            },
        )
    } else {
        (
            Rgb {
                r: 0x24,
                g: 0x28,
                b: 0x2e,
            },
            Rgb {
                r: 0xfb,
                g: 0xfb,
                b: 0xfc,
            },
        )
    }
}

fn hsla(color: Rgb) -> Hsla {
    Rgba {
        r: f32::from(color.r) / 255.,
        g: f32::from(color.g) / 255.,
        b: f32::from(color.b) / 255.,
        a: 1.,
    }
    .into()
}

impl Focusable for TerminalView {
    fn focus_handle(&self, _: &App) -> FocusHandle {
        self.focus.clone()
    }
}

impl Render for TerminalView {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let dark = cx.theme().is_dark();
        // Follow the space the grid was given last frame.
        if let Some(bounds) = self.bounds.get() {
            let size = self.fit(bounds);
            if let Some(session) = self.session.as_mut() {
                session.resize(size);
            }
        }
        let focused = self.focus.is_focused(window);
        let (rows, cursor) = self.screen(dark, focused, cx);
        let store = self.bounds.clone();
        let view = cx.entity().downgrade();
        let banner = match &self.state {
            TerminalState::Running => None,
            TerminalState::Exited(code) => Some(match code {
                Some(0) | None => "Session ended. Press Enter to start a new one.".to_owned(),
                Some(code) => {
                    format!("Session ended with exit code {code}. Press Enter to start a new one.")
                }
            }),
            TerminalState::Failed(error) => Some(format!(
                "Could not start the terminal: {}. Press Enter to try again.",
                text(error)
            )),
        };
        div()
            .id("terminal")
            .test_support()
            .key_context("Terminal")
            .track_focus(&self.focus)
            .size_full()
            .flex()
            .flex_col()
            .bg(hsla(defaults(dark).1))
            .text_color(hsla(defaults(dark).0))
            .text_size(px(FONT_SIZE))
            .font_family(cx.theme().mono_font_family.clone())
            .cursor(CursorStyle::IBeam)
            .on_key_down(cx.listener(Self::key_down))
            .on_mouse_down(MouseButton::Left, cx.listener(Self::mouse_down))
            .on_mouse_move(cx.listener(Self::mouse_move))
            .on_scroll_wheel(cx.listener(Self::scroll))
            .child(
                div()
                    .relative()
                    .flex_1()
                    .min_h(px(0.))
                    .m(px(INSET))
                    .overflow_hidden()
                    .child(
                        canvas(
                            move |bounds, _, cx| {
                                if store.get() != Some(bounds) {
                                    store.set(Some(bounds));
                                    // Draw again at the new size; a frame in
                                    // progress cannot be refreshed.
                                    cx.defer(move |cx| {
                                        let _ = view.update(cx, |_, cx| cx.notify());
                                    });
                                }
                            },
                            |_, _, _, _| {},
                        )
                        .absolute()
                        .size_full(),
                    )
                    .children(rows)
                    .children(cursor),
            )
            .when_some(banner, |d, banner| {
                d.child(
                    div()
                        .id("terminal-ended")
                        .test_support()
                        .flex_shrink_0()
                        .px(px(INSET + 4.))
                        .py(px(6.))
                        .text_size(px(11.))
                        .font_family(cx.theme().font_family.clone())
                        .bg(cx.theme().secondary)
                        .text_color(cx.theme().muted_foreground)
                        .child(banner),
                )
            })
    }
}

impl crate::app::Desktop {
    /// Why a sandbox cannot have a terminal right now, if it cannot.
    pub fn terminal_blocker(&self, name: &str) -> Option<String> {
        match &self.options.source {
            Source::Demo => {
                return Some(
                    "Demo sandboxes have no shell. Connect to a manager to open a terminal.".into(),
                );
            }
            Source::Local(_) if cfg!(windows) => {
                return Some("Local terminals are not available on Windows yet.".into());
            }
            _ => {}
        }
        let row = self.inventory.rows().iter().find(|r| r.name == name)?;
        if row.state != "running" {
            return Some(format!(
                "{} is {}. Start it to open a terminal.",
                text(name),
                row.state_label()
            ));
        }
        let ssh = self
            .host
            .snapshot
            .sandboxes
            .iter()
            .find(|s| s.name == name)
            .is_none_or(|s| s.ssh);
        if matches!(self.options.source, Source::Remote { .. }) && !ssh {
            return Some(format!(
                "Terminals through a remote manager use SSH, which is off for {}. Turn it on in the sandbox's settings.",
                text(name)
            ));
        }
        None
    }

    /// Show the sandbox's terminal, starting its shell unless one is running.
    /// Everything that happens here is shown in the sandbox's Terminal tab,
    /// which this selects: from a row menu, the menu's row may not have been
    /// the selected one.
    pub fn open_terminal(&mut self, name: &str, window: &mut Window, cx: &mut Context<Self>) {
        self.detail_tab = Tab::Terminal;
        if self.inventory.selected().is_none_or(|row| row.name != name) {
            self.inventory.select(name);
            self.sync_table(cx);
        }
        if let Some(view) = self.terminals.get(name).filter(|v| v.read(cx).running()) {
            view.focus_handle(cx).focus(window, cx);
            cx.notify();
            return;
        }
        // A blocker is explained in the tab itself; see terminal_tab.
        if self.terminal_blocker(name).is_some() {
            cx.notify();
            return;
        }
        let command = launcher::executable(
            self.options.gantry.as_deref(),
            self.options.managed_gantry.as_deref(),
        )
        .and_then(|program| {
            // An explicit --gantry path is trusted as given; say so plainly
            // here rather than as a failed spawn inside the terminal.
            anyhow::ensure!(
                program.is_file(),
                "The Gantry CLI at {} does not exist.",
                program.display()
            );
            session_command(&self.options.source, name, &program)
        });
        let command = match command {
            Ok(command) => command,
            Err(error) => {
                self.terminal_error = Some((name.to_owned(), text(&format!("{error:#}"))));
                cx.notify();
                return;
            }
        };
        self.terminal_error = None;
        let view = cx.new(|cx| TerminalView::new(command, window, cx));
        view.focus_handle(cx).focus(window, cx);
        self.terminals.insert(name.to_owned(), view);
        cx.notify();
    }

    /// The Terminal tab: the running shell, or how to start one.
    pub fn terminal_tab(&self, name: &str, cx: &mut Context<Self>) -> AnyElement {
        if let Some(view) = self.terminals.get(name) {
            let terminal = view.read(cx);
            let (state, color) = match &terminal.state {
                TerminalState::Running => ("running".to_owned(), cx.theme().success),
                TerminalState::Exited(Some(code)) => {
                    (format!("ended · exit {code}"), cx.theme().muted_foreground)
                }
                TerminalState::Exited(None) => ("ended".to_owned(), cx.theme().muted_foreground),
                TerminalState::Failed(_) => ("failed".to_owned(), cx.theme().danger),
            };
            let title = terminal
                .title
                .clone()
                .unwrap_or_else(|| match &self.options.source {
                    Source::Remote { name: profile, .. } => {
                        format!("gantry ssh {name} · {profile}")
                    }
                    _ => format!("gantry exec {name}"),
                });
            let sandbox = name.to_owned();
            return div()
                .flex()
                .flex_col()
                .size_full()
                .child(
                    div()
                        .flex()
                        .items_center()
                        .gap_2()
                        .h(px(30.))
                        .flex_shrink_0()
                        .px(px(12.))
                        .border_b_1()
                        .border_color(cx.theme().border)
                        .text_size(px(11.))
                        .child(Icon::new(IconName::SquareTerminal).size(px(13.)))
                        .child(
                            div()
                                .flex_1()
                                .min_w(px(0.))
                                .truncate()
                                .font_family(cx.theme().mono_font_family.clone())
                                .child(text(&title)),
                        )
                        .child(crate::widgets::pill(&state, color, cx))
                        .child(
                            Button::new("terminal-close")
                                .ghost()
                                .xsmall()
                                .label("Close")
                                .tooltip("End the shell and close the terminal")
                                .on_click(cx.listener(move |this, _, _, cx| {
                                    this.terminals.remove(&sandbox);
                                    cx.notify();
                                })),
                        ),
                )
                .child(div().flex_1().min_h(px(0.)).child(view.clone()))
                .into_any_element();
        }
        let blocker = self.terminal_blocker(name);
        let error = self
            .terminal_error
            .as_ref()
            .filter(|(sandbox, _)| sandbox == name)
            .map(|(_, error)| error.clone());
        let how = match &self.options.source {
            Source::Remote { name: profile, .. } => {
                format!("Runs gantry ssh {name} through {profile}, in a shell inside the sandbox.")
            }
            _ => format!("Runs gantry exec {name} on this machine, in a shell inside the sandbox."),
        };
        let sandbox = name.to_owned();
        div()
            .id("terminal-empty")
            .test_support()
            .size_full()
            .flex()
            .flex_col()
            .items_center()
            .justify_center()
            .gap_3()
            .p(px(20.))
            .child(
                Icon::new(IconName::SquareTerminal)
                    .size(px(28.))
                    .text_color(cx.theme().muted_foreground),
            )
            .child(
                div()
                    .text_size(px(13.))
                    .font_weight(FontWeight::MEDIUM)
                    .child(format!("Open a shell in {}", text(name))),
            )
            .child(match (&error, &blocker) {
                (Some(error), _) => div()
                    .id("terminal-error")
                    .test_support()
                    .max_w(px(460.))
                    .child(crate::widgets::inspector_note(
                        IconName::CircleAlert,
                        cx.theme().danger,
                        "The terminal could not start.",
                        error,
                        cx,
                    )),
                (None, Some(blocker)) => div()
                    .id("terminal-blocked")
                    .test_support()
                    .max_w(px(460.))
                    .child(crate::widgets::inspector_note(
                        IconName::Info,
                        cx.theme().warning,
                        "A terminal is not available.",
                        &text(blocker),
                        cx,
                    )),
                (None, None) => div()
                    .id("terminal-how")
                    .test_support()
                    .max_w(px(420.))
                    .text_center()
                    .text_size(px(11.))
                    .text_color(cx.theme().muted_foreground)
                    .child(text(&how)),
            })
            .child(
                Button::new("terminal-open")
                    .small()
                    .label("Open Terminal")
                    .disabled(blocker.is_some())
                    .on_click(cx.listener(move |this, _, window, cx| {
                        this.open_terminal(&sandbox, window, cx)
                    })),
            )
            .child(
                div()
                    .text_size(px(10.))
                    .text_color(cx.theme().muted_foreground)
                    .child("Tip: double-click a sandbox to open its terminal."),
            )
            .into_any_element()
    }
}
