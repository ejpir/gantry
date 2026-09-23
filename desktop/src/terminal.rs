//! The integrated terminal's engine, independent of GPUI: which command
//! attaches to a sandbox, how key presses become terminal input, the colour
//! palette, and a PTY session run by alacritty's emulator on its own thread.

use crate::{commands::name_path, options::Source};
use alacritty_terminal::{
    event::{Event, EventListener, WindowSize},
    event_loop::{EventLoop, EventLoopSender, Msg},
    grid::Dimensions,
    sync::FairMutex,
    term::{Config, Term, TermMode, color::Colors},
    tty,
    vte::ansi::{Color, NamedColor, Rgb},
};
use anyhow::{Result, bail};
use std::{
    borrow::Cow,
    path::{Path, PathBuf},
    sync::Arc,
};

/// The CLI invocation that attaches a terminal to a sandbox, as the TUI's
/// open action does.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionCommand {
    pub program: PathBuf,
    pub args: Vec<String>,
    pub env: Vec<(String, String)>,
}

/// `gantry exec NAME` for the local manager's sandboxes, which needs no SSH;
/// `gantry ssh NAME -remote PROFILE` through a remote manager, which needs
/// SSH enabled in the sandbox and uses this desktop's profile store.
pub fn session_command(source: &Source, sandbox: &str, program: &Path) -> Result<SessionCommand> {
    name_path(sandbox)?;
    let mut env = vec![
        // An ambient default must never retarget the session at a
        // same-named sandbox elsewhere.
        ("GANTRY_REMOTE".to_owned(), String::new()),
        ("TERM".to_owned(), "xterm-256color".to_owned()),
        ("COLORTERM".to_owned(), "truecolor".to_owned()),
    ];
    let args = match source {
        Source::Local(_) => vec!["exec".into(), sandbox.into()],
        Source::Remote { name, config_dir } => {
            env.push(("GANTRY_MANAGER_SOCKET".into(), String::new()));
            env.push((
                "GANTRY_HOME".into(),
                config_dir.join("sandboxes").display().to_string(),
            ));
            vec!["ssh".into(), sandbox.into(), "-remote".into(), name.clone()]
        }
        Source::Demo => bail!("Demo sandboxes have no terminal"),
    };
    Ok(SessionCommand {
        program: program.to_owned(),
        args,
        env,
    })
}

/// Modifier keys held with a key press.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Modifiers {
    pub control: bool,
    pub alt: bool,
    pub shift: bool,
    /// Command on macOS, Super elsewhere: always the app's, never the
    /// terminal's.
    pub platform: bool,
}

/// The bytes a key press sends, as xterm encodes them, or `None` when the
/// terminal leaves the key to the app. `key` is GPUI's key name and
/// `key_char` the text it would type. With `alt_is_meta`, Alt prefixes ESC
/// (Linux, Windows); otherwise Option composes characters (macOS).
pub fn key_input(
    key: &str,
    key_char: Option<&str>,
    mods: Modifiers,
    mode: TermMode,
    alt_is_meta: bool,
) -> Option<Vec<u8>> {
    if mods.platform {
        return None;
    }
    let param = 1 + u8::from(mods.shift) + 2 * u8::from(mods.alt) + 4 * u8::from(mods.control);
    let cursor = |end: char| {
        if param > 1 {
            format!("\x1b[1;{param}{end}")
        } else if mode.contains(TermMode::APP_CURSOR) {
            format!("\x1bO{end}")
        } else {
            format!("\x1b[{end}")
        }
    };
    let tilde = |code: u8| {
        if param > 1 {
            format!("\x1b[{code};{param}~")
        } else {
            format!("\x1b[{code}~")
        }
    };
    let function = |end: char| {
        if param > 1 {
            format!("\x1b[1;{param}{end}")
        } else {
            format!("\x1bO{end}")
        }
    };
    let meta = |bytes: &[u8]| {
        let mut out = Vec::with_capacity(bytes.len() + 1);
        if mods.alt {
            out.push(0x1b);
        }
        out.extend_from_slice(bytes);
        out
    };
    let sequence = match key {
        "up" => cursor('A'),
        "down" => cursor('B'),
        "right" => cursor('C'),
        "left" => cursor('D'),
        "home" => cursor('H'),
        "end" => cursor('F'),
        "insert" => tilde(2),
        "delete" => tilde(3),
        "pageup" => tilde(5),
        "pagedown" => tilde(6),
        "f1" => function('P'),
        "f2" => function('Q'),
        "f3" => function('R'),
        "f4" => function('S'),
        "f5" => tilde(15),
        "f6" => tilde(17),
        "f7" => tilde(18),
        "f8" => tilde(19),
        "f9" => tilde(20),
        "f10" => tilde(21),
        "f11" => tilde(23),
        "f12" => tilde(24),
        "enter" => return Some(meta(b"\r")),
        "escape" => return Some(b"\x1b".to_vec()),
        "tab" if mods.shift => return Some(b"\x1b[Z".to_vec()),
        "tab" => return Some(meta(b"\t")),
        "backspace" if mods.control => return Some(meta(&[0x08])),
        "backspace" => return Some(meta(&[0x7f])),
        "space" if mods.control => return Some(meta(&[0])),
        _ if mods.control => {
            let mut chars = key.chars();
            let (Some(c), None) = (chars.next(), chars.next()) else {
                return None;
            };
            let code = match c.to_ascii_lowercase() {
                c @ 'a'..='z' => c as u8 - b'a' + 1,
                '@' | '2' | ' ' => 0,
                '[' | '3' => 0x1b,
                '\\' | '4' => 0x1c,
                ']' | '5' => 0x1d,
                '^' | '6' => 0x1e,
                '_' | '-' | '7' => 0x1f,
                '?' | '8' => 0x7f,
                _ => return None,
            };
            return Some(meta(&[code]));
        }
        _ => {
            let text = key_char.filter(|t| !t.is_empty()).or_else(|| {
                // Space may arrive without the text it types.
                (key == "space").then_some(" ")
            })?;
            if mods.alt && alt_is_meta {
                return Some(meta(text.as_bytes()));
            }
            return Some(text.as_bytes().to_vec());
        }
    };
    Some(sequence.into_bytes())
}

/// Pasted text as terminal input. A program that asked for bracketed paste
/// gets it bracketed, with ESC removed so the text cannot end the bracket
/// early and run as keystrokes; otherwise line breaks arrive as Enter.
pub fn paste_input(text: &str, mode: TermMode) -> Vec<u8> {
    if mode.contains(TermMode::BRACKETED_PASTE) {
        let body: String = text.chars().filter(|&c| c != '\x1b').collect();
        format!("\x1b[200~{body}\x1b[201~").into_bytes()
    } else {
        text.replace("\r\n", "\r").replace('\n', "\r").into_bytes()
    }
}

/// The 16 ANSI colours, tuned for the app's dark and light surfaces.
const DARK: [u32; 16] = [
    0x1d2024, 0xe06c75, 0x98c379, 0xe5c07b, 0x61afef, 0xc678dd, 0x56b6c2, 0xc8ccd4, 0x5c6370,
    0xef7f88, 0xb5e890, 0xf0d08a, 0x82c2ff, 0xd99af0, 0x7fd4de, 0xf0f2f5,
];
const LIGHT: [u32; 16] = [
    0x2b2f36, 0xc0392b, 0x3f7f3b, 0x9a7328, 0x2f6db5, 0x8e44ad, 0x1f8a93, 0xbfc4cc, 0x6b7280,
    0xd9534f, 0x4e9a4a, 0xb5892f, 0x3d82d4, 0xa55bc4, 0x2aa1ab, 0xf5f6f8,
];

fn rgb(hex: u32) -> Rgb {
    Rgb {
        r: (hex >> 16) as u8,
        g: (hex >> 8) as u8,
        b: hex as u8,
    }
}

/// A cell colour as RGB: the program's own palette changes (OSC 4/10/11)
/// first, then the 16 ANSI colours, the 6×6×6 cube and the grey ramp.
/// `foreground` and `background` are the view's defaults.
pub fn color_rgb(
    color: Color,
    colors: &Colors,
    dark: bool,
    foreground: Rgb,
    background: Rgb,
) -> Rgb {
    let ansi = |index: usize| rgb(if dark { DARK[index] } else { LIGHT[index] });
    match color {
        Color::Spec(rgb) => rgb,
        Color::Indexed(index) => colors[index as usize].unwrap_or_else(|| indexed(index, ansi)),
        Color::Named(name) => colors[name].unwrap_or_else(|| match name {
            NamedColor::Foreground | NamedColor::BrightForeground => foreground,
            NamedColor::Background => background,
            NamedColor::Cursor => foreground,
            NamedColor::DimForeground => dim(foreground),
            name if (name as usize) < 16 => ansi(name as usize),
            // Dim black..white follow the normal colours, darkened.
            name => dim(ansi(
                (name as usize).saturating_sub(NamedColor::DimBlack as usize) % 8,
            )),
        }),
    }
}

fn indexed(index: u8, ansi: impl Fn(usize) -> Rgb) -> Rgb {
    match index {
        0..=15 => ansi(index as usize),
        16..=231 => {
            let step = |v: u8| if v == 0 { 0 } else { 55 + v * 40 };
            let i = index - 16;
            Rgb {
                r: step(i / 36),
                g: step(i / 6 % 6),
                b: step(i % 6),
            }
        }
        _ => {
            let v = 8 + (index - 232) * 10;
            Rgb { r: v, g: v, b: v }
        }
    }
}

fn dim(color: Rgb) -> Rgb {
    let scale = |v: u8| (u16::from(v) * 2 / 3) as u8;
    Rgb {
        r: scale(color.r),
        g: scale(color.g),
        b: scale(color.b),
    }
}

/// The terminal grid's size in cells.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GridSize {
    pub columns: usize,
    pub lines: usize,
}

impl Dimensions for GridSize {
    fn total_lines(&self) -> usize {
        self.lines
    }

    fn screen_lines(&self) -> usize {
        self.lines
    }

    fn columns(&self) -> usize {
        self.columns
    }
}

impl GridSize {
    /// The largest grid that fits `width` × `height` pixels of cells, never
    /// smaller than 2×1 so the emulator always has a cursor position.
    pub fn fitting(width: f32, height: f32, cell_width: f32, cell_height: f32) -> Self {
        let fit = |space: f32, cell: f32| {
            if cell > 0. && space.is_finite() {
                (space / cell).floor().max(0.) as usize
            } else {
                0
            }
        };
        Self {
            columns: fit(width, cell_width).max(2),
            lines: fit(height, cell_height).max(1),
        }
    }

    fn window(self, cell_width: f32, cell_height: f32) -> WindowSize {
        WindowSize {
            num_lines: self.lines.min(u16::MAX as usize) as u16,
            num_cols: self.columns.min(u16::MAX as usize) as u16,
            cell_width: cell_width.round().clamp(1., f32::from(u16::MAX)) as u16,
            cell_height: cell_height.round().clamp(1., f32::from(u16::MAX)) as u16,
        }
    }
}

/// Forwards the emulator's events to the UI thread.
#[derive(Clone)]
pub struct Listener(async_channel::Sender<Event>);

impl EventListener for Listener {
    fn send_event(&self, event: Event) {
        let _ = self.0.try_send(event);
    }
}

/// One PTY running the attach command, with the emulator's screen. Dropping
/// it shuts the I/O thread down, which hangs up on the command.
pub struct Session {
    pub term: Arc<FairMutex<Term<Listener>>>,
    sender: EventLoopSender,
    size: GridSize,
    cell: (f32, f32),
    /// The desktop's own handle on the command's side of the PTY; see
    /// [`open_pty`]. Closed after the I/O thread is told to stop.
    #[cfg(unix)]
    _hold: std::os::fd::OwnedFd,
}

impl Session {
    /// Spawn `command` in a PTY of `size`. Events arrive on the receiver:
    /// `Wakeup` for new output, `ChildExit` with the command's status, then
    /// `Exit` once its last output is on screen, and requests (`PtyWrite`,
    /// `ClipboardStore`, …) the UI answers.
    pub fn spawn(
        command: &SessionCommand,
        size: GridSize,
        cell_width: f32,
        cell_height: f32,
    ) -> Result<(Self, async_channel::Receiver<Event>)> {
        let options = tty::Options {
            shell: Some(tty::Shell::new(
                command.program.display().to_string(),
                command.args.clone(),
            )),
            working_directory: None,
            drain_on_exit: true,
            env: command.env.iter().cloned().collect(),
            #[cfg(windows)]
            escape_args: true,
        };
        #[cfg(unix)]
        let (pty, hold) = open_pty(&options, size.window(cell_width, cell_height))?;
        #[cfg(not(unix))]
        let pty = tty::new(&options, size.window(cell_width, cell_height), 0)?;
        let (sender, receiver) = async_channel::unbounded();
        let listener = Listener(sender);
        let term = Arc::new(FairMutex::new(Term::new(
            Config {
                scrolling_history: 10_000,
                ..Default::default()
            },
            &size,
            listener.clone(),
        )));
        let event_loop = EventLoop::new(term.clone(), listener, pty, true, false)?;
        let sender = event_loop.channel();
        // The I/O thread runs until shutdown or the command's exit.
        drop(event_loop.spawn());
        Ok((
            Self {
                term,
                sender,
                size,
                cell: (cell_width, cell_height),
                #[cfg(unix)]
                _hold: hold,
            },
            receiver,
        ))
    }

    pub fn write(&self, bytes: impl Into<Cow<'static, [u8]>>) {
        let _ = self.sender.send(Msg::Input(bytes.into()));
    }

    pub fn size(&self) -> GridSize {
        self.size
    }

    /// The grid and cell size, as programs ask for it (CSI 14 t).
    pub fn window_size(&self) -> WindowSize {
        self.size.window(self.cell.0, self.cell.1)
    }

    /// Resize the screen and the PTY; the command sees SIGWINCH.
    pub fn resize(&mut self, size: GridSize) {
        if size == self.size {
            return;
        }
        self.size = size;
        self.term.lock().resize(size);
        let _ = self.sender.send(Msg::Resize(self.window_size()));
    }
}

/// Open the PTY and start the command in it, keeping a handle on the
/// command's side. alacritty drains a command's last output after it exits,
/// but gives up on it when the screen is locked for drawing and the next read
/// fails because the command's side closed. Held open, that read waits
/// instead, so the last lines (often the CLI's error) are never dropped.
#[cfg(unix)]
fn open_pty(
    options: &tty::Options,
    window: WindowSize,
) -> Result<(tty::Pty, std::os::fd::OwnedFd)> {
    use alacritty_terminal::tty::ToWinsize;
    let pty = rustix_openpty::openpty(None, Some(&window.to_winsize()))?;
    // Close-on-exec: the command gets its own copy from the spawn, not this.
    let hold = pty.user.try_clone()?;
    Ok((tty::from_fd(options, 0, pty.controller, pty.user)?, hold))
}

impl Drop for Session {
    fn drop(&mut self) {
        let _ = self.sender.send(Msg::Shutdown);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys(key: &str, key_char: Option<&str>, mods: Modifiers) -> Option<Vec<u8>> {
        key_input(key, key_char, mods, TermMode::default(), true)
    }

    #[test]
    fn keys_encode_as_xterm_does() {
        let none = Modifiers::default();
        let ctrl = Modifiers {
            control: true,
            ..none
        };
        let alt = Modifiers { alt: true, ..none };
        let shift = Modifiers {
            shift: true,
            ..none
        };
        assert_eq!(keys("a", Some("a"), none).unwrap(), b"a");
        assert_eq!(keys("a", Some("A"), shift).unwrap(), b"A");
        assert_eq!(keys("é", Some("é"), none).unwrap(), "é".as_bytes());
        assert_eq!(keys("c", Some("c"), ctrl).unwrap(), [3]);
        assert_eq!(keys("r", None, ctrl).unwrap(), [18]);
        assert_eq!(keys("[", None, ctrl).unwrap(), [0x1b]);
        assert_eq!(keys("space", Some(" "), ctrl).unwrap(), [0]);
        assert_eq!(keys("b", Some("b"), alt).unwrap(), b"\x1bb");
        assert_eq!(keys("enter", None, none).unwrap(), b"\r");
        assert_eq!(keys("backspace", None, none).unwrap(), [0x7f]);
        assert_eq!(keys("tab", None, shift).unwrap(), b"\x1b[Z");
        assert_eq!(keys("up", None, none).unwrap(), b"\x1b[A");
        assert_eq!(keys("left", None, ctrl).unwrap(), b"\x1b[1;5D");
        assert_eq!(keys("pageup", None, none).unwrap(), b"\x1b[5~");
        assert_eq!(keys("delete", None, shift).unwrap(), b"\x1b[3;2~");
        assert_eq!(keys("f1", None, none).unwrap(), b"\x1bOP");
        assert_eq!(keys("f12", None, none).unwrap(), b"\x1b[24~");
        // Programs in application cursor mode (vim, less) get SS3 arrows.
        assert_eq!(
            key_input("up", None, none, TermMode::APP_CURSOR, true).unwrap(),
            b"\x1bOA"
        );
        // The platform modifier is the app's; macOS Option composes text.
        let platform = Modifiers {
            platform: true,
            ..none
        };
        assert_eq!(keys("c", Some("c"), platform), None);
        assert_eq!(
            key_input("e", Some("é"), alt, TermMode::default(), false).unwrap(),
            "é".as_bytes()
        );
        assert_eq!(keys("shift", None, shift), None);
    }

    #[test]
    fn pastes_are_bracketed_only_when_asked_and_cannot_escape() {
        assert_eq!(paste_input("a\nb\r\nc", TermMode::default()), b"a\rb\rc");
        assert_eq!(
            paste_input("ls\x1b[201~rm", TermMode::BRACKETED_PASTE),
            b"\x1b[200~ls[201~rm\x1b[201~"
        );
    }

    #[test]
    fn colours_resolve_through_overrides_ansi_cube_and_greys() {
        let colors = Colors::default();
        let fg = Rgb { r: 1, g: 2, b: 3 };
        let bg = Rgb { r: 4, g: 5, b: 6 };
        let resolve = |color| color_rgb(color, &colors, true, fg, bg);
        assert_eq!(resolve(Color::Named(NamedColor::Foreground)), fg);
        assert_eq!(resolve(Color::Named(NamedColor::Background)), bg);
        assert_eq!(resolve(Color::Named(NamedColor::Red)), rgb(DARK[1]));
        assert_eq!(resolve(Color::Indexed(9)), rgb(DARK[9]));
        assert_eq!(resolve(Color::Indexed(16)), Rgb { r: 0, g: 0, b: 0 });
        assert_eq!(
            resolve(Color::Indexed(231)),
            Rgb {
                r: 255,
                g: 255,
                b: 255
            }
        );
        assert_eq!(resolve(Color::Indexed(232)), Rgb { r: 8, g: 8, b: 8 });
        let spec = Rgb { r: 9, g: 8, b: 7 };
        assert_eq!(resolve(Color::Spec(spec)), spec);
        let mut changed = Colors::default();
        changed[NamedColor::Red] = Some(spec);
        assert_eq!(
            color_rgb(Color::Named(NamedColor::Red), &changed, true, fg, bg),
            spec
        );
    }

    #[test]
    fn grids_fit_their_pixels_and_never_collapse() {
        assert_eq!(
            GridSize::fitting(805., 402., 8., 20.),
            GridSize {
                columns: 100,
                lines: 20
            }
        );
        assert_eq!(
            GridSize::fitting(0., 0., 8., 20.),
            GridSize {
                columns: 2,
                lines: 1
            }
        );
        assert_eq!(GridSize::fitting(100., 100., 0., 0.).columns, 2);
    }

    #[test]
    fn sessions_attach_with_exec_locally_and_ssh_remotely() {
        let program = Path::new("/opt/gantry");
        let local = session_command(&Source::Local("/s.sock".into()), "dev", program).unwrap();
        assert_eq!(local.args, ["exec", "dev"]);
        assert!(local.env.contains(&("GANTRY_REMOTE".into(), String::new())));
        let remote = session_command(
            &Source::Remote {
                name: "build".into(),
                config_dir: "/cfg".into(),
            },
            "dev",
            program,
        )
        .unwrap();
        assert_eq!(remote.args, ["ssh", "dev", "-remote", "build"]);
        assert!(
            remote
                .env
                .contains(&("GANTRY_HOME".into(), "/cfg/sandboxes".into()))
        );
        assert!(session_command(&Source::Demo, "dev", program).is_err());
        assert!(session_command(&Source::Local("/s.sock".into()), "../x", program).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn a_session_runs_its_command_in_a_pty_and_reports_the_exit() {
        let command = SessionCommand {
            program: "/bin/sh".into(),
            args: vec!["-c".into(), "stty size; printf 'hello\\n'; exit 3".into()],
            env: vec![],
        };
        let size = GridSize {
            columns: 40,
            lines: 10,
        };
        let (session, events) = Session::spawn(&command, size, 8., 16.).unwrap();
        // The exit status comes first; Exit follows once output is drained.
        let mut status = None;
        loop {
            match events
                .recv_blocking()
                .expect("the session ends with its command")
            {
                Event::ChildExit(exit) => status = Some(exit),
                Event::Exit => break,
                _ => {}
            }
        }
        assert_eq!(status.and_then(|s| s.code()), Some(3));
        let screen: String = {
            let term = session.term.lock();
            let grid = term.grid();
            (0..size.lines as i32)
                .map(|line| {
                    let row = &grid[alacritty_terminal::index::Line(line)];
                    (0..size.columns)
                        .map(|column| row[alacritty_terminal::index::Column(column)].c)
                        .collect::<String>()
                        .trim_end()
                        .to_owned()
                })
                .collect::<Vec<_>>()
                .join("\n")
        };
        assert!(screen.contains("10 40"), "{screen}");
        assert!(screen.contains("hello"), "{screen}");
    }
}
