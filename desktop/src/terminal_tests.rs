//! The integrated terminal against real PTYs: local commands stand in for
//! `gantry exec`, typed through GPUI's key dispatch with the app's bindings.

use crate::app::Connection;
use crate::{
    bind_keys,
    terminal_view::{TerminalState, TerminalView},
    ui_tests::desktop,
};
use gantry_desktop::{connector::Target, detail::Tab, options::Source, terminal::SessionCommand};
use gpui_kit::component::Root;
use gpui_kit::test::TestWindowExt;
use gpui_kit::{AppContext, Entity, Focusable, TestAppContext, WindowHandle, px, size};
use std::time::{Duration, Instant};

fn terminal(cx: &mut TestAppContext, script: &str) -> (WindowHandle<Root>, Entity<TerminalView>) {
    // The PTY's reader is a real thread that wakes the UI's event task.
    cx.executor().allow_parking();
    cx.update(|cx| {
        gpui_kit::init(cx);
        bind_keys(cx);
    });
    let command = SessionCommand {
        program: "/bin/sh".into(),
        args: vec!["-c".into(), script.into()],
        env: vec![],
    };
    let mut view = None;
    let window = cx.open_window(size(px(900.), px(500.)), |window, cx| {
        let terminal = cx.new(|cx| TerminalView::new(command, window, cx));
        terminal.focus_handle(cx).focus(window, cx);
        view = Some(terminal.clone());
        Root::new(terminal, window, cx)
    });
    (window, view.unwrap())
}

/// The visible screen as text, one trimmed line per row.
fn screen(view: &Entity<TerminalView>, cx: &mut TestAppContext) -> String {
    view.update(cx, |view, _| view.screen_text())
}

/// Let the PTY thread and the UI catch up until `done` holds.
fn wait(
    cx: &mut TestAppContext,
    window: WindowHandle<Root>,
    view: &Entity<TerminalView>,
    done: impl Fn(&TerminalView, &str) -> bool,
) {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        cx.run_until_parked();
        cx.update_window(window.into(), |_, window, cx| window.render_frame(cx))
            .unwrap();
        let text = screen(view, cx);
        if view.read_with(cx, |view, _| done(view, &text)) {
            return;
        }
        let state = view.read_with(cx, |view, _| view.state.clone());
        assert!(
            Instant::now() < deadline,
            "timed out in {state:?}; screen:\n{text}"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[gpui_kit::test]
fn typing_reaches_the_shell_and_its_output_is_drawn(cx: &mut TestAppContext) {
    let (window, view) = terminal(cx, r#"IFS= read -r line; printf 'got[%s]\n' "$line""#);
    // The grid follows the pane: 900 px wide at 13 px mono is well over 80.
    wait(cx, window, &view, |view, _| view.grid_columns() > 80);
    cx.simulate_keystrokes(window.into(), "h i space t h e r e enter");
    wait(cx, window, &view, |view, text| {
        text.contains("got[hi there]") && view.state == TerminalState::Exited(Some(0))
    });
}

#[gpui_kit::test]
fn ctrl_c_interrupts_the_shell_instead_of_copying(cx: &mut TestAppContext) {
    let (window, view) = terminal(
        cx,
        r#"trap 'echo interrupted; exit 7' INT; echo ready; while :; do sleep 0.05; done"#,
    );
    wait(cx, window, &view, |_, text| text.contains("ready"));
    // Escape and Ctrl+R belong to the app elsewhere; here they are the shell's.
    cx.simulate_keystrokes(window.into(), "escape ctrl-r ctrl-c");
    wait(cx, window, &view, |view, text| {
        text.contains("interrupted") && view.state == TerminalState::Exited(Some(7))
    });
}

#[gpui_kit::test]
fn an_ended_session_starts_again_on_enter(cx: &mut TestAppContext) {
    // The command waits for a line, echoes it and exits, so a restart is
    // visible as a new prompt that is still running.
    let (window, view) = terminal(cx, r#"echo prompt; IFS= read -r line; echo "said $line""#);
    wait(cx, window, &view, |_, text| text.contains("prompt"));
    cx.simulate_keystrokes(window.into(), "o n e enter");
    wait(cx, window, &view, |view, text| {
        text.contains("said one") && view.state == TerminalState::Exited(Some(0))
    });
    cx.update_window(window.into(), |_, window, _| {
        assert!(window.try_find("terminal-ended").is_some());
    })
    .unwrap();
    cx.simulate_keystrokes(window.into(), "enter");
    wait(cx, window, &view, |view, text| {
        view.state == TerminalState::Running && text.contains("prompt") && !text.contains("said")
    });
}

#[gpui_kit::test]
fn double_clicking_a_demo_sandbox_explains_why_there_is_no_shell(cx: &mut TestAppContext) {
    let (handle, desktop) = desktop(cx);
    cx.update_window(handle.into(), |_, window, cx| {
        desktop.update(cx, |this, cx| {
            this.inventory.select("dev");
            this.open_terminal("dev", window, cx);
            assert_eq!(this.detail_tab, Tab::Terminal);
            assert!(this.terminals.is_empty());
            assert!(
                this.terminal_blocker("dev")
                    .unwrap_or_default()
                    .contains("Demo sandboxes")
            );
        });
    })
    .unwrap();
    cx.update_window(handle.into(), |_, window, cx| {
        window.render_frame(cx);
        assert!(window.try_find("terminal-empty").is_some());
        assert!(window.try_find("terminal-blocked").is_some());
        // Open Terminal is disabled: clicking it starts nothing.
        window.click("terminal-open", cx);
    })
    .unwrap();
    assert!(desktop.read_with(cx, |this, _| this.terminals.is_empty()));
}

#[gpui_kit::test]
fn a_terminal_that_cannot_start_says_why_in_its_tab(cx: &mut TestAppContext) {
    let (handle, desktop) = desktop(cx);
    cx.update_window(handle.into(), |_, window, cx| {
        desktop.update(cx, |this, cx| {
            // A live local manager, as the app sees one, but no CLI to run.
            this.options.source = Source::Local("/nonexistent/gantry-test.sock".into());
            this.options.gantry = Some("/nonexistent/gantry".into());
            this.target = Some(Target {
                source: this.options.source.clone(),
                profile: None,
            });
            this.connection = Connection::Connected("v1".into());
            this.inventory.select("agent");
            // From a row menu: dev is running but not the selected row.
            this.open_terminal("dev", window, cx);
            assert_eq!(this.inventory.selected().unwrap().name, "dev");
            assert!(this.terminals.is_empty());
            let (sandbox, error) = this.terminal_error.clone().unwrap();
            assert_eq!(sandbox, "dev");
            assert!(!error.is_empty());
        });
    })
    .unwrap();
    cx.update_window(handle.into(), |_, window, cx| {
        window.render_frame(cx);
        assert!(window.try_find("terminal-error").is_some());
        assert!(window.try_find("terminal-blocked").is_none());
    })
    .unwrap();
    // With a program that runs, clicking Open Terminal opens it and the error
    // is gone.
    cx.executor().allow_parking();
    cx.update_window(handle.into(), |_, window, cx| {
        desktop.update(cx, |this, _| this.options.gantry = Some("/bin/echo".into()));
        window.render_frame(cx);
        window.click("terminal-open", cx);
    })
    .unwrap();
    cx.update_window(handle.into(), |_, window, cx| {
        desktop.read_with(cx, |this, _| {
            assert!(this.terminal_error.is_none());
            assert!(this.terminals.contains_key("dev"));
        });
        window.render_frame(cx);
        assert!(window.try_find("terminal").is_some());
        assert!(window.try_find("terminal-empty").is_none());
    })
    .unwrap();
}
