//! Menus capture a row name AND verified source at opening. Refresh, selection,
//! or profile changes can never turn a menu click into a different host's write.
use crate::app::Desktop;
use gantry_desktop::{
    commands::Command, connector::Target, dashboard_wire::SandboxConfigRequest, forms::Kind,
    inventory::Sandbox,
};
use gpui_kit::assets::IconName;
use gpui_kit::component::menu::{PopupMenu, PopupMenuItem};
use gpui_kit::{ClipboardItem, Context, Focusable, IntoElement, ParentElement, WeakEntity, Window};

#[derive(Clone, Copy)]
pub enum RowAction {
    Terminal,
    Start,
    Stop,
    Edit,
    Delete,
    CopyName,
    CopyImage,
}
impl Desktop {
    pub fn open_row_menu(
        &mut self,
        event: &gpui_kit::MouseDownEvent,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if event.button != gpui_kit::MouseButton::Right {
            return;
        }
        // gpui-component 0.6.4's ContextMenu retains its own dismiss subscription
        // through an Rc cycle. Intercept in capture phase and own the popup here.
        // Hit-test the last painted rows, not an ordinal from a newer snapshot.
        cx.stop_propagation();
        self.context_menu = None;
        self.context_subscription = None;
        if self.form.is_some() {
            return;
        }
        let painted = self
            .table
            .read(cx)
            .delegate()
            .painted_rows
            .iter()
            .rev()
            .find(|r| r.bounds.contains(&event.position))
            .cloned();
        let Some(painted) = painted else {
            return;
        };
        if painted.target != self.target {
            return;
        }
        self.inventory.select(&painted.row.name);
        self.sync_table(cx);
        let focus = self.table.focus_handle(cx);
        let owner = cx.weak_entity();
        let target = self.target.clone();
        let can_write = self.can_write();
        let scope = self.source_name();
        let menu = PopupMenu::build(window, cx, move |menu, _, _| {
            sandbox_menu(
                owner,
                painted.row,
                target,
                can_write,
                scope,
                menu.action_context(focus),
            )
        });
        menu.focus_handle(cx).focus(window, cx);
        self.context_subscription = Some(cx.subscribe_in(
            &menu,
            window,
            |this, _, _: &gpui_kit::DismissEvent, window, cx| {
                this.context_menu = None;
                this.context_subscription = None;
                if this.form.is_none() {
                    this.focus_inventory(window, cx);
                }
                cx.notify();
            },
        ));
        self.context_menu = Some(menu);
        self.context_position = event.position;
        cx.notify();
    }
    pub fn row_menu_layer(&self) -> Option<gpui_kit::AnyElement> {
        self.context_menu.as_ref().map(|menu| {
            gpui_kit::deferred(
                gpui_kit::anchored()
                    .position(self.context_position)
                    .snap_to_window_with_margin(gpui_kit::px(8.))
                    .child(menu.clone()),
            )
            .with_priority(2)
            .into_any_element()
        })
    }
    pub fn row_action(
        &mut self,
        name: &str,
        target: Option<&Target>,
        action: RowAction,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if self.page != gantry_desktop::workspace::Page::Sandboxes
            || self.form.is_some()
            || target != self.target.as_ref()
        {
            return;
        }
        let Some(row) = self.inventory.rows().iter().find(|r| r.name == name) else {
            return;
        };
        match action {
            RowAction::CopyName => {
                cx.write_to_clipboard(ClipboardItem::new_string(row.name.clone()));
                return;
            }
            RowAction::CopyImage => {
                cx.write_to_clipboard(ClipboardItem::new_string(row.image_label().into()));
                return;
            }
            // A shell reads and writes only inside the sandbox; it needs no
            // manager write access.
            RowAction::Terminal => {
                let name = row.name.clone();
                self.open_terminal(&name, window, cx);
                return;
            }
            _ => {}
        }
        if !self.can_write() {
            return;
        }
        let kind = match action {
            RowAction::Start if row.state == "stopped" => {
                Kind::Confirm(Command::Start(name.into()))
            }
            RowAction::Stop if row.state == "running" => Kind::Confirm(Command::Stop(name.into())),
            RowAction::Delete if row.state == "stopped" => {
                Kind::Confirm(Command::Delete(name.into()))
            }
            RowAction::Edit => {
                let Some(r) = self.host.snapshot.sandboxes.iter().find(|r| r.name == name) else {
                    return;
                };
                Kind::Configure(SandboxConfigRequest {
                    name: r.name.clone(),
                    mem_mb: r.mem_mb,
                    vcpus: r.vcpus,
                    process_isolation: r.process_isolation.clone(),
                    ssh: r.ssh,
                    dev_containers: r.dev_containers,
                })
            }
            _ => return,
        };
        self.open_form(kind, window, cx);
    }
}
pub fn sandbox_menu(
    owner: WeakEntity<Desktop>,
    row: Sandbox,
    target: Option<Target>,
    can_write: bool,
    scope: String,
    menu: PopupMenu,
) -> PopupMenu {
    let mut menu = menu
        .min_w(gpui_kit::px(258.))
        .label(format!("{} · {scope}", row.name))
        .separator();
    for (label, icon, action, disabled) in [
        (
            "Open Terminal",
            IconName::SquareTerminal,
            RowAction::Terminal,
            row.state != "running",
        ),
        (
            "Start",
            IconName::Play,
            RowAction::Start,
            !can_write || row.state != "stopped",
        ),
        (
            "Stop",
            IconName::Square,
            RowAction::Stop,
            !can_write || row.state != "running",
        ),
        (
            "Edit Settings…",
            IconName::Settings,
            RowAction::Edit,
            !can_write,
        ),
        ("Copy Name", IconName::Copy, RowAction::CopyName, false),
        (
            "Copy Image Reference",
            IconName::Copy,
            RowAction::CopyImage,
            false,
        ),
        (
            "Delete…",
            IconName::Trash,
            RowAction::Delete,
            !can_write || row.state != "stopped",
        ),
    ] {
        if matches!(action, RowAction::Edit | RowAction::Delete) {
            menu = menu.separator();
        }
        let owner = owner.clone();
        let name = row.name.clone();
        let target = target.clone();
        let mut item = PopupMenuItem::new(label).icon(icon).disabled(disabled);
        if matches!(action, RowAction::Edit) {
            // Display the keybinding. The explicit handler takes precedence over
            // dispatching this action, retaining the menu's captured target.
            item = item.action(Box::new(crate::app::EditSandbox));
        }
        menu = menu.item(item.on_click(move |_, window, cx| {
            // Let the popup finish dismissal/focus restoration before mounting
            // an editor; its captured name/source are still rechecked afterward.
            let owner = owner.clone();
            let name = name.clone();
            let target = target.clone();
            window.defer(cx, move |window, cx| {
                let _ = owner.update(cx, |this, cx| {
                    this.row_action(&name, target.as_ref(), action, window, cx)
                });
            });
        }));
    }
    menu
}
