use crate::{
    app::{Connection, Desktop},
    ui_tests::{desktop, desktop_at},
};
use gantry_desktop::{
    commands::Command,
    connector::Target,
    forms::{Intent, Kind},
    options::Source,
};
use gpui_kit::test::{TestAppContextExt, TestWindowExt};
use gpui_kit::{AppContext, Context, TestAppContext, px};
use std::time::Duration;

fn connected(this: &mut Desktop, source: Source, cx: &mut Context<Desktop>) {
    this.options.source = source.clone();
    this.target = Some(Target {
        source,
        profile: None,
    });
    this.connection = Connection::Connected("v1".into());
    cx.notify();
}
fn local() -> Source {
    Source::Local("/private/test/manager.sock".into())
}
fn remote() -> Source {
    Source::Remote {
        name: "build".into(),
        config_dir: "/private/client".into(),
    }
}

#[gpui_kit::test]
fn sliders_update_exact_fields_but_never_submit_or_round_existing_settings(
    cx: &mut TestAppContext,
) {
    let (handle, desktop) = desktop_at(cx, 1040., 640.);
    cx.update_window(handle.into(), |_, window, cx| {
        desktop.update(cx, |this, cx| connected(this, local(), cx));
        window.click("sandbox-edit", cx);
        window.render_frame(cx);
        assert_eq!(
            desktop.read(cx).form.as_ref().unwrap().inputs[0]
                .value(cx)
                .as_ref(),
            "4096"
        );
        assert!(window.find(("form-slider", 0usize)).bounds().size.width > px(60.));
        window.click(("form-slider", 0usize), cx);
        window.click(("form-slider", 1usize), cx);
    })
    .unwrap();
    cx.update_window(handle.into(), |_, window, cx| {
        let form = desktop.read(cx).form.as_ref().unwrap();
        assert_ne!(form.inputs[0].value(cx).as_ref(), "4096");
        assert_eq!(
            form.inputs[0].value(cx).parse::<f32>().unwrap(),
            form.sliders[&0].read(cx).value().end()
        );
        assert_eq!(
            form.inputs[1].value(cx).parse::<f32>().unwrap(),
            form.sliders[&1].read(cx).value().end()
        );
        assert!(!desktop.read(cx).writing);
        window.click(("form-input", 0usize), cx);
        window.press(
            if cfg!(target_os = "macos") {
                "cmd-a"
            } else {
                "ctrl-a"
            },
            cx,
        );
        window.input("513", cx);
    })
    .unwrap();
    cx.update_window(handle.into(), |_, window, cx| {
        let form = desktop.read(cx).form.as_ref().unwrap();
        assert_eq!(form.inputs[0].value(cx).as_ref(), "513");
        assert_eq!(form.sliders[&0].read(cx).value().end(), 513.);
        let values = form
            .spec
            .fields
            .iter()
            .zip(&form.inputs)
            .map(|(f, i)| {
                (
                    f.key.into(),
                    zeroize::Zeroizing::new(i.value(cx).to_string()),
                )
            })
            .collect();
        let Intent::Manager(Command::Configure(request)) =
            form.spec.build(&values, &desktop.read(cx).host).unwrap()
        else {
            panic!()
        };
        assert_eq!(request.mem_mb, 513);
        assert_eq!(request.name, "dev");
        window.click("form-cancel", cx);
        assert!(!desktop.read(cx).writing);
    })
    .unwrap();
}

#[gpui_kit::test]
fn slider_endpoints_and_accessibility_changes_keep_the_exact_field_in_sync(
    cx: &mut TestAppContext,
) {
    let (handle, desktop) = desktop(cx);
    cx.update_window(handle.into(), |_, window, cx| {
        desktop.update(cx, |this, cx| {
            connected(this, local(), cx);
            this.host.resource_limits.min_memory_mb = 97;
            this.host.resource_limits.max_memory_mb = 999;
        });
        window.click("sandbox-edit", cx);
        window.render_frame(cx);
        let slider = desktop.read(cx).form.as_ref().unwrap().sliders[&0].clone();
        slider.update(cx, |state, cx| {
            state.update_value_by_position(
                gpui_kit::Axis::Horizontal,
                state.bounds().origin,
                false,
                window,
                cx,
            )
        });
    })
    .unwrap();
    cx.update_window(handle.into(), |_, window, cx| {
        let form = desktop.read(cx).form.as_ref().unwrap();
        assert_eq!(form.inputs[0].value(cx).as_ref(), "97");
        let slider = form.sliders[&0].clone();
        slider.update(cx, |state, cx| {
            state.update_value_by_position(
                gpui_kit::Axis::Horizontal,
                gpui_kit::point(state.bounds().right(), state.bounds().top()),
                false,
                window,
                cx,
            )
        });
    })
    .unwrap();
    cx.update_window(handle.into(), |_, window, cx| {
        let form = desktop.read(cx).form.as_ref().unwrap();
        assert_eq!(form.inputs[0].value(cx).as_ref(), "999");
        let slider = form.sliders[&0].clone();
        // The toolkit's accessibility handler uses this setter, not Change.
        slider.update(cx, |state, cx| state.set_value(871., window, cx));
    })
    .unwrap();
    cx.update_window(handle.into(), |_, _, cx| {
        assert_eq!(
            desktop.read(cx).form.as_ref().unwrap().inputs[0]
                .value(cx)
                .as_ref(),
            "871"
        );
        assert!(!desktop.read(cx).writing);
    })
    .unwrap();
}

#[gpui_kit::test]
fn out_of_range_saved_resources_are_not_silently_changed_on_open(cx: &mut TestAppContext) {
    let (handle, desktop) = desktop(cx);
    cx.update_window(handle.into(), |_, window, cx| {
        desktop.update(cx, |this, cx| {
            connected(this, local(), cx);
            this.host.resource_limits.max_memory_mb = 1024;
            this.host.resource_limits.max_vcpus = 1;
        });
        window.click("sandbox-edit", cx);
        window.render_frame(cx);
        let form = desktop.read(cx).form.as_ref().unwrap();
        assert_eq!(form.inputs[0].value(cx).as_ref(), "4096");
        assert_eq!(form.inputs[1].value(cx).as_ref(), "4");
        assert_eq!(form.sliders[&0].read(cx).max_value(), 1024.);
        window.click("form-submit", cx);
        assert!(!desktop.read(cx).writing);
        assert!(desktop.read(cx).form.as_ref().unwrap().error.is_some());
    })
    .unwrap();
}

#[gpui_kit::test]
async fn folder_picker_preserves_spaces_cancellation_and_explicit_save(cx: &mut TestAppContext) {
    let (handle, desktop) = desktop(cx);
    cx.update_window(handle.into(), |_, window, cx| {
        desktop.update(cx, |this, cx| {
            connected(this, local(), cx);
            this.open_form(Kind::Share(None), window, cx);
        });
        window.click(("form-browse", 2usize), cx);
        desktop.update(cx, |this, cx| this.submit_form(window, cx));
        assert!(!desktop.read(cx).writing);
    })
    .unwrap();
    assert!(cx.did_prompt_for_paths());
    cx.simulate_path_prompt_response(|options| {
        assert!(options.directories && !options.files && !options.multiple);
        Some(vec!["/tmp/a project with spaces".into()])
    });
    cx.wait_for(handle.into(), Duration::from_secs(1), |_, cx| {
        desktop
            .read(cx)
            .form
            .as_ref()
            .unwrap()
            .picking_path
            .is_none()
    })
    .await;
    cx.update_window(handle.into(), |_, window, cx| {
        assert_eq!(
            desktop.read(cx).form.as_ref().unwrap().inputs[2]
                .value(cx)
                .as_ref(),
            "/tmp/a project with spaces"
        );
        assert!(!desktop.read(cx).writing);
        window.click(("form-browse", 2usize), cx);
    })
    .unwrap();
    cx.simulate_path_prompt_response(|_| None);
    cx.wait_for(handle.into(), Duration::from_secs(1), |_, cx| {
        desktop
            .read(cx)
            .form
            .as_ref()
            .unwrap()
            .picking_path
            .is_none()
    })
    .await;
    cx.update_window(handle.into(), |_, _, cx| {
        assert_eq!(
            desktop.read(cx).form.as_ref().unwrap().inputs[2]
                .value(cx)
                .as_ref(),
            "/tmp/a project with spaces"
        );
        assert!(!desktop.read(cx).writing);
    })
    .unwrap();
}

#[gpui_kit::test]
async fn late_picker_response_cannot_edit_a_replacement_form(cx: &mut TestAppContext) {
    let (handle, desktop) = desktop(cx);
    cx.update_window(handle.into(), |_, window, cx| {
        desktop.update(cx, |this, cx| {
            connected(this, local(), cx);
            this.open_form(Kind::Share(None), window, cx);
            this.browse_form_path(2, window, cx);
            this.close_form(window, cx);
            this.open_form(Kind::Share(None), window, cx);
        });
    })
    .unwrap();
    cx.simulate_path_prompt_response(|_| Some(vec!["/tmp/old selection".into()]));
    // Yield until the detached chooser completion has run.
    cx.background_executor
        .timer(Duration::from_millis(10))
        .await;
    cx.update_window(handle.into(), |_, _, cx| {
        let form = desktop.read(cx).form.as_ref().unwrap();
        assert_eq!(form.inputs[2].value(cx).as_ref(), "");
        assert!(form.picking_path.is_none());
    })
    .unwrap();
}

#[gpui_kit::test]
async fn picker_rechecks_target_and_guest_paths_never_browse(cx: &mut TestAppContext) {
    let (handle, desktop) = desktop(cx);
    cx.update_window(handle.into(), |_, window, cx| {
        desktop.update(cx, |this, cx| {
            connected(this, local(), cx);
            this.open_form(Kind::Share(None), window, cx);
            this.browse_form_path(3, window, cx); // guest mountpoint
        });
    })
    .unwrap();
    assert!(!cx.did_prompt_for_paths());
    cx.update_window(handle.into(), |_, window, cx| {
        desktop.update(cx, |this, cx| {
            this.browse_form_path(2, window, cx);
            connected(this, remote(), cx);
        });
    })
    .unwrap();
    cx.simulate_path_prompt_response(|_| Some(vec!["/tmp/local-only".into()]));
    cx.wait_for(handle.into(), Duration::from_secs(1), |_, cx| {
        desktop
            .read(cx)
            .form
            .as_ref()
            .unwrap()
            .picking_path
            .is_none()
    })
    .await;
    cx.update_window(handle.into(), |_, window, cx| {
        let form = desktop.read(cx).form.as_ref().unwrap();
        assert_eq!(form.inputs[2].value(cx).as_ref(), "");
        assert!(form.error.is_some());
        assert!(!desktop.read(cx).writing);
        desktop.update(cx, |this, cx| {
            this.close_form(window, cx);
            this.open_form(Kind::Share(None), window, cx);
            this.browse_form_path(2, window, cx);
        });
        window.render_frame(cx);
        assert!(window.try_find(("form-browse", 2usize)).is_none());
    })
    .unwrap();
    assert!(!cx.did_prompt_for_paths());
}

#[gpui_kit::test]
async fn picker_rejects_relative_paths_without_overwriting_the_draft(cx: &mut TestAppContext) {
    let (handle, desktop) = desktop(cx);
    cx.update_window(handle.into(), |_, window, cx| {
        desktop.update(cx, |this, cx| {
            connected(this, local(), cx);
            this.open_form(Kind::Create, window, cx);
            this.form.as_ref().unwrap().inputs[2].set_value("/tmp/existing-kernel", window, cx);
            this.browse_form_path(2, window, cx);
        });
    })
    .unwrap();
    cx.simulate_path_prompt_response(|options| {
        assert!(options.files && !options.directories && !options.multiple);
        Some(vec!["relative-kernel".into()])
    });
    cx.wait_for(handle.into(), Duration::from_secs(1), |_, cx| {
        desktop
            .read(cx)
            .form
            .as_ref()
            .unwrap()
            .picking_path
            .is_none()
    })
    .await;
    cx.update_window(handle.into(), |_, _, cx| {
        let form = desktop.read(cx).form.as_ref().unwrap();
        assert_eq!(form.inputs[2].value(cx).as_ref(), "/tmp/existing-kernel");
        assert!(form.error.is_some());
        assert!(!desktop.read(cx).writing);
    })
    .unwrap();
}

#[cfg(unix)]
#[gpui_kit::test]
async fn picker_never_lossily_decodes_non_utf8_paths(cx: &mut TestAppContext) {
    use std::os::unix::ffi::OsStringExt;
    let (handle, desktop) = desktop(cx);
    cx.update_window(handle.into(), |_, window, cx| {
        desktop.update(cx, |this, cx| {
            connected(this, local(), cx);
            this.open_form(Kind::Share(None), window, cx);
            this.browse_form_path(2, window, cx);
        });
    })
    .unwrap();
    cx.simulate_path_prompt_response(|_| {
        Some(vec![
            std::ffi::OsString::from_vec(b"/tmp/non-utf8-\xff".to_vec()).into(),
        ])
    });
    cx.wait_for(handle.into(), Duration::from_secs(1), |_, cx| {
        desktop
            .read(cx)
            .form
            .as_ref()
            .unwrap()
            .picking_path
            .is_none()
    })
    .await;
    cx.update_window(handle.into(), |_, _, cx| {
        let form = desktop.read(cx).form.as_ref().unwrap();
        assert_eq!(form.inputs[2].value(cx).as_ref(), "");
        assert!(form.error.is_some());
        assert!(!desktop.read(cx).writing);
    })
    .unwrap();
}

#[gpui_kit::test]
async fn desktop_ca_picker_works_while_a_remote_manager_is_selected(cx: &mut TestAppContext) {
    let (handle, desktop) = desktop(cx);
    cx.update_window(handle.into(), |_, window, cx| {
        desktop.update(cx, |this, cx| {
            connected(this, remote(), cx);
            this.config_dir = Some("/private/client".into());
            this.open_form(Kind::RemoteAdd, window, cx);
        });
        window.click(("form-browse", 2usize), cx);
    })
    .unwrap();
    cx.simulate_path_prompt_response(|options| {
        assert!(options.files && !options.directories && !options.multiple);
        Some(vec!["/tmp/public CA.pem".into()])
    });
    cx.wait_for(handle.into(), Duration::from_secs(1), |_, cx| {
        desktop
            .read(cx)
            .form
            .as_ref()
            .unwrap()
            .picking_path
            .is_none()
    })
    .await;
    cx.update_window(handle.into(), |_, _, cx| {
        assert_eq!(
            desktop.read(cx).form.as_ref().unwrap().inputs[2]
                .value(cx)
                .as_ref(),
            "/tmp/public CA.pem"
        );
        assert!(!desktop.read(cx).writing);
    })
    .unwrap();
}
