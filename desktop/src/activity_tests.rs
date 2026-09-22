use crate::{activity::Phase, ui_tests::desktop};
use gantry_desktop::{connector::Target, options::Source, profiles::RemoteProfile};
use gpui_kit::{AppContext, TestAppContext};

#[gpui_kit::test]
fn activity_is_bounded_and_progress_updates_in_place(cx: &mut TestAppContext) {
    let (handle, view) = desktop(cx);
    cx.update_window(handle.into(), |_, _, cx| {
        view.update(cx, |this, _| {
            for id in 0..125 {
                this.begin_activity(id, None, format!("Operation {id}"));
            }
            assert_eq!(this.activity.len(), 100);
            assert_eq!(this.activity.first().unwrap().id, 25);
            this.record_activity(124, Phase::Working, "Starting…");
            this.record_activity(124, Phase::Complete, "Confirmed by manager");
            assert_eq!(this.activity.len(), 100);
            let entry = this.activity.last().unwrap();
            assert_eq!(entry.title, "Operation 124");
            assert!(entry.phase == Phase::Complete);
            assert_eq!(entry.message, "Confirmed by manager");
        })
    })
    .unwrap();
}
#[test]
fn activity_never_mixes_a_replaced_profile_with_its_previous_manager() {
    let source = Source::Remote {
        name: "build".into(),
        config_dir: "/private/catalog".into(),
    };
    let target = Target {
        source: source.clone(),
        profile: Some(RemoteProfile {
            name: "build".into(),
            url: "https://old.example:7443".into(),
            ca_cert: String::new(),
            fingerprint: String::new(),
        }),
    };
    let entry = crate::activity::Entry::new(
        1,
        source.clone(),
        Some(target.clone()),
        "Save settings · dev".into(),
    );
    assert!(entry.visible(&source, Some(&target)));
    let mut replacement = target.clone();
    replacement.profile.as_mut().unwrap().url = "https://new.example:7443".into();
    assert!(!entry.visible(&source, Some(&replacement)));
    assert!(!entry.visible(&Source::Local("/private/manager.sock".into()), None));
}
