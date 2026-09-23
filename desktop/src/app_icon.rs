//! The Gantry mark as the application icon in the Dock, taskbar and window
//! switcher. The desktop ships as a bare executable rather than an app
//! bundle, so there is no bundle icon: macOS gets it at startup, X11 through
//! the window options, and Windows from the executable's resources
//! (build.rs). The images are rendered from assets/app-icon.svg.

/// Set the macOS Dock and app-switcher icon. Call once the app has launched.
#[cfg(target_os = "macos")]
pub fn install() {
    use objc2::{AllocAnyThread, MainThreadMarker};
    use objc2_app_kit::{NSApplication, NSImage};
    use objc2_foundation::NSData;

    let Some(main_thread) = MainThreadMarker::new() else {
        return;
    };
    let data = NSData::with_bytes(include_bytes!("../assets/app-icon.png"));
    let Some(image) = NSImage::initWithData(NSImage::alloc(), &data) else {
        return;
    };
    // SAFETY: called on the main thread with a valid image, which AppKit
    // retains.
    unsafe {
        NSApplication::sharedApplication(main_thread).setApplicationIconImage(Some(&image));
    }
}

#[cfg(not(target_os = "macos"))]
pub fn install() {}

/// The X11 window icon. Wayland compositors look the icon up by app id.
#[cfg(target_os = "linux")]
pub fn window_icon() -> Option<std::sync::Arc<image::RgbaImage>> {
    image::load_from_memory_with_format(
        include_bytes!("../assets/app-icon-256.png"),
        image::ImageFormat::Png,
    )
    .ok()
    .map(|icon| std::sync::Arc::new(icon.into_rgba8()))
}
