use gantry_desktop::profiles::{RemoteProfile, validate_name};

fn profile(url: &str) -> RemoteProfile {
    RemoteProfile {
        name: "team".into(),
        url: url.into(),
        fingerprint: String::new(),
        ca_cert: String::new(),
    }
}

#[test]
fn only_explicit_credential_free_https_origins_are_accepted() {
    for url in [
        "http://host",
        "https://user:password@host",
        "https://@host",
        "https://host/path",
        "https://host/..",
        "https://host?",
        "https://host#",
        "https://host/#x",
        "https://host\\path",
        " https://host",
    ] {
        assert!(profile(url).validate().is_err(), "accepted {url}");
    }
    for url in [
        "https://localhost:8443",
        "https://example.com/",
        "https://[::1]:8443",
    ] {
        profile(url).validate().unwrap();
    }
    for name in ["", "../team", "team.prod", "a/b", ".."] {
        assert!(validate_name(name).is_err());
    }
}

#[test]
fn ca_material_must_be_public_and_pins_well_formed() {
    let generated = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let mut p = profile("https://localhost");
    p.ca_cert = generated.cert.pem();
    p.validate().unwrap();
    p.ca_cert.push_str(&generated.signing_key.serialize_pem());
    assert!(p.validate().is_err());
    p.ca_cert = "-----BEGIN CERTIFICATE-----\nYWJj\n-----END CERTIFICATE-----".into();
    assert!(p.validate().is_err());
    p.ca_cert.clear();
    for invalid in ["sha256:abcd", "sha512:0000", "sha256:ZZZZ"] {
        p.fingerprint = invalid.into();
        assert!(p.validate().is_err());
    }
}

#[cfg(unix)]
mod private_store {
    use std::{
        fs,
        os::{
            fd::AsRawFd,
            unix::fs::{PermissionsExt, symlink},
        },
        path::Path,
    };

    const TOKEN: &str = "synthetic-private-bearer-token";

    fn store() -> tempfile::TempDir {
        let root = tempfile::Builder::new()
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap();
        fs::create_dir(root.path().join("remotes")).unwrap();
        fs::set_permissions(
            root.path().join("remotes"),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        write(
            root.path(),
            "remotes.json",
            r#"{"remotes":[{"name":"team","url":"https://localhost:8443"}]}"#,
        );
        write(root.path(), "remotes/store.lock", "");
        write(root.path(), "remotes/team.token", TOKEN);
        root
    }

    fn write(root: &Path, name: &str, value: &str) {
        let path = root.join(name);
        fs::write(&path, value).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    #[test]
    fn existing_cli_profile_format_and_token_rotation_are_supported() {
        let root = store();
        let (profile, token) = gantry_desktop::profiles::load(root.path(), "team").unwrap();
        assert_eq!(profile.url, "https://localhost:8443");
        assert_eq!(token.expose(), TOKEN);
        assert!(!format!("{token:?}").contains(TOKEN));
        write(
            root.path(),
            "remotes/team.token",
            "rotated-bearer-value\r\n",
        );
        let (_, token) = gantry_desktop::profiles::load(root.path(), "team").unwrap();
        assert_eq!(token.expose(), "rotated-bearer-value");
        fs::remove_file(root.path().join("remotes/team.token")).unwrap();
        assert!(gantry_desktop::profiles::load(root.path(), "team").is_err());
    }

    #[test]
    fn unsafe_tokens_symlinks_and_duplicate_profiles_are_refused() {
        let root = store();
        let token = root.path().join("remotes/team.token");
        fs::set_permissions(&token, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(gantry_desktop::profiles::load(root.path(), "team").is_err());
        fs::remove_file(&token).unwrap();
        symlink(root.path().join("remotes.json"), &token).unwrap();
        assert!(gantry_desktop::profiles::load(root.path(), "team").is_err());
        fs::remove_file(&token).unwrap();
        write(root.path(), "remotes/team.token", TOKEN);
        write(
            root.path(),
            "remotes.json",
            r#"{"remotes":[{"name":"team","url":"https://one.example"},{"name":"team","url":"https://two.example"}]}"#,
        );
        assert!(gantry_desktop::profiles::load(root.path(), "team").is_err());
    }

    #[test]
    fn profile_replacement_cannot_pair_a_previous_origin_with_a_new_token() {
        let root = store();
        let lock = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(root.path().join("remotes/store.lock"))
            .unwrap();
        // SAFETY: flock receives a live owned descriptor and valid flags. This
        // is the same exclusive lock the Go CLI holds across remove/add.
        assert_eq!(
            unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
            0
        );
        write(root.path(), "remotes/team.token", "new-server-bearer-token");
        assert!(
            gantry_desktop::profiles::load(root.path(), "team")
                .unwrap_err()
                .to_string()
                .contains("being updated")
        );
        write(
            root.path(),
            "remotes.json",
            r#"{"remotes":[{"name":"team","url":"https://new.example"}]}"#,
        );
        drop(lock);
        let (profile, token) = gantry_desktop::profiles::load(root.path(), "team").unwrap();
        assert_eq!(profile.url, "https://new.example");
        assert_eq!(token.expose(), "new-server-bearer-token");
    }
}
