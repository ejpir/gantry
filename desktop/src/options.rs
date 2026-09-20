use std::{
    ffi::OsString,
    path::{Component, Path, PathBuf},
};

use anyhow::{Result, bail};

pub const HELP: &str = "Gantry Desktop — read-only local sandbox inspector

Usage: gantry-desktop [--socket PATH | --demo] [--theme system|dark|light]

  --socket PATH   Connect to this private Gantry manager socket
  --demo          Show clearly labeled sample data; no manager connection
  --theme MODE    Initial appearance (default: system)
  -h, --help      Show this help

The default socket is ~/.gantry/manager.sock. GANTRY_MANAGER_SOCKET and
GANTRY_HOME are resolved like gantry serve. Start the manager separately;
this application never starts, stops, or modifies sandboxes.

Local socket connections require Linux or macOS in this first preview.
";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Source {
    Local(PathBuf),
    Demo,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Appearance {
    #[default]
    System,
    Dark,
    Light,
}

impl Appearance {
    pub fn label(self) -> &'static str {
        match self {
            Self::System => "System",
            Self::Dark => "Dark",
            Self::Light => "Light",
        }
    }

    pub fn next(self) -> Self {
        match self {
            Self::System => Self::Dark,
            Self::Dark => Self::Light,
            Self::Light => Self::System,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Options {
    pub source: Source,
    pub appearance: Appearance,
}

#[derive(Default)]
pub struct SocketDefaults {
    pub manager_socket: Option<PathBuf>,
    pub gantry_home: Option<PathBuf>,
    pub home: Option<PathBuf>,
}

impl SocketDefaults {
    pub fn from_env() -> Self {
        let path = |key| {
            std::env::var_os(key)
                .filter(|value| !value.is_empty())
                .map(PathBuf::from)
        };
        Self {
            manager_socket: path("GANTRY_MANAGER_SOCKET"),
            gantry_home: path("GANTRY_HOME"),
            home: path("HOME").or_else(|| path("USERPROFILE")),
        }
    }

    fn resolve(self) -> Result<PathBuf> {
        if let Some(path) = self.manager_socket {
            return Ok(path);
        }
        if let Some(path) = self.gantry_home {
            // Match filepath.Dir(filepath.Clean(GANTRY_HOME)) in the manager.
            // This is a lexical cleanup, not filesystem/symlink canonicalization.
            let path = clean_path(&path);
            return Ok(path.parent().unwrap_or(&path).join("manager.sock"));
        }
        if let Some(path) = self.home {
            return Ok(path.join(".gantry/manager.sock"));
        }
        bail!("Cannot locate the manager socket without a home directory; pass --socket PATH")
    }
}

fn clean_path(path: &Path) -> PathBuf {
    let mut result = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => match result.components().next_back() {
                Some(Component::Normal(_)) => {
                    result.pop();
                }
                Some(Component::RootDir) => {}
                _ => result.push(component.as_os_str()),
            },
            _ => result.push(component.as_os_str()),
        }
    }
    if result.as_os_str().is_empty() {
        result.push(".");
    }
    result
}

impl Options {
    /// None means --help, which must work without a display or home directory.
    pub fn parse(
        args: impl IntoIterator<Item = OsString>,
        defaults: SocketDefaults,
    ) -> Result<Option<Self>> {
        let mut args = args.into_iter();
        let mut socket = None;
        let mut demo = false;
        let mut appearance = Appearance::System;
        while let Some(arg) = args.next() {
            match arg.to_str() {
                Some("-h" | "--help") => return Ok(None),
                Some("--demo") => demo = true,
                Some("--socket") => {
                    if socket.is_some() {
                        bail!("--socket can only be specified once");
                    }
                    let value = args
                        .next()
                        .filter(|value| {
                            !value.is_empty() && !value.to_string_lossy().starts_with("--")
                        })
                        .ok_or_else(|| anyhow::anyhow!("--socket requires a path"))?;
                    socket = Some(PathBuf::from(value));
                }
                Some("--theme") => {
                    appearance = match args.next().as_deref().and_then(|value| value.to_str()) {
                        Some("system") => Appearance::System,
                        Some("dark") => Appearance::Dark,
                        Some("light") => Appearance::Light,
                        _ => bail!("--theme requires system, dark, or light"),
                    };
                }
                _ => bail!(
                    "Unknown argument: {}. Use --help for usage.",
                    arg.to_string_lossy()
                ),
            }
        }
        if demo && socket.is_some() {
            bail!("--demo and --socket cannot be combined");
        }
        let source = if demo {
            Source::Demo
        } else {
            Source::Local(match socket {
                Some(path) => path,
                None => defaults.resolve()?,
            })
        };
        Ok(Some(Self { source, appearance }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str], defaults: SocketDefaults) -> Result<Option<Options>> {
        Options::parse(args.iter().map(OsString::from), defaults)
    }

    #[test]
    fn default_path_matches_manager() {
        let defaults = SocketDefaults {
            home: Some("/home/test".into()),
            ..Default::default()
        };
        assert_eq!(
            parse(&[], defaults).unwrap().unwrap().source,
            Source::Local("/home/test/.gantry/manager.sock".into())
        );
    }

    #[test]
    fn socket_precedence_matches_manager() {
        let defaults = || SocketDefaults {
            manager_socket: Some("/private/override.sock".into()),
            gantry_home: Some("/state/sandboxes".into()),
            home: Some("/home/test".into()),
        };
        assert_eq!(
            parse(&[], defaults()).unwrap().unwrap().source,
            Source::Local("/private/override.sock".into())
        );
        assert_eq!(
            parse(&["--socket", "/explicit.sock"], defaults())
                .unwrap()
                .unwrap()
                .source,
            Source::Local("/explicit.sock".into())
        );
        let defaults = SocketDefaults {
            gantry_home: Some("/state/sandboxes/".into()),
            ..Default::default()
        };
        assert_eq!(
            parse(&[], defaults).unwrap().unwrap().source,
            Source::Local("/state/manager.sock".into())
        );
    }

    #[test]
    fn gantry_home_is_cleaned_before_selecting_its_parent() {
        for (home, expected) in [
            ("/state/old/../sandboxes/", "/state/manager.sock"),
            ("/state/sandboxes/..", "/manager.sock"),
            ("/", "/manager.sock"),
            ("sandboxes", "manager.sock"),
            ("../state/sandboxes", "../state/manager.sock"),
        ] {
            let defaults = SocketDefaults {
                gantry_home: Some(home.into()),
                ..Default::default()
            };
            assert_eq!(
                parse(&[], defaults).unwrap().unwrap().source,
                Source::Local(expected.into())
            );
        }
    }

    #[test]
    fn demo_is_explicit_and_does_not_require_home() {
        let options = parse(&["--demo", "--theme", "dark"], SocketDefaults::default())
            .unwrap()
            .unwrap();
        assert_eq!(options.source, Source::Demo);
        assert_eq!(options.appearance, Appearance::Dark);
        assert!(parse(&["--demo", "--socket", "x"], SocketDefaults::default()).is_err());
    }

    #[test]
    fn invalid_options_fail_instead_of_silently_connecting_elsewhere() {
        for args in [
            &["--remote", "team"][..],
            &["--socket"],
            &["--socket", "--demo"],
            &["--theme", "sepia"],
        ] {
            assert!(parse(args, SocketDefaults::default()).is_err());
        }
        assert!(parse(&[], SocketDefaults::default()).is_err());
        assert!(
            parse(&["--help"], SocketDefaults::default())
                .unwrap()
                .is_none()
        );
    }
}
