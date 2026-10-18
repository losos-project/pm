//! Each user's own containers, for `pm container`.
//!
//! pm runs no container itself, as it runs no machine itself: the first installed
//! plugin that manages containers, such as podman, turns a [`Request`] into steps, and
//! pm runs them exactly as it runs a machine plugin's ([`crate::machine::carry_out`]),
//! held to the programs the plugin listed. A container is its user's, and runs as
//! them: [`Place`] tells the plugin whether that user is root, whose containers would
//! run with the whole system's privilege, so the plugin can refuse them.

use crate::machine::{Step, run_steps};
use miette::miette;
use std::{
    fs,
    os::unix::fs::MetadataExt as _,
    path::{Path, PathBuf},
};

/// Something to do to the containers of the user running pm.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    /// Print every container's name.
    List,
    /// Print the named container's state.
    Status(String),
    /// Print the named container's published ports.
    Ports(String),
    /// Make and start what a compose file describes.
    Up(PathBuf),
    /// Make what a compose file describes, stopped.
    Create(PathBuf),
    /// Stop and remove what a compose file describes.
    Down(PathBuf),
    /// Start the named container.
    Start(String),
    /// Stop the named container.
    Stop(String),
    /// Pause the named container.
    Pause(String),
    /// Resume the named container.
    Unpause(String),
    /// Remove the named, stopped container.
    Remove(String),
    /// Print the versions of what runs containers.
    Version,
}

impl Request {
    /// What the request does, for a log line or an error.
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            Self::List => "list the containers".into(),
            Self::Status(name) => format!("tell the state of the container {name}"),
            Self::Ports(name) => format!("list the ports of the container {name}"),
            Self::Up(file) => format!("start what {} describes", file.display()),
            Self::Create(file) => format!("make what {} describes", file.display()),
            Self::Down(file) => format!("remove what {} describes", file.display()),
            Self::Start(name) => format!("start the container {name}"),
            Self::Stop(name) => format!("stop the container {name}"),
            Self::Pause(name) => format!("pause the container {name}"),
            Self::Unpause(name) => format!("resume the container {name}"),
            Self::Remove(name) => format!("remove the container {name}"),
            Self::Version => "tell what runs containers".into(),
        }
    }
}

/// Whose containers a request is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Place {
    /// Whether the user running pm is not root.
    pub rootless: bool,
}

impl Place {
    /// The running user's place.
    #[must_use]
    pub fn for_this_user() -> Self {
        // The owner of /proc/self is the process's effective user, which std has no
        // other safe way to tell.
        let root = fs::metadata("/proc/self").is_ok_and(|me| me.uid() == 0);
        Self { rootless: !root }
    }
}

/// Something that knows how to carry out a [`Request`].
pub trait Manager {
    /// The steps that carry `request` out for the user `place` describes, in order.
    ///
    /// # Errors
    ///
    /// Nothing on the host manages containers, or the one that does refused.
    fn container_steps(&self, request: &Request, place: &Place) -> miette::Result<Vec<Step>>;
}

/// Carry `request` out: ask `manager` for its steps and run them, as a machine
/// request's are.
///
/// # Errors
///
/// The manager refused, a program is missing, or a step failed.
pub fn carry_out(manager: &dyn Manager, request: &Request) -> miette::Result<()> {
    let steps = manager.container_steps(request, &Place::for_this_user())?;
    run_steps(&steps, &request.describe())
}

/// Whether `name` can name a container: 1-64 characters of letters, digits, `_`, `.`
/// and `-`, starting with a letter or a digit, which is what Podman and Docker take.
/// Checked before a plugin sees it, so that no plugin has to be trusted to quote it.
///
/// # Errors
///
/// When it cannot.
pub fn check_container_name(name: &str) -> miette::Result<()> {
    let usable = (1..=64).contains(&name.len())
        && name.starts_with(|c: char| c.is_ascii_alphanumeric())
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'));
    if usable {
        Ok(())
    } else {
        Err(miette!(
            "`{name}` cannot name a container: 1-64 characters of letters, digits, `_`, `.` \
             and `-`, starting with a letter or a digit"
        ))
    }
}

/// `file` as an absolute path to a compose file that is there.
///
/// # Errors
///
/// It is not a file, or its absolute path cannot be found.
pub fn compose_file(file: &Path) -> miette::Result<PathBuf> {
    let absolute = fs::canonicalize(file)
        .map_err(|error| miette!("cannot find the compose file {}: {error}", file.display()))?;
    if !absolute.is_file() {
        return Err(miette!("{} is not a compose file", file.display()));
    }
    // A plugin gets the path as a string, so it has to be one.
    if absolute.to_str().is_none() {
        return Err(miette!(
            "{} is not a path a plugin can be given: it is not UTF-8",
            file.display()
        ));
    }
    Ok(absolute)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn container_names_are_what_podman_takes() {
        for name in ["WinBoat", "web.1", "a", "db_2-x"] {
            assert!(check_container_name(name).is_ok(), "{name}");
        }
        let long = "a".repeat(65);
        for name in ["", "-x", ".x", "a b", "a/b", "ä", &long] {
            assert!(check_container_name(name).is_err(), "{name}");
        }
    }

    #[test]
    fn a_compose_file_is_made_absolute_and_must_exist() {
        let directory = tempfile::tempdir().unwrap();
        let file = directory.path().join("compose.yml");
        fs::write(&file, "services: {}\n").unwrap();
        assert_eq!(
            compose_file(&file).unwrap(),
            fs::canonicalize(&file).unwrap()
        );
        assert!(compose_file(&directory.path().join("missing.yml")).is_err());
        assert!(compose_file(directory.path()).is_err());
    }
}
