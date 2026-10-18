//! A pm plugin that runs each user's containers, for `pm container`, with rootless
//! Podman.
//!
//! A container is its user's: Podman runs it in user namespaces of theirs, with no
//! daemon and no privilege beyond what that user has, its images and its state in
//! their own home. Root's containers would run with the whole system's privilege,
//! so this plugin refuses root's requests, and with it pm runs no rootful container.
//!
//! Compose files go to podman-compose, which turns each into Podman's own commands.
//!
//! The plugin only writes command lines. It reaches nothing: like every pm plugin it
//! runs in a metered WebAssembly instance whose one import is `log`, and what it can
//! make pm run is [`LAUNCHERS`], which `pm plugins` prints.
//!
//! It boots no package's own kernel and manages no machine: `launch-machine`
//! declines, and pm starts QEMU for a package itself.

wit_bindgen::generate!({ path: "../../wit", world: "container-plugin" });

struct Podman;

/// Every program the plugin may have pm run.
pub(crate) const LAUNCHERS: [&str; 2] = ["podman", "podman-compose"];

impl Guest for Podman {
    fn describe() -> Manifest {
        Manifest {
            name: "podman".into(),
            version: env!("CARGO_PKG_VERSION").into(),
            summary: "Runs each user's containers with rootless Podman".into(),
            hooks: Vec::new(),
            grants_at_most: Vec::new(),
            source_extensions: Vec::new(),
            symbols: Vec::new(),
        }
    }

    // It classifies nothing and scans nothing: `hooks` is empty, so pm never calls
    // these, but the `plugin` world every world includes still exports them.
    fn classify_command(_command: String) -> Option<Verdict> {
        None
    }

    fn scan_source(_file: SourceFile) -> Vec<Grant> {
        Vec::new()
    }

    fn launchers() -> Vec<String> {
        LAUNCHERS.map(Into::into).to_vec()
    }

    fn container_plan(
        request: ContainerRequest,
        place: ContainerPlace,
    ) -> Result<Vec<MachineStep>, String> {
        steps(request, place)
    }

    fn launch_machine(_machine: Machine) -> Result<Option<Launch>, String> {
        Ok(None)
    }
}

export!(Podman);

/// The steps that carry `request` out for the user `place` describes.
fn steps(request: ContainerRequest, place: ContainerPlace) -> Result<Vec<MachineStep>, String> {
    if !place.rootless {
        return Err(
            "containers run rootless only, as the user they belong to, and root's \
                    would have the whole system's privilege: ask as that user"
                .into(),
        );
    }
    Ok(match request {
        ContainerRequest::List => vec![step(
            "list the containers",
            podman(&["ps", "--all", "--format", "{{.Names}}"]),
        )],
        ContainerRequest::Status(name) => vec![step(
            &format!("tell the state of the container {name}"),
            podman(&["inspect", "--format", "{{.State.Status}}", "--", &name]),
        )],
        ContainerRequest::Ports(name) => vec![step(
            &format!("list the ports of the container {name}"),
            podman(&["port", "--", &name]),
        )],
        ContainerRequest::Up(file) => vec![step(
            &format!("start what {file} describes"),
            compose(&file, &["up", "--detach"]),
        )],
        ContainerRequest::Create(file) => vec![step(
            &format!("make what {file} describes"),
            compose(&file, &["up", "--no-start"]),
        )],
        ContainerRequest::Down(file) => vec![step(
            &format!("remove what {file} describes"),
            compose(&file, &["down"]),
        )],
        ContainerRequest::Start(name) => action("start", &name),
        ContainerRequest::Stop(name) => action("stop", &name),
        ContainerRequest::Pause(name) => action("pause", &name),
        ContainerRequest::Unpause(name) => action("unpause", &name),
        ContainerRequest::Remove(name) => vec![step(
            &format!("remove the container {name}"),
            podman(&["container", "rm", "--", &name]),
        )],
        ContainerRequest::Version => vec![
            step("tell Podman's version", podman(&["--version"])),
            step(
                "tell podman-compose's version",
                launch("podman-compose", &["--version"]),
            ),
        ],
    })
}

/// `podman container <verb> <name>`, as one step.
fn action(verb: &str, name: &str) -> Vec<MachineStep> {
    vec![step(
        &format!("{verb} the container {name}"),
        podman(&["container", verb, "--", name]),
    )]
}

fn podman(args: &[&str]) -> Launch {
    launch("podman", args)
}

/// podman-compose on `file`. pm runs every step in a directory of its own, so the file
/// is named by the absolute path pm gave, and podman-compose takes the directory it
/// is in as the project's, for what the file names relative to itself.
fn compose(file: &str, args: &[&str]) -> Launch {
    let mut all = vec!["--file", file];
    all.extend_from_slice(args);
    launch("podman-compose", &all)
}

fn step(summary: &str, run: Launch) -> MachineStep {
    MachineStep {
        summary: summary.into(),
        run,
        when: None,
        unless: None,
        undo: None,
    }
}

fn launch(program: &str, args: &[&str]) -> Launch {
    Launch {
        program: program.into(),
        args: args.iter().map(|&arg| arg.into()).collect(),
        files: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ME: ContainerPlace = ContainerPlace { rootless: true };

    fn lines(request: ContainerRequest) -> Vec<String> {
        steps(request, ME)
            .unwrap()
            .iter()
            .map(|step| {
                std::iter::once(step.run.program.as_str())
                    .chain(step.run.args.iter().map(String::as_str))
                    .collect::<Vec<_>>()
                    .join(" ")
            })
            .collect()
    }

    #[test]
    fn root_is_refused_whatever_it_asks() {
        let root = ContainerPlace { rootless: false };
        for request in [
            ContainerRequest::List,
            ContainerRequest::Version,
            ContainerRequest::Start("WinBoat".into()),
            ContainerRequest::Up("/root/compose.yml".into()),
        ] {
            assert!(steps(request, root).is_err());
        }
    }

    #[test]
    fn compose_files_go_to_podman_compose_by_their_absolute_path() {
        let file = "/home/me/.winboat/podman-compose.yml";
        assert_eq!(
            lines(ContainerRequest::Up(file.into())),
            [format!("podman-compose --file {file} up --detach")]
        );
        assert_eq!(
            lines(ContainerRequest::Create(file.into())),
            [format!("podman-compose --file {file} up --no-start")]
        );
        assert_eq!(
            lines(ContainerRequest::Down(file.into())),
            [format!("podman-compose --file {file} down")]
        );
    }

    #[test]
    fn a_container_is_named_after_every_option() {
        assert_eq!(
            lines(ContainerRequest::Start("WinBoat".into())),
            ["podman container start -- WinBoat"]
        );
        assert_eq!(
            lines(ContainerRequest::Unpause("WinBoat".into())),
            ["podman container unpause -- WinBoat"]
        );
        assert_eq!(
            lines(ContainerRequest::Remove("WinBoat".into())),
            ["podman container rm -- WinBoat"]
        );
        assert_eq!(
            lines(ContainerRequest::Status("WinBoat".into())),
            ["podman inspect --format {{.State.Status}} -- WinBoat"]
        );
        assert_eq!(
            lines(ContainerRequest::Ports("WinBoat".into())),
            ["podman port -- WinBoat"]
        );
    }

    #[test]
    fn listing_and_versions_print_what_they_ask() {
        assert_eq!(
            lines(ContainerRequest::List),
            ["podman ps --all --format {{.Names}}"]
        );
        assert_eq!(
            lines(ContainerRequest::Version),
            ["podman --version", "podman-compose --version"]
        );
    }

    #[test]
    fn every_program_is_a_launcher() {
        let requests = [
            ContainerRequest::List,
            ContainerRequest::Version,
            ContainerRequest::Up("/f.yml".into()),
            ContainerRequest::Stop("x".into()),
        ];
        for request in requests {
            for step in steps(request, ME).unwrap() {
                assert!(LAUNCHERS.contains(&step.run.program.as_str()));
            }
        }
    }
}
