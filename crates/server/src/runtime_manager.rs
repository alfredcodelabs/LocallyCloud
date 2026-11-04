//! User-facing runtime management. Downloads are explicit; serving AWS never calls this.
use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{symlink, DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::Stdio;

use serde_json::{json, Value};

const IMPORTER: &str = include_str!("../../../scripts/import-lambda-runtime.py");
pub const USAGE: &str = "Usage: locallycloud runtime <COMMAND>\n\n\
Commands:\n\
  install RUNTIME       Prepare one official AWS runtime for this machine\n\
  list                  List installed runtimes\n\
  check-updates [NAME]  Check installed runtimes without changing them\n\
  update RUNTIME        Verify and activate the current upstream version\n\
  rollback RUNTIME      Switch back to the previous installed version\n\
  remove RUNTIME        Remove a runtime if no execution environment uses it\n\n\
Options:\n\
  --json                Print structured output\n\
  --directory PATH      Override LOCALLYCLOUD_RUNTIME_PACKS_DIR\n\
  --arch x86_64|arm64    Override automatic host architecture selection\n\
  --digest sha256:HEX    Pin install/update to an immutable image digest\n\
  -h, --help            Print this help\n\n\
Examples: nodejs24.x, python3.14, ruby4.0, dotnet10, provided.al2023 (Go bootstrap).\n\
Preparation requires Python 3. Listing, rollback and removal do not.\n\
No server, state database or KMS master key is required.";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Help,
    Install,
    List,
    CheckUpdates,
    Update,
    Remove,
    Rollback,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Options {
    action: Action,
    runtime: Option<String>,
    architecture: Option<String>,
    directory: Option<PathBuf>,
    digest: Option<String>,
    json: bool,
}

#[derive(Clone)]
struct Runtime {
    name: String,
    repository: &'static str,
    reference: String,
}

fn failure(message: impl Into<String>) -> io::Error {
    io::Error::other(message.into())
}

fn runtime(name: &str) -> Result<Runtime, String> {
    let (repository, reference) = locallycloud_lambda::runtime_pack::official_image(name)
        .map_err(|error| error.to_string())?;
    let repository = repository
        .strip_prefix("lambda/")
        .ok_or("invalid official repository")?;
    Ok(Runtime {
        name: name.to_owned(),
        repository,
        reference,
    })
}

fn architecture() -> Result<&'static str, String> {
    match std::env::consts::ARCH {
        "x86_64" => Ok("x86_64"),
        "aarch64" => Ok("arm64"),
        _ => Err("runtime packs require an x86_64 or arm64 Linux host".into()),
    }
}

fn valid_digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|v| {
        v.len() == 64
            && v.bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    })
}

pub fn parse(args: &[String]) -> Result<Options, String> {
    let action = match args.first().map(String::as_str) {
        None | Some("--help" | "-h") => Action::Help,
        Some("install") => Action::Install,
        Some("list") => Action::List,
        Some("check-updates") => Action::CheckUpdates,
        Some("update") => Action::Update,
        Some("remove") => Action::Remove,
        Some("rollback") => Action::Rollback,
        _ => return Err(format!("unknown runtime command\n\n{USAGE}")),
    };
    let mut options = Options {
        action,
        runtime: None,
        architecture: None,
        directory: None,
        digest: None,
        json: false,
    };
    let mut args = args.iter().skip(1);
    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--json" if !options.json => options.json = true,
            "--help" | "-h" => options.action = Action::Help,
            "--arch" if options.architecture.is_none() => {
                let value = args.next().ok_or("--arch requires x86_64 or arm64")?;
                if !matches!(value.as_str(), "x86_64" | "arm64") {
                    return Err("--arch requires x86_64 or arm64".into());
                }
                options.architecture = Some(value.clone());
            }
            "--directory" if options.directory.is_none() => {
                let value = args
                    .next()
                    .filter(|v| !v.is_empty())
                    .ok_or("--directory requires a path")?;
                options.directory = Some(PathBuf::from(value));
            }
            "--digest" if options.digest.is_none() => {
                let value = args.next().ok_or("--digest requires sha256:HEX")?;
                if !valid_digest(value) {
                    return Err("--digest requires a lowercase sha256 digest".into());
                }
                options.digest = Some(value.clone());
            }
            name if !name.starts_with('-') && options.runtime.is_none() => {
                runtime(name)?;
                options.runtime = Some(name.into());
            }
            other => return Err(format!("unknown or duplicate runtime argument: {other}")),
        }
    }
    if options.action == Action::Help {
        return Ok(options);
    }
    match (options.action, options.runtime.is_some()) {
        (Action::Install | Action::Update | Action::Remove | Action::Rollback, false) => {
            return Err("this command requires a runtime name".into())
        }
        (Action::List, true) => return Err("list does not accept a runtime name".into()),
        _ => {}
    }
    if options.digest.is_some() && !matches!(options.action, Action::Install | Action::Update) {
        return Err("--digest is only valid for install/update".into());
    }
    Ok(options)
}

fn directory(options: &Options) -> Result<PathBuf, String> {
    let configured = options.directory.clone().or_else(|| {
        std::env::var_os("LOCALLYCLOUD_RUNTIME_PACKS_DIR")
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
    });
    let path = configured.unwrap_or_else(|| {
        std::env::var_os("LOCALLYCLOUD_WORK_DIR")
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| locallycloud_compute::private_dir::work_dir("lambda"))
            .join("runtime-packs")
    });
    if path.is_absolute() {
        Ok(path)
    } else {
        std::env::current_dir()
            .map(|cwd| cwd.join(path))
            .map_err(|e| e.to_string())
    }
}

fn private(path: &Path) -> io::Result<()> {
    validate_location(path)?;
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)?;
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o022 != 0
    {
        return Err(failure("runtime store directory must not be a link"));
    }
    Ok(())
}

fn validate_location(path: &Path) -> io::Result<()> {
    if !path.is_absolute()
        || path
            .components()
            .any(|p| matches!(p, std::path::Component::ParentDir))
    {
        return Err(failure(
            "runtime store paths must be absolute and contain no parent traversal",
        ));
    }
    for parent in path.ancestors() {
        match fs::symlink_metadata(parent) {
            Ok(metadata) if !metadata.is_dir() => {
                return Err(failure(
                    "runtime store paths must not contain links or files",
                ))
            }
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

fn lock(path: &Path, operation: i32) -> io::Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.nlink() != 1 {
        return Err(failure("runtime lock must be a regular file with one link"));
    }
    loop {
        if unsafe { libc::flock(file.as_raw_fd(), operation) } == 0 {
            return Ok(file);
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

fn metadata(path: &Path) -> io::Result<Value> {
    read_json(&path.join("manifest.json"), 65536)
}

fn read_json(path: &Path, limit: u64) -> io::Result<Value> {
    use std::io::Read;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    if !file.metadata()?.is_file() {
        return Err(failure("runtime metadata must be a regular file"));
    }
    let mut contents = Vec::new();
    file.take(limit + 1).read_to_end(&mut contents)?;
    if contents.len() as u64 > limit {
        return Err(failure("runtime manifest exceeds its limit"));
    }
    serde_json::from_slice(&contents).map_err(io::Error::other)
}

fn resolve(root: &Path, path: &Path) -> io::Result<PathBuf> {
    let resolved = fs::canonicalize(path)?;
    if resolved == root || !resolved.starts_with(root) {
        return Err(failure("runtime pointer escapes its store"));
    }
    Ok(resolved)
}

fn resolve_version(root: &Path, path: &Path, spec: &Runtime, arch: &str) -> io::Result<PathBuf> {
    let resolved = resolve(root, path)?;
    let version_root = root.join(".versions").join(&spec.name).join(arch);
    if resolved != root.join(&spec.name).join(arch)
        && resolved.parent() != Some(version_root.as_path())
    {
        return Err(failure(
            "runtime pointer does not reference one of its own versions",
        ));
    }
    let manifest = metadata(&resolved)?;
    if manifest["runtime"] != spec.name || manifest["architecture"] != arch {
        return Err(failure("runtime version identity mismatch"));
    }
    let digest = version_id(&manifest)?;
    if resolved.parent() == Some(version_root.as_path())
        && resolved.file_name().and_then(|n| n.to_str()) != Some(digest)
    {
        return Err(failure("runtime directory does not match its image digest"));
    }
    Ok(resolved)
}

fn confirm_current(root: &Path, spec: &Runtime, arch: &str, digest: &Value) -> io::Result<bool> {
    let _catalog = lock(&root.join(".catalog.lock"), libc::LOCK_SH)?;
    let active = root.join(&spec.name).join(arch);
    let path = optional_version(root, &active, spec, arch)?.ok_or_else(|| {
        failure("runtime was removed during preparation; update was not activated")
    })?;
    if metadata(&path)?["source"]["imageDigest"] != *digest {
        return Ok(false);
    }
    locallycloud_lambda::runtime_pack::validate(&path, &spec.name, arch)?;
    Ok(true)
}

fn previous(root: &Path, runtime: &str, arch: &str) -> PathBuf {
    root.join(runtime).join(format!(".previous-{arch}"))
}

fn installed(root: &Path, name: Option<&str>, arch: Option<&str>) -> io::Result<Vec<Value>> {
    if !root.exists() {
        return Ok(vec![]);
    }
    let root = fs::canonicalize(root)?;
    let _catalog = lock(&root.join(".catalog.lock"), libc::LOCK_SH)?;
    let mut rows = vec![];
    for entry in fs::read_dir(&root)? {
        let entry = entry?;
        let Some(runtime_name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if runtime(&runtime_name).is_err() || name.is_some_and(|n| n != runtime_name) {
            continue;
        }
        if !entry.file_type()?.is_dir() {
            return Err(failure("runtime family is not a real directory"));
        }
        for architecture in ["x86_64", "arm64"] {
            if arch.is_some_and(|a| a != architecture) {
                continue;
            }
            let active = entry.path().join(architecture);
            if fs::symlink_metadata(&active).is_err_and(|e| e.kind() == io::ErrorKind::NotFound) {
                continue;
            }
            let path = resolve(&root, &active)?;
            let current = metadata(&path)?;
            if current["runtime"] != runtime_name || current["architecture"] != architecture {
                return Err(failure(
                    "installed runtime identity does not match its directory",
                ));
            }
            let prior = previous(&root, &runtime_name, architecture);
            let previous_digest = match fs::symlink_metadata(&prior) {
                Ok(_) => Some(metadata(&resolve(&root, &prior)?)?["source"]["imageDigest"].clone()),
                Err(e) if e.kind() == io::ErrorKind::NotFound => None,
                Err(e) => return Err(e),
            };
            rows.push(json!({"runtime":runtime_name,"architecture":architecture,"digest":current["source"]["imageDigest"],"previousDigest":previous_digest}));
        }
    }
    rows.sort_by(|a, b| {
        a["runtime"]
            .as_str()
            .cmp(&b["runtime"].as_str())
            .then(a["architecture"].as_str().cmp(&b["architecture"].as_str()))
    });
    Ok(rows)
}

async fn blocking<T: Send + 'static>(
    work: impl FnOnce() -> io::Result<T> + Send + 'static,
) -> Result<T, String> {
    tokio::task::spawn_blocking(work)
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| e.to_string())
}

async fn backend(arguments: &[String]) -> Result<Value, String> {
    use tokio::io::AsyncReadExt;
    let importing = arguments.first().is_some_and(|command| command == "import");
    let mut preparation = tokio::process::Command::new("python3");
    preparation
        .arg("-c")
        .arg(IMPORTER)
        .args(arguments)
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .stdin(Stdio::null())
        .stdout(if importing {
            Stdio::null()
        } else {
            Stdio::piped()
        })
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let parent = unsafe { libc::getpid() };
    // SAFETY: only async-signal-safe syscalls execute between fork and exec.
    unsafe {
        preparation.pre_exec(move || {
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM) != 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::getppid() != parent {
                return Err(io::Error::from_raw_os_error(libc::ECHILD));
            }
            Ok(())
        });
    }
    let command = preparation.spawn();
    let mut child = command.map_err(|e| match e.kind() {
        io::ErrorKind::NotFound => "Python 3 is required to prepare/check official runtimes. Install python3 (Debian/Ubuntu) or python (Arch); running already installed runtimes does not need it.".to_string(),
        _ => format!("could not start runtime preparation: {e}"),
    })?;
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let output = tokio::spawn(async move {
        let mut bytes = vec![];
        if let Some(stdout) = stdout {
            stdout
                .take(16 * 1024 * 1024)
                .read_to_end(&mut bytes)
                .await?;
        }
        Ok::<_, io::Error>(bytes)
    });
    let errors = tokio::spawn(async move {
        let mut bytes = vec![];
        if let Some(stderr) = stderr {
            stderr.take(65536).read_to_end(&mut bytes).await?;
        }
        Ok::<_, io::Error>(bytes)
    });
    let status = tokio::select! {
        status = child.wait() => status.map_err(|e| e.to_string())?,
        _ = tokio::signal::ctrl_c() => {
            // A terminal normally signals both processes. Give Python time to remove
            // its exclusive partial file; direct signals to this CLI are forwarded.
            if tokio::time::timeout(std::time::Duration::from_millis(250),child.wait()).await.is_err() {
                if let Some(pid)=child.id(){unsafe{libc::kill(pid as i32,libc::SIGINT);}}
                if tokio::time::timeout(std::time::Duration::from_secs(3),child.wait()).await.is_err(){let _=child.kill().await;let _=child.wait().await;}
            }
            output.abort();errors.abort();
            return Err("runtime preparation interrupted; installed versions were not changed".into());
        },
    };
    let output = output
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| e.to_string())?;
    let errors = errors
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| e.to_string())?;
    if !status.success() {
        // Upstream HTTP error handling omits registry bearer tokens and signed URLs.
        let error = String::from_utf8_lossy(&errors);
        return Err(format!("runtime preparation failed: {}", error.trim()));
    }
    if importing {
        return Ok(Value::Null);
    }
    serde_json::from_slice(&output)
        .map_err(|_| "runtime preparation returned an invalid result".into())
}

fn image_args(runtime: &Runtime, arch: &str, path: &Path, digest: Option<&str>) -> Vec<String> {
    vec![
        "inspect".into(),
        "--repository".into(),
        runtime.repository.into(),
        "--reference".into(),
        digest.unwrap_or(&runtime.reference).into(),
        "--runtime".into(),
        runtime.name.clone(),
        "--architecture".into(),
        if arch == "x86_64" { "amd64" } else { "arm64" }.into(),
        "--work".into(),
        path.display().to_string(),
    ]
}

fn version_id(manifest: &Value) -> io::Result<&str> {
    manifest["source"]["imageDigest"]
        .as_str()
        .filter(|v| valid_digest(v))
        .and_then(|v| v.strip_prefix("sha256:"))
        .ok_or_else(|| failure("runtime image digest is invalid"))
}

fn pointer(target: &Path, active: &Path) -> io::Result<()> {
    let temporary = active.with_file_name(format!(".pointer-{}", uuid::Uuid::new_v4()));
    let parent = active
        .parent()
        .ok_or_else(|| failure("runtime pointer has no parent"))?;
    let from: Vec<_> = parent.components().collect();
    let to: Vec<_> = target.components().collect();
    let common = from.iter().zip(&to).take_while(|(a, b)| a == b).count();
    let mut relative = PathBuf::new();
    for _ in common..from.len() {
        relative.push("..");
    }
    for part in &to[common..] {
        relative.push(part.as_os_str());
    }
    symlink(relative, &temporary)?;
    if let Err(error) = fs::rename(&temporary, active) {
        let _ = fs::remove_file(temporary);
        return Err(error);
    }
    File::open(parent)?.sync_all()
}

fn remove_tree(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut directories = vec![path.to_owned()];
    while let Some(directory) = directories.pop() {
        if !fs::symlink_metadata(&directory)?.is_dir() {
            continue;
        }
        let mode = fs::metadata(&directory)?.permissions().mode();
        fs::set_permissions(&directory, fs::Permissions::from_mode(mode | 0o700))?;
        for entry in fs::read_dir(&directory)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                directories.push(entry.path());
            }
        }
    }
    fs::remove_dir_all(path)
}

fn optional_version(
    root: &Path,
    path: &Path,
    spec: &Runtime,
    arch: &str,
) -> io::Result<Option<PathBuf>> {
    match fs::symlink_metadata(path) {
        Ok(_) => resolve_version(root, path, spec, arch).map(Some),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

fn set_pointer(target: Option<&Path>, path: &Path) -> io::Result<()> {
    match target {
        Some(target) if fs::canonicalize(path).is_ok_and(|current| current == target) => Ok(()),
        Some(target) => pointer(target, path),
        None => match fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        },
    }
}

fn journal_path(root: &Path, spec: &Runtime, arch: &str) -> PathBuf {
    root.join(&spec.name)
        .join(format!(".transaction-{arch}.json"))
}

fn publish_pointers(
    root: &Path,
    spec: &Runtime,
    arch: &str,
    active_target: &Path,
    prior_target: Option<&Path>,
) -> io::Result<()> {
    use std::io::Write;
    let active = root.join(&spec.name).join(arch);
    let prior = previous(root, &spec.name, arch);
    let old_active = optional_version(root, &active, spec, arch)?;
    let old_prior = optional_version(root, &prior, spec, arch)?;
    let relative = |p: &Path| {
        p.strip_prefix(root)
            .map(Path::to_path_buf)
            .map_err(io::Error::other)
    };
    let record = json!({"oldActive":old_active.as_deref().map(relative).transpose()?,"oldPrevious":old_prior.as_deref().map(relative).transpose()?,"newActive":relative(active_target)?,"newPrevious":prior_target.map(relative).transpose()?});
    let journal = journal_path(root, spec, arch);
    let temporary = journal.with_file_name(format!(".transaction-tmp-{}", uuid::Uuid::new_v4()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)?;
    file.write_all(&serde_json::to_vec(&record).map_err(io::Error::other)?)?;
    file.sync_all()?;
    fs::rename(&temporary, &journal)?;
    File::open(
        journal
            .parent()
            .ok_or_else(|| failure("journal parent missing"))?,
    )?
    .sync_all()?;
    let result = (|| {
        set_pointer(prior_target, &prior)?;
        pointer(active_target, &active)
    })();
    if let Err(error) = result {
        // Keep the journal if restoration fails; the next command retries recovery.
        set_pointer(old_active.as_deref(), &active)?;
        set_pointer(old_prior.as_deref(), &prior)?;
        fs::remove_file(&journal)?;
        return Err(error);
    }
    fs::remove_file(journal)?;
    Ok(())
}

fn recover(root: &Path) -> io::Result<()> {
    if !root.exists() {
        return Ok(());
    }
    let root = fs::canonicalize(root)?;
    let _catalog = lock(&root.join(".catalog.lock"), libc::LOCK_EX)?;
    let stages = root.join(".staging");
    validate_location(&stages)?;
    if stages.exists() {
        for entry in fs::read_dir(&stages)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().into_owned();
            let Some((name, id)) = name.split_once('-') else {
                continue;
            };
            if runtime(name).is_err() || uuid::Uuid::parse_str(id).is_err() {
                continue;
            }
            if !entry.file_type()?.is_dir() {
                return Err(failure("runtime staging directory must not be a link"));
            }
            match lock(&entry.path().join(".owner"), libc::LOCK_EX | libc::LOCK_NB) {
                Ok(_lease) => remove_tree(&entry.path())?,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => return Err(e),
            }
        }
    }
    for family in fs::read_dir(&root)? {
        let family = family?;
        let Ok(spec) = runtime(&family.file_name().to_string_lossy()) else {
            continue;
        };
        if !family.file_type()?.is_dir() {
            return Err(failure("runtime family is not a real directory"));
        }
        for arch in ["x86_64", "arm64"] {
            let path = journal_path(&root, &spec, arch);
            let record = match read_json(&path, 65536) {
                Ok(record) => record,
                Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
                Err(e) => return Err(e),
            };
            if ["oldActive", "oldPrevious", "newActive", "newPrevious"]
                .iter()
                .any(|field| record.get(field).is_none())
            {
                return Err(failure("runtime journal is incomplete"));
            }
            let target = |key: &str| -> io::Result<Option<PathBuf>> {
                let value = &record[key];
                if value.is_null() {
                    return Ok(None);
                }
                let path = Path::new(
                    value
                        .as_str()
                        .ok_or_else(|| failure("invalid runtime journal target"))?,
                );
                if path.is_absolute()
                    || path
                        .components()
                        .any(|c| !matches!(c, std::path::Component::Normal(_)))
                {
                    return Err(failure("unsafe runtime journal target"));
                }
                resolve_version(&root, &root.join(path), &spec, arch).map(Some)
            };
            let new_active =
                target("newActive")?.ok_or_else(|| failure("journal active target missing"))?;
            let active = root.join(&spec.name).join(arch);
            let prior = previous(&root, &spec.name, arch);
            if optional_version(&root, &active, &spec, arch)?.as_ref() == Some(&new_active) {
                set_pointer(target("newPrevious")?.as_deref(), &prior)?;
            } else {
                set_pointer(target("oldActive")?.as_deref(), &active)?;
                set_pointer(target("oldPrevious")?.as_deref(), &prior)?;
            }
            fs::remove_file(path)?;
        }
    }
    Ok(())
}

fn adopt_legacy(root: &Path, spec: &Runtime, arch: &str, path: &Path) -> io::Result<PathBuf> {
    if fs::symlink_metadata(path)?.file_type().is_symlink() {
        return resolve_version(root, path, spec, arch);
    }
    let _lease = lock(&path.join(".lease"), libc::LOCK_EX | libc::LOCK_NB).map_err(|_| failure("runtime is in use; stop its functions or server before managing this older installation"))?;
    let versions = root.join(".versions").join(&spec.name).join(arch);
    private(&versions)?;
    let current = metadata(path)?;
    let destination = versions.join(version_id(&current)?);
    if destination.exists() {
        return Err(failure(
            "legacy runtime version already exists; resolve the duplicate before updating",
        ));
    }
    fs::rename(path, &destination)?;
    if let Err(error) = pointer(&destination, path) {
        let _ = fs::rename(&destination, path);
        return Err(error);
    }
    Ok(destination)
}

fn prune_versions(root: &Path, runtime: &str, arch: &str, keep: &[PathBuf]) -> io::Result<()> {
    let versions = root.join(".versions").join(runtime).join(arch);
    validate_location(&versions)?;
    if !versions.exists() {
        return Ok(());
    }
    for entry in fs::read_dir(&versions)? {
        let entry = entry?;
        if keep.contains(&entry.path()) {
            continue;
        }
        if !entry.file_type()?.is_dir() {
            return Err(failure("runtime version is not a real directory"));
        }
        let Ok(_lease) = lock(&entry.path().join(".lease"), libc::LOCK_EX | libc::LOCK_NB) else {
            continue;
        };
        remove_tree(&entry.path())?;
    }
    Ok(())
}

fn publish(
    root: &Path,
    runtime: &Runtime,
    arch: &str,
    stage: &Path,
    update: bool,
) -> io::Result<Value> {
    let _catalog = lock(&root.join(".catalog.lock"), libc::LOCK_EX)?;
    let family = root.join(&runtime.name);
    private(&family)?;
    let active = family.join(arch);
    let existing = match fs::symlink_metadata(&active) {
        Ok(_) => Some(adopt_legacy(root, runtime, arch, &active)?),
        Err(e) if e.kind() == io::ErrorKind::NotFound => None,
        Err(e) => return Err(e),
    };
    if existing.is_some() && !update {
        let expected = metadata(stage)?;
        if existing.as_ref().is_some_and(|path| {
            metadata(path).is_ok_and(|actual| {
                actual["source"]["imageDigest"] == expected["source"]["imageDigest"]
            })
        }) {
            return Ok(
                json!({"operation":"install","runtime":runtime.name,"architecture":arch,"status":"already-installed","digest":expected["source"]["imageDigest"]}),
            );
        }
        return Err(failure(
            "runtime was installed concurrently; rerun install to inspect it",
        ));
    }
    if existing.is_none() && update {
        return Err(failure(
            "runtime was removed during preparation; update was not activated",
        ));
    }
    let manifest = metadata(stage)?;
    let versions = root.join(".versions").join(&runtime.name).join(arch);
    private(&versions)?;
    let destination = versions.join(version_id(&manifest)?);
    if existing.as_ref() == Some(&destination) {
        locallycloud_lambda::runtime_pack::validate(&destination, &runtime.name, arch)?;
        return Ok(
            json!({"operation":"update","runtime":runtime.name,"architecture":arch,"status":"up-to-date","digest":manifest["source"]["imageDigest"]}),
        );
    }
    if destination.exists() {
        if metadata(&destination)?["source"]["imageDigest"] != manifest["source"]["imageDigest"] {
            return Err(failure(
                "existing runtime version does not match the requested image digest",
            ));
        }
        locallycloud_lambda::runtime_pack::validate(&destination, &runtime.name, arch)?;
    } else {
        fs::rename(stage, &destination)?;
    }
    publish_pointers(root, runtime, arch, &destination, existing.as_deref())?;
    let mut keep = vec![destination];
    keep.extend(existing);
    if let Err(error) = prune_versions(root, &runtime.name, arch, &keep) {
        eprintln!("Runtime activated; unused version cleanup deferred: {error}");
    }
    Ok(
        json!({"operation":if update{"update"}else{"install"},"runtime":runtime.name,"architecture":arch,"status":if update{"updated"}else{"installed"},"digest":manifest["source"]["imageDigest"]}),
    )
}

async fn install(
    root: PathBuf,
    spec: Runtime,
    arch: String,
    digest: Option<String>,
    update: bool,
) -> Result<Value, String> {
    let root = blocking(move || {
        private(&root)?;
        fs::canonicalize(root)
    })
    .await?;
    let inspect_root = root.clone();
    let name = spec.name.clone();
    let inspect_arch = arch.clone();
    let existing =
        blocking(move || installed(&inspect_root, Some(&name), Some(&inspect_arch))).await?;
    if let Some(row) = existing.first() {
        if !update {
            if digest
                .as_ref()
                .is_some_and(|d| row["digest"].as_str() != Some(d))
            {
                return Err(
                    "a different version is installed; use runtime update --digest to change it"
                        .into(),
                );
            }
            let current_root = root.clone();
            let current_spec = spec.clone();
            let current_arch = arch.clone();
            let expected = row["digest"].clone();
            if !blocking(move || {
                confirm_current(&current_root, &current_spec, &current_arch, &expected)
            })
            .await?
            {
                return Err("runtime changed concurrently; retry installation".into());
            }
            let mut result = row.clone();
            result["operation"] = json!("install");
            result["status"] = json!("already-installed");
            return Ok(result);
        }
    } else if update {
        return Err("runtime is not installed; use runtime install first".into());
    }
    let stage = root
        .join(".staging")
        .join(format!("{}-{}", spec.name, uuid::Uuid::new_v4()));
    let prepare = stage.clone();
    let blob_root = root.join(".blobs");
    let prepare_root = root.clone();
    let _stage_lease = blocking(move || {
        let _catalog = lock(&prepare_root.join(".catalog.lock"), libc::LOCK_EX)?;
        private(&prepare)?;
        private(&blob_root)?;
        lock(&prepare.join(".owner"), libc::LOCK_EX | libc::LOCK_NB)
    })
    .await?;
    eprintln!("Preparing {} ({arch})…", spec.name);
    let result = async {
        let info = backend(&image_args(&spec,&arch,&stage,digest.as_deref())).await?;
        if existing.first().is_some_and(|row| row["digest"]==info["imageDigest"]) {
            let current_root=root.clone();let current_spec=spec.clone();let current_arch=arch.clone();let expected=info["imageDigest"].clone();
            if blocking(move||confirm_current(&current_root,&current_spec,&current_arch,&expected)).await? {
                return Ok(json!({"operation":"update","runtime":spec.name,"architecture":arch,"status":"up-to-date","digest":info["imageDigest"]}));
            }
        }
        backend(&["import".into(),"--runtime".into(),spec.name.clone(),"--work".into(),stage.display().to_string(),"--blobs".into(),root.join(".blobs").display().to_string(),"--max-compressed".into(),(512u64*1024*1024).to_string(),"--max-expanded".into(),(2u64*1024*1024*1024).to_string(),"--max-entries".into(),"100000".into()]).await?;
        let validate_stage=stage.clone(); let name=spec.name.clone();let validate_arch=arch.clone();
        blocking(move || locallycloud_lambda::runtime_pack::validate(&validate_stage,&name,&validate_arch)).await?;
        let publish_root=root.clone();let publish_stage=stage.clone();
        blocking(move || publish(&publish_root,&spec,&arch,&publish_stage,update)).await
    }.await;
    let cleanup = stage.clone();
    let _ = blocking(move || {
        if cleanup.exists() {
            remove_tree(&cleanup)?;
        }
        Ok(())
    })
    .await;
    result
}

fn rollback(root: &Path, spec: &Runtime, arch: &str) -> io::Result<Value> {
    let root = fs::canonicalize(root)?;
    let _catalog = lock(&root.join(".catalog.lock"), libc::LOCK_EX)?;
    let active = root.join(&spec.name).join(arch);
    let prior = previous(&root, &spec.name, arch);
    let current = resolve_version(&root, &active, spec, arch)?;
    let old = resolve_version(&root, &prior, spec, arch)
        .map_err(|_| failure("no previous version is available for rollback"))?;
    locallycloud_lambda::runtime_pack::validate(&old, &spec.name, arch)?;
    publish_pointers(&root, spec, arch, &old, Some(&current))?;
    let manifest = metadata(&old)?;
    Ok(
        json!({"operation":"rollback","runtime":spec.name,"architecture":arch,"status":"rolled-back","digest":manifest["source"]["imageDigest"],"previousDigest":metadata(&current)?["source"]["imageDigest"]}),
    )
}

fn collect_blobs(root: &Path) -> io::Result<()> {
    let mut referenced = HashSet::new();
    let versions = root.join(".versions");
    // A preparation may still need a cached layer that is not referenced by a published pack.
    if fs::read_dir(root.join(".staging")).is_ok_and(|mut entries| entries.next().is_some()) {
        return Ok(());
    }
    fn visit(path: &Path, referenced: &mut HashSet<String>, depth: usize) -> io::Result<()> {
        if depth > 4 {
            return Ok(());
        }
        if !path.exists() {
            return Ok(());
        }
        if !fs::symlink_metadata(path)?.is_dir() {
            return Err(failure("runtime version catalog contains a link"));
        }
        let manifest = path.join("image-manifest.json");
        if manifest.exists() {
            let value = read_json(&manifest, 8 * 1024 * 1024)?;
            if let Some(layers) = value["layers"].as_array() {
                for layer in layers {
                    if let Some(digest) = layer["digest"].as_str() {
                        referenced.insert(digest.to_owned());
                    }
                }
            }
            return Ok(());
        }
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                visit(&entry.path(), referenced, depth + 1)?;
            }
        }
        Ok(())
    }
    visit(&versions, &mut referenced, 0)?;
    // Legacy imports may keep their layer manifests beside their direct active rootfs.
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        if runtime(&entry.file_name().to_string_lossy()).is_ok() {
            for arch in ["x86_64", "arm64"] {
                let p = entry.path().join(arch);
                if fs::symlink_metadata(&p).is_ok_and(|m| m.is_dir()) {
                    visit(&p, &mut referenced, 0)?;
                }
            }
        }
    }
    let blobs = root.join(".blobs");
    validate_location(&blobs)?;
    if !blobs.exists() {
        return Ok(());
    }
    for entry in fs::read_dir(blobs)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if let Some((hash, tail)) = name.split_once(".tar.gz.") {
            if tail.ends_with(".part")
                && valid_digest(&format!("sha256:{hash}"))
                && entry.file_type()?.is_file()
            {
                if let Ok(_lease) = lock(
                    &entry.path().with_file_name(format!("{hash}.tar.lock")),
                    libc::LOCK_EX | libc::LOCK_NB,
                ) {
                    fs::remove_file(entry.path())?;
                }
                continue;
            }
        }
        let Some(hash) = name.strip_suffix(".tar.gz") else {
            continue;
        };
        let digest = format!("sha256:{hash}");
        if valid_digest(&digest) && entry.file_type()?.is_file() && !referenced.contains(&digest) {
            fs::remove_file(entry.path())?;
        }
    }
    Ok(())
}

fn remove(root: &Path, spec: &Runtime, arch: &str) -> io::Result<Value> {
    if !root.exists() {
        return Ok(
            json!({"operation":"remove","runtime":spec.name,"architecture":arch,"status":"not-installed"}),
        );
    }
    let root = fs::canonicalize(root)?;
    let _catalog = lock(&root.join(".catalog.lock"), libc::LOCK_EX)?;
    let active = root.join(&spec.name).join(arch);
    let current = optional_version(&root, &active, spec, arch)?;
    let version_root = root.join(".versions").join(&spec.name).join(arch);
    validate_location(&version_root)?;
    let mut paths: Vec<_> = current.into_iter().collect();
    if version_root.exists() {
        for entry in fs::read_dir(&version_root)? {
            let path = resolve_version(&root, &entry?.path(), spec, arch)?;
            if !paths.contains(&path) {
                paths.push(path);
            }
        }
    }
    let mut leases = vec![];
    for path in &paths {
        if !fs::symlink_metadata(path)?.is_dir() {
            return Err(failure("runtime version is not a real directory"));
        }
        leases.push(
            lock(&path.join(".lease"), libc::LOCK_EX | libc::LOCK_NB).map_err(|_| {
                failure("runtime is in use; stop its functions or server before removing it")
            })?,
        );
    }
    match fs::symlink_metadata(&active) {
        Ok(m) if m.file_type().is_symlink() => fs::remove_file(&active)?,
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let prior = previous(&root, &spec.name, arch);
    match fs::remove_file(prior) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    };
    for path in paths {
        remove_tree(&path)?;
    }
    if let Err(error) = collect_blobs(&root) {
        eprintln!("Runtime removed; cached layer cleanup deferred: {error}");
    }
    Ok(json!({"operation":"remove","runtime":spec.name,"architecture":arch,"status":"removed"}))
}

fn print_result(result: &Value, structured: bool) -> Result<(), String> {
    if structured {
        println!(
            "{}",
            serde_json::to_string_pretty(result).map_err(|e| e.to_string())?
        );
        return Ok(());
    }
    if let Some(rows) = result["runtimes"].as_array() {
        if rows.is_empty() {
            println!("No runtimes installed.");
        }
        for row in rows {
            println!(
                "{} ({}) — {}",
                row["runtime"].as_str().unwrap_or(""),
                row["architecture"].as_str().unwrap_or(""),
                match row["updateAvailable"].as_bool() {
                    Some(true) => "update available",
                    Some(false) => "up to date",
                    None => "installed",
                }
            );
        }
    } else {
        println!(
            "{} ({}) — {}",
            result["runtime"].as_str().unwrap_or(""),
            result["architecture"].as_str().unwrap_or(""),
            result["status"].as_str().unwrap_or("completed")
        );
    }
    Ok(())
}

pub async fn execute(options: &Options) -> Result<(), String> {
    if options.action == Action::Help {
        println!("{USAGE}");
        return Ok(());
    }
    let root = directory(options)?;
    let check_root = root.clone();
    blocking(move || {
        validate_location(&check_root)?;
        if check_root.exists() {
            let m = fs::metadata(&check_root)?;
            if m.uid() != unsafe { libc::geteuid() } || m.mode() & 0o022 != 0 {
                return Err(failure(
                    "runtime store must be owned by this user and not writable by others",
                ));
            }
        }
        recover(&check_root)
    })
    .await?;
    let arch = options
        .architecture
        .clone()
        .unwrap_or(architecture()?.into());
    let result = match options.action {
        Action::Help => unreachable!(),
        Action::List | Action::CheckUpdates => {
            let read_root = root.clone();
            let name = options.runtime.clone();
            let filter = options.architecture.clone();
            let mut rows =
                blocking(move || installed(&read_root, name.as_deref(), filter.as_deref())).await?;
            if options.action == Action::CheckUpdates {
                for row in &mut rows {
                    let name = row["runtime"].as_str().ok_or("runtime name missing")?;
                    let arch = row["architecture"]
                        .as_str()
                        .ok_or("runtime architecture missing")?;
                    let lookup_root = root.clone();
                    let lookup_runtime = runtime(name)?;
                    let lookup_arch = arch.to_owned();
                    let (resolved, _lease) = blocking(move || {
                        let root = fs::canonicalize(lookup_root)?;
                        let catalog = lock(&root.join(".catalog.lock"), libc::LOCK_SH)?;
                        let resolved = resolve_version(
                            &root,
                            &root.join(&lookup_runtime.name).join(&lookup_arch),
                            &lookup_runtime,
                            &lookup_arch,
                        )?;
                        let lease = lock(&resolved.join(".lease"), libc::LOCK_SH)?;
                        drop(catalog);
                        Ok((resolved, lease))
                    })
                    .await?;
                    let info = backend(&[
                        "check".into(),
                        "--work".into(),
                        resolved.display().to_string(),
                    ])
                    .await?;
                    row["availableDigest"] = info["availableDigest"].clone();
                    row["digest"] = info["installedDigest"].clone();
                    row["updateAvailable"] = info["updateAvailable"].clone();
                }
            }
            json!({"operation":if options.action==Action::List{"list"}else{"check-updates"},"runtimes":rows})
        }
        Action::Install | Action::Update => {
            install(
                root,
                runtime(options.runtime.as_deref().ok_or("runtime missing")?)?,
                arch,
                options.digest.clone(),
                options.action == Action::Update,
            )
            .await?
        }
        Action::Rollback | Action::Remove => {
            let spec = runtime(options.runtime.as_deref().ok_or("runtime missing")?)?;
            let action = options.action;
            blocking(move || match action {
                Action::Rollback => rollback(&root, &spec, &arch),
                Action::Remove => remove(&root, &spec, &arch),
                _ => unreachable!(),
            })
            .await?
        }
    };
    print_result(&result, options.json)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../..")
                .canonicalize()
                .unwrap()
                .join("compatibility-tests/.work/runtime-manager-unit")
                .join(uuid::Uuid::new_v4().to_string());
            private(&root).unwrap();
            Self(fs::canonicalize(root).unwrap())
        }
        fn version(&self, name: &str, letter: char) -> PathBuf {
            let digest = letter.to_string().repeat(64);
            let path = self
                .0
                .join(".versions")
                .join(name)
                .join("x86_64")
                .join(&digest);
            private(&path).unwrap();
            private(&self.0.join(name)).unwrap();
            fs::write(path.join("manifest.json"),serde_json::to_vec(&json!({"runtime":name,"architecture":"x86_64","source":{"imageDigest":format!("sha256:{digest}")}})).unwrap()).unwrap();
            path
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = remove_tree(&self.0);
        }
    }

    #[test]
    fn commands_validate_names_options_and_automatic_architecture() {
        for name in [
            "nodejs24.x",
            "python3.14",
            "ruby4.0",
            "ruby3.4",
            "dotnet10",
            "dotnet8",
            "provided.al2023",
        ] {
            let options = parse(&["install".into(), name.into(), "--json".into()]).unwrap();
            assert_eq!(options.runtime.as_deref(), Some(name));
            assert!(options.architecture.is_none());
        }
        for args in [
            vec!["install", "../outside"],
            vec!["install", "nodejs22.x;exit"],
            vec!["remove"],
            vec!["list", "nodejs22.x"],
            vec!["list", "--arch", "amd64"],
            vec!["update", "nodejs22.x", "--digest", "latest"],
            vec!["list", "--json", "--json"],
        ] {
            assert!(parse(&args.into_iter().map(str::to_owned).collect::<Vec<_>>()).is_err());
        }
    }

    #[test]
    fn removal_rejects_store_and_foreign_family_aliases_before_deleting_anything() {
        let fixture = Fixture::new();
        let foreign = fixture.version("python3.13", 'a');
        let spec = runtime("nodejs22.x").unwrap();
        private(&fixture.0.join(&spec.name)).unwrap();
        let active = fixture.0.join(&spec.name).join("x86_64");
        pointer(&fixture.0, &active).unwrap();
        assert!(remove(&fixture.0, &spec, "x86_64").is_err());
        assert!(foreign.exists());
        pointer(&foreign, &active).unwrap();
        assert!(remove(&fixture.0, &spec, "x86_64").is_err());
        assert!(foreign.exists());
    }

    #[test]
    fn busy_versions_cannot_be_removed_and_relative_aliases_survive_store_moves() {
        let mut fixture = Fixture::new();
        let spec = runtime("nodejs22.x").unwrap();
        let version = fixture.version(&spec.name, 'a');
        let active = fixture.0.join(&spec.name).join("x86_64");
        pointer(&version, &active).unwrap();
        assert!(!fs::read_link(&active).unwrap().is_absolute());
        let lease = lock(&version.join(".lease"), libc::LOCK_SH).unwrap();
        assert!(remove(&fixture.0, &spec, "x86_64").is_err());
        assert_eq!(resolve(&fixture.0, &active).unwrap(), version);
        drop(lease);
        let moved = fixture
            .0
            .with_file_name(format!("moved-{}", uuid::Uuid::new_v4()));
        fs::rename(&fixture.0, &moved).unwrap();
        fixture.0 = moved;
        let active = fixture.0.join(&spec.name).join("x86_64");
        assert_eq!(
            resolve(&fixture.0, &active).unwrap(),
            fixture
                .0
                .join(".versions")
                .join(&spec.name)
                .join("x86_64")
                .join("a".repeat(64))
        );
        remove(&fixture.0, &spec, "x86_64").unwrap();
        assert!(!active.exists());
    }

    #[test]
    fn failed_activation_restores_both_pointers() {
        let fixture = Fixture::new();
        let spec = runtime("nodejs22.x").unwrap();
        let candidate = fixture.version(&spec.name, 'b');
        let old_previous = fixture.version(&spec.name, 'c');
        let legacy = fixture.0.join(&spec.name).join("x86_64");
        private(&legacy).unwrap();
        fs::write(legacy.join("manifest.json"),serde_json::to_vec(&json!({"runtime":spec.name,"architecture":"x86_64","source":{"imageDigest":format!("sha256:{}","a".repeat(64))}})).unwrap()).unwrap();
        pointer(&old_previous, &previous(&fixture.0, &spec.name, "x86_64")).unwrap();
        assert!(publish_pointers(&fixture.0, &spec, "x86_64", &candidate, Some(&legacy)).is_err());
        assert!(legacy.is_dir());
        assert_eq!(
            resolve(&fixture.0, &previous(&fixture.0, &spec.name, "x86_64")).unwrap(),
            old_previous
        );
        assert!(!journal_path(&fixture.0, &spec, "x86_64").exists());
    }

    #[test]
    fn interrupted_activation_recovers_before_and_after_commit() {
        let fixture = Fixture::new();
        let spec = runtime("nodejs22.x").unwrap();
        let a = fixture.version(&spec.name, 'a');
        let b = fixture.version(&spec.name, 'b');
        let c = fixture.version(&spec.name, 'c');
        let active = fixture.0.join(&spec.name).join("x86_64");
        let prior = previous(&fixture.0, &spec.name, "x86_64");
        let record = json!({"oldActive":a.strip_prefix(&fixture.0).unwrap(),"oldPrevious":c.strip_prefix(&fixture.0).unwrap(),"newActive":b.strip_prefix(&fixture.0).unwrap(),"newPrevious":a.strip_prefix(&fixture.0).unwrap()});
        let journal = journal_path(&fixture.0, &spec, "x86_64");
        pointer(&a, &active).unwrap();
        pointer(&a, &prior).unwrap();
        fs::write(&journal, serde_json::to_vec(&record).unwrap()).unwrap();
        recover(&fixture.0).unwrap();
        assert_eq!(resolve(&fixture.0, &active).unwrap(), a);
        assert_eq!(resolve(&fixture.0, &prior).unwrap(), c);
        pointer(&b, &active).unwrap();
        pointer(&c, &prior).unwrap();
        fs::write(&journal, serde_json::to_vec(&record).unwrap()).unwrap();
        recover(&fixture.0).unwrap();
        assert_eq!(resolve(&fixture.0, &active).unwrap(), b);
        assert_eq!(resolve(&fixture.0, &prior).unwrap(), a);
    }

    #[test]
    fn removing_one_runtime_preserves_other_runtimes_shared_layers() {
        let fixture = Fixture::new();
        let spec = runtime("nodejs22.x").unwrap();
        let node = fixture.version(&spec.name, 'a');
        let python = fixture.version("python3.13", 'b');
        pointer(&node, &fixture.0.join(&spec.name).join("x86_64")).unwrap();
        pointer(&python, &fixture.0.join("python3.13/x86_64")).unwrap();
        let layer = "c".repeat(64);
        let orphan = "d".repeat(64);
        private(&fixture.0.join(".blobs")).unwrap();
        fs::write(
            fixture.0.join(".blobs").join(format!("{layer}.tar.gz")),
            b"cached",
        )
        .unwrap();
        fs::write(
            fixture.0.join(".blobs").join(format!("{orphan}.tar.gz")),
            b"unused",
        )
        .unwrap();
        fs::write(
            python.join("image-manifest.json"),
            serde_json::to_vec(&json!({"layers":[{"digest":format!("sha256:{layer}")}]})).unwrap(),
        )
        .unwrap();
        remove(&fixture.0, &spec, "x86_64").unwrap();
        assert!(python.exists());
        assert!(fixture
            .0
            .join(".blobs")
            .join(format!("{layer}.tar.gz"))
            .exists());
        assert!(!fixture
            .0
            .join(".blobs")
            .join(format!("{orphan}.tar.gz"))
            .exists());
    }

    #[test]
    fn version_digest_binding_and_post_network_snapshot_are_revalidated() {
        let fixture = Fixture::new();
        let spec = runtime("nodejs22.x").unwrap();
        let a = fixture.version(&spec.name, 'a');
        let b = fixture.version(&spec.name, 'b');
        let active = fixture.0.join(&spec.name).join("x86_64");
        pointer(&b, &active).unwrap();
        assert!(!confirm_current(
            &fixture.0,
            &spec,
            "x86_64",
            &json!(format!("sha256:{}", "a".repeat(64)))
        )
        .unwrap());
        fs::remove_file(&active).unwrap();
        assert!(confirm_current(
            &fixture.0,
            &spec,
            "x86_64",
            &json!(format!("sha256:{}", "a".repeat(64)))
        )
        .is_err());
        fs::copy(b.join("manifest.json"), a.join("manifest.json")).unwrap();
        assert!(resolve_version(&fixture.0, &a, &spec, "x86_64").is_err());
    }

    #[test]
    fn partial_cleanup_respects_the_downloaders_actual_layer_lock() {
        let fixture = Fixture::new();
        let blobs = fixture.0.join(".blobs");
        private(&blobs).unwrap();
        let hash = "a".repeat(64);
        let partial = blobs.join(format!(
            "{hash}.tar.gz.{}.part",
            uuid::Uuid::new_v4().simple()
        ));
        fs::write(&partial, b"incomplete").unwrap();
        let writer = lock(&blobs.join(format!("{hash}.tar.lock")), libc::LOCK_EX).unwrap();
        collect_blobs(&fixture.0).unwrap();
        assert!(partial.exists());
        drop(writer);
        collect_blobs(&fixture.0).unwrap();
        assert!(!partial.exists());
    }
}
