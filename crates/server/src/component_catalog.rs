//! Release catalogs are read only by explicit component management commands.
use std::io;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::component_manager::{valid_digest, MAX_BINARY};

const MAX_CATALOG: usize = 64 * 1024;
const MAX_NOTICES: usize = 2 * 1024 * 1024;
pub(super) const REQUIRED_CAPABILITIES: &[&str] =
    &["stream-cursors-v1", "mrec-outbox-v1", "backups-v1"];

#[derive(Deserialize)]
struct Catalog {
    schema: u32,
    component: String,
    protocol: u32,
    version: String,
    capabilities: Vec<String>,
    artifacts: Vec<Artifact>,
}

#[derive(Deserialize)]
struct Artifact {
    architecture: Architecture,
    binary: File,
    notices: File,
}

#[derive(Clone, Copy, Deserialize, PartialEq, Eq, Hash)]
enum Architecture {
    #[serde(rename = "x86_64")]
    X86_64,
    #[serde(rename = "arm64")]
    Arm64,
}

impl Architecture {
    fn name(self) -> &'static str {
        match self {
            Self::X86_64 => "x86_64",
            Self::Arm64 => "arm64",
        }
    }
    fn machine(self) -> u16 {
        match self {
            Self::X86_64 => 62,
            Self::Arm64 => 183,
        }
    }
}

#[derive(Deserialize)]
struct File {
    name: String,
    sha256: String,
    size: usize,
}

pub(super) struct Release {
    pub version: String,
    artifact: Artifact,
    location: Location,
}

#[derive(Clone)]
enum Location {
    Local(PathBuf),
    Https(reqwest::Url),
}

impl Location {
    fn parse(source: &str) -> io::Result<Self> {
        if source.starts_with("https://") {
            let url =
                reqwest::Url::parse(source).map_err(|_| invalid("invalid catalog HTTPS URL"))?;
            if !url.username().is_empty() || url.password().is_some() || url.fragment().is_some() {
                return Err(invalid(
                    "component URLs must not contain credentials or fragments",
                ));
            }
            Ok(Self::Https(url))
        } else if source.contains("://") {
            Err(invalid("component downloads require HTTPS"))
        } else {
            Ok(Self::Local(PathBuf::from(source)))
        }
    }

    fn sibling(&self, name: &str) -> io::Result<Self> {
        // Catalog validation restricts names to the exact architecture-specific asset names.
        match self {
            Self::Local(path) => Ok(Self::Local(
                path.parent().unwrap_or(Path::new(".")).join(name),
            )),
            Self::Https(url) => Ok(Self::Https(
                url.join(name)
                    .map_err(|_| invalid("invalid component asset URL"))?,
            )),
        }
    }

    async fn read(&self, maximum: usize) -> io::Result<Vec<u8>> {
        let mut bytes = Vec::new();
        match self {
            Self::Local(path) => {
                use tokio::io::AsyncReadExt;
                let file = tokio::fs::File::open(path).await?;
                if !file.metadata().await?.is_file() {
                    return Err(invalid("component source must be a regular file"));
                }
                file.take(maximum as u64 + 1)
                    .read_to_end(&mut bytes)
                    .await?;
            }
            Self::Https(url) => {
                let client = reqwest::Client::builder()
                    .https_only(true)
                    .redirect(reqwest::redirect::Policy::limited(5))
                    .timeout(std::time::Duration::from_secs(180))
                    .build()
                    .map_err(io::Error::other)?;
                let mut response = client
                    .get(url.clone())
                    .send()
                    .await
                    .and_then(reqwest::Response::error_for_status)
                    .map_err(|error| io::Error::other(error.without_url()))?;
                while let Some(chunk) = response
                    .chunk()
                    .await
                    .map_err(|error| io::Error::other(error.without_url()))?
                {
                    if bytes.len().saturating_add(chunk.len()) > maximum {
                        return Err(invalid("component source exceeds its size limit"));
                    }
                    bytes.extend_from_slice(&chunk);
                }
            }
        }
        if bytes.len() > maximum {
            return Err(invalid("component source exceeds its size limit"));
        }
        Ok(bytes)
    }
}

fn invalid(message: &str) -> io::Error {
    io::Error::other(message)
}

fn architecture() -> io::Result<Architecture> {
    match std::env::consts::ARCH {
        "x86_64" => Ok(Architecture::X86_64),
        "aarch64" => Ok(Architecture::Arm64),
        _ => Err(invalid(
            "ExtendDB components support Linux x86_64 and arm64 only",
        )),
    }
}

fn parse(bytes: &[u8], architecture: Architecture, location: Location) -> io::Result<Release> {
    if bytes.len() > MAX_CATALOG {
        return Err(invalid("component catalog exceeds 64 KiB"));
    }
    let catalog: Catalog = serde_json::from_slice(bytes).map_err(io::Error::other)?;
    if catalog.schema != 1
        || catalog.component != "extenddb"
        || catalog.protocol != 1
        || catalog.version.is_empty()
        || catalog.version.len() > 128
        || !catalog
            .version
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        || !REQUIRED_CAPABILITIES
            .iter()
            .all(|required| catalog.capabilities.iter().any(|v| v == required))
        || catalog.artifacts.is_empty()
        || catalog.artifacts.len() > 2
    {
        return Err(invalid("incompatible ExtendDB component catalog"));
    }
    let mut seen = std::collections::HashSet::new();
    for artifact in &catalog.artifacts {
        if !seen.insert(artifact.architecture) {
            return Err(invalid("invalid or duplicate component architecture"));
        }
        let name = format!(
            "locallycloud-extenddb-worker-linux-{}",
            artifact.architecture.name()
        );
        for (file, expected, maximum) in [
            (&artifact.binary, name.clone(), MAX_BINARY),
            (
                &artifact.notices,
                format!("{name}.LICENSES.txt"),
                MAX_NOTICES,
            ),
        ] {
            if file.name != expected
                || !valid_digest(&file.sha256)
                || file.size == 0
                || file.size > maximum
            {
                return Err(invalid("invalid component asset metadata"));
            }
        }
    }
    let artifact = catalog
        .artifacts
        .into_iter()
        .find(|a| a.architecture == architecture)
        .ok_or_else(|| invalid("no ExtendDB component is available for this architecture"))?;
    Ok(Release {
        version: catalog.version,
        artifact,
        location,
    })
}

pub(super) async fn resolve(source: Option<&str>) -> io::Result<Release> {
    let default = format!(
        "https://github.com/alfredcodelabs/LocallyCloud/releases/download/v{}/components.json",
        env!("CARGO_PKG_VERSION")
    );
    let location = Location::parse(source.unwrap_or(&default))?;
    let bytes = location.read(MAX_CATALOG).await.map_err(|error| {
        io::Error::other(format!("cannot read the component release catalog: {error}; use --catalog PATH|HTTPS_URL or --source PATH --sha256 HEX for an explicit artifact"))
    })?;
    parse(&bytes, architecture()?, location)
}

pub(super) async fn download_explicit(source: &str, digest: &str) -> io::Result<Vec<u8>> {
    let bytes = Location::parse(source)?.read(MAX_BINARY).await?;
    if format!("{:x}", Sha256::digest(&bytes)) != digest {
        return Err(invalid("component checksum mismatch"));
    }
    validate_binary(&bytes, architecture()?)?;
    Ok(bytes)
}

impl Release {
    pub fn digest(&self) -> &str {
        &self.artifact.binary.sha256
    }

    async fn download_file(&self, file: &File) -> io::Result<Vec<u8>> {
        let bytes = self.location.sibling(&file.name)?.read(file.size).await?;
        if bytes.len() != file.size || format!("{:x}", Sha256::digest(&bytes)) != file.sha256 {
            return Err(invalid("component asset checksum or size mismatch"));
        }
        Ok(bytes)
    }

    pub async fn download(&self) -> io::Result<(Vec<u8>, Vec<u8>)> {
        let binary = self.download_file(&self.artifact.binary).await?;
        validate_binary(&binary, self.artifact.architecture)?;
        let notices = self.download_file(&self.artifact.notices).await?;
        Ok((binary, notices))
    }
}

fn validate_binary(bytes: &[u8], architecture: Architecture) -> io::Result<()> {
    let machine = architecture.machine();
    let header = bytes
        .get(..64)
        .ok_or_else(|| invalid("truncated component ELF header"))?;
    if !header.starts_with(b"\x7fELF\x02\x01\x01")
        || !matches!(u16::from_le_bytes([header[16], header[17]]), 2 | 3)
        || u16::from_le_bytes([header[18], header[19]]) != machine
    {
        return Err(invalid("component ELF does not match its architecture"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn fixture() -> serde_json::Value {
        json!({"schema":1,"component":"extenddb","protocol":1,"version":"v0.1.0-beta.4",
            "capabilities": REQUIRED_CAPABILITIES,
            "artifacts":[{"architecture":"x86_64",
                "binary":{"name":"locallycloud-extenddb-worker-linux-x86_64","sha256":"a".repeat(64),"size":64},
                "notices":{"name":"locallycloud-extenddb-worker-linux-x86_64.LICENSES.txt","sha256":"b".repeat(64),"size":32}}]})
    }

    fn select(value: &serde_json::Value, arch: Architecture) -> io::Result<Release> {
        parse(
            &serde_json::to_vec(value).unwrap(),
            arch,
            Location::Local("/private/components.json".into()),
        )
    }

    #[test]
    fn catalog_rejects_unsafe_assets_and_incompatible_contracts() {
        assert!(select(&fixture(), Architecture::X86_64).is_ok());
        assert!(select(&fixture(), Architecture::Arm64).is_err());
        for (field, value) in [
            ("schema", json!(2)),
            ("protocol", json!(2)),
            ("component", json!("other")),
            ("capabilities", json!([])),
        ] {
            let mut catalog = fixture();
            catalog[field] = value;
            assert!(select(&catalog, Architecture::X86_64).is_err());
        }
        for (field, value) in [
            ("name", json!("../worker")),
            ("sha256", json!("../escape")),
            ("size", json!(MAX_BINARY + 1)),
        ] {
            let mut catalog = fixture();
            catalog["artifacts"][0]["binary"][field] = value;
            assert!(select(&catalog, Architecture::X86_64).is_err());
        }
        let mut duplicate = fixture();
        let artifact = duplicate["artifacts"][0].clone();
        duplicate["artifacts"]
            .as_array_mut()
            .unwrap()
            .push(artifact);
        assert!(select(&duplicate, Architecture::X86_64).is_err());
        assert!(parse(
            &vec![b' '; MAX_CATALOG + 1],
            Architecture::X86_64,
            Location::Local("index".into())
        )
        .is_err());
    }

    #[test]
    fn architecture_selection_and_elf_validation_cover_both_targets() {
        for (arch, machine) in [(Architecture::X86_64, 62u16), (Architecture::Arm64, 183u16)] {
            let mut catalog = fixture();
            catalog["artifacts"][0]["architecture"] = json!(arch.name());
            catalog["artifacts"][0]["binary"]["name"] = json!(format!(
                "locallycloud-extenddb-worker-linux-{}",
                arch.name()
            ));
            catalog["artifacts"][0]["notices"]["name"] = json!(format!(
                "locallycloud-extenddb-worker-linux-{}.LICENSES.txt",
                arch.name()
            ));
            assert!(select(&catalog, arch).is_ok());
            let mut elf = vec![0; 64];
            elf[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
            elf[16..18].copy_from_slice(&3u16.to_le_bytes());
            elf[18..20].copy_from_slice(&machine.to_le_bytes());
            assert!(validate_binary(&elf, arch).is_ok());
            assert!(validate_binary(&elf[..20], arch).is_err());
            elf[18] ^= 1;
            assert!(validate_binary(&elf, arch).is_err());
        }
    }

    #[test]
    fn catalog_locations_reject_insecure_urls_and_credentials() {
        for source in [
            "http://example.com/index",
            "https://user:password@example.com/index",
            "https://example.com/index#fragment",
            "file:///tmp/index",
        ] {
            assert!(Location::parse(source).is_err());
        }
        assert!(Location::parse("https://example.com/releases/index.json").is_ok());
        assert!(Location::parse("/private/index.json").is_ok());
    }
}
