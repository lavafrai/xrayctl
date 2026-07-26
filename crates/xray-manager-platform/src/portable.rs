use async_trait::async_trait;
use futures_util::StreamExt;
use reqwest::redirect::{Attempt, Policy};
use reqwest::{Client, StatusCode};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tempfile::NamedTempFile;
use tokio::process::Command;
use xray_manager_core::config::ManagerConfig;
use xray_manager_core::domain::Node;
use xray_manager_core::events::ManagerEvent;
use xray_manager_core::ports::{
    BackendComponent, BackendDescriptor, BackendProbe, BackendSelection, Capability, Clock,
    CommandOutput, CommandRunner, DownloadRequest, DownloadedArtifact, Downloader, EventSink,
    FileSystem, LayoutProvider, ManagerPaths, ProbeResult, Release, ReleaseProvider, XrayRunner,
    XrayTestRequest,
};
use xray_manager_core::{ManagerError, Result};

#[derive(Debug, Clone, Default)]
pub struct PortableLocalLayout;

#[async_trait]
impl LayoutProvider for PortableLocalLayout {
    async fn paths(&self) -> Result<ManagerPaths> {
        let root = std::env::current_dir()
            .map_err(|error| ManagerError::Io(error.to_string()))?
            .join(".xray-manager");
        Ok(ManagerPaths {
            config_dir: root.join("config"),
            state_dir: root.join("state"),
            cache_dir: root.join("cache"),
            runtime_dir: root.join("run"),
            install_dir: root.join("opt"),
            executable: root.join("bin/xrayctl"),
        })
    }
}

pub struct PortableBackendFactory;

#[async_trait]
impl crate::registry::BackendFactory for PortableBackendFactory {
    fn descriptor(&self) -> BackendDescriptor {
        BackendDescriptor {
            id: "portable-local".into(),
            contract_version: 1,
            capabilities: [Capability::Layout].into_iter().collect(),
            platform: std::env::consts::OS.into(),
            requirements: Vec::new(),
        }
    }

    async fn probe(&self) -> Result<BackendProbe> {
        Ok(BackendProbe {
            available: true,
            reason: None,
        })
    }

    fn create(
        &self,
        capability: Capability,
        _config: &ManagerConfig,
        _selections: &[BackendSelection],
    ) -> Result<BackendComponent> {
        match capability {
            Capability::Layout => Ok(BackendComponent::Layout(std::sync::Arc::new(
                PortableLocalLayout,
            ))),
            _ => Err(ManagerError::PlatformUnsupported {
                capability,
                platform: std::env::consts::OS.into(),
                backend: Some("portable-local".into()),
                reason: "portable-local provides only filesystem layout".into(),
                recommendation: Some("select a backend that provides this capability".into()),
            }),
        }
    }
}

pub fn register_portable(registry: &mut crate::registry::BackendRegistry) {
    registry.register(PortableBackendFactory);
}

#[derive(Clone)]
pub struct HttpClient {
    max_redirects: usize,
    connect_timeout: Duration,
}

impl HttpClient {
    pub fn new(max_redirects: usize) -> Result<Self> {
        Self::with_connect_timeout(max_redirects, Duration::from_secs(10))
    }

    pub fn with_connect_timeout(max_redirects: usize, connect_timeout: Duration) -> Result<Self> {
        build_http_client(max_redirects, connect_timeout)?;
        Ok(Self {
            max_redirects,
            connect_timeout,
        })
    }
}

fn build_http_client(max_redirects: usize, connect_timeout: Duration) -> Result<Client> {
    let policy = Policy::custom(move |attempt: Attempt<'_>| {
        if attempt.previous().len() >= max_redirects {
            return attempt.error("too many redirects");
        }
        if attempt.previous().last().is_some_and(|previous| {
            previous.scheme() == "https" && attempt.url().scheme() != "https"
        }) {
            return attempt.error("HTTPS to HTTP redirect is forbidden");
        }
        attempt.follow()
    });
    let client = Client::builder()
        .redirect(policy)
        .connect_timeout(connect_timeout)
        .user_agent(concat!("xray-manager/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|error| ManagerError::Download(error.to_string()))?;
    Ok(client)
}

#[async_trait]
impl Downloader for HttpClient {
    async fn download(&self, request: DownloadRequest) -> Result<DownloadedArtifact> {
        let url = url::Url::parse(&request.url)
            .map_err(|_| ManagerError::Download("invalid download URL".into()))?;
        if url.scheme() != "https" {
            return Err(ManagerError::Download("only HTTPS is allowed".into()));
        }
        let client = build_http_client(
            request.max_redirects.min(self.max_redirects),
            self.connect_timeout,
        )?;
        let max_bytes = request.max_bytes;
        tokio::time::timeout(request.timeout, async {
            let response = client
                .get(url)
                .send()
                .await
                .map_err(|error| ManagerError::Download(error.without_url().to_string()))?;
            if response.status() != StatusCode::OK {
                return Err(ManagerError::Download(format!(
                    "server returned {}",
                    response.status()
                )));
            }
            if response
                .content_length()
                .is_some_and(|length| length > max_bytes)
            {
                return Err(ManagerError::Download("size limit exceeded".into()));
            }
            let final_url = response.url().to_string();
            let content_type = response
                .headers()
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned);
            let mut stream = response.bytes_stream();
            let mut bytes = Vec::new();
            while let Some(chunk) = stream.next().await {
                let chunk = chunk
                    .map_err(|_| ManagerError::Download("response body transfer failed".into()))?;
                let next_len = bytes
                    .len()
                    .checked_add(chunk.len())
                    .ok_or_else(|| ManagerError::Download("size overflow".into()))?;
                if next_len > max_bytes as usize {
                    return Err(ManagerError::Download("size limit exceeded".into()));
                }
                bytes.extend_from_slice(&chunk);
            }
            Ok(DownloadedArtifact {
                bytes,
                final_url,
                content_type,
            })
        })
        .await
        .map_err(|_| ManagerError::Download("request timed out".into()))?
    }
}

#[derive(Clone)]
pub struct GithubReleaseProvider {
    client: HttpClient,
}

impl GithubReleaseProvider {
    pub fn new(client: HttpClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl ReleaseProvider for GithubReleaseProvider {
    async fn stable_release(&self, repository: &str) -> Result<Release> {
        let artifact = self
            .client
            .download(DownloadRequest {
                url: format!("https://api.github.com/repos/{repository}/releases"),
                max_bytes: 10 * 1024 * 1024,
                timeout: Duration::from_secs(20),
                max_redirects: 5,
            })
            .await?;
        let releases: Vec<Release> = serde_json::from_slice(&artifact.bytes)
            .map_err(|error| ManagerError::Download(error.to_string()))?;
        releases
            .into_iter()
            .find(|release| !release.prerelease)
            .ok_or_else(|| ManagerError::Download("no stable release found".into()))
    }
}

#[derive(Debug, Clone, Default)]
pub struct NativeFileSystem;

#[async_trait]
impl FileSystem for NativeFileSystem {
    async fn acquire_lock(
        &self,
        path: &Path,
    ) -> Result<Box<dyn xray_manager_core::ports::FileLockGuard>> {
        Ok(Box::new(crate::artifacts::OperationLock::acquire(path)?))
    }

    async fn read(&self, path: &Path) -> Result<Vec<u8>> {
        tokio::fs::read(path)
            .await
            .map_err(|error| ManagerError::Io(error.to_string()))
    }

    async fn list_files(&self, path: &Path) -> Result<Vec<PathBuf>> {
        let mut entries = match tokio::fs::read_dir(path).await {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(ManagerError::Io(error.to_string())),
        };
        let mut files = Vec::new();
        while let Some(entry) = entries
            .next_entry()
            .await
            .map_err(|error| ManagerError::Io(error.to_string()))?
        {
            if entry
                .file_type()
                .await
                .map_err(|error| ManagerError::Io(error.to_string()))?
                .is_file()
            {
                files.push(entry.path());
            }
        }
        files.sort();
        Ok(files)
    }

    async fn write_atomic(&self, path: &Path, bytes: &[u8], mode: Option<u32>) -> Result<()> {
        let parent = path
            .parent()
            .ok_or_else(|| ManagerError::Io("destination has no parent".into()))?
            .to_owned();
        let path = path.to_owned();
        let bytes = bytes.to_vec();
        tokio::task::spawn_blocking(move || {
            fs::create_dir_all(&parent).map_err(|error| ManagerError::Io(error.to_string()))?;
            let mut temporary = NamedTempFile::new_in(&parent)
                .map_err(|error| ManagerError::Io(error.to_string()))?;
            temporary
                .write_all(&bytes)
                .and_then(|()| temporary.as_file().sync_all())
                .map_err(|error| ManagerError::Io(error.to_string()))?;
            set_mode(temporary.path(), mode)?;
            #[cfg(windows)]
            {
                let temporary_path = temporary
                    .into_temp_path()
                    .keep()
                    .map_err(|error| ManagerError::Io(error.error.to_string()))?;
                replace_path_windows(&temporary_path, &path)?;
            }
            #[cfg(not(windows))]
            {
                temporary
                    .persist(&path)
                    .map_err(|error| ManagerError::Io(error.error.to_string()))?;
                sync_directory(&parent)?;
            }
            Ok(())
        })
        .await
        .map_err(|error| ManagerError::Io(error.to_string()))?
    }

    async fn create_dir_all(&self, path: &Path) -> Result<()> {
        tokio::fs::create_dir_all(path)
            .await
            .map_err(|error| ManagerError::Io(error.to_string()))
    }

    async fn set_permissions(&self, path: &Path, mode: u32) -> Result<()> {
        set_mode(path, Some(mode))
    }

    async fn exists(&self, path: &Path) -> Result<bool> {
        Ok(tokio::fs::try_exists(path)
            .await
            .map_err(|error| ManagerError::Io(error.to_string()))?)
    }

    async fn remove_owned(&self, path: &Path, ownership_root: &Path) -> Result<()> {
        let path = absolute_lexical(path)?;
        let root = absolute_lexical(ownership_root)?;
        if !path.starts_with(&root) || path == root {
            return Err(ManagerError::Io(format!(
                "refusing to remove path outside ownership root: {}",
                path.display()
            )));
        }
        let metadata = match tokio::fs::symlink_metadata(&path).await {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(ManagerError::Io(error.to_string())),
        };
        if metadata.is_dir() {
            tokio::fs::remove_dir_all(path).await
        } else {
            tokio::fs::remove_file(path).await
        }
        .map_err(|error| ManagerError::Io(error.to_string()))
    }

    async fn switch_generation(
        &self,
        current: &Path,
        previous: &Path,
        target: &Path,
    ) -> Result<()> {
        switch_generation(current, previous, target)
    }

    async fn rollback_generation(&self, current: &Path, previous: &Path) -> Result<()> {
        let target = generation_target(previous)?;
        switch_generation(current, previous, &target)
    }

    async fn restore_generation(
        &self,
        current: &Path,
        previous: &Path,
        current_target: Option<&Path>,
        previous_target: Option<&Path>,
    ) -> Result<()> {
        replace_pointer(current, current_target)?;
        replace_pointer(previous, previous_target)
    }

    async fn prune_generations(
        &self,
        root: &Path,
        current: &Path,
        previous: &Path,
        keep: usize,
    ) -> Result<()> {
        prune_generations(root, current, previous, keep)
    }
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: Option<u32>) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    if let Some(mode) = mode {
        fs::set_permissions(path, fs::Permissions::from_mode(mode))
            .map_err(|error| ManagerError::Io(error.to_string()))?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: Option<u32>) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<()> {
    fs::File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| ManagerError::Io(error.to_string()))
}

fn absolute_lexical(path: &Path) -> Result<PathBuf> {
    let absolute = if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir()
            .map_err(|error| ManagerError::Io(error.to_string()))?
            .join(path)
    };
    let mut normalized = PathBuf::new();
    for component in absolute.components() {
        match component {
            std::path::Component::ParentDir => {
                normalized.pop();
            }
            std::path::Component::CurDir => {}
            other => normalized.push(other.as_os_str()),
        }
    }
    Ok(normalized)
}

fn prune_generations(root: &Path, current: &Path, previous: &Path, keep: usize) -> Result<()> {
    let entries = match fs::read_dir(root) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(ManagerError::Io(error.to_string())),
    };
    let mut protected = [
        generation_target(current).ok(),
        generation_target(previous).ok(),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>();
    protected.sort();
    protected.dedup();
    let additional_limit = keep.saturating_sub(protected.len());
    let mut directories = entries
        .filter_map(std::result::Result::ok)
        .filter_map(|entry| {
            let file_type = entry.file_type().ok()?;
            if !file_type.is_dir() || file_type.is_symlink() {
                return None;
            }
            let modified = entry
                .metadata()
                .and_then(|metadata| metadata.modified())
                .unwrap_or(SystemTime::UNIX_EPOCH);
            Some((modified, entry.path()))
        })
        .collect::<Vec<_>>();
    directories.sort_by_key(|entry| std::cmp::Reverse(entry.0));
    let mut retained_additional = 0usize;
    for (_, path) in directories {
        if protected.iter().any(|target| target == &path) {
            continue;
        }
        if retained_additional < additional_limit {
            retained_additional = retained_additional.saturating_add(1);
            continue;
        }
        fs::remove_dir_all(path).map_err(|error| ManagerError::Io(error.to_string()))?;
    }
    Ok(())
}

#[cfg(unix)]
fn generation_target(pointer: &Path) -> Result<PathBuf> {
    fs::read_link(pointer).map_err(|error| ManagerError::Io(error.to_string()))
}

#[cfg(not(unix))]
fn generation_target(pointer: &Path) -> Result<PathBuf> {
    fs::read_to_string(pointer)
        .map(|value| PathBuf::from(value.trim()))
        .map_err(|error| ManagerError::Io(error.to_string()))
}

#[cfg(unix)]
fn switch_generation(current: &Path, previous: &Path, target: &Path) -> Result<()> {
    use std::os::unix::fs::symlink;
    let parent = current
        .parent()
        .ok_or_else(|| ManagerError::Io("generation pointer has no parent".into()))?;
    if let Ok(old) = fs::read_link(current) {
        let previous_new = previous.with_extension("new");
        let _ = fs::remove_file(&previous_new);
        symlink(old, &previous_new).map_err(|error| ManagerError::Io(error.to_string()))?;
        fs::rename(previous_new, previous).map_err(|error| ManagerError::Io(error.to_string()))?;
    }
    let current_new = current.with_extension("new");
    let _ = fs::remove_file(&current_new);
    symlink(target, &current_new).map_err(|error| ManagerError::Io(error.to_string()))?;
    fs::rename(current_new, current).map_err(|error| ManagerError::Io(error.to_string()))?;
    sync_directory(parent)
}

#[cfg(unix)]
fn replace_pointer(pointer: &Path, target: Option<&Path>) -> Result<()> {
    use std::os::unix::fs::symlink;
    let parent = pointer
        .parent()
        .ok_or_else(|| ManagerError::Io("generation pointer has no parent".into()))?;
    if let Some(target) = target {
        let replacement = pointer.with_extension("restore");
        let _ = fs::remove_file(&replacement);
        symlink(target, &replacement).map_err(|error| ManagerError::Io(error.to_string()))?;
        fs::rename(replacement, pointer).map_err(|error| ManagerError::Io(error.to_string()))?;
    } else {
        match fs::remove_file(pointer) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(ManagerError::Io(error.to_string())),
        }
    }
    sync_directory(parent)
}

#[cfg(not(unix))]
fn switch_generation(current: &Path, previous: &Path, target: &Path) -> Result<()> {
    let old = fs::read_to_string(current).ok();
    if let Some(old) = old {
        write_pointer_windows(previous, old.as_bytes())?;
    }
    write_pointer_windows(current, target.to_string_lossy().as_bytes())
}

#[cfg(not(unix))]
fn replace_pointer(pointer: &Path, target: Option<&Path>) -> Result<()> {
    if let Some(target) = target {
        write_pointer_windows(pointer, target.to_string_lossy().as_bytes())
    } else {
        match fs::remove_file(pointer) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(ManagerError::Io(error.to_string())),
        }
    }
}

#[cfg(windows)]
fn write_pointer_windows(destination: &Path, bytes: &[u8]) -> Result<()> {
    let parent = destination
        .parent()
        .ok_or_else(|| ManagerError::Io("generation pointer has no parent".into()))?;
    fs::create_dir_all(parent).map_err(|error| ManagerError::Io(error.to_string()))?;
    let mut temporary =
        NamedTempFile::new_in(parent).map_err(|error| ManagerError::Io(error.to_string()))?;
    temporary
        .write_all(bytes)
        .and_then(|()| temporary.as_file().sync_all())
        .map_err(|error| ManagerError::Io(error.to_string()))?;
    let temporary_path = temporary
        .into_temp_path()
        .keep()
        .map_err(|error| ManagerError::Io(error.error.to_string()))?;
    replace_path_windows(&temporary_path, destination)
}

#[cfg(windows)]
fn replace_path_windows(source_path: &Path, destination: &Path) -> Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
    };

    let source = source_path
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let target = destination
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let moved = unsafe {
        MoveFileExW(
            source.as_ptr(),
            target.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if moved == 0 {
        let error = std::io::Error::last_os_error();
        let _ = fs::remove_file(source_path);
        return Err(ManagerError::Io(error.to_string()));
    }
    Ok(())
}

#[derive(Debug, Clone, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn unix_timestamp(&self) -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64
    }
}

#[derive(Debug, Clone, Default)]
pub struct TracingEventSink;

impl EventSink for TracingEventSink {
    fn emit(&self, event: ManagerEvent) {
        tracing::debug!(?event, "manager event");
    }
}

#[derive(Debug, Clone, Default)]
pub struct ProcessCommandRunner;

#[async_trait]
impl CommandRunner for ProcessCommandRunner {
    async fn run(&self, program: &str, args: &[String]) -> Result<CommandOutput> {
        let output = Command::new(program)
            .args(args)
            .output()
            .await
            .map_err(|error| ManagerError::Io(error.to_string()))?;
        Ok(CommandOutput {
            status: output.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        })
    }
}

#[derive(Debug, Clone, Default)]
pub struct ProcessXrayRunner;

#[async_trait]
impl XrayRunner for ProcessXrayRunner {
    async fn version(&self, executable: &Path) -> Result<String> {
        let output = Command::new(executable)
            .arg("version")
            .output()
            .await
            .map_err(|error| ManagerError::Io(error.to_string()))?;
        if !output.status.success() {
            return Err(ManagerError::Validation(
                String::from_utf8_lossy(&output.stderr).into_owned(),
            ));
        }
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
    }

    async fn test_config(&self, request: &XrayTestRequest) -> Result<()> {
        // Xray's `run -test` still initializes TUN inbounds. During an ordinary
        // node switch the active service already owns that interface, so testing
        // the unmodified candidate would reject every otherwise-valid config.
        // The committed generation is not changed: only this disposable
        // validation copy omits TUN, while the subsequent service restart and
        // healthcheck validate the real runtime configuration.
        let validation = prepare_xray_validation_config(&request.config_dir)?;
        let output = Command::new(&request.executable)
            .env("XRAY_LOCATION_ASSET", &request.asset_dir)
            .args(["run", "-test", "-confdir"])
            .arg(validation.path())
            .output()
            .await
            .map_err(|error| ManagerError::Io(error.to_string()))?;
        if output.status.success() {
            Ok(())
        } else {
            let diagnostic = sanitize_xray_diagnostic(&output.stderr);
            tracing::warn!(
                target: "xray_manager_platform::xray",
                status = ?output.status.code(),
                diagnostic = %diagnostic,
                "Xray rejected candidate configuration"
            );
            Err(ManagerError::Validation(format!(
                "Xray rejected the candidate configuration ({diagnostic}); \
                     run xrayctl --verbose doctor for manager diagnostics"
            )))
        }
    }

    async fn probe(&self, _node: &Node, _config: &ManagerConfig) -> Result<ProbeResult> {
        #[cfg(target_os = "linux")]
        {
            return probe_with_temporary_xray(_node, _config).await;
        }
        #[cfg(not(target_os = "linux"))]
        Err(ManagerError::Other(
            "real Xray probes are unavailable on this platform".into(),
        ))
    }

    async fn healthcheck(&self, config: &ManagerConfig) -> Result<()> {
        for proxy_url in [
            format!(
                "socks5h://{}:{}",
                config.proxy.listen, config.proxy.socks_port
            ),
            format!("http://{}:{}", config.proxy.listen, config.proxy.http_port),
        ] {
            let proxy = reqwest::Proxy::all(&proxy_url)
                .map_err(|_| ManagerError::Other("failed to configure healthcheck proxy".into()))?;
            let client = Client::builder()
                .proxy(proxy)
                .connect_timeout(Duration::from_secs(config.general.connect_timeout_seconds))
                .timeout(Duration::from_secs(config.general.request_timeout_seconds))
                .redirect(Policy::limited(2))
                .build()
                .map_err(|error| ManagerError::Other(error.without_url().to_string()))?;
            let response = client
                .get(&config.general.healthcheck_url)
                .send()
                .await
                .map_err(|error| ManagerError::Other(error.without_url().to_string()))?;
            if !response.status().is_success() && !response.status().is_redirection() {
                return Err(ManagerError::Other(format!(
                    "healthcheck returned {}",
                    response.status()
                )));
            }
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
async fn probe_with_temporary_xray(node: &Node, config: &ManagerConfig) -> Result<ProbeResult> {
    use xray_manager_core::render::render_xray_config;
    use xray_manager_core::routing::RoutingConfig;

    let listener = std::net::TcpListener::bind(("127.0.0.1", 0))
        .map_err(|error| ManagerError::Io(error.to_string()))?;
    let socks_port = listener
        .local_addr()
        .map_err(|error| ManagerError::Io(error.to_string()))?
        .port();
    drop(listener);
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0))
        .map_err(|error| ManagerError::Io(error.to_string()))?;
    let http_port = listener
        .local_addr()
        .map_err(|error| ManagerError::Io(error.to_string()))?
        .port();
    drop(listener);

    let mut candidate_config = config.clone();
    candidate_config.proxy.socks_port = socks_port;
    candidate_config.proxy.http_port = http_port;
    candidate_config.tun.enabled = false;
    let routing = RoutingConfig::preset("global-proxy")?;
    let rendered = render_xray_config(&candidate_config, Some(node), &routing, Vec::new())?;
    let temporary = tempfile::tempdir().map_err(|error| ManagerError::Io(error.to_string()))?;
    for (name, value) in rendered {
        let bytes = serde_json::to_vec_pretty(&value)
            .map_err(|error| ManagerError::InvalidConfig(error.to_string()))?;
        tokio::fs::write(temporary.path().join(name), bytes)
            .await
            .map_err(|error| ManagerError::Io(error.to_string()))?;
    }
    let mut child = Command::new("/opt/xray-manager/core/current/xray")
        .env("XRAY_LOCATION_ASSET", "/opt/xray-manager/assets/current")
        .args(["run", "-confdir"])
        .arg(temporary.path())
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .map_err(|error| ManagerError::Io(error.to_string()))?;
    let timeout = Duration::from_secs(config.menu.probe_timeout_seconds.max(1));
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if tokio::net::TcpStream::connect(("127.0.0.1", socks_port))
            .await
            .is_ok()
        {
            break;
        }
        if let Some(status) = child
            .try_wait()
            .map_err(|error| ManagerError::Io(error.to_string()))?
        {
            return Ok(ProbeResult {
                latency_ms: None,
                error: Some(format!("temporary Xray exited with {status}")),
            });
        }
        if tokio::time::Instant::now() >= deadline {
            terminate_child(&mut child).await;
            return Ok(ProbeResult {
                latency_ms: None,
                error: Some("temporary Xray did not become ready".into()),
            });
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let proxy = reqwest::Proxy::all(format!("socks5h://127.0.0.1:{socks_port}"))
        .map_err(|_| ManagerError::Other("failed to configure probe proxy".into()))?;
    let client = Client::builder()
        .proxy(proxy)
        .timeout(timeout)
        .redirect(Policy::limited(2))
        .build()
        .map_err(|error| ManagerError::Other(error.without_url().to_string()))?;
    let started = tokio::time::Instant::now();
    let result = client.get(&config.general.healthcheck_url).send().await;
    let elapsed = started.elapsed().as_millis().min(u64::MAX as u128) as u64;
    terminate_child(&mut child).await;
    match result {
        Ok(response) if response.status().is_success() || response.status().is_redirection() => {
            Ok(ProbeResult {
                latency_ms: Some(elapsed),
                error: None,
            })
        }
        Ok(response) => Ok(ProbeResult {
            latency_ms: None,
            error: Some(format!("healthcheck returned {}", response.status())),
        }),
        Err(error) => Ok(ProbeResult {
            latency_ms: None,
            error: Some(error.without_url().to_string()),
        }),
    }
}

fn prepare_xray_validation_config(config_dir: &Path) -> Result<tempfile::TempDir> {
    let temporary = tempfile::tempdir().map_err(|error| ManagerError::Io(error.to_string()))?;
    let entries = fs::read_dir(config_dir).map_err(|error| ManagerError::Io(error.to_string()))?;
    let mut removed_tun_inbounds = 0usize;

    for entry in entries {
        let entry = entry.map_err(|error| ManagerError::Io(error.to_string()))?;
        let file_type = entry
            .file_type()
            .map_err(|error| ManagerError::Io(error.to_string()))?;
        if !file_type.is_file() {
            continue;
        }
        let source = entry.path();
        let destination = temporary.path().join(entry.file_name());
        if source.extension().and_then(std::ffi::OsStr::to_str) != Some("json") {
            fs::copy(&source, &destination).map_err(|error| ManagerError::Io(error.to_string()))?;
            continue;
        }

        let bytes = fs::read(&source).map_err(|error| ManagerError::Io(error.to_string()))?;
        let mut value: serde_json::Value = serde_json::from_slice(&bytes)
            .map_err(|error| ManagerError::InvalidConfig(error.to_string()))?;
        if let Some(inbounds) = value
            .get_mut("inbounds")
            .and_then(serde_json::Value::as_array_mut)
        {
            let original_len = inbounds.len();
            inbounds.retain(|inbound| {
                inbound.get("protocol").and_then(serde_json::Value::as_str) != Some("tun")
            });
            removed_tun_inbounds += original_len.saturating_sub(inbounds.len());
        }
        let bytes = serde_json::to_vec_pretty(&value)
            .map_err(|error| ManagerError::InvalidConfig(error.to_string()))?;
        fs::write(destination, bytes).map_err(|error| ManagerError::Io(error.to_string()))?;
    }

    tracing::debug!(
        removed_tun_inbounds,
        "prepared side-effect-free Xray validation configuration"
    );
    Ok(temporary)
}

fn sanitize_xray_diagnostic(stderr: &[u8]) -> String {
    let text = String::from_utf8_lossy(stderr);
    let last_line = text
        .lines()
        .rev()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .unwrap_or("no diagnostic was returned");
    let mut sanitized = last_line
        .split_whitespace()
        .map(|word| {
            if word.contains("://") {
                "[redacted-uri]"
            } else {
                word
            }
        })
        .collect::<Vec<_>>()
        .join(" ");
    sanitized.truncate(512);
    sanitized
}

#[cfg(target_os = "linux")]
async fn terminate_child(child: &mut tokio::process::Child) {
    if let Some(id) = child.id() {
        let _ = nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(id as i32),
            nix::sys::signal::Signal::SIGTERM,
        );
        if tokio::time::timeout(Duration::from_secs(1), child.wait())
            .await
            .is_ok()
        {
            return;
        }
    }
    let _ = child.kill().await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn validation_copy_removes_only_tun_inbounds() {
        let source = tempfile::tempdir().unwrap();
        fs::write(
            source.path().join("20_inbounds.json"),
            serde_json::to_vec(&json!({
                "inbounds": [
                    {"tag": "socks-in", "protocol": "socks"},
                    {"tag": "tun-in", "protocol": "tun"},
                    {"tag": "http-in", "protocol": "http"}
                ]
            }))
            .unwrap(),
        )
        .unwrap();
        fs::write(
            source.path().join("30_outbounds.json"),
            serde_json::to_vec(&json!({"outbounds": [{"protocol": "vless"}]})).unwrap(),
        )
        .unwrap();

        let validation = prepare_xray_validation_config(source.path()).unwrap();
        let inbounds: serde_json::Value =
            serde_json::from_slice(&fs::read(validation.path().join("20_inbounds.json")).unwrap())
                .unwrap();
        let protocols: Vec<&str> = inbounds["inbounds"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|inbound| inbound["protocol"].as_str())
            .collect();
        assert_eq!(protocols, ["socks", "http"]);

        let outbounds: serde_json::Value =
            serde_json::from_slice(&fs::read(validation.path().join("30_outbounds.json")).unwrap())
                .unwrap();
        assert_eq!(outbounds["outbounds"][0]["protocol"], "vless");
    }

    #[test]
    fn xray_diagnostic_redacts_uri_tokens_and_is_bounded() {
        let diagnostic = sanitize_xray_diagnostic(
            b"first line\nfailed to use vless://sensitive@example.invalid:443/path\n",
        );
        assert_eq!(diagnostic, "failed to use [redacted-uri]");
        assert!(diagnostic.len() <= 512);
    }

    #[tokio::test]
    async fn atomic_write_replaces_existing_file() {
        let temp = tempfile::tempdir().expect("temporary directory");
        let path = temp.path().join("state.json");
        let filesystem = NativeFileSystem;
        filesystem
            .write_atomic(&path, b"old", None)
            .await
            .expect("initial write");
        filesystem
            .write_atomic(&path, b"new", None)
            .await
            .expect("replacement");
        assert_eq!(filesystem.read(&path).await.expect("read"), b"new");
        assert!(!path.with_extension("replace-backup").exists());
    }

    #[tokio::test]
    async fn owned_removal_rejects_root_itself() {
        let temp = tempfile::tempdir().expect("temporary directory");
        let filesystem = NativeFileSystem;
        assert!(
            filesystem
                .remove_owned(temp.path(), temp.path())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn generation_rollback_swaps_current_and_previous() {
        let temp = tempfile::tempdir().expect("temporary directory");
        let filesystem = NativeFileSystem;
        let current = temp.path().join("current");
        let previous = temp.path().join("previous");
        let first = temp.path().join("generations/one");
        let second = temp.path().join("generations/two");
        std::fs::create_dir_all(&first).expect("first generation");
        std::fs::create_dir_all(&second).expect("second generation");
        filesystem
            .switch_generation(&current, &previous, &first)
            .await
            .expect("initial switch");
        filesystem
            .switch_generation(&current, &previous, &second)
            .await
            .expect("second switch");
        filesystem
            .rollback_generation(&current, &previous)
            .await
            .expect("rollback");
        assert_eq!(generation_target(&current).expect("current target"), first);
        assert_eq!(
            generation_target(&previous).expect("previous target"),
            second
        );
    }

    #[tokio::test]
    async fn failed_activation_restores_both_generation_pointers() {
        let temp = tempfile::tempdir().expect("temporary directory");
        let filesystem = NativeFileSystem;
        let current = temp.path().join("current");
        let previous = temp.path().join("previous");
        let first = temp.path().join("generations/one");
        let second = temp.path().join("generations/two");
        let failed = temp.path().join("generations/failed");
        for path in [&first, &second, &failed] {
            std::fs::create_dir_all(path).expect("generation");
        }
        filesystem
            .switch_generation(&current, &previous, &first)
            .await
            .expect("first switch");
        filesystem
            .switch_generation(&current, &previous, &second)
            .await
            .expect("second switch");
        filesystem
            .switch_generation(&current, &previous, &failed)
            .await
            .expect("candidate switch");
        filesystem
            .restore_generation(&current, &previous, Some(&second), Some(&first))
            .await
            .expect("exact restore");
        assert_eq!(generation_target(&current).expect("current"), second);
        assert_eq!(generation_target(&previous).expect("previous"), first);
    }

    #[tokio::test]
    async fn generation_pruning_preserves_current_and_previous() {
        let temp = tempfile::tempdir().expect("temporary directory");
        let filesystem = NativeFileSystem;
        let root = temp.path().join("generations");
        let current = temp.path().join("current");
        let previous = temp.path().join("previous");
        let paths = (0..4)
            .map(|index| root.join(index.to_string()))
            .collect::<Vec<_>>();
        for path in &paths {
            std::fs::create_dir_all(path).expect("generation");
        }
        filesystem
            .switch_generation(&current, &previous, &paths[0])
            .await
            .expect("first switch");
        filesystem
            .switch_generation(&current, &previous, &paths[1])
            .await
            .expect("second switch");
        filesystem
            .prune_generations(&root, &current, &previous, 2)
            .await
            .expect("prune");
        assert!(paths[0].exists());
        assert!(paths[1].exists());
        assert!(!paths[2].exists());
        assert!(!paths[3].exists());
    }

    #[test]
    fn parses_github_release_wire_shape() {
        let releases: Vec<Release> = serde_json::from_str(
            r#"[{
                "tag_name": "v1.2.3",
                "prerelease": false,
                "assets": [{
                    "name": "Xray-linux-64.zip",
                    "browser_download_url": "https://example.test/xray.zip",
                    "size": 123
                }]
            }]"#,
        )
        .expect("release response should parse");
        assert_eq!(releases[0].tag, "v1.2.3");
        assert_eq!(
            releases[0].assets[0].download_url,
            "https://example.test/xray.zip"
        );
    }

    #[tokio::test]
    async fn download_timeout_is_enforced_before_network_is_required() {
        let client = HttpClient::new(0).expect("client");
        let result = client
            .download(DownloadRequest {
                url: "https://example.invalid/file".into(),
                max_bytes: 16,
                timeout: Duration::ZERO,
                max_redirects: 0,
            })
            .await;
        assert!(
            matches!(result, Err(ManagerError::Download(message)) if message == "request timed out")
        );
    }
}
