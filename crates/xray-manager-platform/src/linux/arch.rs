use super::{TunInternalAction, run_tun_internal};
use crate::artifacts::{extract_xray_zip, validate_asset};
use crate::portable::{
    GithubReleaseProvider, HttpClient, NativeFileSystem, ProcessCommandRunner, ProcessXrayRunner,
    SystemClock,
};
use crate::templates;
use async_trait::async_trait;
use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use xray_manager_core::config::ManagerConfig;
use xray_manager_core::domain::ManagerState;
use xray_manager_core::ports::{
    BackendSelection, Capability, Clock, CommandRunner, DownloadRequest, Downloader, ExecutionPlan,
    FileSystem, PlanAction, PlatformInstaller, ReleaseProvider, UpgradeTarget, XrayRunner,
    XrayTestRequest,
};
use xray_manager_core::render::render_xray_config;
use xray_manager_core::routing::RoutingConfig;
use xray_manager_core::{ManagerError, Result};

#[derive(Clone)]
pub struct ArchInstaller {
    config: ManagerConfig,
    downloader: HttpClient,
    releases: GithubReleaseProvider,
    filesystem: NativeFileSystem,
    runner: ProcessCommandRunner,
    xray: ProcessXrayRunner,
    installed_backends: BTreeMap<String, String>,
}

struct PreparedInstall {
    core_version: String,
    core_directory: PathBuf,
    asset_generation: String,
    asset_directory: PathBuf,
    config_generation: String,
    config_directory: Option<PathBuf>,
}

impl ArchInstaller {
    pub fn new(config: ManagerConfig, selections: &[BackendSelection]) -> Result<Self> {
        let downloader = HttpClient::with_connect_timeout(
            5,
            std::time::Duration::from_secs(config.general.connect_timeout_seconds),
        )?;
        Ok(Self {
            config,
            releases: GithubReleaseProvider::new(downloader.clone()),
            downloader,
            filesystem: NativeFileSystem,
            runner: ProcessCommandRunner,
            xray: ProcessXrayRunner,
            installed_backends: selections
                .iter()
                .map(|selection| {
                    (
                        selection.capability.to_string(),
                        selection.backend_id.clone(),
                    )
                })
                .collect(),
        })
    }

    async fn run_checked(&self, program: &str, args: &[String]) -> Result<()> {
        let output = self.runner.run(program, args).await?;
        if output.status == 0 {
            Ok(())
        } else {
            Err(ManagerError::Other(format!(
                "{program} failed: {}",
                output.stderr.trim()
            )))
        }
    }

    async fn run_best_effort(&self, program: &str, args: &[String]) {
        let _ = self.runner.run(program, args).await;
    }

    async fn group_has_members(&self, group: &str) -> bool {
        self.runner
            .run("getent", &["group".into(), group.into()])
            .await
            .ok()
            .filter(|output| output.status == 0)
            .and_then(|output| {
                output
                    .stdout
                    .trim()
                    .split(':')
                    .nth(3)
                    .map(|members| !members.trim().is_empty())
            })
            .unwrap_or(false)
    }

    async fn ensure_identities(&self) -> Result<Vec<String>> {
        let mut created = Vec::new();
        for group in ["xray", "xray-manager", "xray-tun"] {
            let existed = self
                .runner
                .run("getent", &["group".into(), group.into()])
                .await?
                .status
                == 0;
            self.run_checked("groupadd", &["-f".into(), group.into()])
                .await?;
            if !existed {
                let identity = format!("group:{group}");
                self.record_created_identity(&identity).await?;
                created.push(identity);
            }
        }
        let exists = self
            .runner
            .run("id", &["-u".into(), "xray".into()])
            .await?
            .status
            == 0;
        if !exists {
            self.run_checked(
                "useradd",
                &[
                    "--system".into(),
                    "--gid".into(),
                    "xray".into(),
                    "--home-dir".into(),
                    "/var/lib/xray-manager".into(),
                    "--shell".into(),
                    "/usr/bin/nologin".into(),
                    "xray".into(),
                ],
            )
            .await?;
            self.record_created_identity("user:xray").await?;
            created.push("user:xray".into());
        }
        Ok(created)
    }

    async fn record_created_identity(&self, identity: &str) -> Result<()> {
        let path = Path::new("/var/lib/xray-manager/state.json");
        let mut state = self.existing_state().await?;
        if !state.created_identities.iter().any(|item| item == identity) {
            state.created_identities.push(identity.into());
            state.created_identities.sort();
        }
        state.installed_backends = self.installed_backends.clone();
        let encoded = serde_json::to_vec_pretty(&state)
            .map_err(|error| ManagerError::Io(error.to_string()))?;
        self.filesystem
            .write_atomic(path, &encoded, Some(0o640))
            .await
    }

    async fn install_self_and_defaults(&self) -> Result<()> {
        let executable =
            std::env::current_exe().map_err(|error| ManagerError::Io(error.to_string()))?;
        let bytes = tokio::fs::read(executable)
            .await
            .map_err(|error| ManagerError::Io(error.to_string()))?;
        self.filesystem
            .write_atomic(Path::new("/usr/local/bin/xrayctl"), &bytes, Some(0o755))
            .await?;
        let config_path = Path::new("/etc/xray-manager/config.toml");
        if !self.filesystem.exists(config_path).await? {
            let encoded = toml::to_string_pretty(&self.config)
                .map_err(|error| ManagerError::InvalidConfig(error.to_string()))?;
            self.filesystem
                .write_atomic(config_path, encoded.as_bytes(), Some(0o640))
                .await?;
        }
        let routing_path = Path::new("/etc/xray-manager/routing.toml");
        if !self.filesystem.exists(routing_path).await? {
            let routing = RoutingConfig::preset("global-proxy")?;
            let encoded = toml::to_string_pretty(&routing)
                .map_err(|error| ManagerError::InvalidConfig(error.to_string()))?;
            self.filesystem
                .write_atomic(routing_path, encoded.as_bytes(), Some(0o640))
                .await?;
        }
        Ok(())
    }

    async fn prepare_core(&self) -> Result<(String, PathBuf, PathBuf)> {
        let release = self
            .releases
            .stable_release(&self.config.core.repository)
            .await?;
        let asset = release
            .assets
            .iter()
            .find(|asset| asset.name == "Xray-linux-64.zip")
            .ok_or_else(|| {
                ManagerError::Download("release has no Xray-linux-64.zip asset".into())
            })?;
        let archive = self
            .downloader
            .download(DownloadRequest {
                url: asset.download_url.clone(),
                max_bytes: self.config.general.max_core_archive_size_mb * 1024 * 1024,
                timeout: std::time::Duration::from_secs(
                    self.config.general.request_timeout_seconds,
                ),
                max_redirects: 5,
            })
            .await?;
        validate_generation_name(&release.tag)?;
        let version_dir = Path::new("/opt/xray-manager/core/versions").join(&release.tag);
        let executable = version_dir.join("xray");
        if self.filesystem.exists(&executable).await?
            && self.xray.version(&executable).await.is_ok()
        {
            return Ok((release.tag, version_dir, executable));
        }
        let staging = Path::new("/opt/xray-manager/core/staging").join(unique_generation());
        let staged_executable = match extract_xray_zip(
            &archive.bytes,
            &staging,
            self.config.general.max_core_archive_size_mb * 1024 * 1024,
        ) {
            Ok(executable) => executable,
            Err(error) => {
                let _ = std::fs::remove_dir_all(&staging);
                return Err(error);
            }
        };
        if let Err(error) = self.xray.version(&staged_executable).await {
            let _ = std::fs::remove_dir_all(&staging);
            return Err(error);
        }
        std::fs::create_dir_all(
            version_dir
                .parent()
                .ok_or_else(|| ManagerError::Io("core version has no parent".into()))?,
        )
        .map_err(|error| ManagerError::Io(error.to_string()))?;
        let versions_root = version_dir
            .parent()
            .ok_or_else(|| ManagerError::Io("core version has no parent".into()))?;
        let quarantined = if std::fs::symlink_metadata(&version_dir).is_ok() {
            let quarantine = versions_root.join(format!(".invalid-{}", unique_generation()));
            std::fs::rename(&version_dir, &quarantine)
                .map_err(|error| ManagerError::Io(error.to_string()))?;
            Some(quarantine)
        } else {
            None
        };
        if let Err(error) = std::fs::rename(&staging, &version_dir) {
            let _ = std::fs::remove_dir_all(&staging);
            if let Some(quarantine) = quarantined.as_ref()
                && let Err(restore_error) = std::fs::rename(quarantine, &version_dir)
            {
                return Err(ManagerError::Io(format!(
                    "failed to activate staged Xray ({error}) and restore the old version ({restore_error})"
                )));
            }
            return Err(ManagerError::Io(error.to_string()));
        }
        std::fs::File::open(versions_root)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| ManagerError::Io(error.to_string()))?;
        let executable = version_dir.join("xray");
        if let Err(error) = self.xray.version(&executable).await {
            let failed = versions_root.join(format!(".failed-{}", unique_generation()));
            if let Err(rename_error) = std::fs::rename(&version_dir, &failed) {
                return Err(ManagerError::Io(format!(
                    "activated Xray failed validation ({error}) and could not be quarantined ({rename_error})"
                )));
            }
            if let Some(quarantine) = quarantined.as_ref()
                && let Err(restore_error) = std::fs::rename(quarantine, &version_dir)
            {
                let _ = std::fs::rename(&failed, &version_dir);
                return Err(ManagerError::Io(format!(
                    "activated Xray failed validation ({error}) and the old version could not be restored ({restore_error})"
                )));
            }
            let _ = self.filesystem.remove_owned(&failed, versions_root).await;
            let _ = std::fs::File::open(versions_root).and_then(|directory| directory.sync_all());
            return Err(error);
        }
        if let Some(quarantine) = quarantined {
            self.filesystem
                .remove_owned(&quarantine, versions_root)
                .await?;
        }
        Ok((release.tag, version_dir, executable))
    }

    async fn prepare_assets(&self) -> Result<(String, PathBuf)> {
        let generation = unique_generation();
        let directory = Path::new("/opt/xray-manager/assets/generations").join(&generation);
        self.filesystem.create_dir_all(&directory).await?;
        for asset in &self.config.assets {
            let result = async {
                let downloaded = self
                    .downloader
                    .download(DownloadRequest {
                        url: asset.url.clone(),
                        max_bytes: self.config.general.max_asset_size_mb * 1024 * 1024,
                        timeout: std::time::Duration::from_secs(
                            self.config.general.request_timeout_seconds,
                        ),
                        max_redirects: 5,
                    })
                    .await?;
                validate_asset(
                    &downloaded.bytes,
                    (self.config.general.max_asset_size_mb * 1024 * 1024) as usize,
                )?;
                self.filesystem
                    .write_atomic(
                        &directory.join(&asset.filename),
                        &downloaded.bytes,
                        Some(0o644),
                    )
                    .await?;
                Result::<()>::Ok(())
            }
            .await;
            if let Err(error) = result {
                let _ = std::fs::remove_dir_all(&directory);
                return Err(error);
            }
        }
        Ok((generation, directory))
    }

    async fn reusable_core(
        &self,
        state: &ManagerState,
    ) -> Result<Option<(String, PathBuf, PathBuf)>> {
        let Some(version) = state.current_core_version.as_ref() else {
            return Ok(None);
        };
        let directory = Path::new("/opt/xray-manager/core/versions").join(version);
        let executable = directory.join("xray");
        if std::fs::read_link("/opt/xray-manager/core/current")
            .ok()
            .as_deref()
            != Some(directory.as_path())
            || !self.filesystem.exists(&executable).await?
        {
            return Ok(None);
        }
        if self.xray.version(&executable).await.is_err() {
            return Ok(None);
        }
        Ok(Some((version.clone(), directory, executable)))
    }

    async fn reusable_assets(&self, state: &ManagerState) -> Result<Option<(String, PathBuf)>> {
        let Some(generation) = state.current_asset_generation.as_ref() else {
            return Ok(None);
        };
        let directory = Path::new("/opt/xray-manager/assets/generations").join(generation);
        if std::fs::read_link("/opt/xray-manager/assets/current")
            .ok()
            .as_deref()
            != Some(directory.as_path())
        {
            return Ok(None);
        }
        let max_bytes = (self.config.general.max_asset_size_mb * 1024 * 1024) as usize;
        for asset in &self.config.assets {
            let path = directory.join(&asset.filename);
            if !self.filesystem.exists(&path).await? {
                return Ok(None);
            }
            let bytes = self.filesystem.read(&path).await?;
            if validate_asset(&bytes, max_bytes).is_err() {
                return Ok(None);
            }
        }
        Ok(Some((generation.clone(), directory)))
    }

    async fn prepare_initial_config(
        &self,
        core: &Path,
        assets: &Path,
    ) -> Result<(String, PathBuf)> {
        let generation = unique_generation();
        let directory = Path::new("/var/lib/xray-manager/generations")
            .join(&generation)
            .join("conf.d");
        let routing = RoutingConfig::preset("global-proxy")?;
        let rendered = render_xray_config(&self.config, None, &routing, vec![])?;
        self.filesystem.create_dir_all(&directory).await?;
        std::fs::set_permissions(
            directory
                .parent()
                .ok_or_else(|| ManagerError::Io("config generation has no parent".into()))?,
            std::fs::Permissions::from_mode(0o750),
        )
        .and_then(|()| std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o750)))
        .map_err(|error| ManagerError::Io(error.to_string()))?;
        for (name, value) in rendered {
            let bytes = serde_json::to_vec_pretty(&value)
                .map_err(|error| ManagerError::InvalidConfig(error.to_string()))?;
            self.filesystem
                .write_atomic(&directory.join(name), &bytes, Some(0o640))
                .await?;
        }
        if let Err(error) = self
            .xray
            .test_config(&XrayTestRequest {
                executable: core.to_owned(),
                config_dir: directory,
                asset_dir: assets.to_owned(),
            })
            .await
        {
            let _ = std::fs::remove_dir_all(
                Path::new("/var/lib/xray-manager/generations").join(&generation),
            );
            return Err(error);
        }
        let target = Path::new("/var/lib/xray-manager/generations").join(&generation);
        Ok((generation, target))
    }

    async fn write_state(
        &self,
        core_version: String,
        asset_generation: String,
        config_generation: String,
        newly_created_identities: Vec<String>,
    ) -> Result<()> {
        let state_path = Path::new("/var/lib/xray-manager/state.json");
        let mut state = if self.filesystem.exists(state_path).await? {
            serde_json::from_slice::<ManagerState>(&self.filesystem.read(state_path).await?)
                .map_err(|error| ManagerError::Io(error.to_string()))?
        } else {
            ManagerState::default()
        };
        state.created_identities.extend(newly_created_identities);
        state.created_identities.sort();
        state.created_identities.dedup();
        if state.current_core_version.as_deref() != Some(core_version.as_str()) {
            state.previous_core_version = state.current_core_version.take();
        }
        if state.current_asset_generation.as_deref() != Some(asset_generation.as_str()) {
            state.previous_asset_generation = state.current_asset_generation.take();
        }
        if state.current_config_generation.as_deref() != Some(config_generation.as_str()) {
            state.previous_config_generation = state.current_config_generation.take();
        }
        state.current_core_version = Some(core_version);
        state.current_asset_generation = Some(asset_generation);
        state.current_config_generation = Some(config_generation);
        state.installed_backends = self.installed_backends.clone();
        let encoded = serde_json::to_vec_pretty(&state)
            .map_err(|error| ManagerError::Io(error.to_string()))?;
        self.filesystem
            .write_atomic(
                Path::new("/var/lib/xray-manager/state.json"),
                &encoded,
                Some(0o640),
            )
            .await
    }

    async fn existing_state(&self) -> Result<ManagerState> {
        let path = Path::new("/var/lib/xray-manager/state.json");
        if !self.filesystem.exists(path).await? {
            return Ok(ManagerState::default());
        }
        serde_json::from_slice(&self.filesystem.read(path).await?)
            .map_err(|error| ManagerError::Io(error.to_string()))
    }

    async fn validate_candidate(
        &self,
        core: &Path,
        assets: &Path,
        config_dir: &Path,
    ) -> Result<()> {
        self.xray
            .test_config(&XrayTestRequest {
                executable: core.to_owned(),
                config_dir: config_dir.to_owned(),
                asset_dir: assets.to_owned(),
            })
            .await
    }

    async fn restore_pointer(
        &self,
        current: &Path,
        previous: &Path,
        current_target: Option<&Path>,
        previous_target: Option<&Path>,
    ) {
        let _ = self
            .filesystem
            .restore_generation(current, previous, current_target, previous_target)
            .await;
    }

    async fn healthcheck(&self) -> Result<()> {
        self.xray.healthcheck(&self.config).await
    }

    async fn activate_install(
        &self,
        candidate: PreparedInstall,
        created_identities: Vec<String>,
    ) -> Result<()> {
        let core_current = Path::new("/opt/xray-manager/core/current");
        let core_previous = Path::new("/opt/xray-manager/core/previous");
        let assets_current = Path::new("/opt/xray-manager/assets/current");
        let assets_previous = Path::new("/opt/xray-manager/assets/previous");
        let config_current = Path::new("/var/lib/xray-manager/current");
        let config_previous = Path::new("/var/lib/xray-manager/previous");
        let old_state = self.existing_state().await?;
        let had_core = self.filesystem.exists(core_current).await?;
        let old_core_current = old_state
            .current_core_version
            .as_ref()
            .map(|version| Path::new("/opt/xray-manager/core/versions").join(version));
        let old_core_previous = old_state
            .previous_core_version
            .as_ref()
            .map(|version| Path::new("/opt/xray-manager/core/versions").join(version));
        let old_assets_current = old_state
            .current_asset_generation
            .as_ref()
            .map(|generation| Path::new("/opt/xray-manager/assets/generations").join(generation));
        let old_assets_previous = old_state
            .previous_asset_generation
            .as_ref()
            .map(|generation| Path::new("/opt/xray-manager/assets/generations").join(generation));
        let old_config_current = old_state
            .current_config_generation
            .as_ref()
            .map(|generation| Path::new("/var/lib/xray-manager/generations").join(generation));
        let old_config_previous = old_state
            .previous_config_generation
            .as_ref()
            .map(|generation| Path::new("/var/lib/xray-manager/generations").join(generation));
        let core_changed = old_state.current_core_version.as_deref()
            != Some(candidate.core_version.as_str())
            || !had_core
            || std::fs::read_link(core_current).ok().as_deref()
                != Some(candidate.core_directory.as_path());
        let assets_changed = old_state.current_asset_generation.as_deref()
            != Some(candidate.asset_generation.as_str())
            || std::fs::read_link(assets_current).ok().as_deref()
                != Some(candidate.asset_directory.as_path());

        if let Some(ref config_directory) = candidate.config_directory {
            self.run_checked(
                "chown",
                &[
                    "-R".into(),
                    "xray:xray".into(),
                    config_directory.to_string_lossy().into_owned(),
                ],
            )
            .await?;
        }
        if core_changed {
            self.filesystem
                .switch_generation(core_current, core_previous, &candidate.core_directory)
                .await?;
        }
        if assets_changed
            && let Err(error) = self
                .filesystem
                .switch_generation(assets_current, assets_previous, &candidate.asset_directory)
                .await
        {
            if core_changed {
                self.restore_pointer(
                    core_current,
                    core_previous,
                    old_core_current.as_deref(),
                    old_core_previous.as_deref(),
                )
                .await;
            }
            return Err(error);
        }
        if let Some(ref config_directory) = candidate.config_directory
            && let Err(error) = self
                .filesystem
                .switch_generation(config_current, config_previous, config_directory)
                .await
        {
            if assets_changed {
                self.restore_pointer(
                    assets_current,
                    assets_previous,
                    old_assets_current.as_deref(),
                    old_assets_previous.as_deref(),
                )
                .await;
            }
            if core_changed {
                self.restore_pointer(
                    core_current,
                    core_previous,
                    old_core_current.as_deref(),
                    old_core_previous.as_deref(),
                )
                .await;
            }
            return Err(error);
        }
        if let Err(error) = self
            .write_state(
                candidate.core_version,
                candidate.asset_generation,
                candidate.config_generation,
                created_identities,
            )
            .await
        {
            if candidate.config_directory.is_some() {
                self.restore_pointer(
                    config_current,
                    config_previous,
                    old_config_current.as_deref(),
                    old_config_previous.as_deref(),
                )
                .await;
            }
            if assets_changed {
                self.restore_pointer(
                    assets_current,
                    assets_previous,
                    old_assets_current.as_deref(),
                    old_assets_previous.as_deref(),
                )
                .await;
            }
            if core_changed {
                self.restore_pointer(
                    core_current,
                    core_previous,
                    old_core_current.as_deref(),
                    old_core_previous.as_deref(),
                )
                .await;
            }
            return Err(error);
        }
        let activation = async {
            self.run_checked("systemctl", &["daemon-reload".into()])
                .await?;
            if self.config.tun.enabled {
                self.run_checked(
                    "systemctl",
                    &[
                        "enable".into(),
                        "--now".into(),
                        "xray-tun-policy.service".into(),
                    ],
                )
                .await?;
            } else {
                self.run_best_effort(
                    "systemctl",
                    &[
                        "disable".into(),
                        "--now".into(),
                        "xray-tun-policy.service".into(),
                    ],
                )
                .await;
                let _ = run_tun_internal(TunInternalAction::PolicyDown, &self.config).await;
            }
            self.run_checked(
                "systemctl",
                &["enable".into(), "--now".into(), "xray.service".into()],
            )
            .await?;
            if old_state.selected_node_id.is_some() {
                self.healthcheck().await?;
            }
            Ok(())
        }
        .await;
        if let Err(error) = activation {
            if candidate.config_directory.is_some() {
                self.restore_pointer(
                    config_current,
                    config_previous,
                    old_config_current.as_deref(),
                    old_config_previous.as_deref(),
                )
                .await;
            }
            if assets_changed {
                self.restore_pointer(
                    assets_current,
                    assets_previous,
                    old_assets_current.as_deref(),
                    old_assets_previous.as_deref(),
                )
                .await;
            }
            if core_changed {
                self.restore_pointer(
                    core_current,
                    core_previous,
                    old_core_current.as_deref(),
                    old_core_previous.as_deref(),
                )
                .await;
            }
            let encoded = serde_json::to_vec_pretty(&old_state)
                .map_err(|encode| ManagerError::Io(encode.to_string()))?;
            self.filesystem
                .write_atomic(
                    Path::new("/var/lib/xray-manager/state.json"),
                    &encoded,
                    Some(0o640),
                )
                .await?;
            if had_core {
                let _ = self
                    .run_checked("systemctl", &["restart".into(), "xray.service".into()])
                    .await;
            } else {
                self.run_best_effort(
                    "systemctl",
                    &["stop".into(), "xray-tun-policy.service".into()],
                )
                .await;
                let _ = run_tun_internal(TunInternalAction::PolicyDown, &self.config).await;
            }
            return Err(error);
        }
        if old_state.selected_node_id.is_some() {
            let mut healthy_state = self.existing_state().await?;
            healthy_state.last_successful_healthcheck =
                Some(SystemClock.unix_timestamp().to_string());
            healthy_state.last_rollback_reason = None;
            let encoded = serde_json::to_vec_pretty(&healthy_state)
                .map_err(|error| ManagerError::Io(error.to_string()))?;
            self.filesystem
                .write_atomic(
                    Path::new("/var/lib/xray-manager/state.json"),
                    &encoded,
                    Some(0o640),
                )
                .await?;
        }
        let _ = prune_owned_generations(
            Path::new("/opt/xray-manager/core/versions"),
            Path::new("/opt/xray-manager/core/current"),
            Path::new("/opt/xray-manager/core/previous"),
            self.config.general.keep_core_versions,
        );
        let _ = prune_owned_generations(
            Path::new("/opt/xray-manager/assets/generations"),
            Path::new("/opt/xray-manager/assets/current"),
            Path::new("/opt/xray-manager/assets/previous"),
            self.config.general.keep_asset_generations,
        );
        let _ = prune_owned_generations(
            Path::new("/var/lib/xray-manager/generations"),
            Path::new("/var/lib/xray-manager/current"),
            Path::new("/var/lib/xray-manager/previous"),
            self.config.general.keep_generations,
        );
        Ok(())
    }

    async fn apply_upgrade(&self, target: UpgradeTarget) -> Result<()> {
        if target == UpgradeTarget::Manager {
            return self.upgrade_manager().await;
        }
        let state = self.existing_state().await?;
        let config_dir = Path::new("/var/lib/xray-manager/current/conf.d");
        if !self.filesystem.exists(config_dir).await? {
            return Err(ManagerError::Validation(
                "cannot upgrade before a validated configuration is installed".into(),
            ));
        }
        let mut new_core = None;
        let mut new_assets = None;
        if matches!(target, UpgradeTarget::All | UpgradeTarget::Core) {
            new_core = Some(self.prepare_core().await?);
            if new_core.as_ref().is_some_and(|(version, _, _)| {
                state.current_core_version.as_deref() == Some(version.as_str())
            }) {
                new_core = None;
            }
        }
        if matches!(target, UpgradeTarget::All | UpgradeTarget::Assets) {
            new_assets = Some(self.prepare_assets().await?);
        }
        if new_core.is_none() && new_assets.is_none() {
            return Ok(());
        }
        let core_executable = new_core
            .as_ref()
            .map(|(_, _, executable)| executable.as_path())
            .unwrap_or_else(|| Path::new("/opt/xray-manager/core/current/xray"));
        let asset_directory = new_assets
            .as_ref()
            .map(|(_, directory)| directory.as_path())
            .unwrap_or_else(|| Path::new("/opt/xray-manager/assets/current"));
        self.validate_candidate(core_executable, asset_directory, config_dir)
            .await?;

        let core_current = Path::new("/opt/xray-manager/core/current");
        let core_previous = Path::new("/opt/xray-manager/core/previous");
        let assets_current = Path::new("/opt/xray-manager/assets/current");
        let assets_previous = Path::new("/opt/xray-manager/assets/previous");
        let old_core_current = state
            .current_core_version
            .as_ref()
            .map(|version| Path::new("/opt/xray-manager/core/versions").join(version));
        let old_core_previous = state
            .previous_core_version
            .as_ref()
            .map(|version| Path::new("/opt/xray-manager/core/versions").join(version));
        let old_assets_current = state
            .current_asset_generation
            .as_ref()
            .map(|generation| Path::new("/opt/xray-manager/assets/generations").join(generation));
        let old_assets_previous = state
            .previous_asset_generation
            .as_ref()
            .map(|generation| Path::new("/opt/xray-manager/assets/generations").join(generation));
        if let Some((_, directory, _)) = &new_core {
            self.filesystem
                .switch_generation(core_current, core_previous, directory)
                .await?;
        }
        if let Some((_, directory)) = &new_assets
            && let Err(error) = self
                .filesystem
                .switch_generation(assets_current, assets_previous, directory)
                .await
        {
            if new_core.is_some() {
                let _ = self
                    .filesystem
                    .restore_generation(
                        core_current,
                        core_previous,
                        old_core_current.as_deref(),
                        old_core_previous.as_deref(),
                    )
                    .await;
            }
            return Err(error);
        }
        let mut updated = state.clone();
        if let Some((version, _, _)) = &new_core {
            updated.previous_core_version = updated.current_core_version.take();
            updated.current_core_version = Some(version.clone());
        }
        if let Some((generation, _)) = &new_assets {
            updated.previous_asset_generation = updated.current_asset_generation.take();
            updated.current_asset_generation = Some(generation.clone());
        }
        let encoded = serde_json::to_vec_pretty(&updated)
            .map_err(|error| ManagerError::Io(error.to_string()))?;
        let write_result = self
            .filesystem
            .write_atomic(
                Path::new("/var/lib/xray-manager/state.json"),
                &encoded,
                Some(0o640),
            )
            .await;
        let restart_result = if write_result.is_ok() {
            let restarted = self
                .run_checked("systemctl", &["restart".into(), "xray.service".into()])
                .await;
            if restarted.is_ok() && state.selected_node_id.is_some() {
                self.healthcheck().await
            } else {
                restarted
            }
        } else {
            write_result
        };
        if let Err(error) = restart_result {
            if new_assets.is_some() {
                let _ = self
                    .filesystem
                    .restore_generation(
                        assets_current,
                        assets_previous,
                        old_assets_current.as_deref(),
                        old_assets_previous.as_deref(),
                    )
                    .await;
            }
            if new_core.is_some() {
                let _ = self
                    .filesystem
                    .restore_generation(
                        core_current,
                        core_previous,
                        old_core_current.as_deref(),
                        old_core_previous.as_deref(),
                    )
                    .await;
            }
            let encoded = serde_json::to_vec_pretty(&state)
                .map_err(|encode| ManagerError::Io(encode.to_string()))?;
            self.filesystem
                .write_atomic(
                    Path::new("/var/lib/xray-manager/state.json"),
                    &encoded,
                    Some(0o640),
                )
                .await?;
            let _ = self
                .run_checked("systemctl", &["restart".into(), "xray.service".into()])
                .await;
            return Err(error);
        }
        let _ = prune_owned_generations(
            Path::new("/opt/xray-manager/core/versions"),
            Path::new("/opt/xray-manager/core/current"),
            Path::new("/opt/xray-manager/core/previous"),
            self.config.general.keep_core_versions,
        );
        let _ = prune_owned_generations(
            Path::new("/opt/xray-manager/assets/generations"),
            Path::new("/opt/xray-manager/assets/current"),
            Path::new("/opt/xray-manager/assets/previous"),
            self.config.general.keep_asset_generations,
        );
        Ok(())
    }

    async fn upgrade_manager(&self) -> Result<()> {
        let repository = self
            .config
            .core
            .manager_repository
            .as_deref()
            .ok_or(ManagerError::ManagerReleaseSourceNotConfigured)?;
        let release = self.releases.stable_release(repository).await?;
        let asset = release
            .assets
            .iter()
            .find(|asset| asset.name == "xrayctl-linux-x86_64")
            .ok_or_else(|| {
                ManagerError::Download("manager release has no xrayctl-linux-x86_64 asset".into())
            })?;
        let downloaded = self
            .downloader
            .download(DownloadRequest {
                url: asset.download_url.clone(),
                max_bytes: self.config.general.max_core_archive_size_mb * 1024 * 1024,
                timeout: std::time::Duration::from_secs(
                    self.config.general.request_timeout_seconds,
                ),
                max_redirects: 5,
            })
            .await?;
        if !downloaded.bytes.starts_with(b"\x7fELF") {
            return Err(ManagerError::Download(
                "manager release asset is not an ELF executable".into(),
            ));
        }
        let mut candidate = tempfile::NamedTempFile::new_in("/usr/local/bin")
            .map_err(|error| ManagerError::Io(error.to_string()))?;
        {
            use std::io::Write;
            candidate
                .write_all(&downloaded.bytes)
                .and_then(|()| candidate.as_file().sync_all())
                .map_err(|error| ManagerError::Io(error.to_string()))?;
        }
        std::fs::set_permissions(candidate.path(), std::fs::Permissions::from_mode(0o755))
            .map_err(|error| ManagerError::Io(error.to_string()))?;
        let version = self
            .runner
            .run(&candidate.path().to_string_lossy(), &["--version".into()])
            .await?;
        if version.status != 0 {
            return Err(ManagerError::Validation(format!(
                "candidate manager failed --version: {}",
                version.stderr.trim()
            )));
        }
        let destination = Path::new("/usr/local/bin/xrayctl");
        let previous = Path::new("/usr/local/bin/xrayctl.previous");
        let old_binary = self.filesystem.read(destination).await?;
        self.filesystem
            .write_atomic(previous, &old_binary, Some(0o755))
            .await?;
        self.filesystem
            .write_atomic(destination, &downloaded.bytes, Some(0o755))
            .await?;
        let doctor = self
            .runner
            .run(
                "/usr/local/bin/xrayctl",
                &["--json".into(), "doctor".into(), "--quick".into()],
            )
            .await?;
        if doctor.status != 0 {
            self.filesystem
                .write_atomic(destination, &old_binary, Some(0o755))
                .await?;
            return Err(ManagerError::Validation(format!(
                "new manager failed doctor --quick and was rolled back: {}",
                doctor.stderr.trim()
            )));
        }
        Ok(())
    }

    async fn apply_install_actions(&self, plan: &ExecutionPlan) -> Result<Vec<String>> {
        std::fs::create_dir_all("/var/lib/xray-manager")
            .map_err(|error| ManagerError::Io(error.to_string()))?;
        std::fs::set_permissions(
            "/var/lib/xray-manager",
            std::fs::Permissions::from_mode(0o750),
        )
        .map_err(|error| ManagerError::Io(error.to_string()))?;
        let mut created_identities = self.ensure_identities().await?;
        for action in &plan.actions {
            match action {
                PlanAction::EnsureDirectory { path, mode } => {
                    std::fs::create_dir_all(path)
                        .map_err(|error| ManagerError::Io(error.to_string()))?;
                    std::fs::set_permissions(path, std::fs::Permissions::from_mode(*mode))
                        .map_err(|error| ManagerError::Io(error.to_string()))?;
                }
                PlanAction::WriteFile {
                    path, description, ..
                } if description == "xray.service" => {
                    self.filesystem
                        .write_atomic(path, templates::xray_service().as_bytes(), Some(0o644))
                        .await?;
                }
                PlanAction::AddIdentityToGroup { identity, group } => {
                    validate_identity_name(identity)?;
                    validate_identity_name(group)?;
                    let memberships = self
                        .runner
                        .run("id", &["-nG".into(), identity.clone()])
                        .await?;
                    if memberships.status != 0 {
                        return Err(ManagerError::Other(format!(
                            "id failed: {}",
                            memberships.stderr.trim()
                        )));
                    }
                    let already_member = memberships
                        .stdout
                        .split_whitespace()
                        .any(|existing| existing == group);
                    self.run_checked(
                        "usermod",
                        &[
                            "--append".into(),
                            "--groups".into(),
                            group.clone(),
                            identity.clone(),
                        ],
                    )
                    .await?;
                    if !already_member {
                        let membership = format!("membership:{identity}:{group}");
                        self.record_created_identity(&membership).await?;
                        created_identities.push(membership);
                    }
                }
                PlanAction::WriteFile {
                    path, description, ..
                } if description == "xray-tun-policy.service" => {
                    self.filesystem
                        .write_atomic(
                            path,
                            templates::tun_policy_service().as_bytes(),
                            Some(0o644),
                        )
                        .await?;
                }
                PlanAction::RequirePackages { .. }
                | PlanAction::DownloadArtifact { .. }
                | PlanAction::RunHealthcheck { .. } => {}
                _ => {}
            }
        }
        self.install_self_and_defaults().await?;
        self.run_checked(
            "chown",
            &[
                "-R".into(),
                "root:xray-manager".into(),
                "/etc/xray-manager".into(),
                "/var/lib/xray-manager".into(),
                "/var/cache/xray-manager".into(),
                "/var/log/xray-manager".into(),
            ],
        )
        .await?;
        let generations = Path::new("/var/lib/xray-manager/generations");
        if generations.exists() {
            self.run_checked(
                "chown",
                &[
                    "-R".into(),
                    "xray:xray".into(),
                    generations.to_string_lossy().into_owned(),
                ],
            )
            .await?;
        }
        for directory in [
            "/etc/xray-manager",
            "/etc/xray-manager/apps.d",
            "/etc/xray-manager/fragments.d",
            "/var/lib/xray-manager",
            "/var/cache/xray-manager",
            "/var/log/xray-manager",
        ] {
            if Path::new(directory).exists() {
                std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o2750))
                    .map_err(|error| ManagerError::Io(error.to_string()))?;
            }
        }
        let subscriptions = Path::new("/etc/xray-manager/subscriptions.d");
        if subscriptions.exists() {
            self.run_checked(
                "chown",
                &[
                    "-R".into(),
                    "root:root".into(),
                    subscriptions.to_string_lossy().into_owned(),
                ],
            )
            .await?;
            std::fs::set_permissions(subscriptions, std::fs::Permissions::from_mode(0o700))
                .map_err(|error| ManagerError::Io(error.to_string()))?;
            for entry in std::fs::read_dir(subscriptions)
                .map_err(|error| ManagerError::Io(error.to_string()))?
            {
                let entry = entry.map_err(|error| ManagerError::Io(error.to_string()))?;
                if entry
                    .file_type()
                    .map_err(|error| ManagerError::Io(error.to_string()))?
                    .is_file()
                {
                    std::fs::set_permissions(entry.path(), std::fs::Permissions::from_mode(0o600))
                        .map_err(|error| ManagerError::Io(error.to_string()))?;
                }
            }
        }
        Ok(created_identities)
    }

    async fn apply_removal(&self, plan: &ExecutionPlan) -> Result<()> {
        let identities = if plan.operation == "purge" {
            serde_json::from_slice::<ManagerState>(
                &self
                    .filesystem
                    .read(Path::new("/var/lib/xray-manager/state.json"))
                    .await
                    .unwrap_or_default(),
            )
            .map(|state| state.created_identities)
            .unwrap_or_default()
        } else {
            Vec::new()
        };
        for unit in ["xray.service", "xray-tun-policy.service"] {
            self.run_best_effort("systemctl", &["stop".into(), unit.into()])
                .await;
            self.run_best_effort("systemctl", &["disable".into(), unit.into()])
                .await;
        }
        let _ = run_tun_internal(TunInternalAction::PolicyDown, &self.config).await;
        for path in [
            "/etc/systemd/system/xray.service",
            "/etc/systemd/system/xray-tun-policy.service",
            "/usr/local/bin/xrayctl",
            "/usr/local/bin/xrayctl.previous",
        ] {
            match std::fs::remove_file(path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(ManagerError::Io(error.to_string())),
            }
        }
        if plan.operation == "purge" {
            for path in [
                "/etc/xray-manager",
                "/var/lib/xray-manager",
                "/var/cache/xray-manager",
                "/var/log/xray-manager",
                "/opt/xray-manager",
            ] {
                match std::fs::remove_dir_all(path) {
                    Ok(()) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => return Err(ManagerError::Io(error.to_string())),
                }
            }
            for identity in &identities {
                if let Some(membership) = identity.strip_prefix("membership:") {
                    let mut parts = membership.split(':');
                    if let (Some(user), Some(group), None) =
                        (parts.next(), parts.next(), parts.next())
                    {
                        self.run_best_effort(
                            "gpasswd",
                            &["--delete".into(), user.into(), group.into()],
                        )
                        .await;
                    }
                }
            }
            if identities.iter().any(|identity| identity == "user:xray") {
                self.run_best_effort("userdel", &["xray".into()]).await;
            }
            for group in ["xray-tun", "xray-manager", "xray"] {
                if identities
                    .iter()
                    .any(|identity| identity == &format!("group:{group}"))
                    && !self.group_has_members(group).await
                {
                    self.run_best_effort("groupdel", &[group.into()]).await;
                }
            }
        }
        self.run_checked("systemctl", &["daemon-reload".into()])
            .await
    }
}

#[async_trait]
impl PlatformInstaller for ArchInstaller {
    async fn plan_install(&self, config: &ManagerConfig) -> Result<ExecutionPlan> {
        let mut backend_ids = self
            .installed_backends
            .iter()
            .filter_map(|(capability, id)| {
                serde_json::from_value::<Capability>(serde_json::Value::String(capability.clone()))
                    .ok()
                    .map(|capability| (capability, id.clone()))
            })
            .collect::<BTreeMap<_, _>>();
        backend_ids
            .entry(Capability::Install)
            .or_insert_with(|| "arch".into());
        backend_ids
            .entry(Capability::Service)
            .or_insert_with(|| "systemd".into());
        Ok(ExecutionPlan {
            operation: "install".into(),
            backend_ids,
            actions: vec![
                PlanAction::EnsureGroup {
                    name: "xray".into(),
                },
                PlanAction::EnsureGroup {
                    name: "xray-manager".into(),
                },
                PlanAction::EnsureGroup {
                    name: "xray-tun".into(),
                },
                PlanAction::EnsureIdentity {
                    name: "xray".into(),
                    system: true,
                },
                PlanAction::EnsureDirectory {
                    path: "/etc/xray-manager".into(),
                    mode: 0o2750,
                },
                PlanAction::EnsureDirectory {
                    path: "/etc/xray-manager/subscriptions.d".into(),
                    mode: 0o700,
                },
                PlanAction::EnsureDirectory {
                    path: "/etc/xray-manager/apps.d".into(),
                    mode: 0o2750,
                },
                PlanAction::EnsureDirectory {
                    path: "/etc/xray-manager/fragments.d".into(),
                    mode: 0o2750,
                },
                PlanAction::EnsureDirectory {
                    path: "/var/lib/xray-manager".into(),
                    mode: 0o2750,
                },
                PlanAction::EnsureDirectory {
                    path: "/var/lib/xray-manager/generations".into(),
                    mode: 0o750,
                },
                PlanAction::EnsureDirectory {
                    path: "/var/lib/xray-manager/backups".into(),
                    mode: 0o750,
                },
                PlanAction::EnsureDirectory {
                    path: "/var/cache/xray-manager/downloads".into(),
                    mode: 0o2750,
                },
                PlanAction::EnsureDirectory {
                    path: "/var/log/xray-manager".into(),
                    mode: 0o2750,
                },
                PlanAction::EnsureDirectory {
                    path: "/run/xray-manager".into(),
                    mode: 0o750,
                },
                PlanAction::EnsureDirectory {
                    path: "/opt/xray-manager/core/versions".into(),
                    mode: 0o755,
                },
                PlanAction::EnsureDirectory {
                    path: "/opt/xray-manager/core/staging".into(),
                    mode: 0o755,
                },
                PlanAction::EnsureDirectory {
                    path: "/opt/xray-manager/assets/generations".into(),
                    mode: 0o755,
                },
                PlanAction::WriteFile {
                    path: "/etc/systemd/system/xray.service".into(),
                    mode: 0o644,
                    description: "xray.service".into(),
                },
                PlanAction::WriteFile {
                    path: "/etc/systemd/system/xray-tun-policy.service".into(),
                    mode: 0o644,
                    description: "xray-tun-policy.service".into(),
                },
                PlanAction::DownloadArtifact {
                    id: "xray-core".into(),
                    destination: "/opt/xray-manager/core/versions".into(),
                },
                PlanAction::DownloadArtifact {
                    id: "assets".into(),
                    destination: "/opt/xray-manager/assets/generations".into(),
                },
                PlanAction::RunHealthcheck {
                    url: config.general.healthcheck_url.clone(),
                },
            ],
        })
    }

    async fn apply(&self, plan: &ExecutionPlan) -> Result<()> {
        if matches!(plan.operation.as_str(), "uninstall" | "purge") {
            return self.apply_removal(plan).await;
        }

        if let Some(target) = match plan.operation.as_str() {
            "upgrade_all" => Some(UpgradeTarget::All),
            "upgrade_core" => Some(UpgradeTarget::Core),
            "upgrade_assets" => Some(UpgradeTarget::Assets),
            "upgrade_manager" => Some(UpgradeTarget::Manager),
            _ => None,
        } {
            return self.apply_upgrade(target).await;
        }

        let created_identities = self.apply_install_actions(plan).await?;
        if matches!(plan.operation.as_str(), "install" | "repair") {
            let existing = self.existing_state().await?;
            let (core_version, core_directory, core) = if plan.operation == "repair" {
                match self.reusable_core(&existing).await? {
                    Some(current) => current,
                    None => self.prepare_core().await?,
                }
            } else {
                self.prepare_core().await?
            };
            let (asset_generation, assets) = if plan.operation == "repair" {
                match self.reusable_assets(&existing).await? {
                    Some(current) => current,
                    None => self.prepare_assets().await?,
                }
            } else {
                self.prepare_assets().await?
            };
            let existing_config = Path::new("/var/lib/xray-manager/current/conf.d");
            let (config_generation, config_directory) = if existing
                .current_config_generation
                .is_some()
                && self.filesystem.exists(existing_config).await?
            {
                self.validate_candidate(&core, &assets, existing_config)
                    .await?;
                (existing.current_config_generation.unwrap_or_default(), None)
            } else {
                let (generation, directory) = self.prepare_initial_config(&core, &assets).await?;
                (generation, Some(directory))
            };
            self.activate_install(
                PreparedInstall {
                    core_version,
                    core_directory,
                    asset_generation,
                    asset_directory: assets,
                    config_generation,
                    config_directory,
                },
                created_identities,
            )
            .await?;
        }
        Ok(())
    }

    async fn plan_repair(&self, config: &ManagerConfig) -> Result<ExecutionPlan> {
        let mut plan = self.plan_install(config).await?;
        plan.operation = "repair".into();
        Ok(plan)
    }

    async fn plan_uninstall(&self, purge: bool) -> Result<ExecutionPlan> {
        let mut actions = vec![
            PlanAction::StopService {
                name: "xray.service".into(),
            },
            PlanAction::StopService {
                name: "xray-tun-policy.service".into(),
            },
            PlanAction::RemoveService {
                name: "xray.service".into(),
            },
            PlanAction::RemoveService {
                name: "xray-tun-policy.service".into(),
            },
            PlanAction::RemoveOwnedPath {
                path: "/usr/local/bin/xrayctl".into(),
            },
            PlanAction::RemoveOwnedPath {
                path: "/usr/local/bin/xrayctl.previous".into(),
            },
        ];
        if purge {
            actions.extend(
                [
                    "/etc/xray-manager",
                    "/var/lib/xray-manager",
                    "/var/cache/xray-manager",
                    "/var/log/xray-manager",
                    "/opt/xray-manager",
                ]
                .into_iter()
                .map(|path| PlanAction::RemoveOwnedPath { path: path.into() }),
            );
        }
        Ok(ExecutionPlan {
            operation: if purge { "purge" } else { "uninstall" }.into(),
            backend_ids: [(Capability::Install, "arch".into())].into_iter().collect(),
            actions,
        })
    }

    async fn plan_upgrade(
        &self,
        _config: &ManagerConfig,
        target: UpgradeTarget,
    ) -> Result<ExecutionPlan> {
        let mut actions = Vec::new();
        if matches!(target, UpgradeTarget::All | UpgradeTarget::Core) {
            actions.push(PlanAction::DownloadArtifact {
                id: "xray-core".into(),
                destination: "/opt/xray-manager/core/versions".into(),
            });
        }
        if matches!(target, UpgradeTarget::All | UpgradeTarget::Assets) {
            actions.push(PlanAction::DownloadArtifact {
                id: "assets".into(),
                destination: "/opt/xray-manager/assets/generations".into(),
            });
        }
        if target == UpgradeTarget::Manager {
            if self.config.core.manager_repository.is_none() {
                return Err(ManagerError::ManagerReleaseSourceNotConfigured);
            }
            actions.push(PlanAction::DownloadArtifact {
                id: "xray-manager".into(),
                destination: "/usr/local/bin/xrayctl".into(),
            });
        }
        actions.push(PlanAction::RestartService {
            name: "xray.service".into(),
        });
        Ok(ExecutionPlan {
            operation: match target {
                UpgradeTarget::All => "upgrade_all",
                UpgradeTarget::Core => "upgrade_core",
                UpgradeTarget::Assets => "upgrade_assets",
                UpgradeTarget::Manager => "upgrade_manager",
            }
            .into(),
            backend_ids: self
                .installed_backends
                .iter()
                .filter_map(|(capability, id)| {
                    serde_json::from_value::<Capability>(serde_json::Value::String(
                        capability.clone(),
                    ))
                    .ok()
                    .map(|capability| (capability, id.clone()))
                })
                .collect(),
            actions,
        })
    }
}

fn unique_generation() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static GENERATION_COUNTER: AtomicU64 = AtomicU64::new(0);
    format!(
        "{}-{}-{}",
        SystemClock.unix_timestamp(),
        std::process::id(),
        GENERATION_COUNTER.fetch_add(1, Ordering::Relaxed)
    )
}

fn validate_generation_name(value: &str) -> Result<()> {
    if value.is_empty()
        || !value.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '.' | '-' | '_')
        })
    {
        return Err(ManagerError::Download(
            "release tag cannot be used as a generation name".into(),
        ));
    }
    Ok(())
}

fn validate_identity_name(value: &str) -> Result<()> {
    if value.is_empty()
        || !value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_'))
    {
        return Err(ManagerError::InvalidConfig(
            "invalid Linux user or group name".into(),
        ));
    }
    Ok(())
}

fn prune_owned_generations(
    root: &Path,
    current: &Path,
    previous: &Path,
    keep: usize,
) -> Result<()> {
    let entries = match std::fs::read_dir(root) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(ManagerError::Io(error.to_string())),
    };
    let mut protected = [
        std::fs::read_link(current).ok(),
        std::fs::read_link(previous).ok(),
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
                .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
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
        std::fs::remove_dir_all(&path).map_err(|error| ManagerError::Io(error.to_string()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn installer() -> ArchInstaller {
        ArchInstaller::new(ManagerConfig::default(), &[]).expect("installer")
    }

    #[tokio::test]
    async fn install_plan_is_semantic_and_contains_no_shell_commands() {
        let plan = installer()
            .plan_install(&ManagerConfig::default())
            .await
            .expect("install plan");
        assert!(!plan.actions.is_empty());
        let json = serde_json::to_string(&plan).expect("plan JSON");
        assert!(!json.contains("systemctl "));
        assert!(!json.contains("nft "));
        assert!(!json.contains("ip rule"));
        assert!(plan.actions.iter().any(|action| {
            matches!(
                action,
                PlanAction::EnsureDirectory { path, mode }
                    if path == Path::new("/etc/xray-manager") && *mode == 0o2750
            )
        }));
        assert!(plan.actions.iter().any(|action| {
            matches!(
                action,
                PlanAction::EnsureDirectory { path, mode }
                    if path == Path::new("/var/log/xray-manager") && *mode == 0o2750
            )
        }));
    }

    #[tokio::test]
    async fn manager_upgrade_requires_a_release_source() {
        let result = installer()
            .plan_upgrade(&ManagerConfig::default(), UpgradeTarget::Manager)
            .await;
        assert!(matches!(
            result,
            Err(ManagerError::ManagerReleaseSourceNotConfigured)
        ));
    }
}
