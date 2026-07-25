use async_trait::async_trait;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use xray_manager_core::config::ManagerConfig;
use xray_manager_core::domain::Node;
use xray_manager_core::events::ManagerEvent;
use xray_manager_core::ports::{
    Clock, DownloadRequest, DownloadedArtifact, Downloader, EventSink, ExecutionPlan, FileSystem,
    IdentityManager, LayoutProvider, ManagerPaths, PackageAdvisor, PlanAction, PlatformInstaller,
    PrivilegeChecker, ProbeResult, ServiceManager, TunManager, UpgradeTarget, XrayRunner,
    XrayTestRequest,
};
use xray_manager_core::{ManagerError, Result};

#[derive(Debug, Clone, Default)]
pub struct FakeEventSink(pub Arc<Mutex<Vec<ManagerEvent>>>);

impl EventSink for FakeEventSink {
    fn emit(&self, event: ManagerEvent) {
        if let Ok(mut events) = self.0.lock() {
            events.push(event);
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct FakeClock(pub i64);

impl Clock for FakeClock {
    fn unix_timestamp(&self) -> i64 {
        self.0
    }
}

#[derive(Debug, Clone)]
pub struct FakeLayout(pub ManagerPaths);

#[async_trait]
impl LayoutProvider for FakeLayout {
    async fn paths(&self) -> Result<ManagerPaths> {
        Ok(self.0.clone())
    }
}

#[derive(Debug, Clone, Default)]
pub struct FakeIdentityManager;

#[async_trait]
impl IdentityManager for FakeIdentityManager {
    async fn ensure_system_identity(&self, _user: &str, _groups: &[String]) -> Result<()> {
        Ok(())
    }

    async fn set_ownership(
        &self,
        _path: &Path,
        _user: &str,
        _group: &str,
        _recursive: bool,
    ) -> Result<()> {
        Ok(())
    }
}

#[derive(Debug, Clone, Default)]
pub struct FakePackageAdvisor;

#[async_trait]
impl PackageAdvisor for FakePackageAdvisor {
    async fn missing_requirements(&self) -> Result<Vec<String>> {
        Ok(Vec::new())
    }

    fn packages_for(&self, requirements: &[String]) -> Vec<String> {
        requirements.to_vec()
    }

    fn install_hint(&self, packages: &[String]) -> Option<String> {
        (!packages.is_empty()).then(|| format!("install {}", packages.join(" ")))
    }
}

#[derive(Debug, Clone, Default)]
pub struct FakePrivilegeChecker;

#[async_trait]
impl PrivilegeChecker for FakePrivilegeChecker {
    async fn is_elevated(&self) -> Result<bool> {
        Ok(true)
    }
}

#[derive(Debug, Clone, Default)]
pub struct FakeDownloader {
    pub responses: Arc<Mutex<BTreeMap<String, Vec<u8>>>>,
}

#[async_trait]
impl Downloader for FakeDownloader {
    async fn download(&self, request: DownloadRequest) -> Result<DownloadedArtifact> {
        let bytes = self
            .responses
            .lock()
            .map_err(|_| ManagerError::Download("fake downloader lock poisoned".into()))?
            .get(&request.url)
            .cloned()
            .ok_or_else(|| ManagerError::Download("no fake response configured".into()))?;
        if bytes.len() as u64 > request.max_bytes {
            return Err(ManagerError::Download("size limit exceeded".into()));
        }
        Ok(DownloadedArtifact {
            bytes,
            final_url: request.url,
            content_type: None,
        })
    }
}

#[derive(Debug, Clone, Default)]
pub struct FakeFileSystem {
    files: Arc<Mutex<BTreeMap<PathBuf, Vec<u8>>>>,
    generations: Arc<Mutex<BTreeMap<PathBuf, PathBuf>>>,
    lock_count: Arc<AtomicUsize>,
}

impl FakeFileSystem {
    pub fn contents(&self, path: &Path) -> Option<Vec<u8>> {
        self.files.lock().ok()?.get(path).cloned()
    }

    pub fn lock_count(&self) -> usize {
        self.lock_count.load(Ordering::Relaxed)
    }
}

#[async_trait]
impl FileSystem for FakeFileSystem {
    async fn acquire_lock(
        &self,
        _path: &Path,
    ) -> Result<Box<dyn xray_manager_core::ports::FileLockGuard>> {
        self.lock_count.fetch_add(1, Ordering::Relaxed);
        struct FakeLockGuard;
        impl xray_manager_core::ports::FileLockGuard for FakeLockGuard {}
        Ok(Box::new(FakeLockGuard))
    }

    async fn read(&self, path: &Path) -> Result<Vec<u8>> {
        self.contents(path)
            .ok_or_else(|| ManagerError::Io(format!("{} not found", path.display())))
    }

    async fn list_files(&self, path: &Path) -> Result<Vec<PathBuf>> {
        let mut paths: Vec<_> = self
            .files
            .lock()
            .map_err(|_| ManagerError::Io("fake filesystem lock poisoned".into()))?
            .keys()
            .filter(|candidate| candidate.parent() == Some(path))
            .cloned()
            .collect();
        paths.sort();
        Ok(paths)
    }

    async fn write_atomic(&self, path: &Path, bytes: &[u8], _mode: Option<u32>) -> Result<()> {
        self.files
            .lock()
            .map_err(|_| ManagerError::Io("fake filesystem lock poisoned".into()))?
            .insert(path.to_owned(), bytes.to_vec());
        Ok(())
    }

    async fn create_dir_all(&self, _path: &Path) -> Result<()> {
        Ok(())
    }

    async fn set_permissions(&self, _path: &Path, _mode: u32) -> Result<()> {
        Ok(())
    }

    async fn exists(&self, path: &Path) -> Result<bool> {
        Ok(self
            .files
            .lock()
            .map_err(|_| ManagerError::Io("fake filesystem lock poisoned".into()))?
            .contains_key(path))
    }

    async fn remove_owned(&self, path: &Path, root: &Path) -> Result<()> {
        if !path.starts_with(root) || path == root {
            return Err(ManagerError::Io("unsafe fake removal".into()));
        }
        self.files
            .lock()
            .map_err(|_| ManagerError::Io("fake filesystem lock poisoned".into()))?
            .retain(|candidate, _| !candidate.starts_with(path));
        Ok(())
    }

    async fn switch_generation(
        &self,
        current: &Path,
        previous: &Path,
        target: &Path,
    ) -> Result<()> {
        let mut generations = self
            .generations
            .lock()
            .map_err(|_| ManagerError::Io("fake generation lock poisoned".into()))?;
        if let Some(old) = generations.get(current).cloned() {
            generations.insert(previous.to_owned(), old);
        }
        generations.insert(current.to_owned(), target.to_owned());
        Ok(())
    }

    async fn rollback_generation(&self, current: &Path, previous: &Path) -> Result<()> {
        let mut generations = self
            .generations
            .lock()
            .map_err(|_| ManagerError::Io("fake generation lock poisoned".into()))?;
        let current_target = generations
            .get(current)
            .cloned()
            .ok_or_else(|| ManagerError::Io("current generation is missing".into()))?;
        let previous_target = generations
            .get(previous)
            .cloned()
            .ok_or_else(|| ManagerError::Io("previous generation is missing".into()))?;
        generations.insert(current.to_owned(), previous_target);
        generations.insert(previous.to_owned(), current_target);
        Ok(())
    }

    async fn restore_generation(
        &self,
        current: &Path,
        previous: &Path,
        current_target: Option<&Path>,
        previous_target: Option<&Path>,
    ) -> Result<()> {
        let mut generations = self
            .generations
            .lock()
            .map_err(|_| ManagerError::Io("fake generation lock poisoned".into()))?;
        if let Some(target) = current_target {
            generations.insert(current.to_owned(), target.to_owned());
        } else {
            generations.remove(current);
        }
        if let Some(target) = previous_target {
            generations.insert(previous.to_owned(), target.to_owned());
        } else {
            generations.remove(previous);
        }
        Ok(())
    }

    async fn prune_generations(
        &self,
        _root: &Path,
        _current: &Path,
        _previous: &Path,
        _keep: usize,
    ) -> Result<()> {
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct FakeXrayRunner {
    pub version: String,
    pub validation_error: Option<String>,
    pub probes: Arc<Mutex<BTreeMap<String, ProbeResult>>>,
}

impl Default for FakeXrayRunner {
    fn default() -> Self {
        Self {
            version: "Xray 0.0-test".into(),
            validation_error: None,
            probes: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }
}

#[async_trait]
impl XrayRunner for FakeXrayRunner {
    async fn version(&self, _executable: &Path) -> Result<String> {
        Ok(self.version.clone())
    }

    async fn test_config(&self, _request: &XrayTestRequest) -> Result<()> {
        self.validation_error
            .as_ref()
            .map_or(Ok(()), |error| Err(ManagerError::Validation(error.clone())))
    }

    async fn probe(&self, node: &Node, _config: &ManagerConfig) -> Result<ProbeResult> {
        self.probes
            .lock()
            .map_err(|_| ManagerError::Other("fake probe lock poisoned".into()))?
            .get(node.id.as_str())
            .cloned()
            .ok_or_else(|| ManagerError::Other("no fake probe result configured".into()))
    }

    async fn healthcheck(&self, _config: &ManagerConfig) -> Result<()> {
        Ok(())
    }
}

#[derive(Debug, Clone, Default)]
pub struct FakeServiceManager {
    active: Arc<Mutex<bool>>,
}

#[derive(Debug, Clone, Default)]
pub struct FakeTunManager {
    active: Arc<Mutex<bool>>,
}

impl FakeTunManager {
    pub fn set_active(&self, active: bool) -> Result<()> {
        *self
            .active
            .lock()
            .map_err(|_| ManagerError::Other("fake TUN lock poisoned".into()))? = active;
        Ok(())
    }
}

#[async_trait]
impl TunManager for FakeTunManager {
    async fn status(&self, _interface: &str) -> Result<bool> {
        self.active
            .lock()
            .map(|active| *active)
            .map_err(|_| ManagerError::Other("fake TUN lock poisoned".into()))
    }
}

#[async_trait]
impl ServiceManager for FakeServiceManager {
    async fn enable(&self, _service: &str) -> Result<()> {
        Ok(())
    }
    async fn disable(&self, _service: &str) -> Result<()> {
        Ok(())
    }
    async fn start(&self, _service: &str) -> Result<()> {
        *self
            .active
            .lock()
            .map_err(|_| ManagerError::Other("fake service lock poisoned".into()))? = true;
        Ok(())
    }
    async fn stop(&self, _service: &str) -> Result<()> {
        *self
            .active
            .lock()
            .map_err(|_| ManagerError::Other("fake service lock poisoned".into()))? = false;
        Ok(())
    }
    async fn restart(&self, service: &str) -> Result<()> {
        self.stop(service).await?;
        self.start(service).await
    }
    async fn is_active(&self, _service: &str) -> Result<bool> {
        Ok(*self
            .active
            .lock()
            .map_err(|_| ManagerError::Other("fake service lock poisoned".into()))?)
    }
    async fn logs(&self, _service: &str, _lines: usize) -> Result<String> {
        Ok("fake service log".into())
    }
}

#[derive(Debug, Clone)]
pub struct FakeInstaller {
    pub paths: ManagerPaths,
    pub apply_error: Option<String>,
    pub apply_count: Arc<AtomicUsize>,
}

impl Default for FakeInstaller {
    fn default() -> Self {
        Self {
            paths: ManagerPaths {
                config_dir: "/etc/xray-manager".into(),
                state_dir: "/var/lib/xray-manager".into(),
                cache_dir: "/var/cache/xray-manager".into(),
                runtime_dir: "/run/xray-manager".into(),
                install_dir: "/opt/xray-manager".into(),
                executable: "/usr/local/bin/xrayctl".into(),
            },
            apply_error: None,
            apply_count: Arc::new(AtomicUsize::new(0)),
        }
    }
}

#[async_trait]
impl PlatformInstaller for FakeInstaller {
    async fn plan_install(&self, config: &ManagerConfig) -> Result<ExecutionPlan> {
        Ok(ExecutionPlan {
            operation: "install".into(),
            backend_ids: BTreeMap::new(),
            actions: vec![
                PlanAction::EnsureIdentity {
                    name: "xray".into(),
                    system: true,
                },
                PlanAction::EnsureDirectory {
                    path: self.paths.config_dir.clone(),
                    mode: 0o750,
                },
                PlanAction::RunHealthcheck {
                    url: config.general.healthcheck_url.clone(),
                },
            ],
        })
    }
    async fn apply(&self, _plan: &ExecutionPlan) -> Result<()> {
        self.apply_count.fetch_add(1, Ordering::Relaxed);
        self.apply_error
            .as_ref()
            .map_or(Ok(()), |error| Err(ManagerError::Other(error.clone())))
    }
    async fn plan_repair(&self, config: &ManagerConfig) -> Result<ExecutionPlan> {
        let mut plan = self.plan_install(config).await?;
        plan.operation = "repair".into();
        Ok(plan)
    }
    async fn plan_uninstall(&self, purge: bool) -> Result<ExecutionPlan> {
        Ok(ExecutionPlan {
            operation: if purge { "purge" } else { "uninstall" }.into(),
            backend_ids: BTreeMap::new(),
            actions: if purge {
                vec![PlanAction::RemoveOwnedPath {
                    path: self.paths.config_dir.clone(),
                }]
            } else {
                Vec::new()
            },
        })
    }
    async fn plan_upgrade(
        &self,
        _config: &ManagerConfig,
        target: UpgradeTarget,
    ) -> Result<ExecutionPlan> {
        Ok(ExecutionPlan {
            operation: match target {
                UpgradeTarget::All => "upgrade_all",
                UpgradeTarget::Core => "upgrade_core",
                UpgradeTarget::Assets => "upgrade_assets",
                UpgradeTarget::Manager => "upgrade_manager",
            }
            .into(),
            backend_ids: BTreeMap::new(),
            actions: vec![PlanAction::DownloadArtifact {
                id: "fake-upgrade".into(),
                destination: self.paths.install_dir.clone(),
            }],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::unsupported::UnsupportedPlatform;
    use std::sync::atomic::AtomicBool;
    use xray_manager_core::ManagerService;
    use xray_manager_core::application::{Operation, OperationOptions, Query};
    use xray_manager_core::domain::ManagerState;
    use xray_manager_core::generation::GenerationService;
    use xray_manager_core::ports::{BackendSet, Capability, CapabilityStatus};
    use xray_manager_core::probe::probe_all;
    use xray_manager_core::protocols::parse_uri;

    #[tokio::test]
    async fn generation_is_not_switched_when_validation_fails() {
        let filesystem = FakeFileSystem::default();
        let runner = FakeXrayRunner {
            validation_error: Some("bad config".into()),
            ..FakeXrayRunner::default()
        };
        let service = GenerationService::new(
            filesystem.clone(),
            runner,
            FakeClock(42),
            FakeEventSink::default(),
        );
        let result = service
            .apply(
                Path::new("/generations"),
                Path::new("/current"),
                Path::new("/previous"),
                "/xray".into(),
                "/assets".into(),
                &[("00.json".into(), b"{}".to_vec())],
            )
            .await;
        assert!(result.is_err());
        assert!(
            !filesystem
                .generations
                .lock()
                .expect("generation lock")
                .contains_key(Path::new("/current"))
        );
    }

    #[tokio::test]
    async fn generation_switches_after_validation() {
        let filesystem = FakeFileSystem::default();
        let service = GenerationService::new(
            filesystem.clone(),
            FakeXrayRunner::default(),
            FakeClock(42),
            FakeEventSink::default(),
        );
        let candidate = service
            .apply(
                Path::new("/generations"),
                Path::new("/current"),
                Path::new("/previous"),
                "/xray".into(),
                "/assets".into(),
                &[("00.json".into(), b"{}".to_vec())],
            )
            .await
            .expect("generation should apply");
        assert_eq!(candidate, PathBuf::from("/generations/42-0"));
    }

    fn test_paths() -> ManagerPaths {
        ManagerPaths {
            config_dir: "/config".into(),
            state_dir: "/state".into(),
            cache_dir: "/cache".into(),
            runtime_dir: "/run".into(),
            install_dir: "/opt".into(),
            executable: "/bin/xrayctl".into(),
        }
    }

    fn test_capabilities() -> Vec<CapabilityStatus> {
        [
            Capability::Install,
            Capability::PackageAdvice,
            Capability::Identity,
            Capability::Service,
            Capability::Tun,
            Capability::Firewall,
            Capability::PolicyRouting,
            Capability::AppRunner,
            Capability::MountIsolation,
            Capability::DesktopProxy,
        ]
        .into_iter()
        .map(|capability| CapabilityStatus {
            capability,
            supported: true,
            backend_id: Some("fake".into()),
            reason: None,
        })
        .collect()
    }

    #[tokio::test]
    async fn subscription_refresh_uses_injected_downloader_and_redacts_url() {
        let filesystem = FakeFileSystem::default();
        let downloader = FakeDownloader::default();
        downloader
            .responses
            .lock()
            .expect("fake downloader")
            .insert(
                "https://secret.example/sub".into(),
                b"vless://123e4567-e89b-12d3-a456-426614174000@example.com:443#Node".to_vec(),
            );
        let installer = FakeInstaller::default();
        let unsupported = UnsupportedPlatform {
            platform: "test".into(),
        };
        let service = ManagerService::new(
            ManagerConfig::default(),
            ManagerState::default(),
            BackendSet {
                selections: Vec::new(),
                capabilities: test_capabilities(),
                layout: FakeLayout(test_paths()),
                installer,
                package_advisor: FakePackageAdvisor,
                identity: FakeIdentityManager,
                service: FakeServiceManager::default(),
                firewall: unsupported.clone(),
                policy_routing: unsupported.clone(),
                tun: FakeTunManager::default(),
                app_runner: unsupported.clone(),
                mount_isolation: unsupported.clone(),
                desktop_proxy: unsupported.clone(),
                privilege: FakePrivilegeChecker,
                inspector: unsupported.clone(),
                xray: FakeXrayRunner::default(),
                events: FakeEventSink::default(),
                filesystem: filesystem.clone(),
                downloader,
                clock: FakeClock(42),
            }
            .erase(),
        );
        service
            .execute(
                Operation::SubscriptionAdd {
                    name: "main".into(),
                    url: "https://secret.example/sub".into(),
                },
                OperationOptions::default(),
            )
            .await
            .expect("subscription add");
        service
            .execute(
                Operation::SubscriptionRefresh { name: None },
                OperationOptions::default(),
            )
            .await
            .expect("subscription refresh");
        let nodes = service.query(Query::Nodes).await.expect("nodes query");
        assert_eq!(nodes.as_array().map(Vec::len), Some(1));
        let id = nodes
            .get(0)
            .and_then(|node| node.get("id"))
            .and_then(serde_json::Value::as_str)
            .expect("public node ID");
        service
            .execute(
                Operation::NodeSelect { id: id.into() },
                OperationOptions::default(),
            )
            .await
            .expect("validated node selection");
        let state: ManagerState = serde_json::from_slice(
            &filesystem
                .contents(Path::new("/state/state.json"))
                .expect("state file"),
        )
        .expect("state JSON");
        assert!(state.selected_node_id.is_some());
        let public = service
            .query(Query::Subscriptions)
            .await
            .expect("subscription query")
            .to_string();
        assert!(!public.contains("secret.example"));
        assert!(
            filesystem
                .contents(Path::new("/state/nodes.json"))
                .is_some()
        );
    }

    #[tokio::test]
    async fn dry_run_never_calls_installer_apply() {
        let installer = FakeInstaller::default();
        let count = installer.apply_count.clone();
        let filesystem = FakeFileSystem::default();
        let unsupported = UnsupportedPlatform {
            platform: "test".into(),
        };
        let service = ManagerService::new(
            ManagerConfig::default(),
            ManagerState::default(),
            BackendSet {
                selections: Vec::new(),
                capabilities: test_capabilities(),
                layout: FakeLayout(test_paths()),
                installer,
                package_advisor: FakePackageAdvisor,
                identity: FakeIdentityManager,
                service: FakeServiceManager::default(),
                firewall: unsupported.clone(),
                policy_routing: unsupported.clone(),
                tun: FakeTunManager::default(),
                app_runner: unsupported.clone(),
                mount_isolation: unsupported.clone(),
                desktop_proxy: unsupported.clone(),
                privilege: unsupported.clone(),
                inspector: unsupported.clone(),
                xray: FakeXrayRunner::default(),
                events: FakeEventSink::default(),
                filesystem: filesystem.clone(),
                downloader: FakeDownloader::default(),
                clock: FakeClock(42),
            }
            .erase(),
        );
        service
            .execute(
                Operation::Install { user: None },
                OperationOptions {
                    dry_run: true,
                    assume_yes: false,
                },
            )
            .await
            .expect("dry-run plan");
        assert_eq!(count.load(Ordering::Relaxed), 0);
        assert_eq!(filesystem.lock_count(), 0);
    }

    #[tokio::test]
    async fn fake_probe_returns_configured_latency() {
        let node = parse_uri(
            "vless://123e4567-e89b-12d3-a456-426614174000@example.com:443#Node",
            "main",
        )
        .expect("node");
        let runner = FakeXrayRunner::default();
        runner.probes.lock().expect("fake probes").insert(
            node.id.as_str().into(),
            ProbeResult {
                latency_ms: Some(42),
                error: None,
            },
        );
        let outcomes = probe_all(
            vec![node],
            ManagerConfig::default(),
            Arc::new(runner),
            Arc::new(FakeEventSink::default()),
            Arc::new(AtomicBool::new(false)),
        )
        .await;
        assert_eq!(outcomes[0].result.latency_ms, Some(42));
    }

    #[tokio::test]
    async fn probe_scheduler_honors_preexisting_cancellation() {
        let node = parse_uri(
            "vless://123e4567-e89b-12d3-a456-426614174000@example.com:443#Node",
            "main",
        )
        .expect("node");
        let outcomes = probe_all(
            vec![node],
            ManagerConfig::default(),
            Arc::new(FakeXrayRunner::default()),
            Arc::new(FakeEventSink::default()),
            Arc::new(AtomicBool::new(true)),
        )
        .await;
        assert_eq!(outcomes[0].result.error.as_deref(), Some("cancelled"));
    }

    #[tokio::test]
    async fn fake_downloader_enforces_size_limit() {
        let downloader = FakeDownloader::default();
        downloader
            .responses
            .lock()
            .expect("fake responses")
            .insert("https://example.test/file".into(), vec![0; 8]);
        let result = downloader
            .download(DownloadRequest {
                url: "https://example.test/file".into(),
                max_bytes: 4,
                timeout: std::time::Duration::from_secs(1),
                max_redirects: 0,
            })
            .await;
        assert!(matches!(result, Err(ManagerError::Download(message)) if message.contains("size")));
    }

    #[tokio::test]
    async fn fake_tun_reports_state_without_claiming_real_platform_support() {
        let tun = FakeTunManager::default();
        assert!(!tun.status("xray0").await.expect("fake status"));
        tun.set_active(true).expect("set fake state");
        assert!(tun.status("xray0").await.expect("fake status"));
    }
}
