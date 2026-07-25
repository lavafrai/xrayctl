use crate::config::ManagerConfig;
use crate::domain::{ManagerState, Node};
use crate::error::Result;
use crate::events::ManagerEvent;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    Layout,
    #[serde(rename = "installer", alias = "install")]
    Install,
    Identity,
    Service,
    Firewall,
    PolicyRouting,
    Tun,
    AppRunner,
    MountIsolation,
    DesktopProxy,
    #[serde(rename = "package_advisor", alias = "package_advice")]
    PackageAdvice,
}

impl fmt::Display for Capability {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let serialized = serde_json::to_value(self)
            .ok()
            .and_then(|value| value.as_str().map(str::to_owned))
            .unwrap_or_else(|| format!("{self:?}"));
        formatter.write_str(&serialized)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BackendSelection {
    pub capability: Capability,
    pub backend_id: String,
    pub source: SelectionSource,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SelectionSource {
    Cli,
    Config,
    InstalledState,
    Automatic,
}

#[derive(Debug, Clone, Serialize)]
pub struct CapabilityStatus {
    pub capability: Capability,
    pub supported: bool,
    pub backend_id: Option<String>,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BackendDescriptor {
    pub id: String,
    pub contract_version: u32,
    pub capabilities: BTreeSet<Capability>,
    pub platform: String,
    pub requirements: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BackendProbe {
    pub available: bool,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct BackendPreferences {
    pub cli: BTreeMap<Capability, String>,
    pub config: BTreeMap<Capability, String>,
    pub installed: BTreeMap<Capability, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionPlan {
    pub operation: String,
    pub backend_ids: BTreeMap<Capability, String>,
    pub actions: Vec<PlanAction>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PlanAction {
    EnsureIdentity {
        name: String,
        system: bool,
    },
    EnsureGroup {
        name: String,
    },
    AddIdentityToGroup {
        identity: String,
        group: String,
    },
    EnsureDirectory {
        path: PathBuf,
        mode: u32,
    },
    WriteFile {
        path: PathBuf,
        mode: u32,
        description: String,
    },
    DownloadArtifact {
        id: String,
        destination: PathBuf,
    },
    RequirePackages {
        packages: Vec<String>,
    },
    InstallService {
        name: String,
    },
    EnableService {
        name: String,
    },
    StartService {
        name: String,
    },
    RestartService {
        name: String,
    },
    StopService {
        name: String,
    },
    RemoveService {
        name: String,
    },
    ConfigureFirewall {
        backend: String,
    },
    ConfigureRoute {
        backend: String,
        table: u32,
    },
    ApplyConfiguration {
        description: String,
    },
    ConfigureDesktopProxy {
        backend: String,
        user: String,
        enabled: bool,
    },
    LaunchApplication {
        executable: String,
        routed: bool,
    },
    RunHealthcheck {
        url: String,
    },
    RemoveOwnedPath {
        path: PathBuf,
    },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum UpgradeTarget {
    All,
    Core,
    Assets,
    Manager,
}

#[derive(Debug, Clone)]
pub struct DownloadRequest {
    pub url: String,
    pub max_bytes: u64,
    pub timeout: Duration,
    pub max_redirects: usize,
}

#[derive(Debug, Clone)]
pub struct DownloadedArtifact {
    pub bytes: Vec<u8>,
    pub final_url: String,
    pub content_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Release {
    #[serde(rename = "tag_name", alias = "tag")]
    pub tag: String,
    pub prerelease: bool,
    pub assets: Vec<ReleaseAsset>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReleaseAsset {
    pub name: String,
    #[serde(rename = "browser_download_url", alias = "download_url")]
    pub download_url: String,
    pub size: u64,
}

#[derive(Debug, Clone)]
pub struct XrayTestRequest {
    pub executable: PathBuf,
    pub config_dir: PathBuf,
    pub asset_dir: PathBuf,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProbeResult {
    pub latency_ms: Option<u64>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PlatformInfo {
    pub os: String,
    pub distribution: Option<String>,
    pub init_system: Option<String>,
    pub desktop: Option<String>,
}

#[async_trait]
pub trait Downloader: Send + Sync {
    async fn download(&self, request: DownloadRequest) -> Result<DownloadedArtifact>;
}

#[async_trait]
pub trait ReleaseProvider: Send + Sync {
    async fn stable_release(&self, repository: &str) -> Result<Release>;
}

#[async_trait]
pub trait XrayRunner: Send + Sync {
    async fn version(&self, executable: &Path) -> Result<String>;
    async fn test_config(&self, request: &XrayTestRequest) -> Result<()>;
    async fn probe(&self, node: &Node, config: &ManagerConfig) -> Result<ProbeResult>;
    async fn healthcheck(&self, config: &ManagerConfig) -> Result<()>;
}

#[async_trait]
pub trait FileSystem: Send + Sync {
    async fn acquire_lock(&self, path: &Path) -> Result<Box<dyn FileLockGuard>>;
    async fn read(&self, path: &Path) -> Result<Vec<u8>>;
    async fn list_files(&self, path: &Path) -> Result<Vec<PathBuf>>;
    async fn write_atomic(&self, path: &Path, bytes: &[u8], mode: Option<u32>) -> Result<()>;
    async fn create_dir_all(&self, path: &Path) -> Result<()>;
    async fn set_permissions(&self, path: &Path, mode: u32) -> Result<()>;
    async fn exists(&self, path: &Path) -> Result<bool>;
    async fn remove_owned(&self, path: &Path, ownership_root: &Path) -> Result<()>;
    async fn switch_generation(&self, current: &Path, previous: &Path, target: &Path)
    -> Result<()>;
    async fn rollback_generation(&self, current: &Path, previous: &Path) -> Result<()>;
    async fn restore_generation(
        &self,
        current: &Path,
        previous: &Path,
        current_target: Option<&Path>,
        previous_target: Option<&Path>,
    ) -> Result<()>;
    async fn prune_generations(
        &self,
        root: &Path,
        current: &Path,
        previous: &Path,
        keep: usize,
    ) -> Result<()>;
}

pub trait FileLockGuard: Send {}

pub trait Clock: Send + Sync {
    fn unix_timestamp(&self) -> i64;
}

pub trait EventSink: Send + Sync {
    fn emit(&self, event: ManagerEvent);
}

#[async_trait]
pub trait LayoutProvider: Send + Sync {
    async fn paths(&self) -> Result<ManagerPaths>;
}

#[async_trait]
pub trait PlatformInstaller: Send + Sync {
    async fn plan_install(&self, config: &ManagerConfig) -> Result<ExecutionPlan>;
    async fn apply(&self, plan: &ExecutionPlan) -> Result<()>;
    async fn plan_repair(&self, config: &ManagerConfig) -> Result<ExecutionPlan>;
    async fn plan_uninstall(&self, purge: bool) -> Result<ExecutionPlan>;
    async fn plan_upgrade(
        &self,
        config: &ManagerConfig,
        target: UpgradeTarget,
    ) -> Result<ExecutionPlan>;
}

#[async_trait]
pub trait PackageAdvisor: Send + Sync {
    async fn missing_requirements(&self) -> Result<Vec<String>>;
    fn packages_for(&self, requirements: &[String]) -> Vec<String>;
    fn install_hint(&self, packages: &[String]) -> Option<String>;
}

#[async_trait]
pub trait IdentityManager: Send + Sync {
    async fn ensure_system_identity(&self, user: &str, groups: &[String]) -> Result<()>;
    async fn set_ownership(
        &self,
        path: &Path,
        user: &str,
        group: &str,
        recursive: bool,
    ) -> Result<()>;
}

#[async_trait]
pub trait ServiceManager: Send + Sync {
    async fn enable(&self, service: &str) -> Result<()>;
    async fn disable(&self, service: &str) -> Result<()>;
    async fn start(&self, service: &str) -> Result<()>;
    async fn stop(&self, service: &str) -> Result<()>;
    async fn restart(&self, service: &str) -> Result<()>;
    async fn is_active(&self, service: &str) -> Result<bool>;
    async fn logs(&self, service: &str, lines: usize) -> Result<String>;
}

#[async_trait]
pub trait FirewallManager: Send + Sync {
    async fn enable(&self, config: &ManagerConfig) -> Result<()>;
    async fn disable(&self) -> Result<()>;
    async fn show(&self) -> Result<String>;
}

#[async_trait]
pub trait PolicyRoutingManager: Send + Sync {
    async fn enable(&self, config: &ManagerConfig) -> Result<()>;
    async fn attach_tun(&self, config: &ManagerConfig) -> Result<()>;
    async fn detach_tun(&self, config: &ManagerConfig) -> Result<()>;
    async fn disable(&self, config: &ManagerConfig) -> Result<()>;
    async fn show(&self, config: &ManagerConfig) -> Result<String>;
}

#[async_trait]
pub trait TunManager: Send + Sync {
    async fn status(&self, interface: &str) -> Result<bool>;
}

#[derive(Debug, Clone)]
pub struct AppLaunchRequest {
    pub command: Vec<String>,
    pub user: String,
    pub override_dns: bool,
    pub clear_proxy_environment: bool,
    pub working_directory: Option<PathBuf>,
    pub environment: BTreeMap<String, String>,
}

impl AppLaunchRequest {
    pub fn sanitized_environment(
        &self,
        mut inherited: BTreeMap<String, String>,
    ) -> BTreeMap<String, String> {
        if self.clear_proxy_environment {
            for key in [
                "HTTP_PROXY",
                "HTTPS_PROXY",
                "ALL_PROXY",
                "NO_PROXY",
                "http_proxy",
                "https_proxy",
                "all_proxy",
                "no_proxy",
            ] {
                inherited.remove(key);
            }
        }
        inherited.extend(self.environment.clone());
        inherited
    }
}

#[async_trait]
pub trait AppRunner: Send + Sync {
    async fn run(&self, request: AppLaunchRequest) -> Result<i32>;
    async fn test_route(&self, request: AppRouteTestRequest) -> Result<AppRouteTestResult>;
}

#[derive(Debug, Clone)]
pub struct AppRouteTestRequest {
    pub user: String,
    pub override_dns: bool,
    pub url: String,
    pub timeout: Duration,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AppRouteTestResult {
    pub direct_ip: String,
    pub routed_ip: String,
    pub routes_differ: bool,
}

#[async_trait]
pub trait MountIsolation: Send + Sync {
    async fn supported(&self) -> Result<bool>;
}

#[async_trait]
pub trait DesktopProxyManager: Send + Sync {
    async fn enable(&self, user: &str, config: &ManagerConfig) -> Result<()>;
    async fn disable(&self, user: &str) -> Result<()>;
}

#[async_trait]
pub trait PrivilegeChecker: Send + Sync {
    async fn is_elevated(&self) -> Result<bool>;
}

#[async_trait]
pub trait PlatformInspector: Send + Sync {
    async fn inspect(&self) -> Result<PlatformInfo>;
}

#[async_trait]
pub trait CommandRunner: Send + Sync {
    async fn run(&self, program: &str, args: &[String]) -> Result<CommandOutput>;
}

#[derive(Debug, Clone)]
pub struct CommandOutput {
    pub status: i32,
    pub stdout: String,
    pub stderr: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManagerPaths {
    pub config_dir: PathBuf,
    pub state_dir: PathBuf,
    pub cache_dir: PathBuf,
    pub runtime_dir: PathBuf,
    pub install_dir: PathBuf,
    pub executable: PathBuf,
}

pub enum BackendComponent {
    Layout(Arc<dyn LayoutProvider>),
    Installer(Arc<dyn PlatformInstaller>),
    PackageAdvisor(Arc<dyn PackageAdvisor>),
    Identity(Arc<dyn IdentityManager>),
    Service(Arc<dyn ServiceManager>),
    Firewall(Arc<dyn FirewallManager>),
    PolicyRouting(Arc<dyn PolicyRoutingManager>),
    Tun(Arc<dyn TunManager>),
    AppRunner(Arc<dyn AppRunner>),
    MountIsolation(Arc<dyn MountIsolation>),
    DesktopProxy(Arc<dyn DesktopProxyManager>),
}

#[derive(Clone)]
pub struct DynBackendSet {
    pub selections: Vec<BackendSelection>,
    pub capabilities: Vec<CapabilityStatus>,
    pub layout: Arc<dyn LayoutProvider>,
    pub installer: Arc<dyn PlatformInstaller>,
    pub package_advisor: Arc<dyn PackageAdvisor>,
    pub identity: Arc<dyn IdentityManager>,
    pub service: Arc<dyn ServiceManager>,
    pub firewall: Arc<dyn FirewallManager>,
    pub policy_routing: Arc<dyn PolicyRoutingManager>,
    pub tun: Arc<dyn TunManager>,
    pub app_runner: Arc<dyn AppRunner>,
    pub mount_isolation: Arc<dyn MountIsolation>,
    pub desktop_proxy: Arc<dyn DesktopProxyManager>,
    pub privilege: Arc<dyn PrivilegeChecker>,
    pub inspector: Arc<dyn PlatformInspector>,
    pub xray: Arc<dyn XrayRunner>,
    pub events: Arc<dyn EventSink>,
    pub filesystem: Arc<dyn FileSystem>,
    pub downloader: Arc<dyn Downloader>,
    pub clock: Arc<dyn Clock>,
}

pub struct BackendSet<L, I, PA, ID, S, FW, PR, T, A, M, DP, PV, PI, X, E, F, D, C> {
    pub selections: Vec<BackendSelection>,
    pub capabilities: Vec<CapabilityStatus>,
    pub layout: L,
    pub installer: I,
    pub package_advisor: PA,
    pub identity: ID,
    pub service: S,
    pub firewall: FW,
    pub policy_routing: PR,
    pub tun: T,
    pub app_runner: A,
    pub mount_isolation: M,
    pub desktop_proxy: DP,
    pub privilege: PV,
    pub inspector: PI,
    pub xray: X,
    pub events: E,
    pub filesystem: F,
    pub downloader: D,
    pub clock: C,
}

impl<L, I, PA, ID, S, FW, PR, T, A, M, DP, PV, PI, X, E, F, D, C>
    BackendSet<L, I, PA, ID, S, FW, PR, T, A, M, DP, PV, PI, X, E, F, D, C>
where
    L: LayoutProvider + 'static,
    I: PlatformInstaller + 'static,
    PA: PackageAdvisor + 'static,
    ID: IdentityManager + 'static,
    S: ServiceManager + 'static,
    FW: FirewallManager + 'static,
    PR: PolicyRoutingManager + 'static,
    T: TunManager + 'static,
    A: AppRunner + 'static,
    M: MountIsolation + 'static,
    DP: DesktopProxyManager + 'static,
    PV: PrivilegeChecker + 'static,
    PI: PlatformInspector + 'static,
    X: XrayRunner + 'static,
    E: EventSink + 'static,
    F: FileSystem + 'static,
    D: Downloader + 'static,
    C: Clock + 'static,
{
    pub fn erase(self) -> DynBackendSet {
        DynBackendSet {
            selections: self.selections,
            capabilities: self.capabilities,
            layout: Arc::new(self.layout),
            installer: Arc::new(self.installer),
            package_advisor: Arc::new(self.package_advisor),
            identity: Arc::new(self.identity),
            service: Arc::new(self.service),
            firewall: Arc::new(self.firewall),
            policy_routing: Arc::new(self.policy_routing),
            tun: Arc::new(self.tun),
            app_runner: Arc::new(self.app_runner),
            mount_isolation: Arc::new(self.mount_isolation),
            desktop_proxy: Arc::new(self.desktop_proxy),
            privilege: Arc::new(self.privilege),
            inspector: Arc::new(self.inspector),
            xray: Arc::new(self.xray),
            events: Arc::new(self.events),
            filesystem: Arc::new(self.filesystem),
            downloader: Arc::new(self.downloader),
            clock: Arc::new(self.clock),
        }
    }
}

pub fn state_backend_preferences(state: &ManagerState) -> BTreeMap<Capability, String> {
    state
        .installed_backends
        .iter()
        .filter_map(|(key, value)| {
            serde_json::from_value::<Capability>(serde_json::Value::String(key.clone()))
                .ok()
                .map(|capability| (capability, value.clone()))
        })
        .collect()
}
