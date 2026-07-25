use crate::cli::Cli;
use anyhow::{Context, bail};
use std::collections::{BTreeMap, BTreeSet};
#[cfg(not(target_os = "linux"))]
use std::sync::Arc;
use xray_manager_core::ManagerService;
use xray_manager_core::config::ManagerConfig;
use xray_manager_core::domain::ManagerState;
#[cfg(target_os = "linux")]
use xray_manager_core::ports::{
    AppRunner, DesktopProxyManager, FirewallManager, IdentityManager, MountIsolation,
    PackageAdvisor, PlatformInstaller, PolicyRoutingManager, ServiceManager, TunManager,
};
use xray_manager_core::ports::{
    BackendComponent, BackendPreferences, Capability, DynBackendSet, LayoutProvider,
    state_backend_preferences,
};
#[cfg(not(target_os = "linux"))]
use xray_manager_platform::portable::PortableLocalLayout;
#[cfg(target_os = "linux")]
use xray_manager_platform::portable::ProcessXrayRunner;
use xray_manager_platform::portable::{
    HttpClient, NativeFileSystem, SystemClock, TracingEventSink,
};
use xray_manager_platform::registry::BackendRegistry;
#[cfg(not(target_os = "linux"))]
use xray_manager_platform::unsupported::LinuxPlanOnlyInstaller;
use xray_manager_platform::unsupported::UnsupportedPlatform;

pub async fn compose(cli: &Cli) -> anyhow::Result<ManagerService> {
    let config = load_config(cli).await?;
    let state = load_state().await?;
    let cli_preferences = parse_backend_overrides(&cli.backend)?;
    let preferences = BackendPreferences {
        cli: cli_preferences,
        config: config.platform.backends.clone(),
        installed: state_backend_preferences(&state),
    };
    let required: BTreeSet<_> = [
        Capability::Layout,
        Capability::Install,
        Capability::Identity,
        Capability::Service,
        Capability::Firewall,
        Capability::PolicyRouting,
        Capability::Tun,
        Capability::AppRunner,
        Capability::MountIsolation,
        Capability::DesktopProxy,
        Capability::PackageAdvice,
    ]
    .into_iter()
    .collect();

    #[cfg(target_os = "linux")]
    let (selections, capabilities, backends) = {
        use std::sync::Arc;
        use xray_manager_platform::linux::{self, LinuxPlatformInspector, LinuxPrivilegeChecker};
        let mut registry = BackendRegistry::default();
        linux::register_production(&mut registry);
        let (selections, capabilities) = registry.resolve(&preferences, &required).await?;
        let components = registry.instantiate(&selections, &config)?;
        let unsupported = Arc::new(UnsupportedPlatform {
            platform: "linux".into(),
        });
        let mut layout: Arc<dyn LayoutProvider> = unsupported.clone();
        let mut installer: Arc<dyn PlatformInstaller> = unsupported.clone();
        let mut package_advisor: Arc<dyn PackageAdvisor> = unsupported.clone();
        let mut identity: Arc<dyn IdentityManager> = unsupported.clone();
        let mut service: Arc<dyn ServiceManager> = unsupported.clone();
        let mut firewall: Arc<dyn FirewallManager> = unsupported.clone();
        let mut policy_routing: Arc<dyn PolicyRoutingManager> = unsupported.clone();
        let mut tun: Arc<dyn TunManager> = unsupported.clone();
        let mut app_runner: Arc<dyn AppRunner> = unsupported.clone();
        let mut mount_isolation: Arc<dyn MountIsolation> = unsupported.clone();
        let mut desktop_proxy: Arc<dyn DesktopProxyManager> = unsupported;
        for component in components {
            match component {
                BackendComponent::Layout(value) => layout = value,
                BackendComponent::Installer(value) => installer = value,
                BackendComponent::PackageAdvisor(value) => package_advisor = value,
                BackendComponent::Identity(value) => identity = value,
                BackendComponent::Service(value) => service = value,
                BackendComponent::Firewall(value) => firewall = value,
                BackendComponent::PolicyRouting(value) => policy_routing = value,
                BackendComponent::Tun(value) => tun = value,
                BackendComponent::AppRunner(value) => app_runner = value,
                BackendComponent::MountIsolation(value) => mount_isolation = value,
                BackendComponent::DesktopProxy(value) => desktop_proxy = value,
            }
        }
        let backends = DynBackendSet {
            selections: selections.clone(),
            capabilities: capabilities.clone(),
            layout,
            installer,
            package_advisor,
            identity,
            service,
            firewall,
            policy_routing,
            tun,
            app_runner,
            mount_isolation,
            desktop_proxy,
            privilege: Arc::new(LinuxPrivilegeChecker),
            inspector: Arc::new(LinuxPlatformInspector),
            xray: Arc::new(ProcessXrayRunner),
            events: Arc::new(TracingEventSink),
            filesystem: Arc::new(NativeFileSystem),
            downloader: Arc::new(HttpClient::with_connect_timeout(
                5,
                std::time::Duration::from_secs(config.general.connect_timeout_seconds),
            )?),
            clock: Arc::new(SystemClock),
        };
        (selections, capabilities, backends)
    };

    #[cfg(not(target_os = "linux"))]
    let (selections, capabilities, backends) = {
        let mut registry = BackendRegistry::default();
        xray_manager_platform::portable::register_portable(&mut registry);
        let (selections, capabilities) = registry.resolve(&preferences, &required).await?;
        let components = registry.instantiate(&selections, &config)?;
        let mut layout: Arc<dyn LayoutProvider> = Arc::new(PortableLocalLayout);
        for component in components {
            if let BackendComponent::Layout(value) = component {
                layout = value;
            }
        }
        let unsupported = Arc::new(UnsupportedPlatform {
            platform: std::env::consts::OS.into(),
        });
        let backends = DynBackendSet {
            selections: selections.clone(),
            capabilities: capabilities.clone(),
            layout,
            installer: Arc::new(LinuxPlanOnlyInstaller {
                platform: std::env::consts::OS.into(),
            }),
            package_advisor: unsupported.clone(),
            identity: unsupported.clone(),
            service: unsupported.clone(),
            firewall: unsupported.clone(),
            policy_routing: unsupported.clone(),
            tun: unsupported.clone(),
            app_runner: unsupported.clone(),
            mount_isolation: unsupported.clone(),
            desktop_proxy: unsupported.clone(),
            privilege: unsupported.clone(),
            inspector: unsupported.clone(),
            xray: unsupported,
            events: Arc::new(TracingEventSink),
            filesystem: Arc::new(NativeFileSystem),
            downloader: Arc::new(HttpClient::with_connect_timeout(
                5,
                std::time::Duration::from_secs(config.general.connect_timeout_seconds),
            )?),
            clock: Arc::new(SystemClock),
        };
        (selections, capabilities, backends)
    };

    let _ = (selections, capabilities);
    Ok(ManagerService::new(config, state, backends))
}

pub(crate) async fn load_config(cli: &Cli) -> anyhow::Result<ManagerConfig> {
    let default_path = default_config_path();
    let path = cli.config.as_ref().unwrap_or(&default_path);
    if !tokio::fs::try_exists(path).await.unwrap_or(false) {
        return Ok(ManagerConfig::default());
    }
    let input = tokio::fs::read_to_string(path)
        .await
        .with_context(|| format!("failed to read {}", path.display()))?;
    ManagerConfig::parse(&input).map_err(anyhow::Error::new)
}

async fn load_state() -> anyhow::Result<ManagerState> {
    let path = default_state_path();
    if !tokio::fs::try_exists(&path).await.unwrap_or(false) {
        return Ok(ManagerState::default());
    }
    let input = tokio::fs::read(&path)
        .await
        .with_context(|| format!("failed to read {}", path.display()))?;
    serde_json::from_slice(&input).with_context(|| format!("failed to parse {}", path.display()))
}

#[cfg(target_os = "linux")]
fn default_config_path() -> std::path::PathBuf {
    "/etc/xray-manager/config.toml".into()
}

#[cfg(not(target_os = "linux"))]
fn default_config_path() -> std::path::PathBuf {
    std::env::current_dir()
        .unwrap_or_default()
        .join(".xray-manager/config/config.toml")
}

#[cfg(target_os = "linux")]
fn default_state_path() -> std::path::PathBuf {
    "/var/lib/xray-manager/state.json".into()
}

#[cfg(not(target_os = "linux"))]
fn default_state_path() -> std::path::PathBuf {
    std::env::current_dir()
        .unwrap_or_default()
        .join(".xray-manager/state/state.json")
}

fn parse_backend_overrides(values: &[String]) -> anyhow::Result<BTreeMap<Capability, String>> {
    let mut result = BTreeMap::new();
    for value in values {
        let (name, id) = value.split_once('=').with_context(|| {
            format!("invalid backend override '{value}', expected capability=id")
        })?;
        if id.is_empty() {
            bail!("backend ID cannot be empty");
        }
        result.insert(parse_capability(name)?, id.into());
    }
    Ok(result)
}

fn parse_capability(value: &str) -> anyhow::Result<Capability> {
    let json = serde_json::Value::String(value.replace('-', "_"));
    serde_json::from_value(json).with_context(|| format!("unknown backend capability '{value}'"))
}
