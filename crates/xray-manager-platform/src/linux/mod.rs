mod adapters;
mod arch;
mod layout;
mod systemd;

pub use adapters::{
    AppNamespaceRequest, ArchPackageAdvisor, IpRoutePolicyManager, Kde6DesktopProxyManager,
    LinuxAppRunner, LinuxIdentityManager, LinuxMountIsolation, LinuxPlatformInspector,
    LinuxPrivilegeChecker, LinuxTunManager, NftablesFirewallManager, enter_app_namespace,
};
pub use arch::ArchInstaller;
pub use layout::LinuxFhsLayout;
pub use systemd::SystemdServiceManager;

use crate::portable::ProcessCommandRunner;
use crate::registry::BackendFactory;
use async_trait::async_trait;
use std::collections::BTreeSet;
use std::sync::Arc;
use xray_manager_core::config::ManagerConfig;
use xray_manager_core::ports::{
    BackendComponent, BackendDescriptor, BackendProbe, BackendSelection, Capability, CommandRunner,
};
use xray_manager_core::{ManagerError, Result};

pub struct LinuxBackendFactory {
    id: &'static str,
    capabilities: BTreeSet<Capability>,
    requirements: Vec<&'static str>,
}

impl LinuxBackendFactory {
    pub fn new(
        id: &'static str,
        capabilities: impl IntoIterator<Item = Capability>,
        requirements: Vec<&'static str>,
    ) -> Self {
        Self {
            id,
            capabilities: capabilities.into_iter().collect(),
            requirements,
        }
    }
}

#[async_trait]
impl BackendFactory for LinuxBackendFactory {
    fn descriptor(&self) -> BackendDescriptor {
        BackendDescriptor {
            id: self.id.into(),
            contract_version: 1,
            capabilities: self.capabilities.clone(),
            platform: "linux".into(),
            requirements: self.requirements.iter().map(ToString::to_string).collect(),
        }
    }

    async fn probe(&self) -> Result<BackendProbe> {
        let missing: Vec<_> = self
            .requirements
            .iter()
            .filter(|program| !command_exists(program))
            .copied()
            .collect();
        if !missing.is_empty() {
            return Ok(BackendProbe {
                available: false,
                reason: Some(format!("missing: {}", missing.join(", "))),
            });
        }
        if self.id == "arch" {
            let release = tokio::fs::read_to_string("/etc/os-release")
                .await
                .unwrap_or_default();
            let distribution = release
                .lines()
                .find_map(|line| line.strip_prefix("ID="))
                .map(|value| value.trim_matches('"'));
            if !matches!(distribution, Some("arch" | "endeavouros")) {
                return Ok(BackendProbe {
                    available: false,
                    reason: Some("host is not Arch Linux or EndeavourOS".into()),
                });
            }
        }
        if self.id == "systemd" {
            let output = ProcessCommandRunner
                .run("systemctl", &["is-system-running".into()])
                .await?;
            let state = output.stdout.trim();
            if !matches!(state, "running" | "degraded") {
                return Ok(BackendProbe {
                    available: false,
                    reason: Some(format!(
                        "systemd system manager is not running (state: {})",
                        if state.is_empty() { "unknown" } else { state }
                    )),
                });
            }
        }
        if self.id == "xray-linux-tun"
            && !tokio::fs::try_exists("/dev/net/tun").await.unwrap_or(false)
        {
            return Ok(BackendProbe {
                available: false,
                reason: Some("/dev/net/tun is unavailable".into()),
            });
        }
        Ok(BackendProbe {
            available: true,
            reason: None,
        })
    }

    fn create(
        &self,
        capability: Capability,
        config: &ManagerConfig,
        selections: &[BackendSelection],
    ) -> Result<BackendComponent> {
        let component = match (self.id, capability) {
            ("linux-fhs", Capability::Layout) => BackendComponent::Layout(Arc::new(LinuxFhsLayout)),
            ("arch", Capability::Install) => BackendComponent::Installer(Arc::new(
                ArchInstaller::new(config.clone(), selections)?,
            )),
            ("arch", Capability::PackageAdvice) => {
                BackendComponent::PackageAdvisor(Arc::new(ArchPackageAdvisor))
            }
            ("linux-identity", Capability::Identity) => {
                BackendComponent::Identity(Arc::new(LinuxIdentityManager::default()))
            }
            ("systemd", Capability::Service) => {
                BackendComponent::Service(Arc::new(SystemdServiceManager::default()))
            }
            ("nftables", Capability::Firewall) => {
                BackendComponent::Firewall(Arc::new(NftablesFirewallManager::default()))
            }
            ("iproute2", Capability::PolicyRouting) => {
                BackendComponent::PolicyRouting(Arc::new(IpRoutePolicyManager::default()))
            }
            ("xray-linux-tun", Capability::Tun) => {
                BackendComponent::Tun(Arc::new(LinuxTunManager::default()))
            }
            ("linux-gid-mountns", Capability::AppRunner) => {
                BackendComponent::AppRunner(Arc::new(LinuxAppRunner::default()))
            }
            ("linux-gid-mountns", Capability::MountIsolation) => {
                BackendComponent::MountIsolation(Arc::new(LinuxMountIsolation))
            }
            ("kde6", Capability::DesktopProxy) => {
                BackendComponent::DesktopProxy(Arc::new(Kde6DesktopProxyManager::default()))
            }
            _ => {
                return Err(ManagerError::PlatformUnsupported {
                    capability,
                    platform: "linux".into(),
                    backend: Some(self.id.into()),
                    reason: format!(
                        "backend '{}' does not provide a factory for {capability}",
                        self.id
                    ),
                    recommendation: Some("select a backend that provides this capability".into()),
                });
            }
        };
        Ok(component)
    }
}

pub(crate) fn command_exists(program: &str) -> bool {
    std::env::var_os("PATH")
        .is_some_and(|paths| std::env::split_paths(&paths).any(|path| path.join(program).is_file()))
}

pub fn register_production(registry: &mut crate::BackendRegistry) {
    registry.register(LinuxBackendFactory::new(
        "linux-fhs",
        [Capability::Layout],
        vec![],
    ));
    registry.register(LinuxBackendFactory::new(
        "arch",
        [Capability::Install, Capability::PackageAdvice],
        vec!["pacman"],
    ));
    registry.register(LinuxBackendFactory::new(
        "linux-identity",
        [Capability::Identity],
        vec![
            "chown", "getent", "groupadd", "gpasswd", "id", "useradd", "usermod",
        ],
    ));
    registry.register(LinuxBackendFactory::new(
        "systemd",
        [Capability::Service],
        vec!["systemctl", "journalctl"],
    ));
    registry.register(LinuxBackendFactory::new(
        "nftables",
        [Capability::Firewall],
        vec!["nft"],
    ));
    registry.register(LinuxBackendFactory::new(
        "iproute2",
        [Capability::PolicyRouting],
        vec!["ip"],
    ));
    registry.register(LinuxBackendFactory::new(
        "xray-linux-tun",
        [Capability::Tun],
        vec!["ip"],
    ));
    registry.register(LinuxBackendFactory::new(
        "linux-gid-mountns",
        [Capability::AppRunner, Capability::MountIsolation],
        vec!["curl", "getent", "id", "mount", "unshare"],
    ));
    registry.register(LinuxBackendFactory::new(
        "kde6",
        [Capability::DesktopProxy],
        vec!["dbus-send", "kwriteconfig6", "runuser"],
    ));
}

#[derive(Debug, Clone, Copy)]
pub enum TunInternalAction {
    PolicyUp,
    PolicyDown,
    FirewallUp,
    FirewallDown,
    RoutesUp,
    RoutesDown,
    Attach,
    Detach,
}

pub fn is_elevated() -> bool {
    nix::unistd::geteuid().is_root()
}

pub fn invoking_user() -> Result<Option<String>> {
    if let Ok(user) = std::env::var("SUDO_USER")
        && !user.is_empty()
        && user != "root"
    {
        validate_login_name(&user)?;
        return Ok(Some(user));
    }
    let Some(uid) = std::env::var("SUDO_UID")
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
        .filter(|uid| *uid != 0)
    else {
        return Ok(None);
    };
    let user = nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(uid))
        .map_err(|error| ManagerError::Other(format!("failed to resolve SUDO_UID: {error}")))?
        .ok_or_else(|| ManagerError::Other(format!("SUDO_UID {uid} has no local account")))?;
    if let Ok(gid) = std::env::var("SUDO_GID")
        && gid.parse::<u32>().ok() != Some(user.gid.as_raw())
    {
        return Err(ManagerError::Other(
            "SUDO_UID and SUDO_GID identify different accounts".into(),
        ));
    }
    validate_login_name(&user.name)?;
    Ok(Some(user.name))
}

fn validate_login_name(value: &str) -> Result<()> {
    if value.is_empty()
        || !value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_'))
    {
        return Err(ManagerError::InvalidConfig(
            "invalid invoking Linux user name".into(),
        ));
    }
    Ok(())
}

pub async fn run_tun_internal(action: TunInternalAction, config: &ManagerConfig) -> Result<()> {
    if !config.tun.enabled
        && matches!(
            action,
            TunInternalAction::Attach | TunInternalAction::Detach
        )
    {
        return Ok(());
    }
    let runner = ProcessCommandRunner;
    match action {
        TunInternalAction::PolicyUp => {
            firewall_up(&runner, config).await?;
            if let Err(error) = routes_up(&runner, config).await {
                let _ = firewall_down(&runner).await;
                return Err(error);
            }
            Ok(())
        }
        TunInternalAction::PolicyDown => {
            let route_result = routes_down(&runner, config).await;
            let firewall_result = firewall_down(&runner).await;
            route_result.and(firewall_result)
        }
        TunInternalAction::FirewallUp => firewall_up(&runner, config).await,
        TunInternalAction::FirewallDown => firewall_down(&runner).await,
        TunInternalAction::RoutesUp => routes_up(&runner, config).await,
        TunInternalAction::RoutesDown => routes_down(&runner, config).await,
        TunInternalAction::Attach => attach(&runner, config).await,
        TunInternalAction::Detach => detach(&runner, config).await,
    }
}

async fn firewall_up(runner: &ProcessCommandRunner, config: &ManagerConfig) -> Result<()> {
    let gid_output = runner
        .run("getent", &["group".into(), "xray-tun".into()])
        .await?;
    let gid = (gid_output.status == 0)
        .then_some(gid_output.stdout)
        .and_then(|line| line.trim().split(':').nth(2).map(str::to_owned))
        .and_then(|value| value.parse::<u32>().ok())
        .ok_or_else(|| ManagerError::Other("unable to resolve xray-tun GID".into()))?;
    let rules = crate::templates::nftables(&config.tun, gid);
    let mut file =
        tempfile::NamedTempFile::new().map_err(|error| ManagerError::Io(error.to_string()))?;
    use std::io::Write;
    file.write_all(rules.as_bytes())
        .and_then(|()| file.as_file().sync_all())
        .map_err(|error| ManagerError::Io(error.to_string()))?;
    firewall_down(runner).await?;
    if let Err(error) = run_checked(
        runner,
        "nft",
        &["-f".into(), file.path().to_string_lossy().into_owned()],
    )
    .await
    {
        let _ = firewall_down(runner).await;
        return Err(error);
    }
    Ok(())
}

async fn firewall_down(runner: &ProcessCommandRunner) -> Result<()> {
    let existing = runner
        .run(
            "nft",
            &[
                "list".into(),
                "table".into(),
                "inet".into(),
                "xray_manager".into(),
            ],
        )
        .await?;
    if existing.status != 0 {
        return Ok(());
    }
    let output = runner
        .run(
            "nft",
            &[
                "delete".into(),
                "table".into(),
                "inet".into(),
                "xray_manager".into(),
            ],
        )
        .await?;
    if output.status == 0 {
        Ok(())
    } else {
        Err(ManagerError::Other(format!(
            "nft failed: {}",
            output.stderr.trim()
        )))
    }
}

async fn routes_up(runner: &ProcessCommandRunner, config: &ManagerConfig) -> Result<()> {
    if let Err(error) = routes_up_inner(runner, config).await {
        let _ = routes_down(runner, config).await;
        return Err(error);
    }
    Ok(())
}

async fn routes_up_inner(runner: &ProcessCommandRunner, config: &ManagerConfig) -> Result<()> {
    let table = config.tun.routing_table.to_string();
    let mark = config.tun.packet_mark.to_string();
    remove_rule(runner, false, &mark, &table).await;
    run_checked(runner, "ip", &rule_args(false, "add", &mark, &table)).await?;
    run_checked(
        runner,
        "ip",
        &[
            "route".into(),
            "replace".into(),
            "blackhole".into(),
            "default".into(),
            "table".into(),
            table.clone(),
            "metric".into(),
            "32767".into(),
        ],
    )
    .await?;
    remove_rule(runner, true, &mark, &table).await;
    run_checked(runner, "ip", &rule_args(true, "add", &mark, &table)).await?;
    run_checked(
        runner,
        "ip",
        &[
            "-6".into(),
            "route".into(),
            "replace".into(),
            "unreachable".into(),
            "default".into(),
            "table".into(),
            table,
            "metric".into(),
            "32767".into(),
        ],
    )
    .await?;
    Ok(())
}

async fn routes_down(runner: &ProcessCommandRunner, config: &ManagerConfig) -> Result<()> {
    let table = config.tun.routing_table.to_string();
    let mark = config.tun.packet_mark.to_string();
    remove_rule(runner, false, &mark, &table).await;
    remove_rule(runner, true, &mark, &table).await;
    for ipv6 in [false, true] {
        let mut args = Vec::new();
        if ipv6 {
            args.push("-6".into());
        }
        args.extend([
            "route".into(),
            "flush".into(),
            "table".into(),
            table.clone(),
        ]);
        let _ = runner.run("ip", &args).await;
    }
    Ok(())
}

async fn attach(runner: &ProcessCommandRunner, config: &ManagerConfig) -> Result<()> {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let output = runner
            .run(
                "ip",
                &[
                    "link".into(),
                    "show".into(),
                    "dev".into(),
                    config.tun.interface_name.clone(),
                ],
            )
            .await?;
        if output.status == 0 {
            break;
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(ManagerError::Other(format!(
                "TUN interface {} did not appear",
                config.tun.interface_name
            )));
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    run_checked(
        runner,
        "ip",
        &[
            "route".into(),
            "replace".into(),
            "default".into(),
            "dev".into(),
            config.tun.interface_name.clone(),
            "table".into(),
            config.tun.routing_table.to_string(),
            "metric".into(),
            "100".into(),
        ],
    )
    .await?;
    if config.tun.ipv6_enabled {
        run_checked(
            runner,
            "ip",
            &[
                "-6".into(),
                "route".into(),
                "replace".into(),
                "default".into(),
                "dev".into(),
                config.tun.interface_name.clone(),
                "table".into(),
                config.tun.routing_table.to_string(),
                "metric".into(),
                "100".into(),
            ],
        )
        .await?;
    }
    Ok(())
}

async fn detach(runner: &ProcessCommandRunner, config: &ManagerConfig) -> Result<()> {
    let _ = runner
        .run(
            "ip",
            &[
                "route".into(),
                "del".into(),
                "default".into(),
                "dev".into(),
                config.tun.interface_name.clone(),
                "table".into(),
                config.tun.routing_table.to_string(),
            ],
        )
        .await;
    if config.tun.ipv6_enabled {
        let _ = runner
            .run(
                "ip",
                &[
                    "-6".into(),
                    "route".into(),
                    "del".into(),
                    "default".into(),
                    "dev".into(),
                    config.tun.interface_name.clone(),
                    "table".into(),
                    config.tun.routing_table.to_string(),
                ],
            )
            .await;
    }
    Ok(())
}

fn rule_args(ipv6: bool, action: &str, mark: &str, table: &str) -> Vec<String> {
    let mut args = Vec::new();
    if ipv6 {
        args.push("-6".into());
    }
    args.extend([
        "rule".into(),
        action.into(),
        "fwmark".into(),
        mark.into(),
        "lookup".into(),
        table.into(),
    ]);
    args
}

async fn remove_rule(runner: &ProcessCommandRunner, ipv6: bool, mark: &str, table: &str) {
    for _ in 0..32 {
        let Ok(output) = runner.run("ip", &rule_args(ipv6, "del", mark, table)).await else {
            break;
        };
        if output.status != 0 {
            break;
        }
    }
}

async fn run_checked(runner: &ProcessCommandRunner, program: &str, args: &[String]) -> Result<()> {
    let output = runner.run(program, args).await?;
    if output.status == 0 {
        Ok(())
    } else {
        Err(ManagerError::Other(format!(
            "{program} failed: {}",
            output.stderr.trim()
        )))
    }
}
