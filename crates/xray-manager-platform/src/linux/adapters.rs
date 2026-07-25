use super::{TunInternalAction, command_exists, run_tun_internal};
use crate::portable::ProcessCommandRunner;
use async_trait::async_trait;
use std::collections::BTreeMap;
use std::path::PathBuf;
use tokio::process::Command;
use xray_manager_core::config::ManagerConfig;
use xray_manager_core::ports::{
    AppLaunchRequest, AppRouteTestRequest, AppRouteTestResult, AppRunner, CommandRunner,
    DesktopProxyManager, FirewallManager, IdentityManager, MountIsolation, PackageAdvisor,
    PlatformInfo, PlatformInspector, PolicyRoutingManager, PrivilegeChecker, TunManager,
};
use xray_manager_core::{ManagerError, Result};

#[derive(Debug, Clone, Default)]
pub struct ArchPackageAdvisor;

#[async_trait]
impl PackageAdvisor for ArchPackageAdvisor {
    async fn missing_requirements(&self) -> Result<Vec<String>> {
        let mut missing = Vec::new();
        for program in [
            "chown",
            "curl",
            "getent",
            "gpasswd",
            "groupadd",
            "id",
            "ip",
            "journalctl",
            "mount",
            "nft",
            "systemctl",
            "unshare",
            "useradd",
            "usermod",
        ] {
            if !command_exists(program) {
                missing.push(program.to_owned());
            }
        }
        Ok(missing)
    }

    fn packages_for(&self, requirements: &[String]) -> Vec<String> {
        let mut packages = requirements
            .iter()
            .map(|package| match package.as_str() {
                "chown" => "coreutils",
                "curl" => "curl",
                "getent" => "glibc",
                "gpasswd" | "groupadd" | "useradd" | "usermod" => "shadow",
                "ip" => "iproute2",
                "mount" | "unshare" => "util-linux",
                "nft" => "nftables",
                "journalctl" | "systemctl" => "systemd",
                other => other,
            })
            .map(str::to_owned)
            .collect::<Vec<String>>();
        packages.sort_unstable();
        packages.dedup();
        packages
    }

    fn install_hint(&self, requirements: &[String]) -> Option<String> {
        let packages = self.packages_for(requirements);
        if packages.is_empty() {
            return None;
        }
        Some(format!("sudo pacman -S --needed {}", packages.join(" ")))
    }
}

#[derive(Debug, Clone, Default)]
pub struct LinuxIdentityManager {
    runner: ProcessCommandRunner,
}

#[async_trait]
impl IdentityManager for LinuxIdentityManager {
    async fn ensure_system_identity(&self, user: &str, groups: &[String]) -> Result<()> {
        validate_identity(user)?;
        let mut requested_groups = groups.to_vec();
        if requested_groups.is_empty() {
            requested_groups.push(user.into());
        }
        for group in &requested_groups {
            validate_identity(group)?;
            if self
                .runner
                .run("getent", &["group".into(), group.clone()])
                .await?
                .status
                != 0
            {
                run_checked(
                    &self.runner,
                    "groupadd",
                    &["--system".into(), group.clone()],
                )
                .await?;
            }
        }
        if self
            .runner
            .run("id", &["--user".into(), user.into()])
            .await?
            .status
            != 0
        {
            run_checked(
                &self.runner,
                "useradd",
                &[
                    "--system".into(),
                    "--no-create-home".into(),
                    "--shell".into(),
                    "/usr/bin/nologin".into(),
                    "--gid".into(),
                    requested_groups[0].clone(),
                    user.into(),
                ],
            )
            .await?;
        }
        if requested_groups.len() > 1 {
            run_checked(
                &self.runner,
                "usermod",
                &[
                    "--append".into(),
                    "--groups".into(),
                    requested_groups[1..].join(","),
                    user.into(),
                ],
            )
            .await?;
        }
        Ok(())
    }

    async fn set_ownership(
        &self,
        path: &std::path::Path,
        user: &str,
        group: &str,
        recursive: bool,
    ) -> Result<()> {
        validate_identity(user)?;
        validate_identity(group)?;
        if !path.is_absolute() {
            return Err(ManagerError::InvalidConfig(
                "ownership target must be absolute".into(),
            ));
        }
        let mut args = Vec::new();
        if recursive {
            args.push("-R".into());
        }
        args.push(format!("{user}:{group}"));
        args.push(path.to_string_lossy().into_owned());
        run_checked(&self.runner, "chown", &args).await
    }
}

#[derive(Debug, Clone, Default)]
pub struct NftablesFirewallManager {
    runner: ProcessCommandRunner,
}

#[async_trait]
impl FirewallManager for NftablesFirewallManager {
    async fn enable(&self, config: &ManagerConfig) -> Result<()> {
        run_tun_internal(TunInternalAction::FirewallUp, config).await
    }

    async fn disable(&self) -> Result<()> {
        run_tun_internal(TunInternalAction::FirewallDown, &ManagerConfig::default()).await
    }

    async fn show(&self) -> Result<String> {
        let output = self
            .runner
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
        if output.status == 0 {
            Ok(output.stdout)
        } else {
            Err(command_error("nft", &output.stderr))
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct IpRoutePolicyManager {
    runner: ProcessCommandRunner,
}

#[async_trait]
impl PolicyRoutingManager for IpRoutePolicyManager {
    async fn enable(&self, config: &ManagerConfig) -> Result<()> {
        run_tun_internal(TunInternalAction::RoutesUp, config).await
    }

    async fn attach_tun(&self, config: &ManagerConfig) -> Result<()> {
        run_tun_internal(TunInternalAction::Attach, config).await
    }

    async fn detach_tun(&self, config: &ManagerConfig) -> Result<()> {
        run_tun_internal(TunInternalAction::Detach, config).await
    }

    async fn disable(&self, config: &ManagerConfig) -> Result<()> {
        run_tun_internal(TunInternalAction::RoutesDown, config).await
    }

    async fn show(&self, config: &ManagerConfig) -> Result<String> {
        let mut output = String::new();
        for args in [
            vec!["rule".into(), "show".into()],
            vec![
                "route".into(),
                "show".into(),
                "table".into(),
                config.tun.routing_table.to_string(),
            ],
            vec!["-6".into(), "rule".into(), "show".into()],
            vec![
                "-6".into(),
                "route".into(),
                "show".into(),
                "table".into(),
                config.tun.routing_table.to_string(),
            ],
        ] {
            let result = self.runner.run("ip", &args).await?;
            if result.status != 0 {
                return Err(command_error("ip", &result.stderr));
            }
            output.push_str(&format!("$ ip {}\n{}", args.join(" "), result.stdout));
        }
        Ok(output)
    }
}

#[derive(Debug, Clone, Default)]
pub struct LinuxTunManager {
    runner: ProcessCommandRunner,
}

#[async_trait]
impl TunManager for LinuxTunManager {
    async fn status(&self, interface: &str) -> Result<bool> {
        let output = self
            .runner
            .run(
                "ip",
                &["link".into(), "show".into(), "dev".into(), interface.into()],
            )
            .await?;
        Ok(output.status == 0)
    }
}

#[derive(Debug, Clone, Default)]
pub struct LinuxMountIsolation;

#[async_trait]
impl MountIsolation for LinuxMountIsolation {
    async fn supported(&self) -> Result<bool> {
        Ok(command_exists("unshare") && command_exists("mount"))
    }
}

#[derive(Debug, Clone, Default)]
pub struct LinuxAppRunner {
    runner: ProcessCommandRunner,
}

impl LinuxAppRunner {
    async fn routed_command(&self, request: AppLaunchRequest) -> Result<Command> {
        if request.command.is_empty() {
            return Err(ManagerError::InvalidConfig(
                "application command cannot be empty".into(),
            ));
        }
        let user = if request.user.is_empty() {
            std::env::var("SUDO_USER").unwrap_or_default()
        } else {
            request.user
        };
        validate_identity(&user)?;
        if user == "root" {
            return Err(ManagerError::InvalidConfig(
                "refusing to launch a routed desktop application as root".into(),
            ));
        }
        let uid = numeric_id(&self.runner, "id", &["-u".into(), user.clone()]).await?;
        let gid = numeric_id(&self.runner, "id", &["-g".into(), user.clone()]).await?;
        let supplementary_gids = numeric_groups(&self.runner, &user).await?;
        let home = user_home(&self.runner, &user).await?;
        let tun_gid = group_id(&self.runner, "xray-tun").await?;
        let executable =
            std::env::current_exe().map_err(|error| ManagerError::Io(error.to_string()))?;
        let mut command = Command::new("unshare");
        command.args([
            "--mount",
            "--fork",
            "--kill-child",
            "--propagation",
            "private",
        ]);
        command.arg(executable).args([
            "internal",
            "app-enter",
            "--uid",
            &uid.to_string(),
            "--gid",
            &gid.to_string(),
            "--tun-gid",
            &tun_gid.to_string(),
            "--user",
            &user,
            "--home",
            &home.to_string_lossy(),
        ]);
        for supplementary_gid in supplementary_gids {
            command
                .arg("--supplementary-gid")
                .arg(supplementary_gid.to_string());
        }
        if request.override_dns {
            command.arg("--override-dns");
        }
        if request.clear_proxy_environment {
            command.arg("--clear-proxy-environment");
        }
        if let Some(directory) = request.working_directory {
            command.arg("--working-directory").arg(directory);
        }
        for (key, value) in request.environment {
            validate_environment_key(&key)?;
            command.arg("--env").arg(format!("{key}={value}"));
        }
        command.arg("--").args(request.command);
        Ok(command)
    }
}

#[async_trait]
impl AppRunner for LinuxAppRunner {
    async fn run(&self, request: AppLaunchRequest) -> Result<i32> {
        let status = self
            .routed_command(request)
            .await?
            .status()
            .await
            .map_err(|error| ManagerError::Io(error.to_string()))?;
        Ok(status.code().unwrap_or(1))
    }

    async fn test_route(&self, request: AppRouteTestRequest) -> Result<AppRouteTestResult> {
        if !command_exists("curl") {
            return Err(ManagerError::PlatformUnsupported {
                capability: xray_manager_core::ports::Capability::AppRunner,
                platform: "linux".into(),
                backend: Some("linux-gid-mountns".into()),
                reason: "route testing requires curl".into(),
                recommendation: Some("Install it explicitly: sudo pacman -S --needed curl".into()),
            });
        }
        let timeout_seconds = request.timeout.as_secs().max(1).to_string();
        let curl_command = vec![
            "curl".into(),
            "--fail".into(),
            "--silent".into(),
            "--show-error".into(),
            "--ipv4".into(),
            "--noproxy".into(),
            "*".into(),
            "--max-time".into(),
            timeout_seconds,
            request.url.clone(),
        ];
        let mut direct = Command::new(&curl_command[0]);
        direct.args(&curl_command[1..]);
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
            direct.env_remove(key);
        }
        let direct = direct
            .output()
            .await
            .map_err(|error| ManagerError::Io(error.to_string()))?;
        if !direct.status.success() {
            return Err(ManagerError::Other(
                "direct IP check failed; verify Internet access and the configured endpoint".into(),
            ));
        }
        let routed = self
            .routed_command(AppLaunchRequest {
                command: curl_command,
                user: request.user,
                override_dns: request.override_dns,
                clear_proxy_environment: true,
                working_directory: None,
                environment: BTreeMap::new(),
            })
            .await?
            .output()
            .await
            .map_err(|error| ManagerError::Io(error.to_string()))?;
        if !routed.status.success() {
            return Err(ManagerError::Other(
                "TUN IP check failed; verify the selective TUN policy and DNS isolation".into(),
            ));
        }
        let direct_ip = parse_external_ip(&direct.stdout, "direct")?;
        let routed_ip = parse_external_ip(&routed.stdout, "TUN")?;
        if direct_ip == routed_ip {
            return Err(ManagerError::Validation(format!(
                "selective route test failed: direct and TUN IP are both {direct_ip}"
            )));
        }
        Ok(AppRouteTestResult {
            direct_ip: direct_ip.to_string(),
            routed_ip: routed_ip.to_string(),
            routes_differ: true,
        })
    }
}

#[derive(Debug, Clone, Default)]
pub struct Kde6DesktopProxyManager {
    runner: ProcessCommandRunner,
}

#[async_trait]
impl DesktopProxyManager for Kde6DesktopProxyManager {
    async fn enable(&self, user: &str, config: &ManagerConfig) -> Result<()> {
        validate_identity(user)?;
        kde_backup(&self.runner, user).await?;
        let entries = [
            ("ProxyType", "1".to_owned()),
            (
                "httpProxy",
                format!("http://{} {}", config.proxy.listen, config.proxy.http_port),
            ),
            (
                "httpsProxy",
                format!("http://{} {}", config.proxy.listen, config.proxy.http_port),
            ),
            (
                "socksProxy",
                format!(
                    "socks://{} {}",
                    config.proxy.listen, config.proxy.socks_port
                ),
            ),
        ];
        for (key, value) in entries {
            kde_write(&self.runner, user, key, &value).await?;
        }
        kde_reload(&self.runner, user).await
    }

    async fn disable(&self, user: &str) -> Result<()> {
        validate_identity(user)?;
        kde_write(&self.runner, user, "ProxyType", "0").await?;
        kde_reload(&self.runner, user).await
    }
}

#[derive(Debug, Clone, Default)]
pub struct LinuxPrivilegeChecker;

#[async_trait]
impl PrivilegeChecker for LinuxPrivilegeChecker {
    async fn is_elevated(&self) -> Result<bool> {
        Ok(nix::unistd::geteuid().is_root())
    }
}

#[derive(Debug, Clone, Default)]
pub struct LinuxPlatformInspector;

#[async_trait]
impl PlatformInspector for LinuxPlatformInspector {
    async fn inspect(&self) -> Result<PlatformInfo> {
        let release = tokio::fs::read_to_string("/etc/os-release")
            .await
            .unwrap_or_default();
        let fields: BTreeMap<_, _> = release
            .lines()
            .filter_map(|line| line.split_once('='))
            .map(|(key, value)| (key, value.trim_matches('"')))
            .collect();
        Ok(PlatformInfo {
            os: "linux".into(),
            distribution: fields.get("ID").map(|value| (*value).to_owned()),
            init_system: command_exists("systemctl").then(|| "systemd".into()),
            desktop: std::env::var("XDG_CURRENT_DESKTOP").ok(),
        })
    }
}

async fn kde_backup(runner: &ProcessCommandRunner, user: &str) -> Result<()> {
    let home = user_home(runner, user).await?;
    let source = home.join(".config/kioslaverc");
    let backup = home.join(".config/kioslaverc.xray-manager-backup");
    let exists = runner
        .run(
            "runuser",
            &[
                "--user".into(),
                user.into(),
                "--".into(),
                "test".into(),
                "-f".into(),
                source.to_string_lossy().into_owned(),
            ],
        )
        .await?;
    if exists.status != 0 {
        return Ok(());
    }
    run_checked(
        runner,
        "runuser",
        &[
            "--user".into(),
            user.into(),
            "--".into(),
            "cp".into(),
            "--preserve=mode,timestamps".into(),
            "--no-clobber".into(),
            source.to_string_lossy().into_owned(),
            backup.to_string_lossy().into_owned(),
        ],
    )
    .await
}

async fn numeric_id(runner: &ProcessCommandRunner, program: &str, args: &[String]) -> Result<u32> {
    let output = runner.run(program, args).await?;
    if output.status != 0 {
        return Err(command_error(program, &output.stderr));
    }
    output
        .stdout
        .trim()
        .parse()
        .map_err(|_| ManagerError::Other(format!("{program} returned a non-numeric ID")))
}

async fn group_id(runner: &ProcessCommandRunner, group: &str) -> Result<u32> {
    let output = runner
        .run("getent", &["group".into(), group.into()])
        .await?;
    if output.status != 0 {
        return Err(command_error("getent", &output.stderr));
    }
    output
        .stdout
        .trim()
        .split(':')
        .nth(2)
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| ManagerError::Other(format!("unable to resolve {group} GID")))
}

async fn numeric_groups(runner: &ProcessCommandRunner, user: &str) -> Result<Vec<u32>> {
    let output = runner.run("id", &["-G".into(), user.into()]).await?;
    if output.status != 0 {
        return Err(command_error("id", &output.stderr));
    }
    output
        .stdout
        .split_whitespace()
        .map(|value| {
            value
                .parse()
                .map_err(|_| ManagerError::Other("id returned a non-numeric group ID".into()))
        })
        .collect()
}

async fn user_home(runner: &ProcessCommandRunner, user: &str) -> Result<PathBuf> {
    let output = runner
        .run("getent", &["passwd".into(), user.into()])
        .await?;
    if output.status != 0 {
        return Err(command_error("getent", &output.stderr));
    }
    output
        .stdout
        .trim()
        .split(':')
        .nth(5)
        .filter(|value| value.starts_with('/'))
        .map(PathBuf::from)
        .ok_or_else(|| ManagerError::Other(format!("unable to resolve home for {user}")))
}

async fn run_checked(runner: &ProcessCommandRunner, program: &str, args: &[String]) -> Result<()> {
    let output = runner.run(program, args).await?;
    if output.status == 0 {
        Ok(())
    } else {
        Err(command_error(program, &output.stderr))
    }
}

fn command_error(program: &str, stderr: &str) -> ManagerError {
    ManagerError::Other(format!("{program} failed: {}", stderr.trim()))
}

fn validate_identity(value: &str) -> Result<()> {
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

fn validate_environment_key(key: &str) -> Result<()> {
    if key.is_empty()
        || key.contains('=')
        || !key
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || character == '_')
    {
        return Err(ManagerError::InvalidConfig(
            "invalid application environment variable name".into(),
        ));
    }
    Ok(())
}

async fn kde_write(
    runner: &ProcessCommandRunner,
    user: &str,
    key: &str,
    value: &str,
) -> Result<()> {
    run_checked(
        runner,
        "runuser",
        &[
            "--login".into(),
            "--user".into(),
            user.into(),
            "--".into(),
            "kwriteconfig6".into(),
            "--file".into(),
            "kioslaverc".into(),
            "--group".into(),
            "Proxy Settings".into(),
            "--key".into(),
            key.into(),
            value.into(),
        ],
    )
    .await
}

async fn kde_reload(runner: &ProcessCommandRunner, user: &str) -> Result<()> {
    let uid = numeric_id(runner, "id", &["-u".into(), user.into()]).await?;
    run_checked(
        runner,
        "runuser",
        &[
            "--user".into(),
            user.into(),
            "--".into(),
            "env".into(),
            format!("DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{uid}/bus"),
            "dbus-send".into(),
            "--session".into(),
            "--type=signal".into(),
            "/KIO/Scheduler".into(),
            "org.kde.KIO.Scheduler.reparseSlaveConfiguration".into(),
            "string:".into(),
        ],
    )
    .await
}

fn parse_external_ip(bytes: &[u8], route: &str) -> Result<std::net::IpAddr> {
    let value = std::str::from_utf8(bytes).map(str::trim).map_err(|_| {
        ManagerError::Validation(format!("{route} IP check returned non-UTF-8 data"))
    })?;
    value.parse().map_err(|_| {
        ManagerError::Validation(format!("{route} IP check returned an invalid IP address"))
    })
}

pub struct AppNamespaceRequest {
    pub uid: u32,
    pub gid: u32,
    pub tun_gid: u32,
    pub user: String,
    pub home: PathBuf,
    pub supplementary_gids: Vec<u32>,
    pub override_dns: bool,
    pub clear_proxy_environment: bool,
    pub working_directory: Option<PathBuf>,
    pub environment: Vec<String>,
    pub command: Vec<String>,
}

pub fn enter_app_namespace(request: AppNamespaceRequest, config: &ManagerConfig) -> Result<()> {
    use nix::mount::{MsFlags, mount};
    use nix::unistd::{Gid, Uid, setgid, setgroups, setuid};
    use std::os::unix::process::CommandExt;

    if request.command.is_empty() {
        return Err(ManagerError::InvalidConfig(
            "application command cannot be empty".into(),
        ));
    }
    if request.override_dns {
        let directory = PathBuf::from("/run/xray-manager/app-dns");
        std::fs::create_dir_all(&directory).map_err(|error| ManagerError::Io(error.to_string()))?;
        let path = directory.join(format!("resolv-{}-{}", request.uid, std::process::id()));
        let contents = config
            .dns
            .tun_servers
            .iter()
            .map(|server| format!("nameserver {server}\n"))
            .collect::<String>();
        std::fs::write(&path, contents).map_err(|error| ManagerError::Io(error.to_string()))?;
        mount(
            Some(path.as_path()),
            "/etc/resolv.conf",
            Option::<&str>::None,
            MsFlags::MS_BIND,
            Option::<&str>::None,
        )
        .map_err(|error| ManagerError::Other(format!("DNS bind mount failed: {error}")))?;
        let _ = std::fs::remove_file(path);
    }
    let mut groups = request.supplementary_gids;
    groups.extend([request.gid, request.tun_gid]);
    groups.sort_unstable();
    groups.dedup();
    let groups = groups.into_iter().map(Gid::from_raw).collect::<Vec<_>>();
    setgroups(&groups)
        .map_err(|error| ManagerError::Other(format!("setgroups failed: {error}")))?;
    setgid(Gid::from_raw(request.gid))
        .map_err(|error| ManagerError::Other(format!("setgid failed: {error}")))?;
    setuid(Uid::from_raw(request.uid))
        .map_err(|error| ManagerError::Other(format!("setuid failed: {error}")))?;

    let mut process = std::process::Command::new(&request.command[0]);
    process.args(&request.command[1..]);
    process.env("HOME", request.home);
    process.env("USER", &request.user);
    process.env("LOGNAME", request.user);
    let runtime_directory = format!("/run/user/{}", request.uid);
    if std::path::Path::new(&runtime_directory).is_dir() {
        process.env("XDG_RUNTIME_DIR", &runtime_directory);
        process.env(
            "DBUS_SESSION_BUS_ADDRESS",
            format!("unix:path={runtime_directory}/bus"),
        );
    }
    if let Some(directory) = request.working_directory {
        process.current_dir(directory);
    }
    if request.clear_proxy_environment {
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
            process.env_remove(key);
        }
    }
    for pair in request.environment {
        let (key, value) = pair.split_once('=').ok_or_else(|| {
            ManagerError::InvalidConfig("application environment must use KEY=VALUE".into())
        })?;
        validate_environment_key(key)?;
        process.env(key, value);
    }
    Err(ManagerError::Io(process.exec().to_string()))
}

#[cfg(test)]
mod tests {
    use super::parse_external_ip;

    #[test]
    fn external_ip_parser_accepts_only_an_ip_address() {
        assert_eq!(
            parse_external_ip(b"203.0.113.9\n", "direct")
                .expect("valid IPv4")
                .to_string(),
            "203.0.113.9"
        );
        assert!(parse_external_ip(b"<html>error</html>", "TUN").is_err());
    }
}
