use crate::{Result, error::ManagerError, ports::Capability};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct ManagerConfig {
    pub general: GeneralConfig,
    pub core: CoreConfig,
    pub proxy: ProxyConfig,
    pub dns: DnsConfig,
    pub tun: TunConfig,
    pub menu: MenuConfig,
    pub assets: Vec<AssetConfig>,
    pub platform: PlatformSelection,
}

impl Default for ManagerConfig {
    fn default() -> Self {
        Self {
            general: GeneralConfig::default(),
            core: CoreConfig::default(),
            proxy: ProxyConfig::default(),
            dns: DnsConfig::default(),
            tun: TunConfig::default(),
            menu: MenuConfig::default(),
            assets: vec![
                AssetConfig {
                    id: "geoip".into(),
                    filename: "geoip.dat".into(),
                    url: "https://raw.githubusercontent.com/runetfreedom/russia-v2ray-rules-dat/release/geoip.dat".into(),
                },
                AssetConfig {
                    id: "geosite".into(),
                    filename: "geosite.dat".into(),
                    url: "https://raw.githubusercontent.com/runetfreedom/russia-v2ray-rules-dat/release/geosite.dat".into(),
                },
            ],
            platform: PlatformSelection::default(),
        }
    }
}

impl ManagerConfig {
    pub fn parse(input: &str) -> Result<Self> {
        let config: Self = toml::from_str(input)
            .map_err(|error| ManagerError::InvalidConfig(error.to_string()))?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<()> {
        if self.proxy.socks_port == 0 || self.proxy.http_port == 0 {
            return Err(ManagerError::InvalidConfig(
                "SOCKS and HTTP ports must be non-zero".into(),
            ));
        }
        if self.proxy.socks_port == self.proxy.http_port {
            return Err(ManagerError::InvalidConfig(
                "SOCKS and HTTP ports must be different".into(),
            ));
        }
        if !self.proxy.listen.is_loopback() {
            return Err(ManagerError::InvalidConfig(
                "proxy listen address must be loopback".into(),
            ));
        }
        if self.menu.probe_concurrency == 0 {
            return Err(ManagerError::InvalidConfig(
                "menu.probe_concurrency must be greater than zero".into(),
            ));
        }
        if self.general.connect_timeout_seconds == 0
            || self.general.request_timeout_seconds == 0
            || self.general.max_subscription_size_mb == 0
            || self.general.max_core_archive_size_mb == 0
            || self.general.max_asset_size_mb == 0
        {
            return Err(ManagerError::InvalidConfig(
                "timeouts and download size limits must be greater than zero".into(),
            ));
        }
        if self.menu.probe_timeout_seconds == 0 {
            return Err(ManagerError::InvalidConfig(
                "menu.probe_timeout_seconds must be greater than zero".into(),
            ));
        }
        if self.menu.latency_green_ms > self.menu.latency_yellow_ms {
            return Err(ManagerError::InvalidConfig(
                "menu.latency_green_ms must not exceed menu.latency_yellow_ms".into(),
            ));
        }
        let healthcheck = url::Url::parse(&self.general.healthcheck_url)
            .map_err(|_| ManagerError::InvalidConfig("invalid healthcheck URL".into()))?;
        if healthcheck.scheme() != "https" {
            return Err(ManagerError::InvalidConfig(
                "healthcheck URL must use HTTPS".into(),
            ));
        }
        if self.tun.enabled && !self.tun.fail_closed {
            return Err(ManagerError::InvalidConfig(
                "selective TUN requires fail_closed = true".into(),
            ));
        }
        if !(576..=9000).contains(&self.tun.mtu) {
            return Err(ManagerError::InvalidConfig(
                "TUN MTU must be between 576 and 9000".into(),
            ));
        }
        if self.dns.mode != "system" {
            return Err(ManagerError::InvalidConfig(
                "only dns.mode = \"system\" is supported".into(),
            ));
        }
        if !matches!(
            self.dns.query_strategy.as_str(),
            "UseIP" | "UseIPv4" | "UseIPv6" | "UseSystem"
        ) {
            return Err(ManagerError::InvalidConfig(
                "dns.query_strategy must be UseIP, UseIPv4, UseIPv6, or UseSystem".into(),
            ));
        }
        if self.tun.override_resolv_conf_for_apps && self.dns.tun_servers.is_empty() {
            return Err(ManagerError::InvalidConfig(
                "dns.tun_servers cannot be empty when per-app DNS override is enabled".into(),
            ));
        }
        if self.tun.interface_name.is_empty()
            || self.tun.interface_name.len() > 15
            || !self.tun.interface_name.chars().all(|character| {
                character.is_ascii_alphanumeric() || matches!(character, '-' | '_')
            })
        {
            return Err(ManagerError::InvalidConfig(
                "TUN interface name must be 1-15 ASCII letters, digits, '-' or '_'".into(),
            ));
        }
        if matches!(self.tun.routing_table, 0 | 253 | 254 | 255) || self.tun.packet_mark == 0 {
            return Err(ManagerError::InvalidConfig(
                "TUN requires a non-system routing table and non-zero packet mark".into(),
            ));
        }
        if self.core.channel != "stable" {
            return Err(ManagerError::InvalidConfig(
                "only core.channel = \"stable\" is supported".into(),
            ));
        }
        if !self.core.pinned_version.is_empty() {
            return Err(ManagerError::InvalidConfig(
                "core.pinned_version is not implemented; leave it empty".into(),
            ));
        }
        validate_repository(&self.core.repository, "core.repository")?;
        if let Some(repository) = &self.core.manager_repository {
            validate_repository(repository, "core.manager_repository")?;
        }
        let (gateway, prefix) = self
            .tun
            .ipv4_gateway
            .split_once('/')
            .ok_or_else(|| ManagerError::InvalidConfig("invalid TUN IPv4 gateway".into()))?;
        if gateway.parse::<Ipv4Addr>().is_err()
            || prefix.parse::<u8>().map_or(true, |prefix| prefix > 32)
        {
            return Err(ManagerError::InvalidConfig(
                "invalid TUN IPv4 gateway".into(),
            ));
        }
        let mut asset_ids = BTreeSet::new();
        let mut asset_filenames = BTreeSet::new();
        for asset in &self.assets {
            if asset.id.is_empty()
                || !asset.id.chars().all(|character| {
                    character.is_ascii_alphanumeric() || matches!(character, '-' | '_')
                })
            {
                return Err(ManagerError::InvalidConfig(
                    "asset IDs may contain only ASCII letters, digits, '-' and '_'".into(),
                ));
            }
            let filename = std::path::Path::new(&asset.filename);
            if asset.filename.is_empty()
                || filename.file_name().and_then(|value| value.to_str())
                    != Some(asset.filename.as_str())
                || filename.components().count() != 1
            {
                return Err(ManagerError::InvalidConfig(
                    "asset filename must be a single UTF-8 file name without a path".into(),
                ));
            }
            if !asset_ids.insert(asset.id.as_str()) {
                return Err(ManagerError::InvalidConfig(format!(
                    "duplicate asset ID '{}'",
                    asset.id
                )));
            }
            if !asset_filenames.insert(asset.filename.as_str()) {
                return Err(ManagerError::InvalidConfig(format!(
                    "duplicate asset filename '{}'",
                    asset.filename
                )));
            }
            let parsed = url::Url::parse(&asset.url)
                .map_err(|error| ManagerError::InvalidConfig(error.to_string()))?;
            if parsed.scheme() != "https" {
                return Err(ManagerError::InvalidConfig(format!(
                    "asset {} must use HTTPS",
                    asset.id
                )));
            }
        }
        Ok(())
    }
}

fn validate_repository(value: &str, field: &str) -> Result<()> {
    let mut parts = value.split('/');
    let owner = parts.next().unwrap_or_default();
    let repository = parts.next().unwrap_or_default();
    if owner.is_empty()
        || repository.is_empty()
        || parts.next().is_some()
        || !value.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.' | '/')
        })
    {
        return Err(ManagerError::InvalidConfig(format!(
            "{field} must use owner/repository form"
        )));
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct GeneralConfig {
    pub keep_generations: usize,
    pub keep_core_versions: usize,
    pub keep_asset_generations: usize,
    pub connect_timeout_seconds: u64,
    pub request_timeout_seconds: u64,
    pub max_subscription_size_mb: u64,
    pub max_core_archive_size_mb: u64,
    pub max_asset_size_mb: u64,
    pub healthcheck_url: String,
}

impl Default for GeneralConfig {
    fn default() -> Self {
        Self {
            keep_generations: 3,
            keep_core_versions: 2,
            keep_asset_generations: 2,
            connect_timeout_seconds: 8,
            request_timeout_seconds: 20,
            max_subscription_size_mb: 20,
            max_core_archive_size_mb: 150,
            max_asset_size_mb: 200,
            healthcheck_url: "https://www.gstatic.com/generate_204".into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct CoreConfig {
    pub repository: String,
    pub channel: String,
    pub pinned_version: String,
    pub manager_repository: Option<String>,
}

impl Default for CoreConfig {
    fn default() -> Self {
        Self {
            repository: "XTLS/Xray-core".into(),
            channel: "stable".into(),
            pinned_version: String::new(),
            manager_repository: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct ProxyConfig {
    pub listen: IpAddr,
    pub socks_port: u16,
    pub http_port: u16,
    pub udp: bool,
    pub sniffing: bool,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            listen: IpAddr::V4(Ipv4Addr::LOCALHOST),
            socks_port: 10808,
            http_port: 10809,
            udp: true,
            sniffing: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct DnsConfig {
    pub mode: String,
    pub tun_servers: Vec<IpAddr>,
    pub query_strategy: String,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            mode: "system".into(),
            tun_servers: vec![
                IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
                IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            ],
            query_strategy: "UseIP".into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct TunConfig {
    pub enabled: bool,
    pub interface_name: String,
    pub mtu: u16,
    pub ipv4_gateway: String,
    pub ipv6_enabled: bool,
    pub routing_table: u32,
    pub packet_mark: u32,
    pub bypass_private_networks: bool,
    pub fail_closed: bool,
    pub override_resolv_conf_for_apps: bool,
}

impl Default for TunConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interface_name: "xray0".into(),
            mtu: 1500,
            ipv4_gateway: "172.31.255.1/30".into(),
            ipv6_enabled: false,
            routing_table: 166,
            packet_mark: 102,
            bypass_private_networks: true,
            fail_closed: true,
            override_resolv_conf_for_apps: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct MenuConfig {
    pub probe_on_open: bool,
    pub probe_concurrency: usize,
    pub probe_timeout_seconds: u64,
    pub latency_green_ms: u64,
    pub latency_yellow_ms: u64,
}

impl Default for MenuConfig {
    fn default() -> Self {
        Self {
            probe_on_open: true,
            probe_concurrency: 4,
            probe_timeout_seconds: 8,
            latency_green_ms: 200,
            latency_yellow_ms: 500,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AssetConfig {
    pub id: String,
    pub filename: String,
    pub url: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct PlatformSelection {
    #[serde(flatten)]
    pub backends: BTreeMap<Capability, String>,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SubscriptionConfig {
    pub name: String,
    pub enabled: bool,
    pub url: String,
    #[serde(default = "default_subscription_format")]
    pub format: String,
}

impl std::fmt::Debug for SubscriptionConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SubscriptionConfig")
            .field("name", &self.name)
            .field("enabled", &self.enabled)
            .field("url", &"[REDACTED]")
            .field("format", &self.format)
            .finish()
    }
}

fn default_subscription_format() -> String {
    "auto".into()
}

impl SubscriptionConfig {
    pub fn validate(&self) -> Result<()> {
        if self.name.is_empty()
            || !self.name.chars().all(|character| {
                character.is_ascii_alphanumeric() || matches!(character, '-' | '_')
            })
        {
            return Err(ManagerError::InvalidConfig(
                "subscription name may contain only ASCII letters, digits, '-' and '_'".into(),
            ));
        }
        let url = url::Url::parse(&self.url)
            .map_err(|_| ManagerError::InvalidConfig("invalid subscription URL".into()))?;
        if url.scheme() != "https" {
            return Err(ManagerError::InvalidConfig(
                "subscription URL must use HTTPS".into(),
            ));
        }
        if self.format != "auto" {
            return Err(ManagerError::InvalidConfig(
                "only subscription format 'auto' is supported".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AppProfile {
    pub name: String,
    pub command: Vec<String>,
    #[serde(default = "default_true")]
    pub clear_proxy_environment: bool,
    #[serde(default)]
    pub override_dns: bool,
    #[serde(default)]
    pub working_directory: Option<PathBuf>,
    #[serde(default)]
    pub environment: BTreeMap<String, String>,
}

fn default_true() -> bool {
    true
}

impl AppProfile {
    pub fn parse(input: &str) -> Result<Self> {
        let profile: Self = toml::from_str(input)
            .map_err(|error| ManagerError::InvalidConfig(error.to_string()))?;
        profile.validate()?;
        Ok(profile)
    }

    pub fn validate(&self) -> Result<()> {
        if self.name.is_empty() || self.command.is_empty() || self.command[0].is_empty() {
            return Err(ManagerError::InvalidConfig(
                "app profile requires a name and non-empty command".into(),
            ));
        }
        if !self
            .name
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_'))
        {
            return Err(ManagerError::InvalidConfig(
                "app profile name may contain only ASCII letters, digits, '-' and '_'".into(),
            ));
        }
        if self.environment.keys().any(|key| {
            key.is_empty()
                || !key
                    .chars()
                    .all(|character| character.is_ascii_alphanumeric() || character == '_')
        }) {
            return Err(ManagerError::InvalidConfig(
                "invalid app profile environment variable name".into(),
            ));
        }
        Ok(())
    }
}
