use blake3::Hasher;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use serde::{Deserializer, Serializer};
use std::collections::BTreeMap;
use std::fmt;

#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NodeId(String);

impl NodeId {
    pub fn new(normalized: &str) -> Self {
        let mut hasher = Hasher::new();
        hasher.update(normalized.as_bytes());
        Self(hasher.finalize().to_hex().to_string())
    }

    pub fn short(&self) -> &str {
        &self.0[..12]
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for NodeId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("NodeId")
            .field(&self.short())
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Vless,
    Vmess,
    Trojan,
    Shadowsocks,
    Hysteria2,
}

impl fmt::Display for Protocol {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct SecretCredentials {
    #[serde(
        serialize_with = "serialize_optional_secret",
        deserialize_with = "deserialize_optional_secret"
    )]
    pub user: Option<SecretString>,
    #[serde(
        serialize_with = "serialize_optional_secret",
        deserialize_with = "deserialize_optional_secret"
    )]
    pub password: Option<SecretString>,
}

impl fmt::Debug for SecretCredentials {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretCredentials([REDACTED])")
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Transport {
    pub kind: String,
    pub path: Option<String>,
    pub host: Option<String>,
    pub service_name: Option<String>,
    pub authority: Option<String>,
    pub mode: Option<String>,
    pub header_type: Option<String>,
    pub seed: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Security {
    pub kind: String,
    pub server_name: Option<String>,
    pub fingerprint: Option<String>,
    pub public_key: Option<String>,
    pub short_id: Option<String>,
    pub spider_x: Option<String>,
    pub alpn: Vec<String>,
    pub allow_insecure: bool,
    pub pinned_peer_cert_sha256: Option<String>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Node {
    pub id: NodeId,
    pub subscription: String,
    pub name: String,
    pub protocol: Protocol,
    pub server: String,
    pub port: u16,
    pub credentials: SecretCredentials,
    pub transport: Transport,
    pub security: Security,
    #[serde(
        serialize_with = "serialize_secret",
        deserialize_with = "deserialize_secret"
    )]
    pub raw_uri: SecretString,
    pub warnings: Vec<String>,
    pub extra: BTreeMap<String, String>,
}

impl fmt::Debug for Node {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Node")
            .field("id", &self.id)
            .field("subscription", &self.subscription)
            .field("name", &self.name)
            .field("protocol", &self.protocol)
            .field("server", &self.server)
            .field("port", &self.port)
            .field("credentials", &self.credentials)
            .field("transport", &self.transport)
            .field("security", &self.security)
            .field("raw_uri", &"[REDACTED]")
            .field("warnings", &self.warnings)
            .finish()
    }
}

impl Node {
    pub fn normalized_identity(&self) -> String {
        let user = self
            .credentials
            .user
            .as_ref()
            .map(ExposeSecret::expose_secret)
            .unwrap_or("");
        let password = self
            .credentials
            .password
            .as_ref()
            .map(ExposeSecret::expose_secret)
            .unwrap_or("");
        format!(
            "{:?}|{}|{}|{}|{}|{:?}|{:?}|{}",
            self.protocol,
            self.server.to_ascii_lowercase(),
            self.port,
            user,
            password,
            self.transport,
            self.security,
            self.subscription
        )
    }

    pub fn refresh_id(&mut self) {
        self.id = NodeId::new(&self.normalized_identity());
    }

    pub fn normalized_name(&self) -> String {
        self.name.trim().to_lowercase()
    }
}

fn serialize_secret<S>(value: &SecretString, serializer: S) -> std::result::Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(value.expose_secret())
}

fn deserialize_secret<'de, D>(deserializer: D) -> std::result::Result<SecretString, D::Error>
where
    D: Deserializer<'de>,
{
    String::deserialize(deserializer).map(SecretString::from)
}

fn serialize_optional_secret<S>(
    value: &Option<SecretString>,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error>
where
    S: Serializer,
{
    value
        .as_ref()
        .map(ExposeSecret::expose_secret)
        .serialize(serializer)
}

fn deserialize_optional_secret<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<SecretString>, D::Error>
where
    D: Deserializer<'de>,
{
    Option::<String>::deserialize(deserializer).map(|value| value.map(SecretString::from))
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct ManagerState {
    pub current_core_version: Option<String>,
    pub previous_core_version: Option<String>,
    pub current_asset_generation: Option<String>,
    pub previous_asset_generation: Option<String>,
    pub current_config_generation: Option<String>,
    pub previous_config_generation: Option<String>,
    pub selected_node_id: Option<String>,
    pub last_successful_healthcheck: Option<String>,
    pub last_rollback_reason: Option<String>,
    pub installed_backends: BTreeMap<String, String>,
    pub created_identities: Vec<String>,
}

pub fn reconcile_selected<'a>(
    old: &Node,
    selected_id: &NodeId,
    refreshed: &'a [Node],
) -> Option<&'a Node> {
    if let Some(exact) = refreshed.iter().find(|node| &node.id == selected_id) {
        return Some(exact);
    }
    let matches: Vec<_> = refreshed
        .iter()
        .filter(|node| {
            node.subscription == old.subscription && node.normalized_name() == old.normalized_name()
        })
        .collect();
    (matches.len() == 1).then(|| matches[0])
}
