mod hysteria2;
mod shadowsocks;
mod trojan;
mod vless;
pub(crate) mod vmess;

use crate::domain::{Node, NodeId, Protocol, SecretCredentials, Security, Transport};
use crate::{ManagerError, Result};
use secrecy::SecretString;
use std::collections::BTreeMap;
use url::Url;

pub use hysteria2::parse_hysteria2;
pub use shadowsocks::parse_shadowsocks;
pub use trojan::parse_trojan;
pub use vless::parse_vless;
pub use vmess::parse_vmess;

pub fn parse_uri(uri: &str, subscription: &str) -> Result<Node> {
    let scheme = uri
        .split_once(':')
        .map(|(scheme, _)| scheme.to_ascii_lowercase())
        .ok_or_else(|| ManagerError::InvalidNode("URI has no scheme".into()))?;
    match scheme.as_str() {
        "vless" => parse_vless(uri, subscription),
        "vmess" => parse_vmess(uri, subscription),
        "trojan" => parse_trojan(uri, subscription),
        "ss" => parse_shadowsocks(uri, subscription),
        "hysteria2" | "hy2" => parse_hysteria2(uri, subscription),
        _ => Err(ManagerError::InvalidNode(format!(
            "unsupported URI scheme: {scheme}"
        ))),
    }
}

struct ParsedNode {
    protocol: Protocol,
    user: Option<String>,
    password: Option<String>,
    transport: Transport,
    security: Security,
    warnings: Vec<String>,
    extra: BTreeMap<String, String>,
}

fn node_from_url(url: &Url, raw_uri: &str, subscription: &str, parsed: ParsedNode) -> Result<Node> {
    let server = url
        .host_str()
        .filter(|host| !host.is_empty())
        .ok_or_else(|| ManagerError::InvalidNode("missing server".into()))?
        .to_owned();
    let port = url
        .port()
        .ok_or_else(|| ManagerError::InvalidNode("missing or invalid port".into()))?;
    let name = url
        .fragment()
        .map(decode_component)
        .filter(|name| !name.trim().is_empty())
        .unwrap_or_else(|| format!("{server}:{port}"));
    let mut node = Node {
        id: NodeId::new("pending"),
        subscription: subscription.into(),
        name,
        protocol: parsed.protocol,
        server,
        port,
        credentials: SecretCredentials {
            user: parsed.user.map(SecretString::from),
            password: parsed.password.map(SecretString::from),
        },
        transport: parsed.transport,
        security: parsed.security,
        raw_uri: SecretString::from(raw_uri.to_owned()),
        warnings: parsed.warnings,
        extra: parsed.extra,
    };
    node.refresh_id();
    Ok(node)
}

fn decode_component(input: &str) -> String {
    percent_encoding::percent_decode_str(input)
        .decode_utf8_lossy()
        .into_owned()
}

fn query_map(url: &Url) -> BTreeMap<String, String> {
    url.query_pairs()
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect()
}

fn split_csv(value: Option<&String>) -> Vec<String> {
    value
        .map(|value| {
            value
                .split(',')
                .filter(|item| !item.is_empty())
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}
