use super::{ParsedNode, node_from_url};
use crate::domain::{Node, Protocol, Security, Transport};
use crate::protocols::vmess::decode_flexible_base64;
use crate::{ManagerError, Result};
use std::collections::BTreeMap;
use url::Url;

pub fn parse_shadowsocks(uri: &str, subscription: &str) -> Result<Node> {
    let body = uri
        .strip_prefix("ss://")
        .ok_or_else(|| ManagerError::InvalidNode("invalid Shadowsocks scheme".into()))?;
    let (without_fragment, fragment) = body.split_once('#').unwrap_or((body, ""));
    let (authority, query) = without_fragment
        .split_once('?')
        .map_or((without_fragment, ""), |parts| parts);
    let expanded = if authority.contains('@') {
        authority.to_owned()
    } else {
        String::from_utf8(decode_flexible_base64(authority)?)
            .map_err(|_| ManagerError::InvalidNode("Shadowsocks Base64 is not UTF-8".into()))?
    };
    let (userinfo, endpoint) = expanded
        .rsplit_once('@')
        .ok_or_else(|| ManagerError::InvalidNode("Shadowsocks URI has no endpoint".into()))?;
    let decoded_userinfo = if userinfo.contains(':') {
        percent_encoding::percent_decode_str(userinfo)
            .decode_utf8_lossy()
            .into_owned()
    } else {
        String::from_utf8(decode_flexible_base64(userinfo)?)
            .map_err(|_| ManagerError::InvalidNode("Shadowsocks userinfo is not UTF-8".into()))?
    };
    let (method, password) = decoded_userinfo
        .split_once(':')
        .ok_or_else(|| ManagerError::InvalidNode("missing Shadowsocks method/password".into()))?;
    let normalized = format!(
        "ss://{}:{}@{}#{}",
        percent_encoding::utf8_percent_encode(method, percent_encoding::NON_ALPHANUMERIC),
        percent_encoding::utf8_percent_encode(password, percent_encoding::NON_ALPHANUMERIC),
        endpoint,
        fragment
    );
    let url =
        Url::parse(&normalized).map_err(|error| ManagerError::InvalidNode(error.to_string()))?;
    let query_map: BTreeMap<String, String> = url::form_urlencoded::parse(query.as_bytes())
        .into_owned()
        .collect();
    let mut warnings = Vec::new();
    if let Some(plugin) = query_map.get("plugin") {
        let known = ["v2ray-plugin", "obfs-local"];
        if known.iter().any(|known| plugin.starts_with(known)) {
            warnings.push(format!(
                "recognized Shadowsocks plugin is not supported by the built-in Xray adapter: {plugin}"
            ));
        } else {
            warnings.push(format!("unsupported Shadowsocks plugin: {plugin}"));
        }
    }
    let mut extra = query_map;
    extra.insert("method".into(), method.into());
    node_from_url(
        &url,
        uri,
        subscription,
        ParsedNode {
            protocol: Protocol::Shadowsocks,
            user: None,
            password: Some(password.into()),
            transport: Transport {
                kind: "tcp".into(),
                ..Transport::default()
            },
            security: Security::default(),
            warnings,
            extra,
        },
    )
}
