use super::{ParsedNode, node_from_url, query_map, split_csv};
use crate::domain::{Node, Protocol, Security, Transport};
use crate::{ManagerError, Result};
use std::collections::{BTreeMap, BTreeSet};
use url::Url;

pub fn parse_hysteria2(uri: &str, subscription: &str) -> Result<Node> {
    let normalized = uri.replacen("hy2://", "hysteria2://", 1);
    let url =
        Url::parse(&normalized).map_err(|error| ManagerError::InvalidNode(error.to_string()))?;
    let auth = percent_encoding::percent_decode_str(url.username())
        .decode_utf8_lossy()
        .into_owned();
    if auth.is_empty() {
        return Err(ManagerError::InvalidNode("Hysteria2 auth is empty".into()));
    }
    let query = query_map(&url);
    let known: BTreeSet<&str> = [
        "sni",
        "insecure",
        "alpn",
        "pinSHA256",
        "obfs",
        "obfs-password",
        "mport",
        "upmbps",
        "downmbps",
    ]
    .into_iter()
    .collect();
    let mut warnings: Vec<String> = query
        .keys()
        .filter(|key| !known.contains(key.as_str()))
        .map(|key| format!("unsupported Hysteria2 parameter: {key}"))
        .collect();
    if query.get("obfs").is_some_and(|value| value != "salamander") {
        warnings.push("unsupported Hysteria2 obfs".into());
    }
    let mut extra = BTreeMap::new();
    for (key, value) in &query {
        extra.insert(key.clone(), value.clone());
    }
    node_from_url(
        &url,
        uri,
        subscription,
        ParsedNode {
            protocol: Protocol::Hysteria2,
            user: None,
            password: Some(auth),
            transport: Transport {
                kind: "hysteria".into(),
                ..Transport::default()
            },
            security: Security {
                kind: "tls".into(),
                server_name: query.get("sni").cloned(),
                alpn: split_csv(query.get("alpn")),
                allow_insecure: query
                    .get("insecure")
                    .is_some_and(|value| matches!(value.as_str(), "1" | "true")),
                pinned_peer_cert_sha256: query.get("pinSHA256").cloned(),
                ..Security::default()
            },
            warnings,
            extra,
        },
    )
}
