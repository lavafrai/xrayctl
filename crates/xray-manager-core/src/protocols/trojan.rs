use super::{ParsedNode, node_from_url, query_map, split_csv};
use crate::domain::{Node, Protocol, Security, Transport};
use crate::{ManagerError, Result};
use std::collections::BTreeSet;
use url::Url;

pub fn parse_trojan(uri: &str, subscription: &str) -> Result<Node> {
    let url = Url::parse(uri).map_err(|error| ManagerError::InvalidNode(error.to_string()))?;
    let password = percent_encoding::percent_decode_str(url.username())
        .decode_utf8_lossy()
        .into_owned();
    if password.is_empty() {
        return Err(ManagerError::InvalidNode("Trojan password is empty".into()));
    }
    let query = query_map(&url);
    let known: BTreeSet<&str> = [
        "security",
        "type",
        "sni",
        "fp",
        "pbk",
        "sid",
        "spx",
        "alpn",
        "path",
        "host",
        "serviceName",
        "authority",
    ]
    .into_iter()
    .collect();
    let warnings = query
        .keys()
        .filter(|key| !known.contains(key.as_str()))
        .map(|key| format!("unknown query parameter: {key}"))
        .collect();
    node_from_url(
        &url,
        uri,
        subscription,
        ParsedNode {
            protocol: Protocol::Trojan,
            user: None,
            password: Some(password),
            transport: Transport {
                kind: query.get("type").cloned().unwrap_or_else(|| "tcp".into()),
                path: query.get("path").cloned(),
                host: query.get("host").cloned(),
                service_name: query.get("serviceName").cloned(),
                authority: query.get("authority").cloned(),
                ..Transport::default()
            },
            security: Security {
                kind: query
                    .get("security")
                    .cloned()
                    .unwrap_or_else(|| "tls".into()),
                server_name: query.get("sni").cloned(),
                fingerprint: query.get("fp").cloned(),
                public_key: query.get("pbk").cloned(),
                short_id: query.get("sid").cloned(),
                spider_x: query.get("spx").cloned(),
                alpn: split_csv(query.get("alpn")),
                ..Security::default()
            },
            warnings,
            extra: query,
        },
    )
}
