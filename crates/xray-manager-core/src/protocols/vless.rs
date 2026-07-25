use super::{ParsedNode, node_from_url, query_map, split_csv};
use crate::domain::{Node, Protocol, Security, Transport};
use crate::{ManagerError, Result};
use std::collections::BTreeSet;
use url::Url;
use uuid::Uuid;

pub fn parse_vless(uri: &str, subscription: &str) -> Result<Node> {
    let url = Url::parse(uri).map_err(|error| ManagerError::InvalidNode(error.to_string()))?;
    let user = url.username().to_owned();
    Uuid::parse_str(&user)
        .map_err(|_| ManagerError::InvalidNode("VLESS user must be a valid UUID".into()))?;
    let query = query_map(&url);
    let known: BTreeSet<&str> = [
        "encryption",
        "flow",
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
        "mode",
        "headerType",
        "seed",
    ]
    .into_iter()
    .collect();
    let mut warnings: Vec<String> = query
        .keys()
        .filter(|key| !known.contains(key.as_str()))
        .map(|key| format!("unknown query parameter: {key}"))
        .collect();
    let transport_kind = query.get("type").map_or("tcp", String::as_str);
    if !matches!(
        transport_kind.to_ascii_lowercase().as_str(),
        "tcp" | "raw" | "websocket" | "ws" | "grpc" | "httpupgrade" | "xhttp" | "splithttp"
    ) {
        warnings.push(format!("unsupported VLESS transport: {transport_kind}"));
    }
    if let Some(header_type) = query.get("headerType")
        && !matches!(header_type.to_ascii_lowercase().as_str(), "none" | "http")
    {
        warnings.push(format!("unsupported RAW headerType: {header_type}"));
    }
    if query.contains_key("seed") {
        warnings.push("legacy seed cannot be mapped to the current Xray transport schema".into());
    }
    let transport = Transport {
        kind: query.get("type").cloned().unwrap_or_else(|| "tcp".into()),
        path: query.get("path").cloned(),
        host: query.get("host").cloned(),
        service_name: query.get("serviceName").cloned(),
        authority: query.get("authority").cloned(),
        mode: query.get("mode").cloned(),
        header_type: query.get("headerType").cloned(),
        seed: query.get("seed").cloned(),
    };
    let security = Security {
        kind: query
            .get("security")
            .cloned()
            .unwrap_or_else(|| "none".into()),
        server_name: query.get("sni").cloned(),
        fingerprint: query.get("fp").cloned(),
        public_key: query.get("pbk").cloned(),
        short_id: query.get("sid").cloned(),
        spider_x: query.get("spx").cloned(),
        alpn: split_csv(query.get("alpn")),
        ..Security::default()
    };
    node_from_url(
        &url,
        uri,
        subscription,
        ParsedNode {
            protocol: Protocol::Vless,
            user: Some(user),
            password: None,
            transport,
            security,
            warnings,
            extra: query,
        },
    )
}
