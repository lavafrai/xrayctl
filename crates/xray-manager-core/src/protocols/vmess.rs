use super::decode_component;
use crate::domain::{Node, NodeId, Protocol, SecretCredentials, Security, Transport};
use crate::{ManagerError, Result};
use base64::Engine;
use secrecy::SecretString;
use serde::Deserialize;
use std::collections::BTreeMap;
use uuid::Uuid;

#[derive(Deserialize)]
struct VmessLink {
    add: String,
    port: serde_json::Value,
    id: String,
    #[serde(default)]
    aid: serde_json::Value,
    #[serde(default)]
    scy: String,
    #[serde(default)]
    net: String,
    #[serde(default, rename = "type")]
    header_type: String,
    #[serde(default)]
    host: String,
    #[serde(default)]
    path: String,
    #[serde(default)]
    tls: String,
    #[serde(default)]
    sni: String,
    #[serde(default)]
    alpn: String,
    #[serde(default)]
    fp: String,
    #[serde(default)]
    ps: String,
}

pub fn parse_vmess(uri: &str, subscription: &str) -> Result<Node> {
    let encoded = uri
        .strip_prefix("vmess://")
        .ok_or_else(|| ManagerError::InvalidNode("invalid VMess scheme".into()))?;
    let bytes = decode_flexible_base64(encoded)?;
    let link: VmessLink = serde_json::from_slice(&bytes)
        .map_err(|error| ManagerError::InvalidNode(format!("invalid VMess JSON: {error}")))?;
    Uuid::parse_str(&link.id)
        .map_err(|_| ManagerError::InvalidNode("VMess id must be a valid UUID".into()))?;
    let port = match link.port {
        serde_json::Value::String(value) => value.parse::<u16>().ok(),
        serde_json::Value::Number(value) => {
            value.as_u64().and_then(|value| u16::try_from(value).ok())
        }
        _ => None,
    }
    .ok_or_else(|| ManagerError::InvalidNode("invalid VMess port".into()))?;
    if link.add.trim().is_empty() {
        return Err(ManagerError::InvalidNode("missing VMess server".into()));
    }
    let transport = Transport {
        kind: if link.net.is_empty() {
            "tcp".into()
        } else {
            link.net
        },
        path: (!link.path.is_empty()).then_some(link.path),
        host: (!link.host.is_empty()).then_some(link.host),
        header_type: (!link.header_type.is_empty()).then_some(link.header_type),
        ..Transport::default()
    };
    let security = Security {
        kind: if link.tls.is_empty() {
            "none".into()
        } else {
            link.tls
        },
        server_name: (!link.sni.is_empty()).then_some(link.sni),
        fingerprint: (!link.fp.is_empty()).then_some(link.fp),
        alpn: link
            .alpn
            .split(',')
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
            .collect(),
        ..Security::default()
    };
    let mut extra = BTreeMap::new();
    extra.insert("alterId".into(), json_scalar(&link.aid));
    extra.insert("security".into(), link.scy);
    let mut node = Node {
        id: NodeId::new("pending"),
        subscription: subscription.into(),
        name: if link.ps.is_empty() {
            format!("{}:{port}", link.add)
        } else {
            decode_component(&link.ps)
        },
        protocol: Protocol::Vmess,
        server: link.add,
        port,
        credentials: SecretCredentials {
            user: Some(SecretString::from(link.id)),
            password: None,
        },
        transport,
        security,
        raw_uri: SecretString::from(uri.to_owned()),
        warnings: Vec::new(),
        extra,
    };
    node.refresh_id();
    Ok(node)
}

fn json_scalar(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(value) => value.clone(),
        other => other.to_string(),
    }
}

pub(crate) fn decode_flexible_base64(input: &str) -> Result<Vec<u8>> {
    let trimmed = input.trim();
    let engines = [
        &base64::engine::general_purpose::STANDARD,
        &base64::engine::general_purpose::STANDARD_NO_PAD,
        &base64::engine::general_purpose::URL_SAFE,
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
    ];
    engines
        .iter()
        .find_map(|engine| engine.decode(trimmed).ok())
        .ok_or_else(|| ManagerError::InvalidNode("invalid Base64".into()))
}
