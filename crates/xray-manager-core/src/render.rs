use crate::config::ManagerConfig;
use crate::domain::{Node, Protocol};
use crate::routing::RoutingConfig;
use crate::{ManagerError, Result};
use secrecy::ExposeSecret;
use serde_json::{Value, json};
use std::collections::BTreeMap;

pub type ConfigFiles = BTreeMap<String, Value>;

pub fn render_xray_config(
    config: &ManagerConfig,
    node: Option<&Node>,
    routing: &RoutingConfig,
    custom: Vec<Value>,
) -> Result<ConfigFiles> {
    let proxy = match node {
        Some(node) => render_proxy_outbound(node)?,
        None => json!({"tag": "proxy", "protocol": "blackhole"}),
    };
    let mut files = BTreeMap::new();
    files.insert(
        "00_log.json".into(),
        json!({"log": {"loglevel": "warning"}}),
    );
    files.insert(
        "10_dns.json".into(),
        json!({"dns": {"queryStrategy": config.dns.query_strategy}}),
    );
    let mut inbounds = vec![
        json!({
            "tag": "socks-in",
            "listen": config.proxy.listen,
            "port": config.proxy.socks_port,
            "protocol": "socks",
            "settings": {"udp": config.proxy.udp},
            "sniffing": {"enabled": config.proxy.sniffing, "destOverride": ["http", "tls"]}
        }),
        json!({
            "tag": "http-in",
            "listen": config.proxy.listen,
            "port": config.proxy.http_port,
            "protocol": "http",
            "settings": {},
            "sniffing": {"enabled": config.proxy.sniffing, "destOverride": ["http", "tls"]}
        }),
    ];
    if config.tun.enabled {
        let mut gateway = vec![config.tun.ipv4_gateway.clone()];
        if config.tun.ipv6_enabled {
            gateway.push("fd00:31:255::1/126".into());
        }
        inbounds.push(json!({
            "tag": "tun-in",
            "protocol": "tun",
            "settings": {
                "name": config.tun.interface_name,
                "mtu": config.tun.mtu,
                "gateway": gateway,
                "autoOutboundsInterface": "auto"
            },
            "sniffing": {"enabled": config.proxy.sniffing, "destOverride": ["http", "tls"]}
        }));
    }
    files.insert("20_inbounds.json".into(), json!({"inbounds": inbounds}));
    files.insert(
        "30_outbounds.json".into(),
        json!({"outbounds": [
            proxy,
            {"tag": "direct", "protocol": "freedom"},
            {"tag": "block", "protocol": "blackhole"}
        ]}),
    );
    files.insert("40_routing.json".into(), routing.to_xray_json());
    files.insert(
        "50_policy.json".into(),
        json!({"policy": {"levels": {"0": {"handshake": 8, "connIdle": 300}}}}),
    );
    let mut custom_config = serde_json::Map::new();
    for fragment in custom {
        let object = fragment.as_object().ok_or_else(|| {
            ManagerError::InvalidConfig("custom fragment must be a JSON object".into())
        })?;
        for (key, value) in object {
            custom_config.insert(key.clone(), value.clone());
        }
    }
    files.insert("80_custom.json".into(), Value::Object(custom_config));
    Ok(files)
}

fn render_proxy_outbound(node: &Node) -> Result<Value> {
    let password = node
        .credentials
        .password
        .as_ref()
        .map(ExposeSecret::expose_secret);
    let user = node
        .credentials
        .user
        .as_ref()
        .map(ExposeSecret::expose_secret);
    let outbound = match node.protocol {
        Protocol::Vless => json!({
            "tag": "proxy",
            "protocol": "vless",
            "settings": {"vnext": [{
                "address": node.server,
                "port": node.port,
                "users": [{
                    "id": required(user, "VLESS UUID")?,
                    "encryption": node.extra.get("encryption").map_or("none", String::as_str),
                    "flow": node.extra.get("flow").map_or("", String::as_str)
                }]
            }]},
            "streamSettings": render_stream(node)?
        }),
        Protocol::Vmess => json!({
            "tag": "proxy",
            "protocol": "vmess",
            "settings": {"vnext": [{
                "address": node.server,
                "port": node.port,
                "users": [{
                    "id": required(user, "VMess UUID")?,
                    "alterId": node.extra.get("alterId").and_then(|v| v.parse::<u32>().ok()).unwrap_or(0),
                    "security": node.extra.get("security").map_or("auto", String::as_str)
                }]
            }]},
            "streamSettings": render_stream(node)?
        }),
        Protocol::Trojan => json!({
            "tag": "proxy",
            "protocol": "trojan",
            "settings": {"servers": [{
                "address": node.server,
                "port": node.port,
                "password": required(password, "Trojan password")?
            }]},
            "streamSettings": render_stream(node)?
        }),
        Protocol::Shadowsocks => {
            if let Some(plugin) = node.extra.get("plugin") {
                return Err(ManagerError::Validation(format!(
                    "Shadowsocks plugin cannot be represented by the built-in Xray adapter: {plugin}"
                )));
            }
            json!({
                "tag": "proxy",
                "protocol": "shadowsocks",
                "settings": {"servers": [{
                    "address": node.server,
                    "port": node.port,
                    "method": node.extra.get("method").map_or("", String::as_str),
                    "password": required(password, "Shadowsocks password")?
                }]}
            })
        }
        Protocol::Hysteria2 => {
            if !node.warnings.is_empty() {
                return Err(ManagerError::Validation(format!(
                    "Hysteria2 node has unsupported parameters: {}",
                    node.warnings.join(", ")
                )));
            }
            let mut stream = render_stream(node)?;
            stream["network"] = json!("hysteria");
            stream["hysteriaSettings"] = json!({
                "version": 2,
                "auth": required(password, "Hysteria2 auth")?
            });
            json!({
                "tag": "proxy",
                "protocol": "hysteria",
                "settings": {"version": 2, "address": node.server, "port": node.port},
                "streamSettings": stream
            })
        }
    };
    Ok(outbound)
}

fn render_stream(node: &Node) -> Result<Value> {
    let method = normalize_network(&node.transport.kind);
    if !matches!(
        method,
        "tcp" | "ws" | "grpc" | "httpupgrade" | "xhttp" | "hysteria"
    ) {
        return Err(ManagerError::Validation(format!(
            "unsupported Xray transport: {}",
            node.transport.kind
        )));
    }
    let mut stream = json!({
        "method": method,
        "network": method,
        "security": node.security.kind
    });
    if node.security.kind == "reality" {
        stream["realitySettings"] = json!({
            "serverName": node.security.server_name,
            "fingerprint": node.security.fingerprint,
            "alpn": node.security.alpn,
            "password": node.security.public_key,
            "publicKey": node.security.public_key,
            "shortId": node.security.short_id,
            "spiderX": node.security.spider_x
        });
    } else if node.security.kind == "tls" {
        stream["tlsSettings"] = json!({
            "serverName": node.security.server_name,
            "fingerprint": node.security.fingerprint,
            "alpn": node.security.alpn,
            "allowInsecure": node.security.allow_insecure,
            "pinnedPeerCertSha256": node.security.pinned_peer_cert_sha256
        });
    }
    let settings_key = match method {
        "ws" => Some("wsSettings"),
        "grpc" => Some("grpcSettings"),
        "httpupgrade" => Some("httpupgradeSettings"),
        "xhttp" => Some("xhttpSettings"),
        _ => None,
    };
    if let Some(key) = settings_key {
        stream[key] = json!({
            "path": node.transport.path,
            "host": node.transport.host,
            "serviceName": node.transport.service_name,
            "authority": node.transport.authority,
            "mode": node.transport.mode
        });
    }
    if method == "tcp"
        && let Some(header_type) = node.transport.header_type.as_deref()
    {
        let header_type = header_type.to_ascii_lowercase();
        if !matches!(header_type.as_str(), "none" | "http") {
            return Err(ManagerError::Validation(format!(
                "unsupported RAW headerType: {header_type}"
            )));
        }
        let mut header = json!({"type": header_type});
        if header_type == "http" {
            if let Some(path) = node.transport.path.as_ref() {
                header["request"]["path"] = json!([path]);
            }
            if let Some(host) = node.transport.host.as_ref() {
                header["request"]["headers"]["Host"] = json!([host]);
            }
        }
        stream["rawSettings"] = json!({"header": header});
    }
    if node.transport.seed.is_some() {
        return Err(ManagerError::Validation(
            "legacy seed cannot be mapped to the current Xray transport schema".into(),
        ));
    }
    if let Some(finalmask) = render_finalmask(node)? {
        stream["finalmask"] = finalmask;
    }
    Ok(stream)
}

fn render_finalmask(node: &Node) -> Result<Option<Value>> {
    let mut finalmask = match node.extra.get("fm") {
        Some(encoded) => match serde_json::from_str::<Value>(encoded) {
            Ok(Value::Object(object)) => object,
            Ok(_) => {
                return Err(ManagerError::Validation(
                    "FinalMask fm must be a JSON object".into(),
                ));
            }
            Err(error) => {
                return Err(ManagerError::Validation(format!(
                    "invalid FinalMask fm JSON: {error}"
                )));
            }
        },
        None => serde_json::Map::new(),
    };

    if let Some(fragment) = node.extra.get("fragment") {
        let mut fields = fragment.split(',');
        let length = fields.next();
        let delay = fields.next();
        let packets = fields.next();
        if fields.next().is_some()
            || !length.is_some_and(is_numeric_range)
            || !delay.is_some_and(is_numeric_range)
            || packets != Some("tlshello")
        {
            return Err(ManagerError::Validation(
                "fragment must use length,delay,tlshello".into(),
            ));
        }
        push_finalmask(
            &mut finalmask,
            "tcp",
            json!({
                "type": "fragment",
                "settings": {
                    "length": length,
                    "delay": delay,
                    "packets": packets
                }
            }),
        )?;
    }

    // Some subscription producers include both the authoritative `fm` JSON
    // and legacy Hysteria aliases for older clients. Applying both would stack
    // the same Salamander/QUIC mask twice and make the connection unusable.
    if node.protocol == Protocol::Hysteria2 && !node.extra.contains_key("fm") {
        if node
            .extra
            .get("obfs")
            .is_some_and(|value| value == "salamander")
        {
            let obfs_password = node
                .extra
                .get("obfs-password")
                .ok_or_else(|| ManagerError::Validation("missing obfs-password".into()))?;
            push_finalmask(
                &mut finalmask,
                "udp",
                json!({"type": "salamander", "settings": {"password": obfs_password}}),
            )?;
        }
        if node.extra.contains_key("mport")
            || node.extra.contains_key("upmbps")
            || node.extra.contains_key("downmbps")
        {
            let quic = finalmask
                .entry("quicParams")
                .or_insert_with(|| json!({}))
                .as_object_mut()
                .ok_or_else(|| {
                    ManagerError::Validation("FinalMask quicParams must be an object".into())
                })?;
            if let Some(ports) = node.extra.get("mport") {
                quic.entry("udpHop")
                    .or_insert_with(|| json!({"ports": ports}));
            }
            if let Some(value) = node.extra.get("upmbps") {
                quic.entry("brutalUp")
                    .or_insert_with(|| json!(format!("{value} mbps")));
            }
            if let Some(value) = node.extra.get("downmbps") {
                quic.entry("brutalDown")
                    .or_insert_with(|| json!(format!("{value} mbps")));
            }
        }
    }

    Ok((!finalmask.is_empty()).then_some(Value::Object(finalmask)))
}

fn push_finalmask(
    finalmask: &mut serde_json::Map<String, Value>,
    direction: &str,
    mask: Value,
) -> Result<()> {
    finalmask
        .entry(direction)
        .or_insert_with(|| Value::Array(Vec::new()))
        .as_array_mut()
        .ok_or_else(|| ManagerError::Validation(format!("FinalMask {direction} must be an array")))?
        .push(mask);
    Ok(())
}

fn is_numeric_range(value: &str) -> bool {
    let mut bounds = value.split('-');
    let start = bounds.next();
    let end = bounds.next();
    bounds.next().is_none()
        && start.is_some_and(|value| value.parse::<u32>().is_ok())
        && end.is_some_and(|value| value.parse::<u32>().is_ok())
}

fn normalize_network(network: &str) -> &str {
    match network.to_ascii_lowercase().as_str() {
        "tcp" | "raw" => "tcp",
        "websocket" | "ws" => "ws",
        "grpc" => "grpc",
        "httpupgrade" => "httpupgrade",
        "xhttp" | "splithttp" => "xhttp",
        "hysteria" => "hysteria",
        _ => network,
    }
}

fn required<'a>(value: Option<&'a str>, label: &str) -> Result<&'a str> {
    value.ok_or_else(|| ManagerError::Validation(format!("missing {label}")))
}
