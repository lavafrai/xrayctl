use base64::Engine;
use serde_json::Value;
use std::collections::BTreeMap;
use xray_manager_core::config::{AppProfile, ManagerConfig};
use xray_manager_core::domain::reconcile_selected;
use xray_manager_core::dto::NodeDto;
use xray_manager_core::ports::AppLaunchRequest;
use xray_manager_core::protocols::parse_uri;
use xray_manager_core::render::render_xray_config;
use xray_manager_core::routing::RoutingConfig;
use xray_manager_core::subscription::parse_subscription;

const UUID: &str = "123e4567-e89b-12d3-a456-426614174000";
const UUID_2: &str = "123e4567-e89b-12d3-a456-426614174001";

fn vless(name: &str) -> String {
    format!("vless://{UUID}@example.com:443?security=tls&type=ws&path=%2Fws#{name}")
}

#[test]
fn parses_vless_and_percent_encoded_name() {
    let node = parse_uri(
        &format!(
            "vless://{UUID}@example.com:443?security=reality&type=grpc&pbk=public&sid=ab#Frankfurt%20One"
        ),
        "main",
    )
    .expect("VLESS should parse");
    assert_eq!(node.name, "Frankfurt One");
    assert_eq!(node.transport.kind, "grpc");
    assert_eq!(node.security.kind, "reality");
}

#[test]
fn rejects_invalid_vless_uuid() {
    assert!(parse_uri("vless://bad@example.com:443", "main").is_err());
}

#[test]
fn rejects_unknown_uri_scheme() {
    assert!(parse_uri("https://example.com/node", "main").is_err());
}

#[test]
fn rejects_missing_port() {
    assert!(parse_uri(&format!("vless://{UUID}@example.com"), "main").is_err());
}

#[test]
fn preserves_unknown_query_as_warning() {
    let node = parse_uri(
        &format!("vless://{UUID}@example.com:443?mystery=yes"),
        "main",
    )
    .expect("VLESS should parse");
    assert_eq!(node.warnings, ["unknown query parameter: mystery"]);
}

#[test]
fn parses_trojan() {
    let node = parse_uri(
        "trojan://secret@example.com:443?security=tls&type=ws&sni=cdn.example#node",
        "main",
    )
    .expect("Trojan should parse");
    assert_eq!(node.name, "node");
    assert_eq!(node.transport.kind, "ws");
}

#[test]
fn parses_vmess_base64_json() {
    let json = serde_json::json!({
        "add": "vmess.example",
        "port": "443",
        "id": UUID,
        "aid": 0,
        "scy": "auto",
        "net": "ws",
        "host": "cdn.example",
        "path": "/ws",
        "tls": "tls",
        "ps": "Warsaw"
    });
    let encoded = base64::engine::general_purpose::STANDARD.encode(json.to_string());
    let node = parse_uri(&format!("vmess://{encoded}"), "main").expect("VMess should parse");
    assert_eq!(node.server, "vmess.example");
    assert_eq!(node.name, "Warsaw");
}

#[test]
fn rejects_invalid_vmess_json() {
    let encoded = base64::engine::general_purpose::STANDARD.encode("not-json");
    assert!(parse_uri(&format!("vmess://{encoded}"), "main").is_err());
}

#[test]
fn parses_shadowsocks_sip002() {
    let credentials = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode("aes-128-gcm:secret");
    let node = parse_uri(
        &format!("ss://{credentials}@ss.example:8388#Stockholm"),
        "main",
    )
    .expect("Shadowsocks should parse");
    assert_eq!(
        node.extra.get("method").map(String::as_str),
        Some("aes-128-gcm")
    );
}

#[test]
fn parses_legacy_shadowsocks_authority() {
    let authority = base64::engine::general_purpose::STANDARD
        .encode("chacha20-ietf-poly1305:secret@ss.example:443");
    let node = parse_uri(&format!("ss://{authority}#Legacy"), "main")
        .expect("legacy Shadowsocks should parse");
    assert_eq!(node.port, 443);
}

#[test]
fn warns_about_unknown_shadowsocks_plugin() {
    let credentials = base64::engine::general_purpose::STANDARD_NO_PAD.encode("aes-256-gcm:secret");
    let node = parse_uri(
        &format!("ss://{credentials}@ss.example:443?plugin=unknown#Plugin"),
        "main",
    )
    .expect("Shadowsocks should parse");
    assert!(node.warnings[0].contains("unsupported"));
}

#[test]
fn recognized_shadowsocks_plugin_is_never_silently_ignored() {
    let credentials = base64::engine::general_purpose::STANDARD_NO_PAD.encode("aes-256-gcm:secret");
    let node = parse_uri(
        &format!("ss://{credentials}@ss.example:443?plugin=v2ray-plugin%3Btls#Plugin"),
        "main",
    )
    .expect("Shadowsocks should parse");
    assert!(node.warnings[0].contains("recognized"));
    let routing = RoutingConfig::preset("global-proxy").expect("preset");
    assert!(render_xray_config(&ManagerConfig::default(), Some(&node), &routing, vec![]).is_err());
}

#[test]
fn raw_http_header_is_rendered_explicitly() {
    let node = parse_uri(
        &format!(
            "vless://{UUID}@example.com:443?type=raw&headerType=http&host=cdn.example&path=%2Fraw"
        ),
        "main",
    )
    .expect("VLESS RAW node should parse");
    let routing = RoutingConfig::preset("global-proxy").expect("preset");
    let files = render_xray_config(&ManagerConfig::default(), Some(&node), &routing, vec![])
        .expect("RAW config should render");
    assert_eq!(
        files["30_outbounds.json"]["outbounds"][0]["streamSettings"]["rawSettings"]["header"]["request"]
            ["headers"]["Host"][0],
        "cdn.example"
    );
}

#[test]
fn parses_hysteria2_alias_and_tls() {
    let node = parse_uri(
        "hy2://password@hy.example:443?sni=cdn.example&alpn=h3&insecure=1#Prague",
        "main",
    )
    .expect("Hysteria2 should parse");
    assert_eq!(node.security.server_name.as_deref(), Some("cdn.example"));
    assert!(node.security.allow_insecure);
}

#[test]
fn unsupported_hysteria_parameter_does_not_break_parse() {
    let node = parse_uri(
        "hysteria2://password@hy.example:443?unknown=value#Prague",
        "main",
    )
    .expect("node should remain visible");
    assert!(!node.warnings.is_empty());
}

#[test]
fn parses_plain_subscription_with_comments() {
    let input = format!("# comment\n\n{}\n", vless("A"));
    let result = parse_subscription(input.as_bytes(), "main").expect("subscription should parse");
    assert_eq!(result.nodes.len(), 1);
}

#[test]
fn parses_whole_subscription_standard_base64() {
    let encoded = base64::engine::general_purpose::STANDARD.encode(vless("A"));
    let result = parse_subscription(encoded.as_bytes(), "main").expect("Base64 should parse");
    assert_eq!(result.nodes.len(), 1);
}

#[test]
fn parses_urlsafe_subscription_without_padding() {
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(vless("A"));
    let result = parse_subscription(encoded.as_bytes(), "main").expect("Base64 should parse");
    assert_eq!(result.nodes.len(), 1);
}

#[test]
fn rejects_html_subscription() {
    assert!(parse_subscription(b"<!doctype html><h1>error</h1>", "main").is_err());
}

#[test]
fn debug_and_dto_redact_secrets() {
    let uri = vless("Secret");
    let node = parse_uri(&uri, "main").expect("node should parse");
    let debug = format!("{node:?}");
    assert!(!debug.contains(UUID));
    assert!(!debug.contains(&uri));
    let dto = serde_json::to_string(&NodeDto::from(&node)).expect("DTO should serialize");
    assert!(!dto.contains(UUID));
    assert!(!dto.contains("vless://"));
}

#[test]
fn fingerprint_ignores_display_name() {
    let first = parse_uri(&vless("One"), "main").expect("node should parse");
    let second = parse_uri(&vless("Two"), "main").expect("node should parse");
    assert_eq!(first.id, second.id);
}

#[test]
fn fingerprint_changes_with_credentials() {
    let first = parse_uri(&vless("One"), "main").expect("node should parse");
    let second = parse_uri(
        &format!("vless://{UUID_2}@example.com:443?security=tls&type=ws&path=%2Fws#One"),
        "main",
    )
    .expect("node should parse");
    assert_ne!(first.id, second.id);
}

#[test]
fn reconciliation_uses_unique_subscription_and_name() {
    let old = parse_uri(&vless("One"), "main").expect("old node");
    let replacement =
        parse_uri(&format!("vless://{UUID_2}@example.com:443#One"), "main").expect("replacement");
    assert_eq!(
        reconcile_selected(&old, &old.id, std::slice::from_ref(&replacement))
            .map(|node| node.id.as_str()),
        Some(replacement.id.as_str())
    );
}

#[test]
fn reconciliation_rejects_ambiguous_name() {
    let old = parse_uri(&vless("One"), "main").expect("old node");
    let first =
        parse_uri(&format!("vless://{UUID_2}@one.example:443#One"), "main").expect("replacement");
    let second = parse_uri(
        "vless://123e4567-e89b-12d3-a456-426614174002@two.example:443#One",
        "main",
    )
    .expect("replacement");
    assert!(reconcile_selected(&old, &old.id, &[first, second]).is_none());
}

#[test]
fn configuration_defaults_are_safe() {
    let config = ManagerConfig::default();
    config.validate().expect("defaults should validate");
    assert!(config.proxy.listen.is_loopback());
    assert_eq!(config.proxy.socks_port, 10808);
    assert_eq!(config.proxy.http_port, 10809);
    assert_eq!(config.tun.routing_table, 166);
    assert!(config.tun.fail_closed);
}

#[test]
fn configuration_rejects_values_that_runtime_cannot_use() {
    let mut config = ManagerConfig::default();
    config.proxy.socks_port = 0;
    assert!(config.validate().is_err());

    let mut config = ManagerConfig::default();
    config.tun.mtu = 500;
    assert!(config.validate().is_err());

    let mut config = ManagerConfig::default();
    config.dns.mode = "ignored-mode".into();
    assert!(config.validate().is_err());

    let mut config = ManagerConfig::default();
    config.dns.tun_servers.clear();
    assert!(config.validate().is_err());
}

#[test]
fn platform_configuration_accepts_public_backend_keys() {
    let config = ManagerConfig::parse(
        r#"
[platform]
layout = "auto"
installer = "auto"
identity = "auto"
service = "auto"
firewall = "auto"
policy_routing = "auto"
tun = "auto"
app_runner = "auto"
mount_isolation = "auto"
desktop_proxy = "auto"
package_advisor = "auto"
"#,
    )
    .expect("platform config");
    assert_eq!(
        config
            .platform
            .backends
            .get(&xray_manager_core::ports::Capability::Install)
            .map(String::as_str),
        Some("auto")
    );
}

#[test]
fn rejects_non_https_asset() {
    let mut config = ManagerConfig::default();
    config.assets[0].url = "http://example.com/geoip.dat".into();
    assert!(config.validate().is_err());
}

#[test]
fn rejects_asset_filename_path_traversal() {
    let mut config = ManagerConfig::default();
    config.assets[0].filename = "../../etc/passwd".into();
    let encoded = toml::to_string(&config).expect("configuration should encode");
    assert!(ManagerConfig::parse(&encoded).is_err());
}

#[test]
fn rejects_duplicate_asset_destinations() {
    let mut config = ManagerConfig::default();
    config.assets[1].filename = config.assets[0].filename.clone();
    let encoded = toml::to_string(&config).expect("configuration should encode");
    assert!(ManagerConfig::parse(&encoded).is_err());
}

#[test]
fn routing_preserves_order_and_adds_catch_all() {
    let routing = RoutingConfig::parse(
        r#"
domain_strategy = "AsIs"
default_outbound = "proxy"

[[rules]]
name = "one"
domain = ["geosite:private"]
outbound = "direct"

[[rules]]
name = "two"
ip = ["geoip:private"]
outbound = "direct"
"#,
    )
    .expect("routing should parse");
    let json = routing.to_xray_json();
    let rules = json["routing"]["rules"].as_array().expect("rules array");
    assert_eq!(rules[0]["domain"][0], "geosite:private");
    assert_eq!(rules[1]["ip"][0], "geoip:private");
    assert_eq!(rules[2]["network"], "tcp,udp");
}

#[test]
fn routing_rejects_unknown_rule_outbound() {
    let input = r#"
domain_strategy = "AsIs"
default_outbound = "proxy"

[[rules]]
name = "broken"
enabled = true
outbound = "missing"
"#;
    assert!(RoutingConfig::parse(input).is_err());
}

#[test]
fn all_runetfreedom_presets_render() {
    for name in ["global-proxy", "runet-blocked-only", "ru-direct"] {
        let preset = RoutingConfig::preset(name).expect("known preset");
        assert!(preset.to_xray_json()["routing"]["rules"].is_array());
    }
}

#[test]
fn renderer_uses_blackhole_without_active_node() {
    let config = ManagerConfig::default();
    let routing = RoutingConfig::preset("global-proxy").expect("preset");
    let files = render_xray_config(&config, None, &routing, Vec::<Value>::new())
        .expect("config should render");
    assert_eq!(
        files["30_outbounds.json"]["outbounds"][0]["protocol"],
        "blackhole"
    );
    assert_eq!(
        files["20_inbounds.json"]["inbounds"][2]["settings"]["name"],
        "xray0"
    );
}

#[test]
fn renderer_keeps_all_outbounds_in_one_file() {
    let config = ManagerConfig::default();
    let routing = RoutingConfig::preset("global-proxy").expect("preset");
    let node = parse_uri(&vless("A"), "main").expect("node");
    let files =
        render_xray_config(&config, Some(&node), &routing, vec![]).expect("config should render");
    assert_eq!(
        files["30_outbounds.json"]["outbounds"]
            .as_array()
            .map(Vec::len),
        Some(3)
    );
}

#[test]
fn hysteria_renderer_maps_confirmed_finalmask_fields() {
    let config = ManagerConfig::default();
    let routing = RoutingConfig::preset("global-proxy").expect("preset");
    let node = parse_uri(
        "hysteria2://secret@hy.example:443?sni=cdn.example&obfs=salamander&obfs-password=mask&mport=20000-20100&upmbps=50&downmbps=100#HY2",
        "main",
    )
    .expect("Hysteria2 should parse");
    let files = render_xray_config(&config, Some(&node), &routing, vec![])
        .expect("Hysteria2 should render");
    let stream = &files["30_outbounds.json"]["outbounds"][0]["streamSettings"];
    assert_eq!(stream["finalmask"]["udp"][0]["type"], "salamander");
    assert_eq!(
        stream["finalmask"]["quicParams"]["udpHop"]["ports"],
        "20000-20100"
    );
}

#[test]
fn hysteria_renderer_refuses_unknown_fields() {
    let config = ManagerConfig::default();
    let routing = RoutingConfig::preset("global-proxy").expect("preset");
    let node = parse_uri(
        "hysteria2://secret@hy.example:443?future-field=value#HY2",
        "main",
    )
    .expect("Hysteria2 should remain visible");
    assert!(render_xray_config(&config, Some(&node), &routing, vec![]).is_err());
}

#[test]
fn app_profile_parses() {
    let profile = AppProfile::parse(
        r#"
name = "discord"
command = ["discord", "--no-proxy-server"]
clear_proxy_environment = true
override_dns = true
environment = { WAYLAND_DISPLAY = "wayland-0" }
"#,
    )
    .expect("app profile");
    assert_eq!(profile.command[0], "discord");
    assert!(profile.override_dns);
}

#[test]
fn app_launch_clears_both_proxy_environment_casings() {
    let request = AppLaunchRequest {
        command: vec!["curl".into()],
        user: "desktop".into(),
        override_dns: false,
        clear_proxy_environment: true,
        working_directory: None,
        environment: [("KEEP".into(), "yes".into())].into_iter().collect(),
    };
    let inherited: BTreeMap<_, _> = [
        ("HTTP_PROXY".into(), "http://127.0.0.1:10809".into()),
        ("all_proxy".into(), "socks5://127.0.0.1:10808".into()),
        ("DISPLAY".into(), ":0".into()),
    ]
    .into_iter()
    .collect();
    let sanitized = request.sanitized_environment(inherited);
    assert!(!sanitized.contains_key("HTTP_PROXY"));
    assert!(!sanitized.contains_key("all_proxy"));
    assert_eq!(sanitized.get("DISPLAY").map(String::as_str), Some(":0"));
    assert_eq!(sanitized.get("KEEP").map(String::as_str), Some("yes"));
}
