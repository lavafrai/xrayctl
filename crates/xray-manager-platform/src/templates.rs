use xray_manager_core::config::{ManagerConfig, TunConfig};

pub fn xray_service() -> &'static str {
    r#"[Unit]
Description=Xray proxy service managed by xrayctl
After=network-online.target xray-tun-policy.service
Wants=network-online.target

[Service]
Type=simple
User=xray
Group=xray
SupplementaryGroups=xray-manager
Environment=XRAY_LOCATION_ASSET=/opt/xray-manager/assets/current
RuntimeDirectory=xray-manager
RuntimeDirectoryMode=0750
ExecStartPre=/opt/xray-manager/core/current/xray run -test -confdir /var/lib/xray-manager/current/conf.d
ExecStart=/opt/xray-manager/core/current/xray run -confdir /var/lib/xray-manager/current/conf.d
ExecStartPost=/usr/local/bin/xrayctl internal tun-attach
ExecStopPost=/usr/local/bin/xrayctl internal tun-detach
Restart=on-failure
RestartSec=3
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
LockPersonality=true
RestrictRealtime=true
DevicePolicy=closed
DeviceAllow=/dev/net/tun rw
ReadOnlyPaths=/etc/xray-manager /opt/xray-manager
ReadWritePaths=/run/xray-manager

[Install]
WantedBy=multi-user.target
"#
}

pub fn tun_policy_service() -> &'static str {
    r#"[Unit]
Description=Selective Xray TUN policy
Before=xray.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/bin/xrayctl internal tun-policy-up
ExecStop=/usr/local/bin/xrayctl internal tun-policy-down
CapabilityBoundingSet=CAP_NET_ADMIN
AmbientCapabilities=CAP_NET_ADMIN
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true

[Install]
WantedBy=multi-user.target
"#
}

pub fn nftables(config: &TunConfig, tun_gid: u32) -> String {
    let private_ipv4 = if config.bypass_private_networks {
        "ip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 } return"
    } else {
        ""
    };
    let private_ipv6 = if config.bypass_private_networks {
        "ip6 daddr fc00::/7 return"
    } else {
        ""
    };
    format!(
        r#"table inet xray_manager {{
  chain output {{
    type route hook output priority mangle; policy accept;
    oifname "lo" return
    ip daddr 127.0.0.0/8 return
    ip daddr 169.254.0.0/16 return
    ip daddr 224.0.0.0/4 return
    ip6 daddr ::1 return
    ip6 daddr fe80::/10 return
    ip6 daddr ff00::/8 return
    {private_ipv4}
    {private_ipv6}
    meta skgid {tun_gid} meta mark set {mark}
  }}
}}
"#,
        mark = config.packet_mark
    )
}

pub fn policy_commands(config: &ManagerConfig) -> Vec<Vec<String>> {
    let mark = config.tun.packet_mark.to_string();
    let table = config.tun.routing_table.to_string();
    vec![
        vec![
            "ip".into(),
            "rule".into(),
            "add".into(),
            "fwmark".into(),
            mark.clone(),
            "lookup".into(),
            table.clone(),
        ],
        vec![
            "ip".into(),
            "route".into(),
            "add".into(),
            "blackhole".into(),
            "default".into(),
            "table".into(),
            table.clone(),
            "metric".into(),
            "32767".into(),
        ],
        vec![
            "ip".into(),
            "-6".into(),
            "rule".into(),
            "add".into(),
            "fwmark".into(),
            mark,
            "lookup".into(),
            table.clone(),
        ],
        vec![
            "ip".into(),
            "-6".into(),
            "route".into(),
            "add".into(),
            "unreachable".into(),
            "default".into(),
            "table".into(),
            table,
            "metric".into(),
            "32767".into(),
        ],
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn never_flushes_global_ruleset() {
        let rendered = nftables(&TunConfig::default(), 991);
        assert!(rendered.contains("table inet xray_manager"));
        assert!(!rendered.contains("flush ruleset"));
        assert!(rendered.contains("meta skgid 991"));
        assert!(rendered.contains("ip6 daddr fc00::/7 return"));
    }

    #[test]
    fn units_have_no_update_timers() {
        assert!(!xray_service().contains("OnCalendar"));
        assert!(xray_service().contains("RuntimeDirectory=xray-manager"));
        assert!(xray_service().contains("SupplementaryGroups=xray-manager"));
        assert!(tun_policy_service().contains("RemainAfterExit=yes"));
    }

    #[test]
    fn policy_commands_use_only_dedicated_table_and_mark() {
        let commands = policy_commands(&ManagerConfig::default());
        let rendered = commands
            .iter()
            .map(|parts| parts.join(" "))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(rendered.contains("fwmark 102 lookup 166"));
        assert!(rendered.contains("blackhole default table 166"));
        assert!(!rendered.contains("table main"));
    }
}
