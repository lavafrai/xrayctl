use crate::{ManagerError, Result};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RoutingConfig {
    #[serde(default = "default_domain_strategy")]
    pub domain_strategy: String,
    #[serde(default = "default_outbound")]
    pub default_outbound: String,
    #[serde(default)]
    pub rules: Vec<RoutingRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RoutingRule {
    pub name: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub domain: Vec<String>,
    #[serde(default)]
    pub ip: Vec<String>,
    pub port: Option<String>,
    pub source_port: Option<String>,
    pub local_port: Option<String>,
    pub network: Option<String>,
    #[serde(default)]
    pub source_ip: Vec<String>,
    #[serde(default)]
    pub local_ip: Vec<String>,
    #[serde(default)]
    pub inbound_tag: Vec<String>,
    #[serde(default)]
    pub protocol: Vec<String>,
    #[serde(default)]
    pub process: Vec<String>,
    pub outbound: String,
}

impl RoutingConfig {
    pub fn parse(input: &str) -> Result<Self> {
        let config: Self = toml::from_str(input)
            .map_err(|error| ManagerError::InvalidConfig(error.to_string()))?;
        if !["proxy", "direct", "block"].contains(&config.default_outbound.as_str()) {
            return Err(ManagerError::InvalidConfig(
                "default_outbound must be proxy, direct, or block".into(),
            ));
        }
        if !["AsIs", "IPIfNonMatch", "IPOnDemand"].contains(&config.domain_strategy.as_str()) {
            return Err(ManagerError::InvalidConfig(
                "domain_strategy must be AsIs, IPIfNonMatch, or IPOnDemand".into(),
            ));
        }
        let mut names = std::collections::BTreeSet::new();
        for rule in &config.rules {
            if rule.name.trim().is_empty() || !names.insert(rule.name.as_str()) {
                return Err(ManagerError::InvalidConfig(
                    "routing rule names must be non-empty and unique".into(),
                ));
            }
            if !["proxy", "direct", "block"].contains(&rule.outbound.as_str()) {
                return Err(ManagerError::InvalidConfig(format!(
                    "routing rule '{}' has an unknown outbound",
                    rule.name
                )));
            }
        }
        Ok(config)
    }

    pub fn to_xray_json(&self) -> Value {
        let mut rules: Vec<Value> = self
            .rules
            .iter()
            .filter(|rule| rule.enabled)
            .map(RoutingRule::to_xray_json)
            .collect();
        rules.push(json!({
            "type": "field",
            "network": "tcp,udp",
            "outboundTag": self.default_outbound
        }));
        json!({
            "routing": {
                "domainStrategy": self.domain_strategy,
                "rules": rules
            }
        })
    }

    pub fn preset(name: &str) -> Result<Self> {
        let rule = |name: &str, domain: Vec<&str>, ip: Vec<&str>, outbound: &str| RoutingRule {
            name: name.into(),
            enabled: true,
            domain: domain.into_iter().map(str::to_owned).collect(),
            ip: ip.into_iter().map(str::to_owned).collect(),
            port: None,
            source_port: None,
            local_port: None,
            network: None,
            source_ip: Vec::new(),
            local_ip: Vec::new(),
            inbound_tag: Vec::new(),
            protocol: Vec::new(),
            process: Vec::new(),
            outbound: outbound.into(),
        };
        match name {
            "global-proxy" => Ok(Self {
                domain_strategy: default_domain_strategy(),
                default_outbound: "proxy".into(),
                rules: vec![
                    rule("private-ip-direct", vec![], vec!["geoip:private"], "direct"),
                    rule(
                        "private-domain-direct",
                        vec!["geosite:private"],
                        vec![],
                        "direct",
                    ),
                ],
            }),
            "runet-blocked-only" => Ok(Self {
                domain_strategy: default_domain_strategy(),
                default_outbound: "direct".into(),
                rules: vec![
                    rule(
                        "blocked-ip-proxy",
                        vec![],
                        vec!["geoip:ru-blocked", "geoip:ru-blocked-community"],
                        "proxy",
                    ),
                    rule(
                        "blocked-domain-proxy",
                        vec!["geosite:ru-blocked", "geosite:ru-blocked-all"],
                        vec![],
                        "proxy",
                    ),
                ],
            }),
            "ru-direct" => Ok(Self {
                domain_strategy: default_domain_strategy(),
                default_outbound: "proxy".into(),
                rules: vec![
                    rule("ru-ip-direct", vec![], vec!["geoip:ru-whitelist"], "direct"),
                    rule(
                        "ru-domain-direct",
                        vec!["geosite:ru-available-only-inside"],
                        vec![],
                        "direct",
                    ),
                ],
            }),
            _ => Err(ManagerError::InvalidConfig(format!(
                "unknown routing preset: {name}"
            ))),
        }
    }
}

impl RoutingRule {
    fn to_xray_json(&self) -> Value {
        let mut object = serde_json::Map::new();
        object.insert("type".into(), json!("field"));
        insert_nonempty(&mut object, "domain", &self.domain);
        insert_nonempty(&mut object, "ip", &self.ip);
        insert_option(&mut object, "port", &self.port);
        insert_option(&mut object, "sourcePort", &self.source_port);
        insert_option(&mut object, "localPort", &self.local_port);
        insert_option(&mut object, "network", &self.network);
        insert_nonempty(&mut object, "source", &self.source_ip);
        insert_nonempty(&mut object, "local", &self.local_ip);
        insert_nonempty(&mut object, "inboundTag", &self.inbound_tag);
        insert_nonempty(&mut object, "protocol", &self.protocol);
        insert_nonempty(&mut object, "process", &self.process);
        object.insert("outboundTag".into(), json!(self.outbound));
        Value::Object(object)
    }
}

fn insert_nonempty(object: &mut serde_json::Map<String, Value>, key: &str, value: &[String]) {
    if !value.is_empty() {
        object.insert(key.into(), json!(value));
    }
}

fn insert_option(object: &mut serde_json::Map<String, Value>, key: &str, value: &Option<String>) {
    if let Some(value) = value {
        object.insert(key.into(), json!(value));
    }
}

fn default_true() -> bool {
    true
}
fn default_domain_strategy() -> String {
    "AsIs".into()
}
fn default_outbound() -> String {
    "proxy".into()
}
