use crate::domain::Node;
use crate::protocols::{parse_uri, vmess::decode_flexible_base64};
use crate::{ManagerError, Result};

#[derive(Debug)]
pub struct SubscriptionParse {
    pub nodes: Vec<Node>,
    pub warnings: Vec<String>,
}

pub fn parse_subscription(input: &[u8], subscription: &str) -> Result<SubscriptionParse> {
    let text = std::str::from_utf8(input)
        .map_err(|_| ManagerError::InvalidSubscription("response is not UTF-8".into()))?;
    if looks_like_html(text) {
        return Err(ManagerError::InvalidSubscription(
            "response looks like an HTML error page".into(),
        ));
    }
    let decoded = if contains_supported_uri(text) {
        text.to_owned()
    } else {
        let bytes = decode_flexible_base64(text)
            .map_err(|_| ManagerError::InvalidSubscription("invalid Base64 response".into()))?;
        String::from_utf8(bytes).map_err(|_| {
            ManagerError::InvalidSubscription("decoded response is not UTF-8".into())
        })?
    };
    let decoded = decode_minimal_html_entities(&decoded);
    let mut nodes = Vec::new();
    let mut warnings = Vec::new();
    for (index, line) in decoded.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        match parse_uri(line, subscription) {
            Ok(node) => nodes.push(node),
            Err(error) => warnings.push(format!("line {}: {error}", index + 1)),
        }
    }
    if nodes.is_empty() {
        return Err(ManagerError::InvalidSubscription(
            "subscription contains no supported nodes".into(),
        ));
    }
    Ok(SubscriptionParse { nodes, warnings })
}

fn contains_supported_uri(text: &str) -> bool {
    [
        "vless://",
        "vmess://",
        "trojan://",
        "ss://",
        "hysteria2://",
        "hy2://",
    ]
    .iter()
    .any(|scheme| text.contains(scheme))
}

fn looks_like_html(text: &str) -> bool {
    let prefix = text.trim_start().to_ascii_lowercase();
    prefix.starts_with("<!doctype html")
        || prefix.starts_with("<html")
        || prefix.starts_with("<?xml")
}

fn decode_minimal_html_entities(value: &str) -> String {
    value
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
}
