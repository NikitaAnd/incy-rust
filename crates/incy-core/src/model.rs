//! Serializable, platform-independent client model.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{Error, Result};

pub const STATE_VERSION: u32 = 1;
pub const MAX_PROFILES: usize = 10_000;
pub const MAX_SUBSCRIPTIONS: usize = 100;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Profile {
    pub id: Uuid,
    pub name: String,
    pub endpoint: Endpoint,
    /// Set when this profile came from a subscription. Manual profiles are kept
    /// independently when a subscription is refreshed or removed.
    #[serde(default)]
    pub subscription_id: Option<Uuid>,
    /// Preserved full Xray JSON for configurations that cannot be represented as
    /// a single share-link endpoint. Present only for explicit JSON imports.
    #[serde(default)]
    pub raw_xray_config: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Endpoint {
    pub address: String,
    pub port: u16,
    pub protocol: Protocol,
    #[serde(default)]
    pub transport: Transport,
    #[serde(default)]
    pub security: Security,
}

impl Endpoint {
    pub fn validate(&self) -> Result<()> {
        validate_host(&self.address)?;
        if self.port == 0 {
            return Err(Error::InvalidProfile("port must be nonzero".into()));
        }
        self.protocol.validate()?;
        self.transport.validate()?;
        self.security.validate()?;
        if matches!(self.protocol, Protocol::Hysteria2 { .. }) {
            if self.transport.network != Network::Raw || !matches!(self.security, Security::Tls { .. }) {
                return Err(Error::InvalidProfile(
                    "Hysteria2 requires a TLS endpoint without an Xray stream transport".into(),
                ));
            }
        }
        if matches!(self.protocol, Protocol::Wireguard(_)) && self.transport.network != Network::Raw {
            return Err(Error::InvalidProfile("WireGuard does not use stream transport".into()));
        }
        if matches!(self.security, Security::Reality { .. })
            && !matches!(self.transport.network, Network::Raw | Network::Grpc | Network::Xhttp)
        {
            return Err(Error::InvalidProfile("REALITY supports RAW, gRPC and XHTTP".into()));
        }
        if matches!(self.protocol, Protocol::Socks { .. }) && self.security != Security::None {
            return Err(Error::InvalidProfile("SOCKS5 cannot wrap its connection in TLS/REALITY".into()));
        }
        Ok(())
    }

    pub fn summary(&self) -> String {
        let security = match &self.security {
            Security::None => "",
            Security::Tls { .. } => " · TLS",
            Security::Reality { .. } => " · REALITY",
        };
        format!("{}{security}", self.protocol.name())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum Protocol {
    Vless {
        id: Uuid,
        #[serde(default)]
        flow: String,
        /// Preserve newer VLESS encryption strings instead of silently changing
        /// them to `none`. The ordinary share-link default remains `none`.
        #[serde(default = "default_encryption")]
        encryption: String,
    },
    Vmess {
        id: Uuid,
        #[serde(default)]
        alter_id: u16,
        #[serde(default = "default_vmess_security")]
        security: String,
    },
    Trojan { password: String },
    Shadowsocks { method: String, password: String },
    Socks {
        #[serde(default)]
        username: String,
        #[serde(default)]
        password: String,
    },
    Hysteria2 {
        auth: String,
        #[serde(default)]
        obfs: Option<HysteriaObfs>,
    },
    Wireguard(Wireguard),
}

fn default_encryption() -> String { "none".into() }
fn default_vmess_security() -> String { "auto".into() }

impl Protocol {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Vless { .. } => "VLESS",
            Self::Vmess { .. } => "VMess",
            Self::Trojan { .. } => "Trojan",
            Self::Shadowsocks { .. } => "Shadowsocks",
            Self::Socks { .. } => "SOCKS5",
            Self::Hysteria2 { .. } => "Hysteria2",
            Self::Wireguard(_) => "WireGuard",
        }
    }
    pub fn validate(&self) -> Result<()> {
        let nonempty = |s: &str| !s.trim().is_empty() && !s.contains(['\r', '\n', '\0']);
        match self {
            Self::Vless { flow, encryption, .. } => {
                if !matches!(flow.as_str(), "" | "xtls-rprx-vision" | "xtls-rprx-vision-udp443")
                    || encryption.trim().is_empty()
                    || encryption.contains(['\r', '\n', '\0'])
                {
                    return Err(Error::InvalidProfile("unsupported VLESS flow/encryption".into()));
                }
            }
            Self::Vmess { security, .. } => {
                if !matches!(security.as_str(), "auto" | "aes-128-gcm" | "chacha20-poly1305" | "none" | "zero") {
                    return Err(Error::InvalidProfile("unsupported VMess security".into()));
                }
            }
            Self::Trojan { password } => {
                if !nonempty(password) { return Err(Error::InvalidProfile("empty Trojan password".into())); }
            }
            Self::Shadowsocks { method, password } => {
                let valid = matches!(method.as_str(), "aes-128-gcm" | "aes-256-gcm" | "chacha20-poly1305" | "xchacha20-poly1305")
                    || matches!(method.as_str(), "2022-blake3-aes-128-gcm" | "2022-blake3-aes-256-gcm" | "2022-blake3-chacha20-poly1305");
                if !valid || !nonempty(password) {
                    return Err(Error::InvalidProfile("unsupported Shadowsocks cipher or empty key".into()));
                }
            }
            Self::Socks { username, password } => {
                if username.contains(['\r', '\n', '\0']) || password.contains(['\r', '\n', '\0'])
                    || (username.is_empty() && !password.is_empty())
                {
                    return Err(Error::InvalidProfile("invalid SOCKS credentials".into()));
                }
            }
            Self::Hysteria2 { auth, obfs } => {
                if !nonempty(auth) || obfs.as_ref().is_some_and(|o| o.kind != "salamander" || o.password.is_empty()) {
                    return Err(Error::InvalidProfile("invalid Hysteria2 authentication/obfuscation".into()));
                }
            }
            Self::Wireguard(wg) => wg.validate()?,
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HysteriaObfs { pub kind: String, pub password: String }

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Wireguard {
    pub secret_key: String,
    pub peer_public_key: String,
    pub addresses: Vec<String>,
    #[serde(default)]
    pub reserved: Vec<u8>,
    #[serde(default)]
    pub preshared_key: String,
    #[serde(default = "default_mtu")]
    pub mtu: u16,
    #[serde(default = "default_keepalive")]
    pub keepalive: u16,
}
fn default_mtu() -> u16 { 1420 }
fn default_keepalive() -> u16 { 25 }
impl Wireguard {
    fn validate(&self) -> Result<()> {
        use base64::{engine::general_purpose::STANDARD, Engine};
        for key in [&self.secret_key, &self.peer_public_key] {
            if STANDARD.decode(key).map(|v| v.len()).unwrap_or(0) != 32 {
                return Err(Error::InvalidProfile("WireGuard keys must be 32-byte standard base64".into()));
            }
        }
        if !self.preshared_key.is_empty() && STANDARD.decode(&self.preshared_key).map(|v| v.len()).unwrap_or(0) != 32 {
            return Err(Error::InvalidProfile("invalid WireGuard preshared key".into()));
        }
        if self.addresses.is_empty() || self.addresses.iter().any(|a| a.parse::<IpAddr>().is_err()) {
            return Err(Error::InvalidProfile("WireGuard requires assigned IP addresses without CIDR suffixes".into()));
        }
        if !(576..=65535).contains(&self.mtu) || self.reserved.len() > 3 {
            return Err(Error::InvalidProfile("invalid WireGuard MTU/reserved bytes".into()));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase")]
pub struct Transport {
    pub network: Network,
    #[serde(default = "default_path")]
    pub path: String,
    #[serde(default)]
    pub host: String,
    #[serde(default)]
    pub service_name: String,
    #[serde(default)]
    pub grpc_multi_mode: bool,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    /// XHTTP extra is retained as JSON; it can contain nested numeric ranges.
    #[serde(default)]
    pub extra: Option<serde_json::Value>,
}
fn default_path() -> String { "/".into() }

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase")]
pub enum Network { #[default] Raw, Ws, Grpc, HttpUpgrade, Xhttp }
impl Network {
    pub fn as_str(self) -> &'static str {
        match self { Self::Raw => "raw", Self::Ws => "ws", Self::Grpc => "grpc", Self::HttpUpgrade => "httpupgrade", Self::Xhttp => "xhttp" }
    }
}
impl Transport {
    fn validate(&self) -> Result<()> {
        for value in std::iter::once(&self.path).chain(std::iter::once(&self.host)).chain(std::iter::once(&self.service_name)).chain(self.headers.keys()).chain(self.headers.values()) {
            if value.contains(['\r', '\n', '\0']) {
                return Err(Error::InvalidProfile("control character in transport field".into()));
            }
        }
        if self.headers.keys().any(|k| k.eq_ignore_ascii_case("host")) {
            return Err(Error::InvalidProfile("use the host field instead of a Host header".into()));
        }
        if self.network != Network::Raw && !self.path.starts_with('/') && self.network != Network::Grpc {
            return Err(Error::InvalidProfile("transport path must start with /".into()));
        }
        if let Some(extra) = &self.extra {
            if !extra.is_object() || self.network != Network::Xhttp {
                return Err(Error::InvalidProfile("extra must be an XHTTP object".into()));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum Security {
    #[default]
    None,
    Tls {
        #[serde(default)]
        sni: String,
        #[serde(default)]
        alpn: Vec<String>,
        #[serde(default = "default_fingerprint")]
        fingerprint: String,
        /// Explicit opt-in only. Never inferred from a share link.
        #[serde(default)]
        allow_insecure: bool,
    },
    Reality {
        #[serde(default)]
        sni: String,
        public_key: String,
        #[serde(default)]
        short_id: String,
        #[serde(default = "default_fingerprint")]
        fingerprint: String,
        #[serde(default = "default_path")]
        spider_x: String,
    },
}
fn default_fingerprint() -> String { "chrome".into() }
impl Security {
    fn validate(&self) -> Result<()> {
        match self {
            Self::None => Ok(()),
            Self::Tls { sni, alpn, fingerprint, .. } => {
                validate_tls_name(sni)?;
                validate_fingerprint(fingerprint)?;
                if alpn.iter().any(|s| s.is_empty() || s.contains(['\r', '\n', '\0', ','])) {
                    return Err(Error::InvalidProfile("invalid ALPN".into()));
                }
                Ok(())
            }
            Self::Reality { sni, public_key, short_id, fingerprint, spider_x } => {
                use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
                validate_tls_name(sni)?;
                validate_fingerprint(fingerprint)?;
                if sni.is_empty() || URL_SAFE_NO_PAD.decode(public_key).map(|v| v.len()).unwrap_or(0) != 32
                    || short_id.len() > 16 || short_id.len() % 2 != 0 || !short_id.bytes().all(|b| b.is_ascii_hexdigit())
                    || !spider_x.starts_with('/') || spider_x.contains(['\r', '\n', '\0'])
                {
                    return Err(Error::InvalidProfile("invalid REALITY SNI/public key/short ID/spider path".into()));
                }
                Ok(())
            }
        }
    }
}
fn validate_fingerprint(value: &str) -> Result<()> {
    if !matches!(value, "" | "chrome" | "firefox" | "safari" | "ios" | "android" | "edge" | "360" | "qq" | "random" | "randomized") {
        return Err(Error::InvalidProfile("unsupported uTLS fingerprint".into()));
    }
    Ok(())
}
fn validate_tls_name(value: &str) -> Result<()> {
    if value.contains(['/', '\r', '\n', '\0', ' ']) || value.parse::<IpAddr>().is_ok() {
        return Err(Error::InvalidProfile("TLS SNI must be a DNS name, not a URL or IP".into()));
    }
    Ok(())
}
pub(crate) fn validate_host(value: &str) -> Result<()> {
    if value.is_empty() || value.len() > 253 || value.contains(['/', '\\', '@', '\r', '\n', '\0', ' ']) {
        return Err(Error::InvalidProfile("invalid server hostname/IP".into()));
    }
    let bare = value.strip_prefix('[').and_then(|v| v.strip_suffix(']')).unwrap_or(value);
    if bare.parse::<IpAddr>().is_ok() { return Ok(()); }
    if value.starts_with('[') || value.ends_with(']') {
        return Err(Error::InvalidProfile("invalid bracketed IP".into()));
    }
    if value.split('.').all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit())) {
        return Err(Error::InvalidProfile("invalid IPv4 address".into()));
    }
    if !value.split('.').all(|p| !p.is_empty() && p.len() <= 63 && p.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') && !p.starts_with('-') && !p.ends_with('-')) {
        return Err(Error::InvalidProfile("invalid server hostname".into()));
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Subscription {
    pub id: Uuid,
    pub name: String,
    /// Contains a bearer token in many providers' URLs; never put it in logs.
    pub url: String,
    pub refresh_secs: u64,
    #[serde(default)]
    pub last_refresh_unix: Option<u64>,
    #[serde(default)]
    pub user_info: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", default)]
pub struct Settings {
    pub xray_path: Option<PathBuf>,
    pub socks_port: u16,
    pub http_port: u16,
    /// Opt-in OS proxy changes. This is NOT a TUN mode or a kill switch.
    pub set_system_proxy: bool,
    /// Executable names whose local proxy connections should use the proxy outbound.
    #[serde(default)]
    pub proxy_apps: Vec<String>,
    /// Executable names whose local proxy connections should use the direct outbound.
    #[serde(default)]
    pub direct_apps: Vec<String>,
    /// Route all system IP traffic through a userspace TUN device when supported.
    #[serde(default)]
    pub tun_mode: bool,
    /// Block non-tunnel egress while TUN is active. Requires tun_mode.
    #[serde(default)]
    pub kill_switch: bool,
    pub routing: Routing,
    pub fragment: Option<Fragment>,
    pub theme: Theme,
    pub language: Language,
}
impl Default for Settings {
    fn default() -> Self {
        Self { xray_path: None, socks_port: 2080, http_port: 2081, set_system_proxy: false,
            proxy_apps: Vec::new(), direct_apps: Vec::new(), tun_mode: false, kill_switch: false,
            routing: Routing::default(), fragment: None, theme: Theme::Dark, language: Language::Ru }
    }
}
impl Settings {
    pub fn validate(&self) -> Result<()> {
        if self.socks_port == 0 || self.http_port == 0 || self.socks_port == self.http_port {
            return Err(Error::InvalidProfile("SOCKS and HTTP need distinct nonzero ports".into()));
        }
        if self.xray_path.as_ref().is_some_and(|p| p.as_os_str().is_empty()) {
            return Err(Error::InvalidProfile("empty Xray path".into()));
        }
        self.routing.validate()?;
        if self.kill_switch && !self.tun_mode {
            return Err(Error::InvalidProfile("kill switch requires TUN mode".into()));
        }
        validate_app_names(&self.proxy_apps, "proxy")?;
        validate_app_names(&self.direct_apps, "direct")?;
        let direct: std::collections::HashSet<String> = self.direct_apps.iter().map(|n| n.to_lowercase()).collect();
        if self.proxy_apps.iter().any(|name| direct.contains(&name.to_lowercase())) {
            return Err(Error::InvalidProfile("an application cannot be both proxy-routed and direct-routed".into()));
        }
        if let Some(f) = &self.fragment { f.validate()?; }
        Ok(())
    }
}
fn validate_app_names(names: &[String], kind: &str) -> Result<()> {
    if names.len() > 64 {
        return Err(Error::InvalidProfile(format!("at most 64 {kind}-routed applications are supported")));
    }
    for name in names {
        let trimmed = name.trim();
        if trimmed.is_empty() || trimmed.len() > 512 || trimmed.contains(['\r', '\n', '\0']) {
            return Err(Error::InvalidProfile(format!("invalid {kind}-routed application name")));
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase")]
pub enum Theme { #[default] Dark, Light, Midnight, Ocean, Forest, System }
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase")]
pub enum Language { #[default] Ru, En }

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", default)]
pub struct Routing {
    pub proxy_domains: Vec<String>,
    pub direct_domains: Vec<String>,
    pub block_domains: Vec<String>,
    pub proxy_ips: Vec<String>,
    pub direct_ips: Vec<String>,
    pub block_ips: Vec<String>,
    pub bypass_lan: bool,
    pub remote_dns: String,
    pub domestic_dns: String,
    pub domestic_domains: Vec<String>,
}
impl Default for Routing {
    fn default() -> Self {
        Self { proxy_domains: vec![], direct_domains: vec![], block_domains: vec![],
            proxy_ips: vec![], direct_ips: vec![], block_ips: vec![], bypass_lan: true,
            remote_dns: "https://1.1.1.1/dns-query".into(), domestic_dns: "223.5.5.5".into(), domestic_domains: vec![] }
    }
}
impl Routing {
    pub fn validate(&self) -> Result<()> {
        for rule in self.proxy_domains.iter().chain(&self.direct_domains).chain(&self.block_domains).chain(&self.domestic_domains) {
            let bare = rule.strip_prefix("domain:").or_else(|| rule.strip_prefix("full:")).or_else(|| rule.strip_prefix("keyword:")).or_else(|| rule.strip_prefix("regexp:")).unwrap_or(rule);
            if bare.is_empty() || bare.len() > 1024 || bare.contains(['/', ' ', '\r', '\n', '\0']) {
                return Err(Error::InvalidProfile("invalid domain routing rule".into()));
            }
            if let Some(domain) = rule.strip_prefix("full:") { validate_host(domain)?; }
        }
        for rule in self.proxy_ips.iter().chain(&self.direct_ips).chain(&self.block_ips) {
            let bare = rule.strip_prefix("geoip:").unwrap_or(rule);
            if bare.is_empty() { return Err(Error::InvalidProfile("empty IP rule".into())); }
            if !rule.starts_with("geoip:") {
                if let Some((addr, bits)) = rule.split_once('/') {
                    let ip: IpAddr = addr.parse().map_err(|_| Error::InvalidProfile("invalid IP routing rule".into()))?;
                    let bits: u8 = bits.parse().map_err(|_| Error::InvalidProfile("invalid CIDR prefix".into()))?;
                    if bits > if ip.is_ipv4() { 32 } else { 128 } { return Err(Error::InvalidProfile("invalid CIDR prefix".into())); }
                } else {
                    rule.parse::<IpAddr>().map_err(|_| Error::InvalidProfile("invalid IP routing rule".into()))?;
                }
            }
        }
        validate_dns(&self.remote_dns)?;
        validate_dns(&self.domestic_dns)?;
        Ok(())
    }
}
fn validate_dns(s: &str) -> Result<()> {
    if s == "localhost" { return Ok(()); }
    if let Some(url) = s.strip_prefix("https://") {
        let authority = url.split('/').next().unwrap_or("");
        let host = authority.split(':').next().unwrap_or("");
        validate_host(host)?;
    } else if s.parse::<IpAddr>().is_err() {
        return Err(Error::InvalidProfile("DNS must be an IP, localhost or HTTPS URL".into()));
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Fragment {
    pub length_min: u16,
    pub length_max: u16,
    pub interval_min_ms: u16,
    pub interval_max_ms: u16,
}
impl Default for Fragment {
    fn default() -> Self { Self { length_min: 100, length_max: 200, interval_min_ms: 10, interval_max_ms: 20 } }
}
impl Fragment {
    pub fn validate(&self) -> Result<()> {
        if self.length_min == 0 || self.length_min > self.length_max || self.interval_min_ms > self.interval_max_ms || self.interval_max_ms > 10_000 {
            return Err(Error::InvalidProfile("invalid fragment length/interval range".into()));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AppState {
    pub version: u32,
    #[serde(default)]
    pub profiles: Vec<Profile>,
    #[serde(default)]
    pub subscriptions: Vec<Subscription>,
    #[serde(default)]
    pub settings: Settings,
    #[serde(default)]
    pub selected_profile: Option<Uuid>,
}
impl Default for AppState {
    fn default() -> Self { Self { version: STATE_VERSION, profiles: vec![], subscriptions: vec![], settings: Settings::default(), selected_profile: None } }
}
impl AppState {
    pub fn validate(&self) -> Result<()> {
        if self.version != STATE_VERSION { return Err(Error::UnsupportedVersion(self.version)); }
        if self.profiles.len() > MAX_PROFILES || self.subscriptions.len() > MAX_SUBSCRIPTIONS {
            return Err(Error::Limit("too many profiles/subscriptions".into()));
        }
        self.settings.validate()?;
        let mut ids = std::collections::HashSet::new();
        for p in &self.profiles {
            if !ids.insert(p.id) || p.name.trim().is_empty() || p.name.len() > 512 { return Err(Error::InvalidProfile("duplicate ID or invalid profile name".into())); }
            p.endpoint.validate()?;
            if let Some(config) = &p.raw_xray_config { crate::config::validate_imported_json(config)?; }
            if p.subscription_id.is_some_and(|id| !self.subscriptions.iter().any(|s| s.id == id)) { return Err(Error::InvalidProfile("orphaned subscription profile".into())); }
        }
        let mut sub_ids = std::collections::HashSet::new();
        for s in &self.subscriptions {
            if !sub_ids.insert(s.id) || !(60..=2_592_000).contains(&s.refresh_secs) { return Err(Error::InvalidProfile("duplicate subscription ID or invalid refresh interval".into())); }
            crate::subscription::validate_url(&s.url)?;
        }
        if self.selected_profile.is_some_and(|id| !ids.contains(&id)) { return Err(Error::InvalidProfile("selected profile does not exist".into())); }
        Ok(())
    }
}
