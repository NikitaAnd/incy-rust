//! Convert a validated endpoint and client policy into an Xray JSON config.
//!
//! Inbound listeners always bind to loopback. No public SOCKS/HTTP listener,
//! privileged TUN device, or system firewall rule is created by this module.

use serde_json::{json, Map, Value};

use crate::error::{Error, Result};
use crate::model::*;

const MAX_IMPORTED_CONFIG_BYTES: usize = 8 * 1024 * 1024;

/// Import a complete Xray JSON document while refusing listeners that expose
/// the imported core to the LAN. Xray itself performs the authoritative schema
/// check when the profile is started.
pub fn import_xray_json(name: &str, input: &str) -> Result<Profile> {
    if input.len() > MAX_IMPORTED_CONFIG_BYTES {
        return Err(Error::Limit("Xray JSON import exceeds 8 MiB".into()));
    }
    let value: Value = serde_json::from_str(input)?;
    validate_imported_json(&value)?;
    let endpoint = Endpoint {
        address: "127.0.0.1".into(),
        port: 1,
        protocol: Protocol::Socks { username: String::new(), password: String::new() },
        transport: Transport::default(),
        security: Security::None,
    };
    Ok(Profile {
        id: uuid::Uuid::new_v4(),
        name: if name.trim().is_empty() { "Imported Xray config".into() } else { name.chars().take(256).collect() },
        endpoint,
        subscription_id: None,
        raw_xray_config: Some(value),
    })
}

pub fn validate_imported_json(value: &Value) -> Result<()> {
    let object = value.as_object().ok_or_else(|| Error::InvalidProfile("Xray import must be a JSON object".into()))?;
    let inbounds = object.get("inbounds").and_then(Value::as_array).ok_or_else(|| Error::InvalidProfile("Xray import needs an inbounds array".into()))?;
    let outbounds = object.get("outbounds").and_then(Value::as_array).ok_or_else(|| Error::InvalidProfile("Xray import needs an outbounds array".into()))?;
    if inbounds.is_empty() || inbounds.len() > 64 || outbounds.is_empty() || outbounds.len() > 128 {
        return Err(Error::InvalidProfile("Xray import needs 1–64 inbounds and 1–128 outbounds".into()));
    }
    for inbound in inbounds {
        let listen = inbound.get("listen").and_then(Value::as_str).ok_or_else(|| Error::InvalidProfile("every imported inbound must explicitly listen on loopback".into()))?;
        let loopback = listen == "localhost" || listen.parse::<std::net::IpAddr>().is_ok_and(|ip| ip.is_loopback());
        if !loopback {
            return Err(Error::InvalidProfile("imported Xray listeners must bind only to localhost/loopback".into()));
        }
    }
    let bytes = serde_json::to_vec(value)?;
    if bytes.len() > MAX_IMPORTED_CONFIG_BYTES {
        return Err(Error::Limit("Xray JSON import exceeds 8 MiB".into()));
    }
    Ok(())
}

pub fn generate(endpoint: &Endpoint, settings: &Settings) -> Result<Value> {
    endpoint.validate()?;
    settings.validate()?;
    if settings.fragment.is_some() && (matches!(endpoint.protocol, Protocol::Hysteria2 { .. } | Protocol::Wireguard(_)) || endpoint.security == Security::None) {
        return Err(Error::InvalidProfile("TLS fragmentation requires a TCP-based TLS/REALITY profile".into()));
    }
    let mut outbound = Map::new();
    outbound.insert("tag".into(), json!("proxy"));
    let settings_json = match &endpoint.protocol {
        Protocol::Vless { id, flow, encryption } => {
            outbound.insert("protocol".into(), json!("vless"));
            json!({"vnext": [{"address": endpoint.address, "port": endpoint.port, "users": [{"id": id, "flow": flow, "encryption": encryption}]}]})
        }
        Protocol::Vmess { id, alter_id, security } => {
            outbound.insert("protocol".into(), json!("vmess"));
            json!({"vnext": [{"address": endpoint.address, "port": endpoint.port, "users": [{"id": id, "alterId": alter_id, "security": security}]}]})
        }
        Protocol::Trojan { password } => {
            outbound.insert("protocol".into(), json!("trojan"));
            json!({"servers": [{"address": endpoint.address, "port": endpoint.port, "password": password}]})
        }
        Protocol::Shadowsocks { method, password } => {
            outbound.insert("protocol".into(), json!("shadowsocks"));
            json!({"servers": [{"address": endpoint.address, "port": endpoint.port, "method": method, "password": password}]})
        }
        Protocol::Socks { username, password } => {
            outbound.insert("protocol".into(), json!("socks"));
            let server = if username.is_empty() { json!({"address": endpoint.address, "port": endpoint.port}) }
                else { json!({"address": endpoint.address, "port": endpoint.port, "users": [{"user": username, "pass": password}]}) };
            json!({"servers": [server]})
        }
        Protocol::Hysteria2 { auth, obfs } => {
            outbound.insert("protocol".into(), json!("hysteria"));
            let mut stream = Map::new();
            stream.insert("network".into(), json!("hysteria"));
            stream.insert("hysteriaSettings".into(), json!({"version": 2, "auth": auth}));
            if let Some(obfs) = obfs {
                stream.insert("finalmask".into(), json!({"udp": [{"type": "salamander", "settings": {"password": obfs.password}}]}));
            }
            apply_security(&mut stream, &endpoint.security, &endpoint.address)?;
            outbound.insert("streamSettings".into(), Value::Object(stream));
            json!({"version": 2})
        }
        Protocol::Wireguard(wg) => {
            outbound.insert("protocol".into(), json!("wireguard"));
            let mut peer = json!({"publicKey": wg.peer_public_key, "endpoint": format!("{}:{}", endpoint.address, endpoint.port), "keepAlive": wg.keepalive});
            if !wg.preshared_key.is_empty() { peer["preSharedKey"] = json!(wg.preshared_key); }
            json!({"secretKey": wg.secret_key, "address": wg.addresses, "peers": [peer], "mtu": wg.mtu, "reserved": wg.reserved, "noKernelTun": true})
        }
    };
    outbound.insert("settings".into(), settings_json);
    if !matches!(endpoint.protocol, Protocol::Hysteria2 { .. } | Protocol::Wireguard(_)) {
        let t = &endpoint.transport;
        let mut stream = Map::new();
        stream.insert("network".into(), json!(t.network.as_str()));
        match t.network {
            Network::Raw => { stream.insert("rawSettings".into(), json!({"header": {"type": "none"}})); }
            Network::Ws => { stream.insert("wsSettings".into(), json!({"path": t.path, "host": t.host, "headers": t.headers})); }
            Network::HttpUpgrade => { stream.insert("httpupgradeSettings".into(), json!({"path": t.path, "host": t.host, "headers": t.headers})); }
            Network::Grpc => { stream.insert("grpcSettings".into(), json!({"serviceName": t.service_name, "authority": t.host, "multiMode": t.grpc_multi_mode})); }
            Network::Xhttp => {
                let mut xhttp = t.extra.as_ref().and_then(Value::as_object).cloned().unwrap_or_default();
                xhttp.insert("path".into(), json!(t.path));
                xhttp.insert("host".into(), json!(t.host));
                stream.insert("xhttpSettings".into(), Value::Object(xhttp));
            }
        }
        apply_security(&mut stream, &endpoint.security, &endpoint.address)?;
        if settings.fragment.is_some() { stream.insert("sockopt".into(), json!({"dialerProxy": "fragment"})); }
        outbound.insert("streamSettings".into(), Value::Object(stream));
    }
    let mut outbounds = vec![Value::Object(outbound), json!({"protocol": "freedom", "tag": "direct", "settings": {"domainStrategy": "UseIP"}}), json!({"protocol": "blackhole", "tag": "block"}), json!({"protocol": "dns", "tag": "dns-out"})];
    if let Some(f) = &settings.fragment {
        outbounds.push(json!({"protocol": "freedom", "tag": "fragment", "settings": {"fragment": {"packets": "tlshello", "length": format!("{}-{}", f.length_min, f.length_max), "interval": format!("{}-{}", f.interval_min_ms, f.interval_max_ms)}}}));
    }
    let r = &settings.routing;
    let mut rules = vec![json!({"type": "field", "inboundTag": ["socks-in", "http-in"], "port": 53, "network": "udp", "outboundTag": "dns-out"})];
    for (domains, ips, tag) in [(&r.block_domains, &r.block_ips, "block"), (&r.proxy_domains, &r.proxy_ips, "proxy"), (&r.direct_domains, &r.direct_ips, "direct")] {
        if !domains.is_empty() { rules.push(json!({"type": "field", "domain": domains, "outboundTag": tag})); }
        if !ips.is_empty() { rules.push(json!({"type": "field", "ip": ips, "outboundTag": tag})); }
    }
    if !r.domestic_domains.is_empty() { rules.push(json!({"type": "field", "domain": r.domestic_domains, "outboundTag": "direct"})); }
    if r.bypass_lan {
        rules.push(json!({"type": "field", "ip": ["geoip:private"], "outboundTag": "direct"}));
        rules.push(json!({"type": "field", "domain": ["full:localhost", "domain:local", "domain:localdomain", "domain:home.arpa"], "outboundTag": "direct"}));
    }
    let mut dns_servers = vec![json!(r.remote_dns)];
    if !r.domestic_domains.is_empty() { dns_servers.push(json!({"address": r.domestic_dns, "domains": r.domestic_domains, "skipFallback": true})); }
    Ok(json!({
        "log": {"loglevel": "warning", "dnsLog": false, "access": "none"},
        "dns": {"servers": dns_servers, "queryStrategy": "UseIP", "tag": "incy-dns"},
        "inbounds": [
            {"tag": "socks-in", "listen": "127.0.0.1", "port": settings.socks_port, "protocol": "socks", "settings": {"auth": "noauth", "udp": true}, "sniffing": sniffing()},
            {"tag": "http-in", "listen": "127.0.0.1", "port": settings.http_port, "protocol": "http", "settings": {"allowTransparent": false}, "sniffing": sniffing()}
        ],
        "outbounds": outbounds,
        "routing": {"domainStrategy": "IPIfNonMatch", "rules": rules}
    }))
}

fn sniffing() -> Value { json!({"enabled": true, "destOverride": ["http", "tls", "quic"], "routeOnly": false}) }
fn apply_security(stream: &mut Map<String, Value>, security: &Security, address: &str) -> Result<()> {
    match security {
        Security::None => { stream.insert("security".into(), json!("none")); }
        Security::Tls { sni, alpn, fingerprint, allow_insecure } => {
            stream.insert("security".into(), json!("tls"));
            stream.insert("tlsSettings".into(), json!({"serverName": if sni.is_empty() { address } else { sni }, "alpn": alpn, "fingerprint": fingerprint, "allowInsecure": allow_insecure}));
        }
        Security::Reality { sni, public_key, short_id, fingerprint, spider_x } => {
            stream.insert("security".into(), json!("reality"));
            stream.insert("realitySettings".into(), json!({"serverName": sni, "publicKey": public_key, "shortId": short_id, "fingerprint": fingerprint, "spiderX": spider_x}));
        }
    }
    Ok(())
}

/// Check every layer using the user's actual core, not a version guessed by us.
pub fn validate_with_xray(binary: &std::path::Path, config: &Value) -> Result<()> {
    let file = crate::store::PrivateFile::write_json(config)?;
    let mut command = std::process::Command::new(binary);
    if let Some(asset_dir) = binary.parent() { command.env("XRAY_LOCATION_ASSET", asset_dir); }
    let output = command.arg("run").arg("-test").arg("-c").arg(file.path()).output()?;
    if !output.status.success() {
        // Core diagnostics may quote credentials. Do not expose them in UI/logs.
        return Err(Error::XrayRejected("check the selected core version and profile fields; raw core output is not displayed because it may contain keys".into()));
    }
    Ok(())
}
