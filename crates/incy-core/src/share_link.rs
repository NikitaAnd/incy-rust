//! Share-link parsing. Parsed endpoints are validated before entering the store.

use std::collections::HashMap;

use base64::{engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD}, Engine};
use serde_json::Value;
use url::Url;
use uuid::Uuid;

use crate::error::{Error, Result};
use crate::model::*;

pub fn decode_base64(input: &str) -> Result<Vec<u8>> {
    let compact: String = input.chars().filter(|c| !c.is_whitespace()).collect();
    for engine in [&STANDARD, &URL_SAFE, &STANDARD_NO_PAD, &URL_SAFE_NO_PAD] {
        if let Ok(bytes) = engine.decode(&compact) { return Ok(bytes); }
    }
    Err(Error::UnsupportedLink)
}

pub fn parse(input: &str) -> Result<Profile> {
    let input = input.trim();
    if input.len() > 64 * 1024 { return Err(Error::Limit("share link is too long".into())); }
    let url = Url::parse(input).map_err(|_| Error::UnsupportedLink)?;
    if url.scheme() == "vmess" { return parse_vmess(input); }
    if !matches!(url.scheme(), "vless" | "trojan" | "ss" | "socks" | "socks5" | "hysteria2" | "hy2" | "wireguard" | "wg") {
        return Err(Error::UnsupportedLink);
    }
    // Older Shadowsocks providers encode method:password@host:port as a single blob.
    let ss_legacy = if url.scheme() == "ss" && url.port().is_none() { Some(parse_ss_legacy(input)?) } else { None };
    // Accessors return percent-encoded values for special-scheme URLs. Decode
    // once, including credentials and fragment names, without form '+' decoding.
    let query: HashMap<String, String> = url.query_pairs().map(|(k, v)| (k.into_owned(), v.into_owned())).collect();
    let get = |key: &str| query.get(key).map(String::as_str).unwrap_or("");
    let (host, port) = if let Some((host, port, _)) = &ss_legacy { (host.clone(), *port) } else {
        (percent_decode(url.host_str().unwrap_or(""))?, url.port().ok_or_else(|| Error::InvalidProfile("missing server port".into()))?)
    };
    let username = percent_decode(url.username())?;
    let password = percent_decode(url.password().unwrap_or(""))?;
    let name = percent_decode(url.fragment().unwrap_or(""))?;
    let transport = parse_transport(&query)?;
    let security = parse_security(&query, first_nonempty(get("sni"), get("peer")).unwrap_or(&host))?;
    let protocol = match url.scheme() {
        "vless" => Protocol::Vless {
            id: Uuid::parse_str(&username).map_err(|_| Error::InvalidProfile("VLESS ID must be a UUID".into()))?,
            flow: get("flow").into(), encryption: nonempty(get("encryption")).unwrap_or("none").into(),
        },
        "trojan" => {
            if password.is_empty() { return Err(Error::InvalidProfile("Trojan password is in the URL userinfo".into())); }
            Protocol::Trojan { password }
        }
        "ss" => match ss_legacy { Some((_, _, protocol)) => protocol, None => parse_ss(&url, &username, &password)? },
        "socks" | "socks5" => Protocol::Socks { username, password },
        "hysteria2" | "hy2" => {
            let auth = if password.is_empty() { username.clone() } else { format!("{username}:{password}") };
            let obfs = match get("obfs") {
                "" | "none" => None,
                "salamander" => Some(HysteriaObfs { kind: "salamander".into(), password: get("obfs-password").into() }),
                _ => return Err(Error::InvalidProfile("unsupported Hysteria2 obfuscation".into())),
            };
            let mut security = if matches!(security, Security::None) { Security::Tls { sni: host.clone(), alpn: vec!["h3".into()], fingerprint: String::new(), allow_insecure: false } } else { security };
            if let Security::Tls { sni, alpn, .. } = &mut security {
                if sni.is_empty() { *sni = host.clone(); }
                if alpn.is_empty() { *alpn = vec!["h3".into()]; }
            }
            let endpoint = Endpoint { address: host, port, protocol: Protocol::Hysteria2 { auth, obfs }, transport: Transport::default(), security };
            endpoint.validate()?;
            return Ok(Profile { id: Uuid::new_v4(), name: display_name(name, &endpoint), endpoint, subscription_id: None, raw_xray_config: None });
        }
        "wireguard" | "wg" => {
            let addresses = get("address").split(',').filter(|s| !s.is_empty()).map(|s| s.split('/').next().unwrap_or(s).to_owned()).collect();
            let reserved = if get("reserved").is_empty() { vec![] } else {
                get("reserved").split(',').map(|v| v.trim().parse::<u8>()).collect::<std::result::Result<Vec<_>, _>>().map_err(|_| Error::InvalidProfile("invalid WireGuard reserved bytes".into()))?
            };
            let parse_num = |key, default| -> Result<u16> { if get(key).is_empty() { Ok(default) } else { get(key).parse().map_err(|_| Error::InvalidProfile("invalid WireGuard numeric field".into())) } };
            Protocol::Wireguard(Wireguard { secret_key: username, peer_public_key: first_nonempty(get("publickey"), get("peerPublicKey")).unwrap_or_else(|| get("publicKey")).into(),
                addresses, reserved, preshared_key: first_nonempty(get("presharedkey"), get("presharedKey")).unwrap_or_else(|| get("preSharedKey")).into(),
                mtu: parse_num("mtu", 1420)?, keepalive: parse_num("keepalive", 25)? })
        }
        _ => unreachable!(),
    };
    let endpoint = Endpoint { address: host, port, protocol, transport, security };
    endpoint.validate()?;
    Ok(Profile { id: Uuid::new_v4(), name: display_name(name, &endpoint), endpoint, subscription_id: None, raw_xray_config: None })
}

fn display_name(name: String, endpoint: &Endpoint) -> String {
    let mut name = if name.trim().is_empty() { format!("{}:{}", endpoint.address, endpoint.port) } else { name.trim().to_owned() };
    name = name.replace(['\r', '\n', '\0'], " ");
    name.chars().take(256).collect()
}

fn parse_vmess(input: &str) -> Result<Profile> {
    let bytes = decode_base64(input.trim_start_matches("vmess://"))?;
    if bytes.len() > 64 * 1024 { return Err(Error::Limit("VMess JSON too large".into())); }
    let v: Value = serde_json::from_slice(&bytes)?;
    let string = |key: &str| v.get(key).map(value_string).unwrap_or_default();
    let host = string("add");
    let port = value_string(v.get("port").ok_or_else(|| Error::InvalidProfile("missing VMess port".into()))?).parse::<u16>().map_err(|_| Error::InvalidProfile("invalid VMess port".into()))?;
    let id = Uuid::parse_str(&string("id")).map_err(|_| Error::InvalidProfile("invalid VMess ID".into()))?;
    let alter_id = if string("aid").is_empty() { 0 } else { string("aid").parse().map_err(|_| Error::InvalidProfile("invalid VMess alterId".into()))? };
    let net_string = string("net");
    let net = match net_string.as_str() { "" | "tcp" | "raw" => "raw", "websocket" => "ws", "h2" => return Err(Error::InvalidProfile("legacy VMess HTTP/2 transport is removed from Xray; use XHTTP".into())), other => other };
    let path = string("path"); let transport_host = string("host"); let sni_value = string("sni");
    let alpn_value = string("alpn"); let fp_value = string("fp"); let tls_value = string("tls");
    let mut query = HashMap::new();
    for (k, value) in [("type", net), ("path", path.as_str()), ("host", transport_host.as_str()), ("serviceName", path.as_str()), ("sni", sni_value.as_str()), ("alpn", alpn_value.as_str()), ("fp", fp_value.as_str()), ("security", tls_value.as_str())] { query.insert(k.to_owned(), value.to_owned()); }
    if string("tls") == "reality" {
        query.insert("pbk".into(), string("pbk"));
        query.insert("sid".into(), string("sid"));
        query.insert("spx".into(), string("spx"));
    }
    // VMess grpc authority and multiplex mode are occasionally supplied in JSON.
    if let Some(extra) = v.get("extra").filter(|v| v.is_object()) { query.insert("extra".into(), extra.to_string()); }
    if let Some(authority) = v.get("authority").and_then(Value::as_str) { query.insert("authority".into(), authority.into()); }
    if v.get("multiMode").and_then(Value::as_bool).unwrap_or(false) { query.insert("mode".into(), "multi".into()); }
    let transport = parse_transport(&query)?;
    let security = if tls_value.is_empty() { Security::None } else { parse_security(&query, if sni_value.is_empty() { &host } else { &sni_value })? };
    let endpoint = Endpoint { address: host, port, protocol: Protocol::Vmess { id, alter_id, security: nonempty(&string("scy")).unwrap_or("auto").into() }, transport, security };
    endpoint.validate()?;
    Ok(Profile { id: Uuid::new_v4(), name: display_name(string("ps"), &endpoint), endpoint, subscription_id: None, raw_xray_config: None })
}

fn value_string(value: &Value) -> String {
    match value { Value::String(s) => s.clone(), Value::Number(n) => n.to_string(), _ => String::new() }
}

fn parse_ss_legacy(input: &str) -> Result<(String, u16, Protocol)> {
    let payload = input.strip_prefix("ss://").ok_or(Error::UnsupportedLink)?
        .split('#').next().unwrap_or("").split('?').next().unwrap_or("");
    let decoded = String::from_utf8(decode_base64(payload)?).map_err(|_| Error::UnsupportedLink)?;
    let (credentials, server) = decoded.rsplit_once('@').ok_or(Error::UnsupportedLink)?;
    let (method, password) = credentials.split_once(':').ok_or(Error::UnsupportedLink)?;
    let parsed = Url::parse(&format!("ss://{server}")).map_err(|_| Error::UnsupportedLink)?;
    let host = percent_decode(parsed.host_str().unwrap_or(""))?;
    let port = parsed.port().ok_or_else(|| Error::InvalidProfile("missing Shadowsocks port".into()))?;
    crate::model::validate_host(&host)?;
    let protocol = Protocol::Shadowsocks { method: method.into(), password: password.into() };
    protocol.validate()?;
    Ok((host, port, protocol))
}

fn parse_ss(url: &Url, username: &str, password: &str) -> Result<Protocol> {
    if !password.is_empty() {
        return Ok(Protocol::Shadowsocks { method: username.to_owned(), password: password.into() });
    }
    // SIP002 base64url userinfo. Also accept legacy base64(method:pass@host:port).
    let decoded = String::from_utf8(decode_base64(username)?).map_err(|_| Error::UnsupportedLink)?;
    if let Some((method, pass)) = decoded.split_once(':') {
        return Ok(Protocol::Shadowsocks { method: method.into(), password: pass.into() });
    }
    // Legacy links put the server inside the encoded section.
    let legacy = Url::parse(&format!("ss://{decoded}")).map_err(|_| Error::UnsupportedLink)?;
    if legacy.host_str().is_some_and(|h| !h.is_empty()) && legacy.port().is_some() && url.host_str().is_none_or(str::is_empty) {
        let method = percent_decode(legacy.username())?;
        let pass = percent_decode(legacy.password().unwrap_or(""))?;
        let mut fixed = url.clone();
        fixed.set_host(legacy.host_str()).map_err(|_| Error::UnsupportedLink)?;
        fixed.set_port(legacy.port()).map_err(|_| Error::UnsupportedLink)?;
        // Caller uses the original URL, so validate the server here separately.
        crate::model::validate_host(legacy.host_str().unwrap_or(""))?;
        return Ok(Protocol::Shadowsocks { method, password: pass });
    }
    Err(Error::UnsupportedLink)
}

fn parse_transport(q: &HashMap<String, String>) -> Result<Transport> {
    let get = |k: &str| q.get(k).map(String::as_str).unwrap_or("");
    let network = match first_nonempty(get("type"), get("net")).unwrap_or("raw") {
        "raw" | "tcp" => Network::Raw, "ws" | "websocket" => Network::Ws,
        "grpc" => Network::Grpc, "httpupgrade" => Network::HttpUpgrade,
        "xhttp" | "splithttp" => Network::Xhttp,
        _ => return Err(Error::InvalidProfile("unsupported transport; import unsupported transports as full Xray JSON".into())),
    };
    let mut path = nonempty(get("path")).unwrap_or("/").to_owned();
    let mut headers = HashMap::new();
    if let Some(ed) = q.get("ed").filter(|_| network == Network::Ws) {
        let _: u32 = ed.parse().map_err(|_| Error::InvalidProfile("invalid WebSocket early-data size".into()))?;
        path.push(if path.contains('?') { '&' } else { '?' });
        path.push_str("ed="); path.push_str(ed);
    }
    if let Some(h) = q.get("header") {
        if h.contains(['{', '}']) {
            let v: Value = serde_json::from_str(h)?;
            if let Some(obj) = v.as_object() {
                for (k, v) in obj {
                    if let Some(v) = v.as_str() { headers.insert(k.clone(), v.to_owned()); }
                }
            }
        }
    }
    let extra = match q.get("extra").filter(|s| !s.is_empty()) {
        Some(s) => Some(serde_json::from_str(s)?), None => None,
    };
    Ok(Transport { network, path, host: get("host").into(), service_name: get("serviceName").into(), grpc_multi_mode: get("mode") == "multi",
        headers: headers.into_iter().collect(), extra })
}
fn nonempty(value: &str) -> Option<&str> { if value.is_empty() { None } else { Some(value) } }
fn first_nonempty<'a>(a: &'a str, b: &'a str) -> Option<&'a str> { nonempty(a).or_else(|| nonempty(b)) }

fn parse_security(q: &HashMap<String, String>, default_sni: &str) -> Result<Security> {
    let get = |k: &str| q.get(k).map(String::as_str).unwrap_or("");
    let sni = nonempty(get("sni")).unwrap_or(default_sni).to_owned();
    let alpn = get("alpn").split(',').filter(|s| !s.is_empty()).map(str::to_owned).collect();
    let fingerprint = get("fp").to_owned();
    match get("security") {
        "" | "none" => Ok(Security::None),
        "tls" => {
            if !get("allowInsecure").is_empty() && get("allowInsecure") != "0" {
                return Err(Error::InvalidProfile("insecure TLS links are refused; import a trusted full config if this is intentional".into()));
            }
            Ok(Security::Tls { sni, alpn, fingerprint: nonempty(&fingerprint).unwrap_or("chrome").into(), allow_insecure: false })
        }
        "reality" => Ok(Security::Reality { sni, public_key: get("pbk").into(), short_id: get("sid").into(), fingerprint: nonempty(&fingerprint).unwrap_or("chrome").into(), spider_x: nonempty(get("spx")).unwrap_or("/").into() }),
        _ => Err(Error::InvalidProfile("unsupported transport security".into())),
    }
}

pub fn percent_decode(s: &str) -> Result<String> {
    let bytes = s.as_bytes(); let mut out = Vec::with_capacity(bytes.len()); let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len() { return Err(Error::UnsupportedLink); }
            let hex = std::str::from_utf8(&bytes[i+1..i+3]).map_err(|_| Error::UnsupportedLink)?;
            out.push(u8::from_str_radix(hex, 16).map_err(|_| Error::UnsupportedLink)?); i += 3;
        } else { out.push(bytes[i]); i += 1; }
    }
    String::from_utf8(out).map_err(|_| Error::UnsupportedLink)
}
