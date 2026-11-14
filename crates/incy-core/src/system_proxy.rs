//! Reversible per-user proxy settings. Deliberately no shell interpolation.
//!
//! A guard owns only settings it successfully changed. Back up the complete
//! prior configuration before touching anything; restore it on disconnect.
//! GNOME, macOS and Windows manual proxy modes are supported. The Linux TUN and
//! nftables kill switch live in `tun.rs`; per-process Xray rules only classify
//! applications that explicitly connect to the local proxy. Transparent
//! per-app capture on Windows/macOS remains platform-specific work.

use std::process::Command;

use crate::error::{Error, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
struct Snapshot { values: Vec<(String, String)> }
pub struct SystemProxyGuard { backend: Backend, snapshot: Snapshot }
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
enum Backend { Windows, Mac, Gnome }

impl SystemProxyGuard {
    pub fn enable(http_port: u16, socks_port: u16) -> Result<Self> {
        #[cfg(target_os = "windows")]
        let backend = Backend::Windows;
        #[cfg(target_os = "macos")]
        let backend = Backend::Mac;
        #[cfg(not(any(target_os = "windows", target_os = "macos")))]
        let backend = Backend::Gnome;
        let snapshot = read_snapshot(backend)?;
        if let Err(error) = apply(backend, http_port, socks_port) {
            let _ = write_snapshot(backend, &snapshot);
            return Err(error);
        }
        Ok(Self { backend, snapshot })
    }
    pub fn restore(self) -> Result<()> { write_snapshot(self.backend, &self.snapshot) }
}

fn output(program: &str, args: &[&str]) -> Result<String> {
    let output = Command::new(program).args(args).output().map_err(|_| Error::SystemProxy(format!("{program} is unavailable")))?;
    if !output.status.success() { return Err(Error::SystemProxy(format!("{program} failed; administrator policy may restrict proxy settings"))); }
    String::from_utf8(output.stdout).map_err(|_| Error::SystemProxy("non-UTF-8 system response".into()))
}
fn read_snapshot(backend: Backend) -> Result<Snapshot> {
    let mut values = Vec::new();
    match backend {
        Backend::Gnome => {
            for (schema, key) in gnome_keys() { values.push((format!("{schema}:{key}"), output("gsettings", &["get", schema, key])?.trim().to_owned())); }
        }
        Backend::Mac => {
            let services = output("networksetup", &["listallnetworkservices"])?;
            for service in services.lines().skip(1).filter(|s| !s.trim().is_empty() && !s.starts_with('*')) {
                for (key, args) in [("web", vec!["-getwebproxy", service]), ("secure", vec!["-getsecurewebproxy", service]), ("socks", vec!["-getsocksfirewallproxy", service]), ("bypass", vec!["-getproxybypassdomains", service])] {
                    values.push((format!("{service}\t{key}"), output("networksetup", &args)?));
                }
            }
        }
        Backend::Windows => {
            for key in ["ProxyEnable", "ProxyServer", "ProxyOverride", "AutoConfigURL"] {
                let result = output("reg", &["query", r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings", "/v", key]);
                values.push((key.into(), result.unwrap_or_else(|_| "<absent>".into())));
            }
        }
    }
    Ok(Snapshot { values })
}
fn apply(backend: Backend, http_port: u16, socks_port: u16) -> Result<()> {
    let port = http_port.to_string();
    let socks = socks_port.to_string();
    match backend {
        Backend::Gnome => {
            // gsettings strings need GVariant quoting; the values here are fixed,
            // while numeric port values remain plain decimal integers.
            gnome_set("org.gnome.system.proxy", "mode", "'manual'")?;
            gnome_set("org.gnome.system.proxy", "use-same-proxy", "false")?;
            for (schema, proxy_port) in [("org.gnome.system.proxy.http", &port), ("org.gnome.system.proxy.https", &port)] {
                gnome_set(schema, "host", "'127.0.0.1'")?;
                gnome_set(schema, "port", proxy_port)?;
                gnome_set(schema, "enabled", "true")?;
                gnome_set(schema, "use-authentication", "false")?;
            }
            // Route GNOME SOCKS-aware apps through the actual local SOCKS listener too.
            gnome_set("org.gnome.system.proxy.socks", "host", "'127.0.0.1'")?;
            gnome_set("org.gnome.system.proxy.socks", "port", &socks)?;
        }
        Backend::Mac => {
            for service in output("networksetup", &["listallnetworkservices"])?.lines().skip(1).filter(|s| !s.trim().is_empty() && !s.starts_with('*')) {
                output("networksetup", &["-setwebproxy", service, "127.0.0.1", &port])?;
                output("networksetup", &["-setsecurewebproxy", service, "127.0.0.1", &port])?;
                output("networksetup", &["-setsocksfirewallproxystate", service, "off"])?;
            }
        }
        Backend::Windows => {
            let root = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings";
            for (key, kind, value) in [("ProxyEnable", "REG_DWORD", "1"), ("ProxyServer", "REG_SZ", &format!("http=127.0.0.1:{port};https=127.0.0.1:{port}")), ("ProxyOverride", "REG_SZ", "localhost;127.*;[::1];<local>")] {
                output("reg", &["add", root, "/v", key, "/t", kind, "/d", value, "/f"])?;
            }
            output("reg", &["delete", root, "/v", "AutoConfigURL", "/f"]).ok();
            notify_windows();
        }
    }
    Ok(())
}
fn write_snapshot(backend: Backend, snapshot: &Snapshot) -> Result<()> {
    let mut first_error = None;
    for (key, value) in &snapshot.values {
        let result = (|| -> Result<()> {
            match backend {
                Backend::Gnome => {
                    let (schema, key) = key.split_once(':').ok_or_else(|| Error::SystemProxy("invalid saved setting".into()))?;
                    output("gsettings", &["set", schema, key, value])?;
                }
                Backend::Mac => {
                    let (service, kind) = key.split_once('\t').ok_or_else(|| Error::SystemProxy("invalid saved service".into()))?;
                    match kind {
                        "bypass" => {
                            let mut args = vec!["-setproxybypassdomains", service];
                            let domains: Vec<&str> = value.lines().map(str::trim).filter(|s| !s.is_empty() && !s.starts_with("There aren't any bypass domains")).collect();
                            if domains.is_empty() { args.push("Empty"); } else { args.extend(domains); }
                            output("networksetup", &args)?;
                        }
                        _ => {
                            let enabled = value.lines().any(|l| l.trim() == "Enabled: Yes");
                            let field = |name: &str| value.lines().find_map(|l| Some(l.trim().strip_prefix(name)?.trim().to_owned())).unwrap_or_default();
                            let server = field("Server:"); let port = field("Port:");
                            let command = match kind { "web" => "-setwebproxy", "secure" => "-setsecurewebproxy", _ => "-setsocksfirewallproxy" };
                            if !server.is_empty() && !port.is_empty() { output("networksetup", &[command, service, &server, &port, if enabled { "on" } else { "off" }])?; }
                            else { let command = match kind { "web" => "-setwebproxystate", "secure" => "-setsecurewebproxystate", _ => "-setsocksfirewallproxystate" }; output("networksetup", &[command, service, "off"])?; }
                        }
                    }
                }
                Backend::Windows => {
                    let root = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings";
                    if value == "<absent>" { output("reg", &["delete", root, "/v", key, "/f"]).ok(); }
                    else {
                        let fields: Vec<&str> = value.split_whitespace().collect();
                        // reg.exe output: name type value (value may contain spaces).
                        if fields.len() >= 3 && fields[1].starts_with("REG_") {
                            let value = value.split_once(fields[1]).map(|(_, rest)| rest.trim()).unwrap_or("");
                            output("reg", &["add", root, "/v", key, "/t", fields[1], "/d", value, "/f"])?;
                        }
                    }
                }
            }
            Ok(())
        })();
        if let Err(e) = result { if first_error.is_none() { first_error = Some(e); } }
    }
    if matches!(backend, Backend::Windows) { notify_windows(); }
    match first_error { Some(e) => Err(e), None => Ok(()) }
}
fn gnome_set(schema: &str, key: &str, value: &str) -> Result<()> {
    output("gsettings", &["set", schema, key, value]).map(|_| ())
}
fn gnome_keys() -> Vec<(&'static str, &'static str)> {
    let mut keys = vec![("org.gnome.system.proxy", "mode"), ("org.gnome.system.proxy", "autoconfig-url"), ("org.gnome.system.proxy", "use-same-proxy"), ("org.gnome.system.proxy", "ignore-hosts")];
    for schema in ["org.gnome.system.proxy.http", "org.gnome.system.proxy.https"] {
        for key in ["host", "port", "use-authentication", "authentication-user", "authentication-password", "enabled"] { keys.push((schema, key)); }
    }
    for key in ["host", "port"] { keys.push(("org.gnome.system.proxy.socks", key)); }
    keys
}
#[cfg(target_os = "windows")]
fn notify_windows() {
    // wininet is a system library; refresh without logoff or a browser restart.
    #[link(name = "wininet")]
    extern "system" { fn InternetSetOptionW(handle: *mut std::ffi::c_void, option: u32, buffer: *mut std::ffi::c_void, length: u32) -> i32; }
    // SAFETY: both calls use null buffer/length with the documented refresh
    // options and no process handle (settings changed for the current user).
    unsafe { InternetSetOptionW(std::ptr::null_mut(), 39, std::ptr::null_mut(), 0); InternetSetOptionW(std::ptr::null_mut(), 37, std::ptr::null_mut(), 0); }
}
#[cfg(not(target_os = "windows"))]
fn notify_windows() {}
