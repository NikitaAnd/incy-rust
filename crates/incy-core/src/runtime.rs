//! Xray process lifetime and optional OS proxy ownership.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::error::{Error, Result};
use crate::model::Settings;
use crate::store::PrivateFile;
use crate::system_proxy::SystemProxyGuard;

#[derive(Clone, Copy)]
pub struct EmbeddedXray<'a> {
    pub executable: &'a [u8],
    pub geoip: &'a [u8],
    pub geosite: &'a [u8],
    pub tun2socks: &'a [u8],
}

pub struct Runtime {
    child: Child,
    _tun: Option<crate::tun::TunnelRuntime>,
    kill_switch: bool,
    // Declaration order matters: proxy is restored and the child stopped before
    // the generated, secret-bearing config is removed.
    _config: PrivateFile,
    _system_proxy: Option<SystemProxyGuard>,
    profile_id: Uuid,
    profile_name: String,
    since: Instant,
    exit_error: Option<String>,
}
impl Runtime {
    pub fn start(profile_id: Uuid, profile_name: &str, mut config: serde_json::Value, settings: &Settings, xray: &Path, tun2socks: Option<&Path>) -> Result<Self> {
        settings.validate()?;
        if settings.kill_switch { crate::config::enforce_kill_switch(&mut config)?; }
        if settings.tun_mode {
            if !cfg!(target_os = "linux") { return Err(Error::Tunnel("TUN mode is currently supported on Linux only".into())); }
            crate::config::mark_outbounds_for_tun(&mut config)?;
            if tun2socks.is_none() { return Err(Error::Tunnel("bundled tun2socks helper is missing".into())); }
        }
        if settings.set_system_proxy && !config_has_http_listener(&config, settings.http_port) {
            return Err(Error::InvalidProfile("system proxy requires an imported HTTP inbound on the configured HTTP port".into()));
        }
        if settings.tun_mode && !config_has_socks_listener(&config, settings.socks_port) {
            return Err(Error::InvalidProfile("TUN mode requires a loopback SOCKS inbound on the configured SOCKS port".into()));
        }
        crate::config::validate_with_xray(xray, &config)?;
        let tcp_ports = local_tcp_inbound_ports(&config);
        for port in &tcp_ports {
            if TcpListener::bind(("127.0.0.1", *port)).is_err() { return Err(Error::PortInUse); }
        }
        let config_file = PrivateFile::write_json(&config)?;
        let mut command = Command::new(xray);
        if let Some(asset_dir) = xray.parent() { command.env("XRAY_LOCATION_ASSET", asset_dir); }
        command.arg("run").arg("-c").arg(config_file.path())
            .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
        #[cfg(target_os = "windows")]
        { use std::os::windows::process::CommandExt; command.creation_flags(0x0800_0000); }
        let mut child = command.spawn()?;
        let startup_probe = if tcp_ports.is_empty() { Duration::from_millis(500) } else { Duration::from_secs(8) };
        let started_at = Instant::now();
        let deadline = started_at + startup_probe;
        loop {
            if child.try_wait()?.is_some() { return Err(Error::XrayStartup); }
            let ready = if tcp_ports.is_empty() {
                started_at.elapsed() >= startup_probe
            } else {
                tcp_ports.iter().all(|port| TcpStream::connect(("127.0.0.1", *port)).is_ok())
            };
            if ready { break; }
            if Instant::now() >= deadline {
                let _ = child.kill(); let _ = child.wait();
                return Err(Error::XrayStartup);
            }
            std::thread::sleep(Duration::from_millis(80));
        }
        let tun = if settings.tun_mode {
            match crate::tun::TunnelRuntime::start(tun2socks.expect("checked above"), settings.socks_port, settings.kill_switch) {
                Ok(tun) => Some(tun),
                Err(error) => { let _ = child.kill(); let _ = child.wait(); return Err(error); }
            }
        } else { None };
        let system_proxy = if settings.set_system_proxy {
            match SystemProxyGuard::enable(settings.http_port, settings.socks_port) {
                Ok(guard) => Some(guard),
                Err(e) => {
                    if let Some(tun) = tun { let _ = tun.stop(); }
                    let _ = child.kill(); let _ = child.wait(); return Err(e);
                }
            }
        } else { None };
        Ok(Self { child, _tun: tun, kill_switch: settings.kill_switch, _config: config_file, _system_proxy: system_proxy, profile_id, profile_name: profile_name.to_owned(), since: Instant::now(), exit_error: None })
    }
    pub fn profile_id(&self) -> Uuid { self.profile_id }
    pub fn profile_name(&self) -> &str { &self.profile_name }
    pub fn elapsed_secs(&self) -> u64 { self.since.elapsed().as_secs() }
    pub fn poll_exit(&mut self) -> Option<String> {
        if self.exit_error.is_none() {
            if self._tun.as_mut().is_some_and(crate::tun::TunnelRuntime::has_exited) {
                self.exit_error = Some(if self.kill_switch {
                    "TUN engine exited unexpectedly; kill switch remains active. Restore routes from Settings after checking the connection.".into()
                } else {
                    "TUN engine exited unexpectedly; network routes are being restored.".into()
                });
            } else {
                match self.child.try_wait() {
                    Ok(Some(status)) => self.exit_error = Some(if self.kill_switch {
                        format!("Xray exited unexpectedly ({status}); kill switch remains active. Restore routes from Settings.")
                    } else {
                        format!("Xray exited unexpectedly ({status}); network routes will be restored.")
                    }),
                    Ok(None) => {}
                    Err(_) => self.exit_error = Some("Cannot monitor Xray; disconnect and reconnect".into()),
                }
            }
        }
        self.exit_error.clone()
    }
    pub fn stop(mut self) -> Result<()> { self.shutdown() }
    fn shutdown(&mut self) -> Result<()> {
        let preserve_kill_switch = self.kill_switch && self.exit_error.is_some();
        let mut first_error = None;
        if let Some(tun) = self._tun.take() {
            if preserve_kill_switch { drop(tun); }
            else if let Err(error) = tun.stop() { first_error = Some(error); }
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
        // The guard restores saved OS settings, including PAC and bypass lists.
        if let Some(guard) = self._system_proxy.take() {
            if let Err(error) = guard.restore() { if first_error.is_none() { first_error = Some(error); } }
        }
        match first_error { Some(error) => Err(error), None => Ok(()) }
    }
}
impl Drop for Runtime { fn drop(&mut self) { let _ = self.shutdown(); } }

fn local_tcp_inbound_ports(config: &serde_json::Value) -> Vec<u16> {
    let Some(inbounds) = config.get("inbounds").and_then(serde_json::Value::as_array) else { return Vec::new(); };
    let mut ports = Vec::new();
    for inbound in inbounds {
        let protocol = inbound.get("protocol").and_then(serde_json::Value::as_str).unwrap_or("");
        if !matches!(protocol, "socks" | "http" | "vmess" | "vless" | "trojan" | "shadowsocks") { continue; }
        let Some(listen) = inbound.get("listen").and_then(serde_json::Value::as_str) else { continue; };
        if !(listen == "localhost" || listen.parse::<std::net::IpAddr>().is_ok_and(|ip| ip.is_loopback())) { continue; }
        let Some(port) = inbound.get("port").and_then(|p| p.as_u64().or_else(|| p.as_str().and_then(|s| s.parse().ok()))).and_then(|p| u16::try_from(p).ok()) else { continue; };
        if port > 0 && !ports.contains(&port) { ports.push(port); }
    }
    ports
}

pub fn http_inbound_port(config: &serde_json::Value) -> Option<u16> {
    config.get("inbounds")?.as_array()?.iter().find_map(|inbound| {
        let is_http = inbound.get("protocol")?.as_str()? == "http";
        let listen = inbound.get("listen")?.as_str()?;
        let local = listen == "localhost" || listen.parse::<std::net::IpAddr>().is_ok_and(|ip| ip.is_loopback());
        if !is_http || !local { return None; }
        inbound.get("port")?.as_u64().or_else(|| inbound.get("port")?.as_str()?.parse().ok()).and_then(|port| u16::try_from(port).ok())
    })
}

fn config_has_socks_listener(config: &serde_json::Value, port: u16) -> bool {
    config.get("inbounds").and_then(serde_json::Value::as_array).is_some_and(|inbounds| {
        inbounds.iter().any(|inbound| {
            inbound.get("protocol").and_then(serde_json::Value::as_str) == Some("socks")
                && inbound.get("port").and_then(|p| p.as_u64().or_else(|| p.as_str().and_then(|s| s.parse().ok()))) == Some(u64::from(port))
                && inbound.get("listen").and_then(serde_json::Value::as_str).is_some_and(|host| host == "localhost" || host.parse::<std::net::IpAddr>().is_ok_and(|ip| ip.is_loopback()))
                && inbound.get("settings").and_then(serde_json::Value::as_object).is_some_and(|socks| {
                    socks.get("udp").and_then(serde_json::Value::as_bool) == Some(true)
                        && socks.get("auth").and_then(serde_json::Value::as_str).is_none_or(|auth| auth == "noauth")
                })
        })
    })
}

fn config_has_http_listener(config: &serde_json::Value, port: u16) -> bool {
    config.get("inbounds").and_then(serde_json::Value::as_array).is_some_and(|inbounds| {
        inbounds.iter().any(|inbound| {
            inbound.get("protocol").and_then(serde_json::Value::as_str) == Some("http")
                && inbound.get("port").and_then(|p| p.as_u64().or_else(|| p.as_str().and_then(|s| s.parse().ok()))) == Some(u64::from(port))
                && inbound.get("listen").and_then(serde_json::Value::as_str).is_some_and(|host| host == "localhost" || host.parse::<std::net::IpAddr>().is_ok_and(|ip| ip.is_loopback()))
        })
    })
}

fn install_embedded_file(dir: &Path, name: &str, bytes: &[u8], executable: bool) -> Result<PathBuf> {
    let destination = dir.join(name);
    let expected = Sha256::digest(bytes);
    if let Ok(existing) = fs::read(&destination) {
        if Sha256::digest(&existing) == expected { return Ok(destination); }
    }
    let temporary = dir.join(format!(".{name}-{}.tmp", Uuid::new_v4()));
    let result = (|| -> Result<()> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(if executable { 0o700 } else { 0o600 });
        }
        let mut file = options.open(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&temporary, fs::Permissions::from_mode(if executable { 0o700 } else { 0o600 }))?;
        }
        if destination.exists() { fs::remove_file(&destination)?; }
        fs::rename(&temporary, &destination)?;
        Ok(())
    })();
    if result.is_err() { let _ = fs::remove_file(&temporary); }
    result?;
    Ok(destination)
}

fn materialize_xray(bundle: EmbeddedXray<'_>) -> Result<PathBuf> {
    let dir = crate::store::default_data_dir()?.join("core");
    crate::store::create_private_dir(&dir)?;
    install_embedded_file(&dir, if cfg!(windows) { "xray.exe" } else { "xray" }, bundle.executable, true)?;
    install_embedded_file(&dir, "geoip.dat", bundle.geoip, false)?;
    install_embedded_file(&dir, "geosite.dat", bundle.geosite, false)?;
    install_embedded_file(&dir, if cfg!(windows) { "tun2socks.exe" } else { "tun2socks" }, bundle.tun2socks, true)?;
    Ok(dir.join(if cfg!(windows) { "xray.exe" } else { "xray" }))
}

pub fn find_tun2socks(embedded: Option<EmbeddedXray<'_>>) -> Result<PathBuf> {
    if let Some(bundle) = embedded {
        let dir = crate::store::default_data_dir()?.join("core");
        crate::store::create_private_dir(&dir)?;
        return install_embedded_file(&dir, if cfg!(windows) { "tun2socks.exe" } else { "tun2socks" }, bundle.tun2socks, true);
    }
    let name = if cfg!(windows) { "tun2socks.exe" } else { "tun2socks" };
    if let Ok(current) = std::env::current_exe() {
        if let Some(dir) = current.parent() {
            for path in [dir.join(name), dir.join("core").join(name)] { if path.is_file() { return Ok(path); } }
        }
    }
    if let Some(paths) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&paths) { let path = dir.join(name); if path.is_file() { return Ok(path); } }
    }
    Err(Error::Tunnel("tun2socks helper was not found".into()))
}

pub fn find_xray(settings: &Settings, embedded: Option<EmbeddedXray<'_>>) -> Result<PathBuf> {
    if let Some(path) = &settings.xray_path {
        return if path.is_file() { Ok(path.clone()) } else { Err(Error::XrayNotFound) };
    }
    if let Some(bundle) = embedded { return materialize_xray(bundle); }
    let name = if cfg!(windows) { "xray.exe" } else { "xray" };
    if let Ok(current) = std::env::current_exe() {
        if let Some(dir) = current.parent() {
            let beside = dir.join(name); if beside.is_file() { return Ok(beside); }
            let nested = dir.join("core").join(name); if nested.is_file() { return Ok(nested); }
        }
    }
    if let Some(paths) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&paths) {
            let path = dir.join(name); if path.is_file() { return Ok(path); }
        }
    }
    Err(Error::XrayNotFound)
}

/// An actual HTTPS request through the local HTTP CONNECT listener. A TCP ping
/// alone would incorrectly report a broken tunnel as healthy.
pub fn probe(http_port: u16) -> Result<Duration> {
    let proxy = ureq::Proxy::new(&format!("http://127.0.0.1:{http_port}")).map_err(|_| Error::XrayStartup)?;
    let agent: ureq::Agent = ureq::Agent::config_builder().proxy(Some(proxy))
        .timeout_global(Some(Duration::from_secs(12))).https_only(true)
        .max_redirects(0).build().into();
    let start = Instant::now();
    let mut response = agent.get("https://www.gstatic.com/generate_204").call().map_err(|_| Error::Http("tunnel probe failed".into()))?;
    let mut sink = Vec::new();
    use std::io::Read;
    response.body_mut().as_reader().take(4096).read_to_end(&mut sink).map_err(|_| Error::Http("interrupted tunnel probe".into()))?;
    Ok(start.elapsed())
}
