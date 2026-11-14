//! Xray process lifetime and optional OS proxy ownership.

use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use uuid::Uuid;

use crate::error::{Error, Result};
use crate::model::Settings;
use crate::store::PrivateFile;
use crate::system_proxy::SystemProxyGuard;

pub struct Runtime {
    child: Child,
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
    pub fn start(profile_id: Uuid, profile_name: &str, config: serde_json::Value, settings: &Settings, xray: &Path) -> Result<Self> {
        settings.validate()?;
        if settings.set_system_proxy && !config_has_http_listener(&config, settings.http_port) {
            return Err(Error::InvalidProfile("system proxy requires an imported HTTP inbound on the configured HTTP port".into()));
        }
        crate::config::validate_with_xray(xray, &config)?;
        for port in [settings.socks_port, settings.http_port] {
            if TcpListener::bind(("127.0.0.1", port)).is_err() { return Err(Error::PortInUse); }
        }
        let config_file = PrivateFile::write_json(&config)?;
        let mut command = Command::new(xray);
        command.arg("run").arg("-c").arg(config_file.path())
            .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
        #[cfg(target_os = "windows")]
        { use std::os::windows::process::CommandExt; command.creation_flags(0x0800_0000); }
        let mut child = command.spawn()?;
        let deadline = Instant::now() + Duration::from_secs(8);
        loop {
            if child.try_wait()?.is_some() { return Err(Error::XrayStartup); }
            let socks = TcpStream::connect(("127.0.0.1", settings.socks_port)).is_ok();
            let http = TcpStream::connect(("127.0.0.1", settings.http_port)).is_ok();
            if socks && http { break; }
            if Instant::now() >= deadline {
                let _ = child.kill(); let _ = child.wait();
                return Err(Error::XrayStartup);
            }
            std::thread::sleep(Duration::from_millis(80));
        }
        let system_proxy = if settings.set_system_proxy {
            match SystemProxyGuard::enable(settings.http_port, settings.socks_port) {
                Ok(guard) => Some(guard),
                Err(e) => { let _ = child.kill(); let _ = child.wait(); return Err(e); }
            }
        } else { None };
        Ok(Self { child, _config: config_file, _system_proxy: system_proxy, profile_id, profile_name: profile_name.to_owned(), since: Instant::now(), exit_error: None })
    }
    pub fn profile_id(&self) -> Uuid { self.profile_id }
    pub fn profile_name(&self) -> &str { &self.profile_name }
    pub fn elapsed_secs(&self) -> u64 { self.since.elapsed().as_secs() }
    pub fn poll_exit(&mut self) -> Option<String> {
        if self.exit_error.is_none() {
            match self.child.try_wait() {
                Ok(Some(status)) => self.exit_error = Some(format!("Xray exited unexpectedly ({status}); proxy settings restored")),
                Ok(None) => {}
                Err(_) => self.exit_error = Some("Cannot monitor Xray; disconnect and reconnect".into()),
            }
        }
        self.exit_error.clone()
    }
    pub fn stop(mut self) -> Result<()> { self.shutdown() }
    fn shutdown(&mut self) -> Result<()> {
        let _ = self.child.kill();
        let _ = self.child.wait();
        // The guard restores saved OS settings, including PAC and bypass lists.
        if let Some(guard) = self._system_proxy.take() { guard.restore()?; }
        Ok(())
    }
}
impl Drop for Runtime { fn drop(&mut self) { let _ = self.shutdown(); } }

pub fn http_inbound_port(config: &serde_json::Value) -> Option<u16> {
    config.get("inbounds")?.as_array()?.iter().find_map(|inbound| {
        let is_http = inbound.get("protocol")?.as_str()? == "http";
        let listen = inbound.get("listen")?.as_str()?;
        let local = listen == "localhost" || listen.parse::<std::net::IpAddr>().is_ok_and(|ip| ip.is_loopback());
        if !is_http || !local { return None; }
        inbound.get("port")?.as_u64().or_else(|| inbound.get("port")?.as_str()?.parse().ok()).and_then(|port| u16::try_from(port).ok())
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

pub fn find_xray(settings: &Settings) -> Result<PathBuf> {
    if let Some(path) = &settings.xray_path {
        return if path.is_file() { Ok(path.clone()) } else { Err(Error::XrayNotFound) };
    }
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
