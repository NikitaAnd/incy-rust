//! Userspace TUN lifecycle. Linux uses iproute2 + tun2socks and an explicit
//! pkexec boundary; unsupported platforms fail closed rather than falling back
//! to the ordinary system proxy.
use std::path::Path;

use crate::{Error, Result};

pub struct TunnelRuntime {
    #[cfg(target_os = "linux")]
    child: std::process::Child,
    active: bool,
}

impl TunnelRuntime {
    pub fn start(helper: &Path, socks_port: u16, kill_switch: bool) -> Result<Self> {
        #[cfg(target_os = "linux")]
        { linux::start(helper, socks_port, kill_switch) }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (helper, socks_port, kill_switch);
            Err(Error::Tunnel("TUN backend is not yet available on this operating system".into()))
        }
    }

    /// Called only for a deliberate disconnect. Drop intentionally leaves
    /// routes/firewall state in place: after a crash, fail closed until recovery.
    pub fn stop(mut self) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            let _ = self.child.kill();
            let _ = self.child.wait();
            linux::run_admin("stop", false)?;
        }
        self.active = false;
        Ok(())
    }

    #[cfg(target_os = "linux")]
    pub fn has_exited(&mut self) -> bool {
        self.child.try_wait().map(|status| status.is_some()).unwrap_or(true)
    }

    #[cfg(not(target_os = "linux"))]
    pub fn has_exited(&mut self) -> bool { false }
}

impl Drop for TunnelRuntime {
    fn drop(&mut self) {
        if !self.active { return; }
        #[cfg(target_os = "linux")]
        {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
        // Do not remove the fail-closed route or firewall from Drop. An
        // unexpected app exit must never silently restore unprotected egress.
    }
}

/// Entry point for the hidden `nikitavpnclient tun-admin` command. It is
/// invoked by pkexec as root and accepts no shell snippets or user paths.
pub fn admin_command(action: &str, kill_switch: bool) -> Result<()> {
    #[cfg(target_os = "linux")]
    { linux::admin_command(action, kill_switch) }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (action, kill_switch);
        Err(Error::Tunnel("privileged TUN operations are Linux-only in this build".into()))
    }
}

/// Restore routes/firewall saved by an earlier TUN session, e.g. after an
/// unexpected process termination. The user is prompted through pkexec.
pub fn restore_previous_state() -> Result<()> {
    #[cfg(target_os = "linux")]
    { linux::run_admin("stop", false) }
    #[cfg(not(target_os = "linux"))]
    { Err(Error::Tunnel("TUN recovery is Linux-only in this build".into())) }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::fs::{self, OpenOptions};
    use std::io::Write;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
    use std::path::Path;
    use std::process::{Child, Command, Stdio};

    use serde::{Deserialize, Serialize};

    use crate::{Error, Result};

    const TUN: &str = "inctun0";
    const MARK: &str = "81";
    const TABLE: &str = "10181";
    const RULE_PRIORITY: &str = "10081";
    const NFT_TABLE: &str = "nikitavpnclient";
    const STATE_DIR: &str = "/run/nikitavpnclient";
    const STATE_FILE: &str = "/run/nikitavpnclient/tun-state.json";

    #[derive(Serialize, Deserialize)]
    struct SavedRoutes { ipv4: Vec<String>, ipv6: Vec<String> }

    fn command(program: &str, args: &[&str]) -> Result<std::process::Output> {
        let output = Command::new(program).args(args).output()
            .map_err(|_| Error::Tunnel(format!("required system tool '{program}' is unavailable")))?;
        if !output.status.success() {
            return Err(Error::Tunnel(format!("system network operation '{program}' failed; no raw command output was exposed")));
        }
        Ok(output)
    }

    fn output_text(program: &str, args: &[&str]) -> Result<String> {
        let out = command(program, args)?;
        String::from_utf8(out.stdout).map_err(|_| Error::Tunnel("invalid response from system network tool".into()))
    }

    fn iface_from_route() -> Result<String> {
        let route = output_text("ip", &["-4", "route", "get", "1.1.1.1"])?;
        let words: Vec<&str> = route.split_whitespace().collect();
        let index = words.iter().position(|word| *word == "dev")
            .ok_or_else(|| Error::Tunnel("cannot determine the physical network interface".into()))?;
        let iface = words.get(index + 1).copied().unwrap_or("");
        if !valid_iface(iface) { return Err(Error::Tunnel("invalid physical interface name".into())); }
        Ok(iface.to_owned())
    }

    fn valid_iface(value: &str) -> bool {
        !value.is_empty() && value.len() <= 15 && value.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b':'))
    }

    pub(super) fn start(helper: &Path, socks_port: u16, kill_switch: bool) -> Result<super::TunnelRuntime> {
        if !helper.is_file() { return Err(Error::Tunnel("bundled tun2socks helper is missing".into())); }
        let iface = iface_from_route()?;
        run_admin("start", kill_switch)?;
        let proxy = format!("socks5://127.0.0.1:{socks_port}");
        let helper_args = vec!["--device".to_owned(), "tun://inctun0".to_owned(), "--proxy".to_owned(), proxy,
            "--interface".to_owned(), iface, "--fwmark".to_owned(), MARK.to_owned(), "--loglevel".to_owned(), "warn".to_owned()];
        let mut child = match Command::new(helper)
            .args(helper_args)
            .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).spawn() {
                Ok(child) => child,
                Err(_) => { let _ = run_admin("stop", false); return Err(Error::Tunnel("cannot start the bundled TUN engine; network routes were restored".into())); }
            };
        std::thread::sleep(std::time::Duration::from_millis(350));
        let status = match child.try_wait() {
            Ok(status) => status,
            Err(_) => { let _ = child.kill(); let _ = child.wait(); let _ = run_admin("stop", false); return Err(Error::Tunnel("cannot monitor the TUN engine; network routes were restored".into())); }
        };
        if status.is_some() {
            let _ = run_admin("stop", false);
            return Err(Error::Tunnel("TUN engine exited during startup; network routes were restored".into()));
        }
        Ok(super::TunnelRuntime { child, active: true })
    }

    pub(super) fn run_admin(action: &str, kill_switch: bool) -> Result<()> {
        let exe = std::env::current_exe().map_err(|_| Error::Tunnel("cannot locate the client executable".into()))?;
        let mut args = vec![exe.as_os_str().to_owned(), "tun-admin".into(), action.into()];
        if kill_switch { args.push("--kill-switch".into()); }
        let status = Command::new("pkexec").args(args).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).status()
            .map_err(|_| Error::Tunnel("administrator authorization (pkexec) is unavailable".into()))?;
        if !status.success() { return Err(Error::Tunnel("administrator authorization or TUN setup was declined".into())); }
        Ok(())
    }

    fn ip(args: &[&str]) -> Result<()> { command("ip", args).map(|_| ()) }
    fn nft_script(script: &str) -> Result<()> {
        let mut child = Command::new("nft").args(["-f", "-"]).stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::null()).spawn()
            .map_err(|_| Error::Tunnel("nftables is unavailable for the kill switch".into()))?;
        child.stdin.take().ok_or_else(|| Error::Tunnel("cannot configure nftables".into()))?.write_all(script.as_bytes())?;
        if !child.wait()?.success() { return Err(Error::Tunnel("nftables rejected the kill-switch rules".into())); }
        Ok(())
    }

    fn state_dir() -> Result<()> {
        match fs::symlink_metadata(STATE_DIR) {
            Ok(meta) if meta.is_dir() && meta.uid() == 0 => {
                fs::set_permissions(STATE_DIR, fs::Permissions::from_mode(0o700))?;
                Ok(())
            }
            Ok(_) => Err(Error::Tunnel("unsafe TUN recovery directory; refusing privileged operation".into())),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir(STATE_DIR)?;
                fs::set_permissions(STATE_DIR, fs::Permissions::from_mode(0o700))?;
                Ok(())
            }
            Err(error) => Err(error.into()),
        }
    }

    fn default_routes(family: &str) -> Result<Vec<String>> {
        let text = output_text("ip", &[family, "route", "show", "default"])?;
        Ok(text.lines().filter(|line| line.split_whitespace().next() == Some("default")).map(str::to_owned).collect())
    }

    fn route_table_args(route: &str, family: &str) -> Result<Vec<String>> {
        let words: Vec<&str> = route.split_whitespace().collect();
        if words.first() != Some(&"default") { return Err(Error::Tunnel("invalid saved default route".into())); }
        let dev_index = words.iter().position(|word| *word == "dev").ok_or_else(|| Error::Tunnel("default route has no device".into()))?;
        let dev = words.get(dev_index + 1).copied().unwrap_or("");
        if !valid_iface(dev) { return Err(Error::Tunnel("invalid route device".into())); }
        let mut args = vec![family.to_owned(), "route".into(), "add".into(), "default".into()];
        if let Some(index) = words.iter().position(|word| *word == "via") {
            let gateway = words.get(index + 1).copied().unwrap_or("");
            gateway.parse::<std::net::IpAddr>().map_err(|_| Error::Tunnel("invalid route gateway".into()))?;
            args.extend(["via".into(), gateway.into()]);
        }
        args.extend(["dev".into(), dev.into(), "table".into(), TABLE.into()]);
        Ok(args)
    }

    fn run_ip_owned(args: &[String]) -> Result<()> {
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        ip(&refs)
    }

    fn replay(routes: &[String], family: &str) -> Result<()> {
        for route in routes {
            let mut args: Vec<String> = vec![family.into(), "route".into(), "add".into()];
            // Kernel output is parsed to arguments, never evaluated by a shell.
            for part in route.split_whitespace() {
                if part.chars().any(|c| !(c.is_ascii_alphanumeric() || matches!(c, '.' | ':' | '/' | '_' | '-' | '='))) {
                    return Err(Error::Tunnel("saved route contained unsafe characters".into()));
                }
                args.push(part.into());
            }
            run_ip_owned(&args)?;
        }
        Ok(())
    }

    fn install_kill_switch() -> Result<()> {
        nft_script(&format!(
            "add table inet {NFT_TABLE}\n\
             add chain inet {NFT_TABLE} output {{ type filter hook output priority -5; policy drop; }}\n\
             add rule inet {NFT_TABLE} output oifname \"lo\" accept\n\
             add rule inet {NFT_TABLE} output oifname \"{TUN}\" accept\n\
             add rule inet {NFT_TABLE} output meta mark {MARK} accept\n"
        ))
    }

    fn restore() -> Result<()> {
        let bytes = fs::read(STATE_FILE).map_err(|_| Error::Tunnel("no saved TUN route state exists".into()))?;
        let saved: SavedRoutes = serde_json::from_slice(&bytes).map_err(|_| Error::Tunnel("saved TUN recovery data is invalid".into()))?;
        let _ = Command::new("nft").args(["delete", "table", "inet", NFT_TABLE]).stdout(Stdio::null()).stderr(Stdio::null()).status();
        let _ = ip(&["-4", "rule", "del", "priority", RULE_PRIORITY, "fwmark", MARK, "table", TABLE]);
        let _ = ip(&["-6", "rule", "del", "priority", RULE_PRIORITY, "fwmark", MARK, "table", TABLE]);
        let _ = ip(&["-4", "route", "flush", "table", TABLE]);
        let _ = ip(&["-6", "route", "flush", "table", TABLE]);
        let _ = ip(&["-4", "route", "flush", "default"]);
        let _ = ip(&["-6", "route", "flush", "default"]);
        let _ = ip(&["link", "delete", "dev", TUN]);
        replay(&saved.ipv4, "-4")?;
        replay(&saved.ipv6, "-6")?;
        fs::remove_file(STATE_FILE)?;
        Ok(())
    }

    pub(super) fn admin_command(action: &str, kill_switch: bool) -> Result<()> {
        if output_text("id", &["-u"])?.trim() != "0" {
            return Err(Error::Tunnel("tun-admin must be launched by pkexec".into()));
        }
        match action {
            "start" => admin_start(kill_switch),
            "stop" => restore(),
            _ => Err(Error::Tunnel("unknown privileged TUN operation".into())),
        }
    }

    fn admin_start(kill_switch: bool) -> Result<()> {
        state_dir()?;
        if Path::new(STATE_FILE).exists() {
            // A prior crash deliberately leaves the fail-closed route and rules
            // installed. Reuse that protected state when reconnecting.
            if Command::new("ip").args(["link", "show", "dev", TUN]).stdout(Stdio::null()).stderr(Stdio::null()).status().is_ok_and(|s| s.success()) {
                if kill_switch { return install_kill_switch_if_missing(); }
                return Ok(());
            }
            restore()?;
        }
        let ipv4 = default_routes("-4")?;
        let ipv6 = default_routes("-6")?;
        if ipv4.is_empty() { return Err(Error::Tunnel("no IPv4 default route is available".into())); }
        let saved = SavedRoutes { ipv4: ipv4.clone(), ipv6: ipv6.clone() };
        let file = OpenOptions::new().write(true).create_new(true).mode(0o600).open(STATE_FILE)?;
        serde_json::to_writer(&file, &saved)?;
        file.sync_all()?;

        let setup = (|| -> Result<()> {
            let uid = std::env::var("PKEXEC_UID").ok().and_then(|s| s.parse::<u32>().ok())
                .ok_or_else(|| Error::Tunnel("pkexec did not provide the desktop user id".into()))?;
            let physical4 = route_table_args(&ipv4[0], "-4")?;
            run_ip_owned(&physical4)?;
            if let Some(route) = ipv6.first() {
                let physical6 = route_table_args(route, "-6")?;
                run_ip_owned(&physical6)?;
            }
            let uid = uid.to_string();
            ip(&["tuntap", "add", "dev", TUN, "mode", "tun", "user", &uid])?;
            ip(&["addr", "add", "198.18.0.1/15", "dev", TUN])?;
            ip(&["-6", "addr", "add", "fdfe:dcba:9876::1/126", "dev", TUN])?;
            ip(&["link", "set", "dev", TUN, "up"])?;
            ip(&["-4", "route", "flush", "default"])?;
            ip(&["-6", "route", "flush", "default"])?;
            ip(&["-4", "route", "add", "default", "dev", TUN])?;
            ip(&["-6", "route", "add", "default", "dev", TUN])?;
            ip(&["-4", "rule", "add", "priority", RULE_PRIORITY, "fwmark", MARK, "table", TABLE])?;
            ip(&["-6", "rule", "add", "priority", RULE_PRIORITY, "fwmark", MARK, "table", TABLE])?;
            if kill_switch { install_kill_switch()?; }
            Ok(())
        })();
        if let Err(error) = setup {
            let _ = restore();
            return Err(error);
        }
        Ok(())
    }

    fn install_kill_switch_if_missing() -> Result<()> {
        let chain = Command::new("nft").args(["list", "chain", "inet", NFT_TABLE, "output"]).output();
        if let Ok(output) = chain {
            if output.status.success() {
                let rules = String::from_utf8_lossy(&output.stdout);
                if rules.contains("policy drop") && rules.contains("oifname") && rules.contains("lo")
                    && rules.contains(TUN) && rules.contains(&format!("meta mark {MARK} accept"))
                { return Ok(()); }
            }
        }
        let _ = Command::new("nft").args(["delete", "table", "inet", NFT_TABLE]).stdout(Stdio::null()).stderr(Stdio::null()).status();
        install_kill_switch()
    }

    #[cfg(test)]
    mod tests {
        use super::{route_table_args, valid_iface};

        #[test]
        fn physical_route_is_copied_to_a_separate_policy_table() {
            let args = route_table_args("default via 192.0.2.1 dev wlp2s0 proto dhcp metric 600", "-4").unwrap();
            assert_eq!(args, ["-4", "route", "add", "default", "via", "192.0.2.1", "dev", "wlp2s0", "table", "10181"].map(String::from).to_vec());
            assert!(route_table_args("default via bad;command dev eth0", "-4").is_err());
        }

        #[test]
        fn interface_names_are_not_shell_fragments() {
            assert!(valid_iface("enp0s3"));
            assert!(!valid_iface("eth0;reboot"));
            assert!(!valid_iface(""));
        }
    }
}
