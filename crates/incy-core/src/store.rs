//! Atomic, versioned local storage. No cloud sync and no analytics.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use uuid::Uuid;

use crate::error::{Error, Result};
use crate::model::*;

const MAX_STATE_BYTES: u64 = 32 * 1024 * 1024;

pub struct Store { path: PathBuf, state: AppState }
impl Store {
    pub fn open_default() -> Result<Self> { Self::open(default_data_dir()?.join("state.json")) }
    pub fn open(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        if let Some(parent) = path.parent() { create_private_dir(parent)?; }
        let state = match fs::File::open(&path) {
            Ok(file) => {
                if file.metadata()?.len() > MAX_STATE_BYTES { return Err(Error::Limit("state file too large".into())); }
                let state: AppState = serde_json::from_reader(file)?;
                state.validate()?;
                state
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => AppState::default(),
            Err(e) => return Err(e.into()),
        };
        Ok(Self { path, state })
    }
    pub fn state(&self) -> &AppState { &self.state }
    pub fn path(&self) -> &Path { &self.path }
    pub fn save(&self) -> Result<()> { self.write_state(&self.state) }
    fn write_state(&self, state: &AppState) -> Result<()> {
        state.validate()?;
        let bytes = serde_json::to_vec_pretty(state)?;
        if bytes.len() as u64 > MAX_STATE_BYTES { return Err(Error::Limit("state file too large".into())); }
        let mut file = PrivateFile::new_in(self.path.parent().ok_or_else(|| Error::InvalidProfile("state path has no parent".into()))?)?;
        file.file.write_all(&bytes)?;
        file.file.sync_all()?;
        // Keep the previous valid generation for manual recovery. On Windows,
        // replace an existing backup before renaming the current file.
        let backup = self.path.with_extension("json.bak");
        if self.path.exists() {
            if backup.exists() { fs::remove_file(&backup)?; }
            fs::rename(&self.path, &backup)?;
        }
        if let Err(e) = fs::rename(file.path(), &self.path) {
            let _ = fs::rename(&backup, &self.path);
            return Err(e.into());
        }
        file.disarm();
        Ok(())
    }
    pub fn update_settings(&mut self, settings: Settings) -> Result<()> {
        let mut next = self.state.clone(); next.settings = settings;
        self.write_state(&next)?; self.state = next; Ok(())
    }
    pub fn select(&mut self, id: Option<Uuid>) -> Result<()> {
        if id.is_some_and(|id| !self.state.profiles.iter().any(|p| p.id == id)) { return Err(Error::NotFound); }
        let mut next = self.state.clone(); next.selected_profile = id;
        self.write_state(&next)?; self.state = next; Ok(())
    }
    pub fn add_profiles(&mut self, profiles: Vec<Profile>) -> Result<Vec<Uuid>> {
        let mut next = self.state.clone();
        if next.profiles.len().saturating_add(profiles.len()) > MAX_PROFILES { return Err(Error::Limit("too many profiles".into())); }
        let ids: Vec<Uuid> = profiles.iter().map(|p| p.id).collect();
        next.profiles.extend(profiles);
        if next.selected_profile.is_none() { next.selected_profile = ids.first().copied(); }
        self.write_state(&next)?; self.state = next; Ok(ids)
    }
    pub fn remove_profile(&mut self, id: Uuid) -> Result<()> {
        let mut next = self.state.clone();
        let before = next.profiles.len(); next.profiles.retain(|p| p.id != id);
        if before == next.profiles.len() { return Err(Error::NotFound); }
        if next.selected_profile == Some(id) { next.selected_profile = next.profiles.first().map(|p| p.id); }
        self.write_state(&next)?; self.state = next; Ok(())
    }
    pub fn add_subscription(&mut self, name: String, url: String, refresh_secs: u64, profiles: Vec<Profile>) -> Result<Uuid> {
        crate::subscription::validate_url(&url)?;
        if profiles.is_empty() { return Err(Error::EmptySubscription); }
        let mut next = self.state.clone();
        if next.subscriptions.len() >= MAX_SUBSCRIPTIONS { return Err(Error::Limit("too many subscriptions".into())); }
        let id = Uuid::new_v4();
        let mut profiles = profiles;
        for p in &mut profiles { p.subscription_id = Some(id); }
        next.subscriptions.push(Subscription { id, name: if name.trim().is_empty() { "Subscription".into() } else { name.chars().take(256).collect() }, url, refresh_secs, last_refresh_unix: Some(crate::subscription::now_unix()), user_info: None });
        next.profiles.extend(profiles);
        if next.selected_profile.is_none() { next.selected_profile = next.profiles.first().map(|p| p.id); }
        self.write_state(&next)?; self.state = next; Ok(id)
    }
    pub fn replace_subscription(&mut self, id: Uuid, mut profiles: Vec<Profile>, user_info: Option<String>) -> Result<()> {
        if profiles.is_empty() { return Err(Error::EmptySubscription); }
        let mut next = self.state.clone();
        if !next.subscriptions.iter().any(|s| s.id == id) { return Err(Error::NotFound); }
        for p in &mut profiles { p.subscription_id = Some(id); }
        let selected_sub = next.selected_profile.and_then(|selected| next.profiles.iter().find(|p| p.id == selected).and_then(|p| p.subscription_id));
        // Match old servers by their full endpoint, preserving the selected UUID
        // whenever possible. Collisions are matched in subscription order.
        let old: Vec<Profile> = next.profiles.iter().filter(|p| p.subscription_id == Some(id)).cloned().collect();
        let mut used = std::collections::HashSet::new();
        for p in &mut profiles {
            if let Some(previous) = old.iter().find(|o| !used.contains(&o.id) && o.endpoint == p.endpoint && o.name == p.name) {
                used.insert(previous.id); p.id = previous.id;
            }
        }
        next.profiles.retain(|p| p.subscription_id != Some(id));
        next.profiles.extend(profiles);
        let sub = next.subscriptions.iter_mut().find(|s| s.id == id).ok_or(Error::NotFound)?;
        sub.last_refresh_unix = Some(crate::subscription::now_unix()); sub.user_info = user_info;
        if next.selected_profile.is_none_or(|sid| !next.profiles.iter().any(|p| p.id == sid)) {
            next.selected_profile = if selected_sub == Some(id) { next.profiles.iter().find(|p| p.subscription_id == Some(id)).map(|p| p.id) } else { next.profiles.first().map(|p| p.id) };
        }
        self.write_state(&next)?; self.state = next; Ok(())
    }
    pub fn remove_subscription(&mut self, id: Uuid, keep_profiles: bool) -> Result<()> {
        let mut next = self.state.clone();
        if !next.subscriptions.iter().any(|s| s.id == id) { return Err(Error::NotFound); }
        next.subscriptions.retain(|s| s.id != id);
        if keep_profiles { for p in &mut next.profiles { if p.subscription_id == Some(id) { p.subscription_id = None; } } }
        else { next.profiles.retain(|p| p.subscription_id != Some(id)); }
        if next.selected_profile.is_none_or(|sid| !next.profiles.iter().any(|p| p.id == sid)) { next.selected_profile = next.profiles.first().map(|p| p.id); }
        self.write_state(&next)?; self.state = next; Ok(())
    }
}

pub fn default_data_dir() -> Result<PathBuf> {
    if let Some(path) = std::env::var_os("INCY_DATA_DIR") { return Ok(PathBuf::from(path)); }
    let home = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")).map(PathBuf::from);
    #[cfg(target_os = "windows")]
    let base = std::env::var_os("APPDATA").map(PathBuf::from).or(home).ok_or_else(|| Error::Storage("APPDATA is not set".into()))?;
    #[cfg(target_os = "macos")]
    let base = home.ok_or_else(|| Error::Storage("HOME is not set".into()))?.join("Library/Application Support");
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    let base = std::env::var_os("XDG_DATA_HOME").map(PathBuf::from).unwrap_or(home.ok_or_else(|| Error::Storage("HOME is not set".into()))?.join(".local/share"));
    Ok(base.join("incy-rust"))
}

pub fn create_private_dir(path: &Path) -> Result<()> {
    fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// A random, exclusively created file. On Unix it is mode 0600 *before* any
/// secret is written. Dropping it removes generated Xray configs on all paths,
/// including validation errors and a handled application shutdown.
pub struct PrivateFile {
    path: PathBuf,
    file: fs::File,
    armed: bool,
}
impl PrivateFile {
    pub fn new_in(dir: &Path) -> Result<Self> {
        create_private_dir(dir)?;
        let path = dir.join(format!(".tmp-{}", Uuid::new_v4()));
        let mut options = OpenOptions::new(); options.write(true).create_new(true);
        #[cfg(unix)]
        { use std::os::unix::fs::OpenOptionsExt; options.mode(0o600); }
        let file = options.open(&path)?;
        Ok(Self { path, file, armed: true })
    }
    pub fn write_json(value: &serde_json::Value) -> Result<Self> {
        let dir = std::env::temp_dir().join(format!("incy-rust-{}", user_id()));
        let mut file = Self::new_in(&dir)?;
        file.file.write_all(&serde_json::to_vec_pretty(value)?)?;
        file.file.sync_all()?;
        Ok(file)
    }
    pub fn path(&self) -> &Path { &self.path }
    fn disarm(&mut self) { self.armed = false; }
}
impl Drop for PrivateFile {
    fn drop(&mut self) { if self.armed { let _ = fs::remove_file(&self.path); } }
}
fn user_id() -> String {
    std::env::var("UID").or_else(|_| std::env::var("USERNAME")).unwrap_or_else(|_| "user".into()).chars().filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_').collect()
}
