//! Bounded HTTPS subscription download and refresh support.

use std::io::Read;
use std::time::Duration;

use url::Url;
use ureq::ResponseExt;
use uuid::Uuid;

use crate::error::{Error, Result};
use crate::model::{AppState, Profile};
use crate::share_link;

pub const MAX_BODY_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_SUBSCRIPTION_PROFILES: usize = 5_000;

pub fn validate_url(input: &str) -> Result<Url> {
    let url = Url::parse(input).map_err(|_| Error::InvalidSubscriptionUrl)?;
    if url.scheme() != "https" || url.host_str().is_none_or(str::is_empty)
        || !url.username().is_empty() || url.password().is_some() || url.fragment().is_some()
        || input.len() > 8192 || input.contains(['\r', '\n', '\0'])
    {
        return Err(Error::InvalidSubscriptionUrl);
    }
    Ok(url)
}

pub fn parse_body(body: &str) -> Result<Vec<Profile>> {
    if body.len() > MAX_BODY_BYTES { return Err(Error::SubscriptionTooLarge); }
    let mut text = body.trim().trim_start_matches('\u{feff}').to_owned();
    let trimmed = text.trim();
    // A JSON Xray document/array is deliberately not interpreted as a base64
    // subscription. Full-config import is a separate, explicit operation.
    if !trimmed.starts_with('{') && !trimmed.starts_with('[')
        && !trimmed.lines().any(|l| l.trim().contains("://"))
        && !trimmed.is_empty()
    {
        let bytes = share_link::decode_base64(trimmed)?;
        if bytes.len() > MAX_BODY_BYTES { return Err(Error::SubscriptionTooLarge); }
        text = String::from_utf8(bytes).map_err(|_| Error::UnsupportedLink)?;
    }
    let mut profiles = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut invalid = 0;
    for line in text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')) {
        match share_link::parse(line) {
            Ok(profile) => {
                // Duplicate lines are common at the end of provider responses.
                let key = format!("{profile:?}");
                if seen.insert(key) { profiles.push(profile); }
            }
            Err(_) => invalid += 1,
        }
        if profiles.len() + invalid > MAX_SUBSCRIPTION_PROFILES { return Err(Error::Limit("too many subscription entries".into())); }
    }
    // A partially corrupt subscription must not silently discard paid servers.
    if invalid > 0 { return Err(Error::InvalidProfile(format!("{invalid} subscription entries could not be parsed; existing servers were not changed"))); }
    if profiles.is_empty() { return Err(Error::EmptySubscription); }
    Ok(profiles)
}

pub struct Download { pub profiles: Vec<Profile>, pub user_info: Option<String> }

pub fn download(url: &str) -> Result<Download> {
    validate_url(url)?;
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(30)))
        .timeout_connect(Some(Duration::from_secs(10)))
        .http_status_as_error(true)
        .https_only(true)
        .proxy(None)
        .max_redirects(0)
        .user_agent(concat!("INCY-Rust/", env!("CARGO_PKG_VERSION")))
        .build().into();
    let response = agent.get(url).header("Accept", "text/plain, application/octet-stream").call();
    let mut response = response.map_err(|e| Error::Http(redacted_http_error(&e)))?;
    // Follow HTTPS-only redirects manually so a provider cannot downgrade a
    // bearer subscription URL to plaintext HTTP.
    for _ in 0..4 {
        if !response.status().is_redirection() { break; }
        let location = response.headers().get("location").and_then(|v| v.to_str().ok()).ok_or_else(|| Error::Http("redirect without Location".into()))?;
        let current = Url::parse(&response.get_uri().to_string()).map_err(|_| Error::InvalidSubscriptionUrl)?;
        let next = current.join(location).map_err(|_| Error::InvalidSubscriptionUrl)?;
        validate_url(next.as_str())?;
        response = agent.get(next.as_str()).call().map_err(|e| Error::Http(redacted_http_error(&e)))?;
    }
    if response.status().is_redirection() { return Err(Error::Http("too many redirects".into())); }
    let user_info = response.headers().get("subscription-userinfo").and_then(|v| v.to_str().ok()).map(|s| s.chars().take(512).collect());
    let mut bytes = Vec::new();
    response.body_mut().as_reader().take((MAX_BODY_BYTES + 1) as u64).read_to_end(&mut bytes).map_err(|_| Error::Http("interrupted or oversized response".into()))?;
    if bytes.len() > MAX_BODY_BYTES { return Err(Error::SubscriptionTooLarge); }
    let text = String::from_utf8(bytes).map_err(|_| Error::UnsupportedLink)?;
    Ok(Download { profiles: parse_body(&text)?, user_info })
}

fn redacted_http_error(error: &ureq::Error) -> String {
    match error {
        ureq::Error::StatusCode(code) => format!("HTTP {code}"),
        ureq::Error::Timeout(_) => "timeout".into(),
        ureq::Error::RedirectFailed => "unsafe redirect".into(),
        ureq::Error::BodyExceedsLimit(_) => "response too large".into(),
        _ => "network/TLS error".into(),
    }
}
pub fn now_unix() -> u64 { std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0) }
pub fn due(state: &AppState) -> Vec<Uuid> {
    let now = now_unix();
    state.subscriptions.iter().filter(|s| s.last_refresh_unix.is_none_or(|last| now.saturating_sub(last) >= s.refresh_secs)).map(|s| s.id).collect()
}
