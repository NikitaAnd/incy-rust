//! Public errors deliberately exclude subscription URLs and server credentials.

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Invalid profile: {0}")]
    InvalidProfile(String),
    #[error("Unsupported share-link scheme or encoding")]
    UnsupportedLink,
    #[error("Subscription must use HTTPS and a valid hostname")]
    InvalidSubscriptionUrl,
    #[error("Subscription is too large (maximum 4 MiB decompressed)")]
    SubscriptionTooLarge,
    #[error("No valid server links in subscription")]
    EmptySubscription,
    #[error("Subscription HTTP request failed ({0})")]
    Http(String),
    #[error("Unsupported state version {0}; this client supports version 1")]
    UnsupportedVersion(u32),
    #[error("Limit exceeded: {0}")]
    Limit(String),
    #[error("Profile not found")]
    NotFound,
    #[error("Xray executable not found; set its path in Settings")]
    XrayNotFound,
    #[error("Xray configuration rejected: {0}")]
    XrayRejected(String),
    #[error("Xray exited before the local proxy became ready")]
    XrayStartup,
    #[error("Local proxy port is already in use")]
    PortInUse,
    #[error("System proxy operation failed: {0}")]
    SystemProxy(String),
    #[error("Cannot change system proxy while connected")]
    Busy,
    #[error("Local storage is unavailable: {0}")]
    Storage(String),
    #[error("File operation failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("Invalid JSON: {0}")]
    Json(#[from] serde_json::Error),
}
pub type Result<T> = std::result::Result<T, Error>;
