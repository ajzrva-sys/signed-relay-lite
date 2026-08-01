//! DKIM signing configuration.

use openssl::pkey::{PKey, Private};
use std::sync::Arc;

/// Configuration for DKIM signing.
///
/// Contains only the essentials for signing: domain, selector, and the RSA
/// private key wrapped in [`Arc`] for shared ownership across async tasks.
#[derive(Clone)]
pub struct SigningConfig {
    /// The signing domain (d= tag). Lowercase, no trailing dot.
    pub domain: String,
    /// The key selector (s= tag). Lowercase, no trailing dot.
    pub selector: String,
    /// RSA private key used for RSA-SHA256 signing.
    pub key: Arc<PKey<Private>>,
}
