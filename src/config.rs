//! Strict startup configuration for signing and relaying mail.

use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use openssl::sign::Signer;
use std::collections::{HashMap, HashSet};
#[cfg(target_os = "linux")]
use std::ffi::{c_char, c_void};
use std::fmt;
use std::fs;
#[cfg(any(target_os = "linux", test))]
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

/// Configuration for DKIM signing.
///
/// Contains only the essentials for signing: domain, selector, and the RSA
/// private key wrapped in [`Arc`] for shared ownership across worker threads.
#[derive(Clone)]
pub struct SigningConfig {
    /// The signing domain (d= tag). Lowercase, no trailing dot.
    pub domain: String,
    /// The key selector (s= tag). Lowercase, no trailing dot.
    pub selector: String,
    /// RSA private key used for RSA-SHA256 signing.
    pub key: Arc<PKey<Private>>,
}

/// The only supported relay transport: TLS from the first byte of the connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RelayTls {
    Implicit,
}

/// Password bytes held only in memory and erased before their allocation is released.
pub struct Secret(Vec<u8>);

impl Secret {
    /// Take ownership of secret bytes so they can be erased on drop.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Make an independently owned, zero-on-drop copy for one relay worker.
    pub fn duplicate(&self) -> Self {
        Self(self.0.clone())
    }

    #[allow(dead_code)]
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Secret([REDACTED])")
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        erase(&mut self.0);
    }
}

fn erase(bytes: &mut [u8]) {
    // Volatile writes prevent the compiler from optimizing away the erasure.
    for byte in bytes {
        // SAFETY: `byte` is a valid, uniquely borrowed byte in this slice.
        unsafe { std::ptr::write_volatile(byte, 0) };
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}

/// Fully validated configuration. Secret file paths are deliberately not retained.
pub struct RuntimeConfig {
    pub signing: SigningConfig,
    pub listen: PathBuf,
    pub relay_host: String,
    pub relay_port: u16,
    pub relay_tls: RelayTls,
    pub relay_username: Option<String>,
    pub relay_password: Option<Secret>,
    pub client_name: String,
    pub relay_workers: usize,
    pub max_message_bytes: usize,
    pub global_message_memory_bytes: usize,
    pub max_concurrent_submissions: usize,
    pub submission_timeout: Duration,
    pub delivery_timeout: Duration,
    pub require_fips: bool,
}

const REQUIRED_SETTINGS: [&str; 17] = [
    "domain",
    "selector",
    "private_key",
    "listen",
    "relay_host",
    "relay_port",
    "relay_tls",
    "relay_username",
    "relay_password_file",
    "client_name",
    "relay_workers",
    "max_message_bytes",
    "global_message_memory_bytes",
    "max_concurrent_submissions",
    "submission_timeout_seconds",
    "delivery_timeout_seconds",
    "require_fips",
];

impl RuntimeConfig {
    pub fn load(path: &Path) -> Result<Self, String> {
        let input = fs::read_to_string(path)
            .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
        let mut values = HashMap::new();
        let allowed: HashSet<&str> = REQUIRED_SETTINGS.iter().copied().collect();

        for (index, raw_line) in input.lines().enumerate() {
            let line = raw_line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (raw_name, raw_value) = line
                .split_once('=')
                .ok_or_else(|| format!("line {}: expected name=value", index + 1))?;
            let name = raw_name.trim();
            let value = raw_value.trim();
            if name.is_empty() {
                return Err(format!("line {}: empty setting name", index + 1));
            }
            if !allowed.contains(name) {
                return Err(format!("line {}: unknown setting {name}", index + 1));
            }
            if values.insert(name.to_owned(), value.to_owned()).is_some() {
                return Err(format!("line {}: duplicate setting {name}", index + 1));
            }
            if value.is_empty() && !matches!(name, "relay_username" | "relay_password_file") {
                return Err(format!("line {}: empty value for {name}", index + 1));
            }
        }

        for name in allowed {
            if !values.contains_key(name) {
                return Err(format!("missing {name}"));
            }
        }

        let value = |name: &str| values.get(name).map(String::as_str).unwrap();
        let domain = validate_dns_name("domain", value("domain"))?;
        let selector = validate_dns_name("selector", value("selector"))?;
        let relay_host = validate_dns_name("relay_host", value("relay_host"))?;
        let client_name = validate_dns_name("client_name", value("client_name"))?;
        let private_key_path = absolute_path("private_key", value("private_key"))?;
        let listen = parse_unix_listen(value("listen"))?;
        let relay_port = parse_positive::<u16>("relay_port", value("relay_port"))?;
        let relay_tls = match value("relay_tls") {
            "implicit" => RelayTls::Implicit,
            _ => return Err("relay_tls must be implicit".to_owned()),
        };
        let relay_workers = parse_positive("relay_workers", value("relay_workers"))?;
        let max_message_bytes = parse_positive("max_message_bytes", value("max_message_bytes"))?;
        let global_message_memory_bytes = parse_positive(
            "global_message_memory_bytes",
            value("global_message_memory_bytes"),
        )?;
        let max_concurrent_submissions = parse_positive(
            "max_concurrent_submissions",
            value("max_concurrent_submissions"),
        )?;
        let submission_timeout = Duration::from_secs(parse_positive(
            "submission_timeout_seconds",
            value("submission_timeout_seconds"),
        )?);
        let delivery_timeout = Duration::from_secs(parse_positive(
            "delivery_timeout_seconds",
            value("delivery_timeout_seconds"),
        )?);
        let require_fips = parse_bool("require_fips", value("require_fips"))?;

        if relay_workers > max_concurrent_submissions {
            return Err("relay_workers must not exceed max_concurrent_submissions".to_owned());
        }
        if global_message_memory_bytes < max_message_bytes {
            return Err(
                "global_message_memory_bytes must be at least max_message_bytes".to_owned(),
            );
        }

        let username = value("relay_username");
        let password_path = value("relay_password_file");
        if username.is_empty() != password_path.is_empty() {
            return Err(
                "relay_username and relay_password_file must both be set or both be empty"
                    .to_owned(),
            );
        }
        let relay_username = (!username.is_empty()).then(|| username.to_owned());
        let relay_password = if password_path.is_empty() {
            None
        } else {
            let password_path = absolute_path("relay_password_file", password_path)?;
            let mut temporary = fs::read(&password_path).map_err(|error| {
                format!(
                    "cannot read relay password {}: {error}",
                    password_path.display()
                )
            })?;
            let secret = Secret::new(temporary.clone());
            erase(&mut temporary);
            Some(secret)
        };

        let mut key_bytes = fs::read(&private_key_path).map_err(|error| {
            format!(
                "cannot read private key {}: {error}",
                private_key_path.display()
            )
        })?;
        let key = parse_private_key(&mut key_bytes)?;
        validate_key(&key)?;

        Ok(Self {
            signing: SigningConfig {
                domain,
                selector,
                key: Arc::new(key),
            },
            listen,
            relay_host,
            relay_port,
            relay_tls,
            relay_username,
            relay_password,
            client_name,
            relay_workers,
            max_message_bytes,
            global_message_memory_bytes,
            max_concurrent_submissions,
            submission_timeout,
            delivery_timeout,
            require_fips,
        })
    }
}

fn parse_private_key(key_bytes: &mut [u8]) -> Result<PKey<Private>, String> {
    let parsed = PKey::private_key_from_pem(key_bytes);
    erase(key_bytes);
    parsed.map_err(|error| format!("cannot parse unencrypted PEM private key: {error}"))
}

fn absolute_path(name: &str, value: &str) -> Result<PathBuf, String> {
    let path = PathBuf::from(value);
    if !path.is_absolute() {
        return Err(format!("{name} must be an absolute path"));
    }
    Ok(path)
}

fn parse_unix_listen(value: &str) -> Result<PathBuf, String> {
    let path = value
        .strip_prefix("unix:")
        .ok_or_else(|| "listen must be an absolute unix: path".to_owned())?;
    if path.as_bytes().contains(&0) {
        return Err("unix listen path must not contain NUL".to_owned());
    }
    absolute_path("unix listen path", path)
}

fn parse_positive<T>(name: &str, value: &str) -> Result<T, String>
where
    T: std::str::FromStr + Default + PartialEq,
{
    let parsed = value
        .parse::<T>()
        .map_err(|_| format!("{name} must be a positive integer"))?;
    if parsed == T::default() {
        return Err(format!("{name} must be greater than zero"));
    }
    Ok(parsed)
}

fn parse_bool(name: &str, value: &str) -> Result<bool, String> {
    match value {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(format!("{name} must be true or false")),
    }
}

pub(crate) fn validate_dns_name(kind: &str, value: &str) -> Result<String, String> {
    let value = value.trim_end_matches('.').to_ascii_lowercase();
    if value.is_empty()
        || value.len() > 253
        || value.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        return Err(format!("invalid {kind}: {value}"));
    }
    Ok(value)
}

pub(crate) fn validate_key(key: &PKey<Private>) -> Result<(), String> {
    let rsa: Rsa<Private> = key
        .rsa()
        .map_err(|_| "private key must be RSA".to_owned())?;
    let bits = rsa.size() * 8;
    if !(2048..=4096).contains(&bits) {
        return Err(format!(
            "RSA key is {bits} bits; 2048 through 4096 required"
        ));
    }
    let mut signer = Signer::new(MessageDigest::sha256(), key)
        .map_err(|error| format!("RSA-SHA256 is unavailable from system OpenSSL: {error}"))?;
    signer
        .update(b"signed-relay-lite startup self-test")
        .and_then(|_| signer.sign_to_vec())
        .map_err(|error| format!("RSA-SHA256 startup self-test failed: {error}"))?;
    Ok(())
}

pub fn check_fips_environment(required: bool) -> Result<(), String> {
    if !required {
        return Ok(());
    }

    #[cfg(target_os = "linux")]
    {
        let path = Path::new("/proc/sys/crypto/fips_enabled");
        evaluate_linux_fips_status(fs::read_to_string(path), openssl_fips_enabled())
    }

    #[cfg(not(target_os = "linux"))]
    Err("FIPS mode cannot be verified on this platform".to_owned())
}

#[cfg(any(target_os = "linux", test))]
fn evaluate_linux_fips_status(
    status: io::Result<String>,
    openssl_enabled: bool,
) -> Result<(), String> {
    match status {
        Ok(value) if value.trim() == "1" && openssl_enabled => Ok(()),
        Ok(value) if value.trim() == "1" => {
            Err("kernel FIPS mode is enabled but system OpenSSL is not in FIPS mode".to_owned())
        }
        Ok(value) if value.trim() == "0" => Err("system FIPS mode is disabled".to_owned()),
        Ok(value) => Err(format!(
            "unexpected FIPS status in /proc/sys/crypto/fips_enabled: {value:?}"
        )),
        Err(error) => Err(format!(
            "cannot inspect /proc/sys/crypto/fips_enabled: {error}"
        )),
    }
}

#[cfg(target_os = "linux")]
fn openssl_fips_enabled() -> bool {
    // SAFETY: the symbol names are NUL-terminated, looked up in the current
    // process, checked for null, and called with their documented OpenSSL ABI.
    unsafe {
        let symbol = libc::dlsym(
            libc::RTLD_DEFAULT,
            b"EVP_default_properties_is_fips_enabled\0".as_ptr() as *const c_char,
        );
        if !symbol.is_null() {
            let check: unsafe extern "C" fn(*mut c_void) -> libc::c_int =
                std::mem::transmute(symbol);
            return check(std::ptr::null_mut()) == 1;
        }

        let symbol = libc::dlsym(libc::RTLD_DEFAULT, b"FIPS_mode\0".as_ptr() as *const c_char);
        if !symbol.is_null() {
            let check: unsafe extern "C" fn() -> libc::c_int = std::mem::transmute(symbol);
            return check() == 1;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::rsa::Rsa;
    use std::collections::BTreeMap;
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::OnceLock;
    use std::time::Duration;

    static FIXTURE_ID: AtomicU64 = AtomicU64::new(0);
    static RSA_PEM: OnceLock<Vec<u8>> = OnceLock::new();

    struct ConfigFixture {
        directory: PathBuf,
        config: PathBuf,
        key: PathBuf,
        password: PathBuf,
        fields: BTreeMap<&'static str, String>,
    }

    impl ConfigFixture {
        fn new() -> Self {
            let directory = std::env::temp_dir().join(format!(
                "signed-relay-lite-config-{}-{}",
                std::process::id(),
                FIXTURE_ID.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&directory).unwrap();
            let key = directory.join("key.pem");
            let pem =
                RSA_PEM.get_or_init(|| Rsa::generate(2048).unwrap().private_key_to_pem().unwrap());
            fs::write(&key, pem).unwrap();
            let password = directory.join("password");
            fs::write(&password, b"s3cret").unwrap();
            let config = directory.join("relay.conf");
            let fields = BTreeMap::from([
                ("domain", "Example.COM.".to_owned()),
                ("selector", "Mail2026".to_owned()),
                ("private_key", key.display().to_string()),
                (
                    "listen",
                    "unix:/run/signed-relay-lite/submit.sock".to_owned(),
                ),
                ("relay_host", "SMTP.Example.NET.".to_owned()),
                ("relay_port", "465".to_owned()),
                ("relay_tls", "implicit".to_owned()),
                ("relay_username", "alice".to_owned()),
                ("relay_password_file", password.display().to_string()),
                ("client_name", "Mailer.Example.COM.".to_owned()),
                ("relay_workers", "4".to_owned()),
                ("max_message_bytes", "26214400".to_owned()),
                ("global_message_memory_bytes", "134217728".to_owned()),
                ("max_concurrent_submissions", "16".to_owned()),
                ("submission_timeout_seconds", "60".to_owned()),
                ("delivery_timeout_seconds", "120".to_owned()),
                ("require_fips", "true".to_owned()),
            ]);
            Self {
                directory,
                config,
                key,
                password,
                fields,
            }
        }

        fn set(&mut self, key: &'static str, value: impl Into<String>) {
            self.fields.insert(key, value.into());
        }

        fn remove(&mut self, key: &'static str) {
            self.fields.remove(key);
        }

        fn render(&self) -> String {
            self.fields
                .iter()
                .map(|(name, value)| format!("{name}={value}\n"))
                .collect()
        }

        fn load(&self) -> Result<RuntimeConfig, String> {
            fs::write(&self.config, self.render()).unwrap();
            RuntimeConfig::load(&self.config)
        }

        fn load_error(&self) -> String {
            self.load()
                .err()
                .expect("configuration unexpectedly loaded")
        }
    }

    impl Drop for ConfigFixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.directory);
        }
    }

    #[test]
    fn normalizes_configured_dns_names() {
        let fixture = ConfigFixture::new();
        let config = fixture.load().unwrap();
        assert_eq!(config.signing.domain, "example.com");
        assert_eq!(config.signing.selector, "mail2026");
        assert_eq!(config.relay_host, "smtp.example.net");
        assert_eq!(config.client_name, "mailer.example.com");
    }

    #[test]
    fn loads_socket_and_relay_transport() {
        let fixture = ConfigFixture::new();
        let config = fixture.load().unwrap();
        assert_eq!(
            config.listen,
            PathBuf::from("/run/signed-relay-lite/submit.sock")
        );
        assert_eq!(config.relay_port, 465);
        assert_eq!(config.relay_tls, RelayTls::Implicit);
    }

    #[test]
    fn loads_numeric_resource_limits() {
        let fixture = ConfigFixture::new();
        let config = fixture.load().unwrap();
        assert_eq!(config.relay_workers, 4);
        assert_eq!(config.max_message_bytes, 26_214_400);
        assert_eq!(config.global_message_memory_bytes, 134_217_728);
        assert_eq!(config.max_concurrent_submissions, 16);
    }

    #[test]
    fn loads_submission_and_delivery_timeouts() {
        let fixture = ConfigFixture::new();
        let config = fixture.load().unwrap();
        assert_eq!(config.submission_timeout, Duration::from_secs(60));
        assert_eq!(config.delivery_timeout, Duration::from_secs(120));
    }

    #[test]
    fn loads_authentication_pair() {
        let fixture = ConfigFixture::new();
        let config = fixture.load().unwrap();
        assert_eq!(config.relay_username.as_deref(), Some("alice"));
        assert_eq!(config.relay_password.unwrap().as_bytes(), b"s3cret");
    }

    #[test]
    fn loaded_key_and_password_outlive_source_files() {
        let fixture = ConfigFixture::new();
        let config = fixture.load().unwrap();
        fs::remove_file(&fixture.key).unwrap();
        fs::remove_file(&fixture.password).unwrap();
        assert!(config.signing.key.rsa().is_ok());
        assert_eq!(config.relay_password.unwrap().as_bytes(), b"s3cret");
    }

    #[test]
    fn loads_required_fips_flag() {
        let mut fixture = ConfigFixture::new();
        fixture.set("require_fips", "false");
        assert!(!fixture.load().unwrap().require_fips);
    }

    #[test]
    fn empty_credential_settings_mean_absent() {
        let mut fixture = ConfigFixture::new();
        fixture.set("relay_username", "");
        fixture.set("relay_password_file", "");
        let config = fixture.load().unwrap();
        assert!(config.relay_username.is_none());
        assert!(config.relay_password.is_none());
    }

    #[test]
    fn rejects_unknown_setting() {
        let fixture = ConfigFixture::new();
        let input = fixture.render() + "mystery=yes\n";
        fs::write(&fixture.config, input).unwrap();
        assert_eq!(
            RuntimeConfig::load(&fixture.config).err().unwrap(),
            "line 18: unknown setting mystery"
        );
    }

    #[test]
    fn rejects_duplicate_setting() {
        let fixture = ConfigFixture::new();
        let input = fixture.render() + "domain=other.example\n";
        fs::write(&fixture.config, input).unwrap();
        assert_eq!(
            RuntimeConfig::load(&fixture.config).err().unwrap(),
            "line 18: duplicate setting domain"
        );
    }

    #[test]
    fn rejects_each_missing_required_setting() {
        for name in REQUIRED_SETTINGS {
            let mut fixture = ConfigFixture::new();
            fixture.remove(name);
            assert_eq!(fixture.load_error(), format!("missing {name}"));
        }
    }

    #[test]
    fn rejects_non_assignment_line() {
        let fixture = ConfigFixture::new();
        let input = fixture.render() + "not-an-assignment\n";
        fs::write(&fixture.config, input).unwrap();
        assert_eq!(
            RuntimeConfig::load(&fixture.config).err().unwrap(),
            "line 18: expected name=value"
        );
    }

    #[test]
    fn rejects_relative_secret_paths() {
        for (name, value, expected) in [
            (
                "private_key",
                "key.pem",
                "private_key must be an absolute path",
            ),
            (
                "relay_password_file",
                "password",
                "relay_password_file must be an absolute path",
            ),
        ] {
            let mut fixture = ConfigFixture::new();
            fixture.set(name, value);
            assert_eq!(fixture.load_error(), expected);
        }
    }

    #[test]
    fn rejects_relative_socket_path() {
        let mut fixture = ConfigFixture::new();
        fixture.set("listen", "unix:submit.sock");
        assert_eq!(
            fixture.load_error(),
            "unix listen path must be an absolute path"
        );
    }

    #[test]
    fn rejects_invalid_dns_fields() {
        for (name, value) in [
            ("domain", "-bad.example"),
            ("selector", "bad_label"),
            ("relay_host", "bad..example"),
            ("client_name", "bad name"),
        ] {
            let mut fixture = ConfigFixture::new();
            fixture.set(name, value);
            assert_eq!(fixture.load_error(), format!("invalid {name}: {value}"));
        }
    }

    #[test]
    fn rejects_unsupported_tls_mode() {
        let mut fixture = ConfigFixture::new();
        fixture.set("relay_tls", "starttls");
        assert_eq!(fixture.load_error(), "relay_tls must be implicit");
    }

    #[test]
    fn requires_complete_authentication_pair() {
        for name in ["relay_username", "relay_password_file"] {
            let mut fixture = ConfigFixture::new();
            fixture.set(name, "");
            assert_eq!(
                fixture.load_error(),
                "relay_username and relay_password_file must both be set or both be empty"
            );
        }
    }

    #[test]
    fn rejects_zero_numeric_settings() {
        for name in [
            "relay_port",
            "relay_workers",
            "max_message_bytes",
            "global_message_memory_bytes",
            "max_concurrent_submissions",
            "submission_timeout_seconds",
            "delivery_timeout_seconds",
        ] {
            let mut fixture = ConfigFixture::new();
            fixture.set(name, "0");
            assert_eq!(
                fixture.load_error(),
                format!("{name} must be greater than zero")
            );
        }
    }

    #[test]
    fn rejects_malformed_numeric_settings() {
        for name in [
            "relay_port",
            "relay_workers",
            "max_message_bytes",
            "global_message_memory_bytes",
            "max_concurrent_submissions",
            "submission_timeout_seconds",
            "delivery_timeout_seconds",
        ] {
            let mut fixture = ConfigFixture::new();
            fixture.set(name, "nope");
            assert_eq!(
                fixture.load_error(),
                format!("{name} must be a positive integer")
            );
        }
    }

    #[test]
    fn requires_worker_count_within_submission_count() {
        let mut fixture = ConfigFixture::new();
        fixture.set("relay_workers", "17");
        assert_eq!(
            fixture.load_error(),
            "relay_workers must not exceed max_concurrent_submissions"
        );
    }

    #[test]
    fn requires_global_budget_at_least_one_message() {
        let mut fixture = ConfigFixture::new();
        fixture.set("global_message_memory_bytes", "100");
        assert_eq!(
            fixture.load_error(),
            "global_message_memory_bytes must be at least max_message_bytes"
        );
    }

    #[test]
    fn requires_strict_boolean() {
        let mut fixture = ConfigFixture::new();
        fixture.set("require_fips", "yes");
        assert_eq!(fixture.load_error(), "require_fips must be true or false");
    }

    #[test]
    fn validates_rsa_key_type_size_and_sha256_signing() {
        let small = PKey::from_rsa(Rsa::generate(1024).unwrap()).unwrap();
        assert!(validate_key(&small).is_err());
        let valid = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
        assert!(validate_key(&valid).is_ok());
    }

    #[test]
    fn secret_debug_is_redacted() {
        let secret = Secret::new(b"top-secret".to_vec());
        let debug = format!("{secret:?}");
        assert!(!debug.contains("top-secret"));
        assert_eq!(debug, "Secret([REDACTED])");
    }

    #[test]
    fn erases_secret_storage() {
        let mut bytes = b"top-secret".to_vec();
        erase(&mut bytes);
        assert!(bytes.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn private_key_pem_buffer_is_erased_even_when_parsing_fails() {
        let mut bytes = b"not a private key".to_vec();
        assert!(parse_private_key(&mut bytes).is_err());
        assert!(bytes.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn missing_linux_fips_status_is_rejected() {
        let missing = io::Error::new(io::ErrorKind::NotFound, "missing procfs status");
        assert!(evaluate_linux_fips_status(Err(missing), false).is_err());
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn required_fips_is_rejected_when_platform_cannot_verify_it() {
        assert!(check_fips_environment(true).is_err());
    }

    #[test]
    fn fips_check_can_be_disabled() {
        assert!(check_fips_environment(false).is_ok());
    }
}
