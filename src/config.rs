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
#[cfg(target_os = "linux")]
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

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

const REQUIRED_SETTINGS: [&str; 16] = [
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
];

impl RuntimeConfig {
    pub fn load(path: &Path) -> Result<Self, String> {
        let input = fs::read_to_string(path)
            .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
        let mut values = HashMap::new();
        let allowed: HashSet<&str> = REQUIRED_SETTINGS
            .iter()
            .copied()
            .chain(std::iter::once("require_fips"))
            .collect();

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

        let key_bytes = fs::read(&private_key_path).map_err(|error| {
            format!(
                "cannot read private key {}: {error}",
                private_key_path.display()
            )
        })?;
        let key = PKey::private_key_from_pem(&key_bytes)
            .map_err(|error| format!("cannot parse unencrypted PEM private key: {error}"))?;
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
        match fs::read_to_string(path) {
            Ok(value) if value.trim() == "1" => {
                return if openssl_fips_enabled() {
                    Ok(())
                } else {
                    Err(
                        "kernel FIPS mode is enabled but system OpenSSL is not in FIPS mode"
                            .to_owned(),
                    )
                };
            }
            Ok(value) if value.trim() == "0" => {
                return Err("system FIPS mode is disabled".to_owned())
            }
            Ok(value) => {
                return Err(format!(
                    "unexpected FIPS status in {}: {value:?}",
                    path.display()
                ))
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(format!("cannot inspect {}: {error}", path.display())),
        }
    }

    Ok(())
}

#[cfg(target_os = "linux")]
fn openssl_fips_enabled() -> bool {
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
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    static FIXTURE_ID: AtomicU64 = AtomicU64::new(0);

    struct Fixture {
        directory: PathBuf,
        config: PathBuf,
        key: PathBuf,
        password: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let directory = std::env::temp_dir().join(format!(
                "signed-relay-lite-config-{}-{nonce}-{}",
                std::process::id(),
                FIXTURE_ID.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&directory).unwrap();
            let key = directory.join("key.pem");
            fs::write(
                &key,
                Rsa::generate(2048).unwrap().private_key_to_pem().unwrap(),
            )
            .unwrap();
            let password = directory.join("password");
            fs::write(&password, b"s3cret").unwrap();
            let config = directory.join("relay.conf");
            Self {
                directory,
                config,
                key,
                password,
            }
        }

        fn valid(&self) -> String {
            format!(
                "domain=Example.COM.\nselector=Mail2026\nprivate_key={}\nlisten=unix:/run/signed-relay-lite/submit.sock\nrelay_host=SMTP.Example.NET.\nrelay_port=465\nrelay_tls=implicit\nrelay_username=alice\nrelay_password_file={}\nclient_name=Mailer.Example.COM.\nrelay_workers=4\nmax_message_bytes=26214400\nglobal_message_memory_bytes=134217728\nmax_concurrent_submissions=16\nsubmission_timeout_seconds=60\ndelivery_timeout_seconds=120\nrequire_fips=true\n",
                self.key.display(),
                self.password.display()
            )
        }

        fn load(&self, input: &str) -> Result<RuntimeConfig, String> {
            fs::write(&self.config, input).unwrap();
            RuntimeConfig::load(&self.config)
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.directory).unwrap();
        }
    }

    fn replace(input: &str, old: &str, new: &str) -> String {
        let output = input.replacen(old, new, 1);
        assert_ne!(output, input);
        output
    }

    #[test]
    fn loads_every_required_setting_and_secrets_once() {
        let fixture = Fixture::new();
        let config = fixture.load(&fixture.valid()).unwrap();
        assert_eq!(config.signing.domain, "example.com");
        assert_eq!(config.signing.selector, "mail2026");
        assert_eq!(
            config.listen,
            PathBuf::from("/run/signed-relay-lite/submit.sock")
        );
        assert_eq!(config.relay_host, "smtp.example.net");
        assert_eq!(config.relay_port, 465);
        assert_eq!(config.relay_tls, RelayTls::Implicit);
        assert_eq!(config.relay_username.as_deref(), Some("alice"));
        assert_eq!(
            config.relay_password.as_ref().unwrap().as_bytes(),
            b"s3cret"
        );
        assert_eq!(config.client_name, "mailer.example.com");
        assert_eq!(config.relay_workers, 4);
        assert_eq!(config.max_message_bytes, 26_214_400);
        assert_eq!(config.global_message_memory_bytes, 134_217_728);
        assert_eq!(config.max_concurrent_submissions, 16);
        assert_eq!(config.submission_timeout, Duration::from_secs(60));
        assert_eq!(config.delivery_timeout, Duration::from_secs(120));
        assert!(config.require_fips);
        fs::remove_file(&fixture.key).unwrap();
        fs::remove_file(&fixture.password).unwrap();
        assert!(config.signing.key.rsa().is_ok());
        assert_eq!(config.relay_password.unwrap().as_bytes(), b"s3cret");
    }

    #[test]
    fn empty_credential_settings_mean_absent() {
        let fixture = Fixture::new();
        let input = replace(
            &replace(&fixture.valid(), "relay_username=alice", "relay_username="),
            &format!("relay_password_file={}", fixture.password.display()),
            "relay_password_file=",
        );
        let config = fixture.load(&input).unwrap();
        assert!(config.relay_username.is_none());
        assert!(config.relay_password.is_none());
    }

    #[test]
    fn rejects_unknown_duplicate_missing_and_malformed_lines() {
        let fixture = Fixture::new();
        let valid = fixture.valid();
        assert!(fixture.load(&(valid.clone() + "mystery=yes\n")).is_err());
        assert!(fixture
            .load(&(valid.clone() + "domain=other.example\n"))
            .is_err());
        for name in REQUIRED_SETTINGS
            .iter()
            .copied()
            .chain(std::iter::once("require_fips"))
        {
            let prefix = format!("{name}=");
            let input = valid
                .lines()
                .filter(|line| !line.starts_with(&prefix))
                .collect::<Vec<_>>()
                .join("\n");
            assert!(fixture.load(&input).is_err(), "accepted missing {name}");
        }
        assert!(fixture.load(&(valid + "not-an-assignment\n")).is_err());
    }

    #[test]
    fn rejects_bad_paths_names_tls_and_credential_pairing() {
        let fixture = Fixture::new();
        let valid = fixture.valid();
        for input in [
            replace(
                &valid,
                &format!("private_key={}", fixture.key.display()),
                "private_key=key.pem",
            ),
            replace(
                &valid,
                &format!("relay_password_file={}", fixture.password.display()),
                "relay_password_file=password",
            ),
            replace(
                &valid,
                "listen=unix:/run/signed-relay-lite/submit.sock",
                "listen=unix:submit.sock",
            ),
            replace(&valid, "domain=Example.COM.", "domain=-bad.example"),
            replace(&valid, "selector=Mail2026", "selector=bad_label"),
            replace(
                &valid,
                "relay_host=SMTP.Example.NET.",
                "relay_host=bad..example",
            ),
            replace(
                &valid,
                "client_name=Mailer.Example.COM.",
                "client_name=bad name",
            ),
            replace(&valid, "relay_tls=implicit", "relay_tls=starttls"),
            replace(&valid, "relay_username=alice", "relay_username="),
            replace(
                &valid,
                &format!("relay_password_file={}", fixture.password.display()),
                "relay_password_file=",
            ),
        ] {
            assert!(
                fixture.load(&input).is_err(),
                "accepted invalid config:\n{input}"
            );
        }
    }

    #[test]
    fn rejects_zero_and_malformed_numbers_and_invalid_relationships() {
        let fixture = Fixture::new();
        let valid = fixture.valid();
        for (old, new) in [
            ("relay_port=465", "relay_port=0"),
            ("relay_port=465", "relay_port=nope"),
            ("relay_workers=4", "relay_workers=0"),
            ("relay_workers=4", "relay_workers=nope"),
            ("max_message_bytes=26214400", "max_message_bytes=0"),
            ("max_message_bytes=26214400", "max_message_bytes=nope"),
            (
                "global_message_memory_bytes=134217728",
                "global_message_memory_bytes=0",
            ),
            (
                "global_message_memory_bytes=134217728",
                "global_message_memory_bytes=nope",
            ),
            (
                "max_concurrent_submissions=16",
                "max_concurrent_submissions=0",
            ),
            (
                "max_concurrent_submissions=16",
                "max_concurrent_submissions=nope",
            ),
            (
                "submission_timeout_seconds=60",
                "submission_timeout_seconds=0",
            ),
            (
                "submission_timeout_seconds=60",
                "submission_timeout_seconds=nope",
            ),
            ("delivery_timeout_seconds=120", "delivery_timeout_seconds=0"),
            (
                "delivery_timeout_seconds=120",
                "delivery_timeout_seconds=nope",
            ),
            ("relay_workers=4", "relay_workers=17"),
            (
                "global_message_memory_bytes=134217728",
                "global_message_memory_bytes=100",
            ),
        ] {
            let input = replace(&valid, old, new);
            assert!(fixture.load(&input).is_err(), "accepted {new}");
        }
    }

    #[test]
    fn requires_strict_boolean() {
        let fixture = Fixture::new();
        assert!(fixture
            .load(&replace(
                &fixture.valid(),
                "require_fips=true",
                "require_fips=yes"
            ))
            .is_err());
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
    fn fips_check_can_be_disabled() {
        assert!(check_fips_environment(false).is_ok());
    }
}
