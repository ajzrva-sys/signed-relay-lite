# Security Policy

## Threat model

signed-relay-lite is designed to run as a local helper on a trusted Unix
host. Its attack surface splits into two planes:

### Submission plane (Unix socket)

* The daemon listens on a **Unix domain socket** whose permissions are set
  to `0o660` at bind time. Only processes that can reach that socket file
  may submit messages.
* The daemon validates that the **existing socket's owner UID** matches its
  own effective UID before reusing a stale socket path, preventing
  symlink/TOCTOU attacks against a leftover file.
* There is **no per-connection authentication** beyond filesystem access
  control on the socket. The design assumption is that all local processes
  able to connect are trusted.
* The SRL1 wire protocol is fixed-format and length-prefixed; every field
  has an explicit size bound checked before allocation.

### Relay plane (upstream smarthost)

* Outbound connections to the smarthost use **implicit TLS with mandatory
  certificate verification** (`SslVerifyMode::PEER` + system CA roots).
  There is no configuration knob to disable this.
* SMTP AUTH credentials (if configured) are read from a file at startup
  and held in memory inside a `Secret` wrapper that **zeroes its buffer
  on drop** using `write_volatile` + a compiler fence to prevent
  dead-store elimination.
* The `Secret` type's `Debug` impl prints `[REDACTED]`; passwords never
  appear in logs.

### Resource limits

| Limit | Controlled by |
|---|---|
| Per-message size | `max_message_bytes` |
| Total in-flight message memory | `global_message_memory_bytes` |
| Concurrent submissions | `max_concurrent_submissions` |
| Recipients per envelope | hardcoded (100) |
| Single address length | hardcoded (254 bytes) |
| SMTP reply lines | hardcoded (256) |
| Diagnostic payload | hardcoded (4096 bytes) |
| Submission timeout | `submission_timeout_seconds` |
| Delivery timeout | `delivery_timeout_seconds` |

All limits are enforced **before** allocating memory for the decoded payload.

### Ambiguous delivery and duplication

If the connection to the smarthost drops after `DATA` but before the final
acceptance response, the result is flagged **ambiguous**. Retrying an
ambiguous submission may deliver the message twice. The daemon never retries
an ambiguous result; the caller owns that decision.

## Secrets and file permissions

### Private key (`private_key`)

* Must be an **unencrypted PEM RSA key** (2048–4096 bits).
* The daemon reads the key at startup and does not retain the file path.
* Recommended permissions: `0400`, owned by the daemon's service account.

```sh
chmod 400 /etc/signed-relay-lite/mail.pem
chown signed-relay:signed-relay /etc/signed-relay-lite/mail.pem
```

### Relay password file (`relay_password_file`)

* Contains the raw SMTP AUTH password (no trailing-newline stripping is
  performed by the daemon — the file contents are the password).
  Use `printf %s 'password' > relay-password`; ordinary `echo` usually adds
  a newline and therefore changes the password.
* The password is loaded into a `Secret` and the temporary buffer is
  **zeroed immediately** after cloning into the `Secret`.
* Recommended permissions: `0400`, owned by the daemon's service account.

```sh
chmod 400 /etc/signed-relay-lite/relay-password
chown signed-relay:signed-relay /etc/signed-relay-lite/relay-password
```

### Submission socket

* Created with mode `0o660` (owner + group read/write).
* Place the daemon's service account and the submitting users in a shared
  group, or use a dedicated group for socket access.

```sh
# Example: allow the "mailsend" group to submit
groupadd mailsend
usermod -aG mailsend www-data   # or whichever user runs signed-relay-sendmail
```

### No secrets in CLI arguments or environment

* `signed-relay-sendmail` accepts only `-f envelope-from` and recipient
  addresses. No passwords, API keys, or tokens appear in `argv`.
* The `SIGNED_RELAY_SOCKET` environment variable contains only a file
  path, not a secret.
* The daemon's `--config` flag takes a file path; secrets live inside the
  referenced file, not on the command line.

## FIPS behavior

When `require_fips=true`:

1. On **Linux**, the daemon checks `/proc/sys/crypto/fips_enabled` for `1`.
2. It then probes the process's loaded OpenSSL for
   `EVP_default_properties_is_fips_enabled` (OpenSSL 3.x) or `FIPS_mode`
   (OpenSSL 1.x) via `dlsym(RTLD_DEFAULT, ...)`.
3. If the kernel says FIPS is enabled but OpenSSL does not confirm it, the
   daemon refuses to start.
4. A missing Linux status file, an unsupported platform, or an unverifiable
   OpenSSL mode is an error. The check fails closed.

When `require_fips=false`, no FIPS checks are performed.

## Responsible disclosure

If you believe you have found a security vulnerability in signed-relay-lite:

1. **Do not open a public issue.**
2. Use **GitHub Private Vulnerability Reporting** if enabled on the
   repository — the "Report a vulnerability" button under the Security tab
   creates a private advisory visible only to maintainers.
3. If private reporting is not available, use a private maintainer contact
   channel published on the repository owner's GitHub profile. Do not put
   vulnerability details in a public issue.
4. Include a description of the vulnerability, steps to reproduce, and the
   potential impact.

We appreciate coordinated disclosure and will credit reporters in the
release notes unless they prefer to remain anonymous.
