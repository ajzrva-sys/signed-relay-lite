# signed-relay-lite

A bounded in-memory DKIM submission relay for a fixed smarthost.

## What this is

signed-relay-lite is a **narrow-purpose submission daemon** — not a general
mail transfer agent (MTA) and not a replacement for Postfix, Sendmail, or
Exim. It does one thing: accept a message on a local Unix socket, DKIM-sign
it, and relay it to exactly one preconfigured smarthost over implicit TLS.

### Key design properties

| Property | Detail |
|---|---|
| **Single smarthost** | All mail is delivered to `relay_host:relay_port`. No routing, no MX lookups, no queue directories. |
| **No disk queue** | Messages live only in process memory. If the daemon exits, undelivered messages are lost. |
| **Caller owns retries** | The submitter (the `signed-relay-sendmail` client or any SRL1-speaking program) is responsible for retrying on transient failure. The daemon does not retry on its own. |
| **Local success = upstream 2xx** | An exit code of `EX_OK` (0) from `signed-relay-sendmail` means the remote smarthost returned a final `250` after the message dot. This is a stronger guarantee than "accepted into a local queue." |
| **Ambiguous failures may duplicate** | If the connection drops after `DATA` but before the final `250`, the result is marked *ambiguous*. Retrying an ambiguous submission may deliver the message twice. Callers must be prepared for this. |
| **Bounded memory** | `global_message_memory_bytes` caps the total memory held by in-flight messages. New submissions block (and eventually time out) when the budget is exhausted. Per-message size is bounded by `max_message_bytes`. |
| **TLS always verified** | Certificate verification (`SslVerifyMode::PEER`) is hardcoded and cannot be disabled. |
| **No SMTPUTF8** | v0.1 does not advertise or support the `SMTPUTF8` SMTP extension. International addresses must be encoded with the standards that predate it. |

## Supported sendmail CLI

The `signed-relay-sendmail` binary provides a deliberately limited subset of
the traditional `sendmail` command-line interface:

```
signed-relay-sendmail [-f envelope-from] [--] recipient...
```

* `-f envelope-from` — **required**. Sets the envelope sender.
* `--` — optional separator; everything after it is treated as a recipient
  even if it starts with `-`.
* One or more recipient addresses must follow.
* The message body is read from **stdin**.
* The submission socket path defaults to `/run/signed-relay-lite/submit.sock`
  and can be overridden with the `SIGNED_RELAY_SOCKET` environment variable
  (must be an absolute path).

No other `sendmail` flags (`-t`, `-i`, `-o`, etc.) are recognized.

### Exit codes

| Code | Name | Meaning |
|---|---|---|
| 0 | `EX_OK` | Delivered — upstream `250` observed. |
| 64 | `EX_USAGE` | Invalid arguments or oversized message. |
| 69 | `EX_UNAVAILABLE` | Permanent failure (`5xx` from smarthost). |
| 75 | `EX_TEMPFAIL` | Transient failure — safe to retry. |

## Building

```sh
# Debug build
cargo build

# Release build (thin LTO, single codegen unit, symbols stripped)
cargo build --release

# Run tests
cargo test
```

Requires Rust ≥ 1.75 and a system OpenSSL (libssl-dev / openssl-devel).

## Fuzzing

Fuzz targets live under `fuzz/` and use `cargo-fuzz` / `libfuzzer-sys`:

```sh
# Install cargo-fuzz (once)
cargo install cargo-fuzz

# Run a specific target
cargo fuzz run submission_frame
cargo fuzz run message
cargo fuzz run smtp_response
```

Corpus seeds are checked in under `fuzz/corpus/`.

## Configuration

The daemon reads a plain-text configuration file:

```sh
signed-relay-lite --config /etc/signed-relay-lite/relay.conf   # serve
signed-relay-lite --check-config /etc/signed-relay-lite/relay.conf  # validate only
signed-relay-lite --help
signed-relay-lite --version
```

See [`example.conf`](example.conf) for a fully commented template.

### Settings reference

| Setting | Type | Description |
|---|---|---|
| `domain` | DNS name | DKIM signing domain (`d=` tag). |
| `selector` | DNS name | DKIM key selector (`s=` tag). |
| `private_key` | absolute path | Unencrypted PEM RSA private key (2048–4096 bits). |
| `listen` | `unix:` path | Unix domain socket for submission (e.g. `unix:/run/signed-relay-lite/submit.sock`). |
| `relay_host` | DNS name | Smarthost hostname. |
| `relay_port` | u16 | Smarthost port (typically 465 for implicit TLS). |
| `relay_tls` | `implicit` | Only implicit TLS is supported (TLS from the first byte). |
| `relay_username` | string | SMTP AUTH username. Set to empty to disable authentication. |
| `relay_password_file` | absolute path | File containing the SMTP AUTH password (raw bytes, no trailing newline handling). Both `relay_username` and `relay_password_file` must be set or both must be empty. |
| `client_name` | DNS name | EHLO/HELO hostname sent to the smarthost. |
| `relay_workers` | usize | Number of dedicated SMTP delivery threads. Must not exceed `max_concurrent_submissions`. |
| `max_message_bytes` | usize | Per-message size limit in bytes (default example: 25 MiB). |
| `global_message_memory_bytes` | usize | Total in-flight message memory cap. Must be ≥ `max_message_bytes`. |
| `max_concurrent_submissions` | usize | Maximum simultaneous submission handlers. |
| `submission_timeout_seconds` | u64 | Timeout for a single submission connection. |
| `delivery_timeout_seconds` | u64 | Timeout for the upstream SMTP delivery. |
| `require_fips` | bool | `true` or `false`. When `true`, startup fails unless FIPS mode is active (Linux only; checks `/proc/sys/crypto/fips_enabled` and the OpenSSL FIPS flag). |

## DKIM provenance

The initial DKIM canonicalization implementation (`src/dkim.rs`) derives from
the separately maintained [ajzrva-sys/dkim-lite](https://github.com/ajzrva-sys/dkim-lite)
project under the Apache-2.0 license.

## Security

See [SECURITY.md](SECURITY.md) for the threat model, file-permission
requirements, and responsible-disclosure instructions.

## License

Apache-2.0 — see [LICENSE](LICENSE) for details.
