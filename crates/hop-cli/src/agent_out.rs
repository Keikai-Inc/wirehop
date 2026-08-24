//! Machine-readable output for agents and scripts (`--json` / `HOP_JSON=1`).
//!
//! One process-wide switch, set once at startup from the global CLI flag.
//! Handlers that have a structured form check [`json_mode`] and emit exactly
//! one JSON document on stdout via [`emit`]; errors leave through
//! [`emit_error`], which prints a single structured envelope on stderr:
//!
//! ```json
//! {"error":{"code":"host_unreachable","message":"...","chain":["..."],"retryable":true}}
//! ```
//!
//! The taxonomy is deliberately small and matched on the rendered error chain.
//! An unrecognized error still gets a well-formed envelope with code
//! `"error"` — agents can always parse, even when we can't classify.

use std::sync::atomic::{AtomicBool, Ordering};

use serde::Serialize;

static JSON_MODE: AtomicBool = AtomicBool::new(false);

/// Set once at startup, before dispatch. `HOP_JSON` (non-empty, not "0") is
/// honored here rather than via clap's `env` feature, which the workspace
/// deliberately omits for binary size.
pub fn set_json_mode(flag: bool) {
    let env = std::env::var("HOP_JSON")
        .map(|v| !v.is_empty() && v != "0")
        .unwrap_or(false);
    JSON_MODE.store(flag || env, Ordering::Relaxed);
}

/// Whether `--json` / `HOP_JSON=1` is in effect.
pub fn json_mode() -> bool {
    JSON_MODE.load(Ordering::Relaxed)
}

/// Progress banners ("Resolved …", "Connecting …"): stdout for humans, stderr
/// in JSON mode so stdout stays a single parseable document.
pub fn banner(msg: &str) {
    if json_mode() {
        eprintln!("{msg}");
    } else {
        println!("{msg}");
    }
}

/// Emit one JSON document on stdout (a single line).
pub fn emit<T: Serialize>(value: &T) {
    // Serialization of our own output structs cannot realistically fail;
    // if it somehow does, an agent still gets valid JSON on stderr.
    match serde_json::to_string(value) {
        Ok(s) => println!("{s}"),
        Err(e) => eprintln!("{{\"error\":{{\"code\":\"internal\",\"message\":\"serialize failed: {e}\"}}}}"),
    }
}

/// Machine-readable error classification, matched against the full rendered
/// error chain (lowercased). Order matters: first hit wins.
fn classify(chain: &str) -> (&'static str, bool) {
    const RULES: &[(&str, &str, bool)] = &[
        // (needle, code, retryable)
        ("timed out", "host_unreachable", true),
        ("unable to reach", "host_unreachable", true),
        ("connection lost", "connection_lost", true),
        ("connection reset", "connection_lost", true),
        ("broken pipe", "connection_lost", true),
        ("early eof", "connection_lost", true),
        ("aborted by peer", "connection_lost", true),
        ("frame too large", "frame_too_large", false),
        ("unknown host alias", "unknown_target", false),
        ("invalid invite", "unknown_target", false),
        ("invalid nodeid", "unknown_target", false),
        ("invalid length", "unknown_target", false),
        ("rejected", "auth_rejected", false),
        ("unauthorized", "auth_rejected", false),
        ("not authorized", "auth_rejected", false),
        ("permission denied", "permission_denied", false),
        ("no such file", "not_found", false),
        ("not found", "not_found", false),
    ];
    for (needle, code, retryable) in RULES {
        if chain.contains(needle) {
            return (code, *retryable);
        }
    }
    ("error", false)
}

#[derive(Serialize)]
struct ErrorEnvelope<'a> {
    error: ErrorBody<'a>,
}

#[derive(Serialize)]
struct ErrorBody<'a> {
    code: &'static str,
    message: String,
    chain: Vec<String>,
    retryable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    hint: Option<&'a str>,
}

/// Print a top-level error and exit-path message. JSON mode: one structured
/// envelope on stderr. Human mode: anyhow-style `Error:` + `Caused by:` chain
/// (same shape users saw when `main` returned `Result` directly).
pub fn emit_error(err: &anyhow::Error) {
    if json_mode() {
        let chain: Vec<String> = err.chain().map(|c| c.to_string()).collect();
        let rendered = format!("{err:#}").to_lowercase();
        let (code, retryable) = classify(&rendered);
        let hint = match code {
            "frame_too_large" => {
                Some("one side predates chunked listings; upgrade both ends of the transfer")
            }
            "host_unreachable" => Some("host may be offline or still redialing; retry with backoff"),
            "unknown_target" => Some("expected a NodeId, invite token, or known host alias"),
            _ => None,
        };
        let envelope = ErrorEnvelope {
            error: ErrorBody {
                code,
                message: err.to_string(),
                chain,
                retryable,
                hint,
            },
        };
        eprintln!(
            "{}",
            serde_json::to_string(&envelope)
                .unwrap_or_else(|_| r#"{"error":{"code":"internal","message":"serialize failed"}}"#.into())
        );
    } else {
        eprintln!("Error: {err}");
        let mut sources = err.chain().skip(1).peekable();
        if sources.peek().is_some() {
            eprintln!("\nCaused by:");
            for cause in sources {
                eprintln!("    {cause}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_maps_known_failures() {
        assert_eq!(classify("connection timed out after 30s"), ("host_unreachable", true));
        assert_eq!(classify("write frame: broken pipe (os error 32)"), ("connection_lost", true));
        assert_eq!(classify("frame too large: 16837690 bytes"), ("frame_too_large", false));
        assert_eq!(
            classify("unknown host alias, invalid invite token, or invalid nodeid"),
            ("unknown_target", false)
        );
        assert_eq!(classify("rejected connection from peer"), ("auth_rejected", false));
        assert_eq!(classify("something novel exploded"), ("error", false));
    }

    #[test]
    fn envelope_is_valid_json_with_expected_fields() {
        let err = anyhow::anyhow!("read frame length").context("agent connection failed");
        let chain: Vec<String> = err.chain().map(|c| c.to_string()).collect();
        assert_eq!(chain.len(), 2);
        let env = ErrorEnvelope {
            error: ErrorBody {
                code: "connection_lost",
                message: err.to_string(),
                chain,
                retryable: true,
                hint: None,
            },
        };
        let s = serde_json::to_string(&env).unwrap();
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["error"]["code"], "connection_lost");
        assert_eq!(v["error"]["retryable"], true);
        assert!(v["error"]["hint"].is_null()); // skipped when None
    }
}
