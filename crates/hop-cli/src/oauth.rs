//! OAuth and API key authentication flows for `hop auth`.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpListener;

use anyhow::{Context, Result};

// ── Provider Definitions ──────────────────────────────────────────

/// How a secret value is sourced from the OAuth token response.
pub enum SecretSource {
    /// Extract a field from the token response JSON.
    Field(&'static str),
    /// Store the provider's client_id.
    ClientId,
    /// Store the provider's client_secret.
    ClientSecret,
    /// Store a fixed string value.
    Fixed(&'static str),
}

/// An OAuth 2.0 provider with PKCE support.
pub struct OAuthProvider {
    pub name: &'static str,
    pub auth_url: &'static str,
    pub token_url: &'static str,
    pub scopes: &'static [&'static str],
    /// Maps hop secret names to where their values come from.
    pub secrets_map: &'static [(&'static str, SecretSource)],
    /// All secret keys this provider's auth flow owns — including legacy
    /// fields from prior flow versions. Used by `cmd_auth` to wipe stale
    /// entries that the current flow doesn't write, so re-auth fully
    /// replaces the credential record rather than partially overwriting.
    pub managed_secrets: &'static [&'static str],
}

/// An API key provider (no OAuth — just prompt for a key).
#[allow(dead_code)]
pub struct ApiKeyProvider {
    pub name: &'static str,
    pub console_url: &'static str,
    pub prompt: &'static str,
    pub secret_name: &'static str,
    /// All secret keys this provider's auth flow owns — see `OAuthProvider`.
    pub managed_secrets: &'static [&'static str],
}

// ── Provider Registry ─────────────────────────────────────────────

static GMAIL: OAuthProvider = OAuthProvider {
    name: "gmail",
    auth_url: "https://accounts.google.com/o/oauth2/v2/auth",
    token_url: "https://oauth2.googleapis.com/token",
    // No client_id/client_secret fields: credentials are injected at BUILD
    // time and resolved by `google_client()`, so the source contains no
    // credential-shaped strings for scanners or push protection to trip on.
    scopes: &[
        "https://www.googleapis.com/auth/gmail.readonly",
        "https://www.googleapis.com/auth/gmail.modify",
        "https://www.googleapis.com/auth/gmail.send",
        "https://www.googleapis.com/auth/calendar.readonly",
    ],
    secrets_map: &[
        ("google_client_id", SecretSource::ClientId),
        ("google_client_secret", SecretSource::ClientSecret),
        ("gmail_refresh_token", SecretSource::Field("refresh_token")),
        ("gmail_token_expiry", SecretSource::Fixed("0")),
    ],
    managed_secrets: &[
        "google_client_id",
        "google_client_secret",
        "gmail_access_token",
        "gmail_refresh_token",
        "gmail_token_expiry",
    ],
};

static ANTHROPIC: ApiKeyProvider = ApiKeyProvider {
    name: "anthropic",
    console_url: "https://console.anthropic.com/settings/keys",
    prompt: "Paste your Anthropic API key",
    secret_name: "ANTHROPIC_API_KEY",
    managed_secrets: &[
        "ANTHROPIC_API_KEY",
        "anthropic_method",
        "anthropic_refresh_token",
        "anthropic_token_expiry",
    ],
};

pub fn oauth_provider(name: &str) -> Option<&'static OAuthProvider> {
    match name {
        "gmail" | "google" => Some(&GMAIL),
        _ => None,
    }
}

// Credentials baked (obfuscated) by build.rs from the release environment.
include!(concat!(env!("OUT_DIR"), "/oauth_baked.rs"));

/// Undo the build-time XOR obfuscation.
fn deobfuscate(bytes: &[u8]) -> String {
    String::from_utf8_lossy(
        &bytes
            .iter()
            .enumerate()
            .map(|(i, b)| b ^ OAUTH_PAD[i % OAUTH_PAD.len()])
            .collect::<Vec<u8>>(),
    )
    .into_owned()
}

/// Resolve the Google OAuth client pair, in priority order:
///
/// 1. **Runtime env** — `HOP_GOOGLE_CLIENT_ID` / `HOP_GOOGLE_CLIENT_SECRET`.
///    Bring your own client (also escapes the shared client's API quota).
/// 2. **Baked at build time** — same variable names, read by `build.rs` and
///    stored XOR-obfuscated so the source has no credential strings and
///    `strings <binary>` does not surface one. Obfuscation, NOT encryption:
///    installed-app client secrets are not confidential per Google, and the
///    pair ships in every binary regardless. See SECURITY.md.
/// 3. Otherwise: no client, and the error explains how to supply one.
fn google_client(_provider: &OAuthProvider) -> Result<(String, String)> {
    fn pick(runtime: &str, baked: Option<&[u8]>) -> Option<String> {
        std::env::var(runtime)
            .ok()
            .filter(|s| !s.is_empty())
            .or_else(|| baked.map(deobfuscate))
            .filter(|s| !s.is_empty())
    }
    let id = pick("HOP_GOOGLE_CLIENT_ID", OAUTH_CLIENT_ID);
    let secret = pick("HOP_GOOGLE_CLIENT_SECRET", OAUTH_CLIENT_SECRET);
    match (id, secret) {
        (Some(i), Some(s)) => Ok((i, s)),
        _ => anyhow::bail!(
            "No Google OAuth client configured.\n\n\
             Official release builds ship one; this build was compiled without \n\
             credentials. Supply your own — which is also how you escape the \n\
             shared client's API quota:\n\n\
             \x20 1. Create a Desktop-app OAuth client at\n\
             \x20    https://console.cloud.google.com/apis/credentials\n\
             \x20 2. export HOP_GOOGLE_CLIENT_ID=... HOP_GOOGLE_CLIENT_SECRET=...\n\
             \x20 3. hop auth gmail"
        ),
    }
}

pub fn api_key_provider(name: &str) -> Option<&'static ApiKeyProvider> {
    match name {
        "anthropic" => Some(&ANTHROPIC),
        _ => None,
    }
}

// ── OAuth Flow ────────────────────────────────────────────────────

/// Run the full OAuth 2.0 + PKCE flow for a provider.
/// Returns a list of (secret_name, secret_value) pairs to store.
pub fn run_oauth_flow(provider: &OAuthProvider) -> Result<Vec<(String, String)>> {
    let (client_id, client_secret) = google_client(provider)?;
    // 1. Generate PKCE verifier + challenge
    let (verifier, challenge) = generate_pkce();

    // 2. Generate state for CSRF prevention
    let mut state_bytes = [0u8; 16];
    rand::fill(&mut state_bytes);
    let state = base64_url_encode(&state_bytes);

    // 3. Bind TCP listener on random port
    let listener = TcpListener::bind("127.0.0.1:0")
        .context("Failed to bind localhost listener for OAuth callback")?;
    let port = listener.local_addr()?.port();
    let redirect_uri = format!("http://localhost:{port}");

    // 4. Build authorization URL
    let scopes = provider.scopes.join(" ");
    let auth_url = format!(
        "{}?client_id={}&redirect_uri={}&response_type=code&scope={}&access_type=offline&prompt=consent&state={}&code_challenge={}&code_challenge_method=S256",
        provider.auth_url,
        url_encode(&client_id),
        url_encode(&redirect_uri),
        url_encode(&scopes),
        url_encode(&state),
        url_encode(&challenge),
    );

    // 5. Open browser
    eprintln!("  Opening browser for {} sign-in...", provider.name);
    open_browser(&auth_url)?;

    // 6. Wait for callback
    eprintln!("  Waiting for authorization...");
    let (code, returned_state) = wait_for_callback(listener)?;

    // Verify state
    if returned_state != state {
        anyhow::bail!("OAuth state mismatch — possible CSRF attack");
    }

    // 7. Exchange code for tokens
    eprintln!("  Exchanging authorization code for tokens...");
    let token_response = exchange_code(
        provider.token_url,
        &code,
        &client_id,
        &client_secret,
        &redirect_uri,
        &verifier,
    )?;

    // 8. Extract secrets from response
    let mut secrets = Vec::new();
    for (secret_name, source) in provider.secrets_map {
        let value = match source {
            SecretSource::Field(field) => token_response
                .get(*field)
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
                .ok_or_else(|| anyhow::anyhow!("Token response missing field: {field}"))?,
            SecretSource::ClientId => client_id.clone(),
            SecretSource::ClientSecret => client_secret.clone(),
            SecretSource::Fixed(val) => val.to_string(),
        };
        secrets.push((secret_name.to_string(), value));
    }

    Ok(secrets)
}

// ── API Key Flow ──────────────────────────────────────────────────

/// Run the Anthropic auth flow. Returns a list of (secret_name, value) pairs.
///
/// Priority:
/// 1. Run `claude setup-token` to create a long-lived token (1 year, stable)
/// 2. Fall back to manual API key entry
pub fn run_api_key_flow(provider: &ApiKeyProvider) -> Result<Vec<(String, String)>> {
    if provider.name == "anthropic" {
        // Try: run setup-token for a long-lived token (1 year, no refresh needed)
        if has_claude_cli() {
            eprintln!("  Creating a long-lived Claude token (valid for 1 year)...");
            eprintln!();

            let output = shell_command_interactive("claude setup-token")
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::inherit())
                .output();

            if let Ok(out) = output && out.status.success() {
                let stdout = String::from_utf8_lossy(&out.stdout);

                if let Some(token) = extract_token_from_output(&stdout) {
                    eprintln!();
                    eprintln!("  Long-lived token created (valid for 1 year).");
                    return Ok(vec![
                        ("ANTHROPIC_API_KEY".to_string(), token),
                        ("anthropic_method".to_string(), "setup_token".to_string()),
                    ]);
                }
            }

            eprintln!("  Could not create setup token. Falling back to API key.");
        }
    }

    // Fall back to manual key entry
    eprintln!(
        "  Opening {} to create an API key...",
        provider.console_url
    );
    let _ = open_browser(provider.console_url);

    eprint!("  {}: ", provider.prompt);
    std::io::stderr().flush()?;

    let mut key = String::new();
    std::io::stdin().read_line(&mut key)?;
    let key = key.trim().to_string();

    if key.is_empty() {
        anyhow::bail!("No API key provided");
    }

    Ok(vec![
        (provider.secret_name.to_string(), key),
        ("anthropic_method".to_string(), "api_key".to_string()),
    ])
}

/// Check if the `claude` CLI binary is available via the user's shell.
fn has_claude_cli() -> bool {
    shell_command("which claude")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// Extract an OAuth token (sk-ant-oat01-...) from setup-token's stdout.
///
/// Searches each line independently. The previous implementation joined all
/// lines with an empty string, then captured alphanumeric chars after the
/// `sk-ant-oat01-` marker — which silently appended the next line's leading
/// word (e.g. "Store" from "Store this token somewhere safe") onto the token,
/// producing an invalid bearer that Anthropic's API rejects with 401.
fn extract_token_from_output(output: &str) -> Option<String> {
    for line in output.lines() {
        let trimmed = line.trim();
        if let Some(start) = trimmed.find("sk-ant-oat01-") {
            let token_chars: String = trimmed[start..]
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
                .collect();
            if token_chars.len() > 20 {
                return Some(token_chars);
            }
        }
    }
    None
}

/// Run a command through the user's login shell so PATH includes
/// nvm, brew, cargo, and other shell-initialized tools.
/// Stdin is set to null to prevent interactive TUI launches.
fn shell_command(cmd: &str) -> std::process::Command {
    let shell = std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_string());
    let mut command = std::process::Command::new(&shell);
    command.args(["-lc", cmd]);
    // Prevent interactive mode — force non-TTY stdin
    command.stdin(std::process::Stdio::null());
    command
}

/// Like shell_command but inherits stdin (for interactive commands like setup-token).
fn shell_command_interactive(cmd: &str) -> std::process::Command {
    let shell = std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_string());
    let mut command = std::process::Command::new(&shell);
    command.args(["-lc", cmd]);
    command
}

// ── PKCE ──────────────────────────────────────────────────────────

fn generate_pkce() -> (String, String) {
    let mut verifier_bytes = [0u8; 32];
    rand::fill(&mut verifier_bytes);
    let verifier = base64_url_encode(&verifier_bytes);

    use sha2::{Digest, Sha256};
    let challenge = base64_url_encode(&Sha256::digest(verifier.as_bytes()));

    (verifier, challenge)
}

// ── Callback Server ───────────────────────────────────────────────

/// Wait for the OAuth callback on the localhost listener.
/// Returns (authorization_code, state).
fn wait_for_callback(listener: TcpListener) -> Result<(String, String)> {
    // Set a timeout so we don't hang forever
    listener.set_nonblocking(false)?;

    let (mut stream, _) = listener.accept().context("No OAuth callback received")?;

    let mut buf = [0u8; 8192];
    let n = stream.read(&mut buf)?;
    let request = String::from_utf8_lossy(&buf[..n]);

    // Parse query parameters from: GET /callback?code=XXX&state=YYY HTTP/1.1
    // Or: GET /?code=XXX&state=YYY HTTP/1.1
    let query = request
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|path| path.split('?').nth(1))
        .unwrap_or("");

    let params: HashMap<&str, &str> = query
        .split('&')
        .filter_map(|pair| {
            let mut parts = pair.splitn(2, '=');
            Some((parts.next()?, parts.next()?))
        })
        .collect();

    // Check for error
    if let Some(error) = params.get("error") {
        let desc = params.get("error_description").unwrap_or(&"");
        // Send error page
        let html = format!(
            "<h1>Authentication Failed</h1><p>{}: {}</p>",
            error, desc
        );
        let response = format!(
            "HTTP/1.1 400 Bad Request\r\nContent-Type: text/html\r\nContent-Length: {}\r\n\r\n{}",
            html.len(),
            html
        );
        let _ = stream.write_all(response.as_bytes());
        anyhow::bail!("OAuth error: {error} — {desc}");
    }

    let code = params
        .get("code")
        .ok_or_else(|| anyhow::anyhow!("No authorization code in callback"))?
        .to_string();
    let state = params.get("state").unwrap_or(&"").to_string();

    // Send success page
    let html = "<html><body style=\"font-family:system-ui;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;background:#111;color:#fff\"><div style=\"text-align:center\"><h1 style=\"color:#10b981\">&#10003; Authenticated</h1><p style=\"color:#888\">You can close this tab and return to your terminal.</p></div></body></html>";
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\n\r\n{}",
        html.len(),
        html
    );
    let _ = stream.write_all(response.as_bytes());

    Ok((code, state))
}

// ── Token Exchange ────────────────────────────────────────────────

fn exchange_code(
    token_url: &str,
    code: &str,
    client_id: &str,
    client_secret: &str,
    redirect_uri: &str,
    code_verifier: &str,
) -> Result<serde_json::Value> {
    let client = reqwest::blocking::Client::new();
    let resp = client
        .post(token_url)
        .form(&[
            ("code", code),
            ("client_id", client_id),
            ("client_secret", client_secret),
            ("redirect_uri", redirect_uri),
            ("grant_type", "authorization_code"),
            ("code_verifier", code_verifier),
        ])
        .send()
        .context("Token exchange request failed")?;

    let status = resp.status();
    let body = resp.text().context("Failed to read token response")?;

    if !status.is_success() {
        anyhow::bail!("Token exchange failed ({status}): {body}");
    }

    serde_json::from_str(&body).context("Failed to parse token response")
}

// ── Browser ───────────────────────────────────────────────────────

fn open_browser(url: &str) -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("open")
            .arg(url)
            .spawn()
            .context("Failed to open browser")?;
    }
    #[cfg(target_os = "linux")]
    {
        std::process::Command::new("xdg-open")
            .arg(url)
            .spawn()
            .context("Failed to open browser (is xdg-open installed?)")?;
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        eprintln!("  Please open this URL in your browser:");
        eprintln!("  {url}");
    }
    Ok(())
}

// ── URL Encoding ──────────────────────────────────────────────────

fn url_encode(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                result.push(b as char);
            }
            _ => {
                result.push_str(&format!("%{b:02X}"));
            }
        }
    }
    result
}

fn base64_url_encode(data: &[u8]) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    URL_SAFE_NO_PAD.encode(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_token_does_not_swallow_next_line() {
        // Realistic `claude setup-token` output: token on its own line,
        // followed by instructional text. Prior bug joined lines with "" and
        // appended "Store" (and would have appended anything else) to the
        // captured token, breaking auth with 401 Invalid bearer token.
        let output = "\
            Your long-lived token:\n\
            sk-ant-oat01-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789-_AAAA\n\
            Store this token somewhere safe.\n\
        ";
        let token = extract_token_from_output(output).expect("token should be extracted");
        assert_eq!(token, "sk-ant-oat01-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789-_AAAA");
        assert!(!token.contains("Store"));
    }

    #[test]
    fn extract_token_handles_inline_label() {
        let output = "Token: sk-ant-oat01-XYZ789-_ABC right here\n";
        let token = extract_token_from_output(output).expect("token should be extracted");
        assert_eq!(token, "sk-ant-oat01-XYZ789-_ABC");
    }

    #[test]
    fn extract_token_returns_none_when_missing() {
        assert!(extract_token_from_output("no token here").is_none());
    }

    /// The build-time XOR must round-trip exactly — otherwise a release would
    /// ship a corrupted client id and `hop auth gmail` would fail with an
    /// opaque Google error rather than anything diagnosable.
    #[test]
    fn obfuscation_round_trips() {
        // Mirror what build.rs does, then decode with the shipping path.
        let sample = "111122223333-abcdefgh.apps.googleusercontent.com";
        let encoded: Vec<u8> = sample
            .as_bytes()
            .iter()
            .enumerate()
            .map(|(i, b)| b ^ OAUTH_PAD[i % OAUTH_PAD.len()])
            .collect();
        assert_ne!(encoded.as_slice(), sample.as_bytes(), "must not be plaintext");
        assert_eq!(deobfuscate(&encoded), sample);
    }

    /// Obfuscated bytes must not contain the recognizable credential prefixes
    /// that scanners (and `strings`) look for.
    #[test]
    fn obfuscation_hides_recognizable_prefixes() {
        for sample in ["GOCSPX-abcdefghijklmnop", "1234-xyz.apps.googleusercontent.com"] {
            let encoded: Vec<u8> = sample
                .as_bytes()
                .iter()
                .enumerate()
                .map(|(i, b)| b ^ OAUTH_PAD[i % OAUTH_PAD.len()])
                .collect();
            let as_text = String::from_utf8_lossy(&encoded);
            assert!(!as_text.contains("GOCSPX"));
            assert!(!as_text.contains("googleusercontent"));
        }
    }

    /// A runtime env var must win over anything baked in, so a self-hoster can
    /// always bring their own client.
    #[test]
    fn runtime_env_overrides_baked_client() {
        // SAFETY: single-threaded test process; restored before returning.
        unsafe {
            std::env::set_var("HOP_GOOGLE_CLIENT_ID", "runtime-id");
            std::env::set_var("HOP_GOOGLE_CLIENT_SECRET", "runtime-secret");
        }
        let (id, secret) = google_client(&GMAIL).expect("env-provided client resolves");
        unsafe {
            std::env::remove_var("HOP_GOOGLE_CLIENT_ID");
            std::env::remove_var("HOP_GOOGLE_CLIENT_SECRET");
        }
        assert_eq!(id, "runtime-id");
        assert_eq!(secret, "runtime-secret");
    }
}
