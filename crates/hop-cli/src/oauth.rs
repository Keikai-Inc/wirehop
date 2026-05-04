//! OAuth and API key authentication flows for `hop auth`.
#![allow(dead_code)] // Legacy credential detection functions kept for reference

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
    pub client_id: &'static str,
    pub client_secret: &'static str,
    pub scopes: &'static [&'static str],
    /// Maps hop secret names to where their values come from.
    pub secrets_map: &'static [(&'static str, SecretSource)],
}

/// An API key provider (no OAuth — just prompt for a key).
#[allow(dead_code)]
pub struct ApiKeyProvider {
    pub name: &'static str,
    pub console_url: &'static str,
    pub prompt: &'static str,
    pub secret_name: &'static str,
}

// ── Provider Registry ─────────────────────────────────────────────

static GMAIL: OAuthProvider = OAuthProvider {
    name: "gmail",
    auth_url: "https://accounts.google.com/o/oauth2/v2/auth",
    token_url: "https://oauth2.googleapis.com/token",
    // hop's registered Desktop app OAuth client (hop-keik-ai project)
    client_id: "REDACTED.apps.googleusercontent.com",
    client_secret: "REDACTED",
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
};

static ANTHROPIC: ApiKeyProvider = ApiKeyProvider {
    name: "anthropic",
    console_url: "https://console.anthropic.com/settings/keys",
    prompt: "Paste your Anthropic API key",
    secret_name: "ANTHROPIC_API_KEY",
};

pub fn oauth_provider(name: &str) -> Option<&'static OAuthProvider> {
    match name {
        "gmail" | "google" => Some(&GMAIL),
        _ => None,
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
        url_encode(provider.client_id),
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
        provider.client_id,
        provider.client_secret,
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
            SecretSource::ClientId => provider.client_id.to_string(),
            SecretSource::ClientSecret => provider.client_secret.to_string(),
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
/// The output contains ASCII art and text; the token is on its own line.
fn extract_token_from_output(output: &str) -> Option<String> {
    // Token lines may be split across multiple lines (line wrapping).
    // Collect all text, then find the token pattern.
    let clean: String = output
        .lines()
        .map(|l| l.trim())
        .collect::<Vec<_>>()
        .join("");

    // Find sk-ant-oat01- and capture until whitespace or non-token char
    if let Some(start) = clean.find("sk-ant-oat01-") {
        let token_chars: String = clean[start..]
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
            .collect();
        if token_chars.len() > 20 {
            return Some(token_chars);
        }
    }

    None
}

// ── Legacy Functions (kept for reference, may be cleaned up later) ──

const MIN_CLAUDE_VERSION: (u32, u32) = (2, 1);

fn is_claude_logged_in() -> bool {
    // Check version first — old versions don't have `auth status`
    let version_output = match shell_command("claude --version").output() {
        Ok(o) if o.status.success() => o,
        _ => return false,
    };
    let version_str = String::from_utf8_lossy(&version_output.stdout);
    if !check_claude_version(&version_str) {
        // Extract version for the error message
        let ver = version_str.trim().lines().next().unwrap_or("unknown");
        eprintln!("  Claude Code {ver} is too old (need >= {}.{}.x).", MIN_CLAUDE_VERSION.0, MIN_CLAUDE_VERSION.1);
        eprintln!("  Update with: npm install -g @anthropic-ai/claude-code@latest");
        return false;
    }

    // Now safe to call auth status
    let output = match shell_command("claude auth status").output() {
        Ok(o) => o,
        Err(_) => return false,
    };
    if !output.status.success() {
        return false;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    // Find JSON in output (may have shell profile noise before it)
    let json_str = if let Some(start) = stdout.find('{') { &stdout[start..] } else { &stdout };
    let Ok(json) = serde_json::from_str::<serde_json::Value>(json_str) else {
        return false;
    };
    json.get("loggedIn").and_then(|v| v.as_bool()).unwrap_or(false)
}

/// Check if the claude version string meets the minimum requirement.
/// Expects format like "2.1.89 (Claude Code)" or similar.
fn check_claude_version(version_output: &str) -> bool {
    let line = version_output.trim().lines().next().unwrap_or("");
    // Extract version numbers from "2.1.89 (Claude Code)" or "2.1.89"
    let version_part = line.split_whitespace().next().unwrap_or("");
    let parts: Vec<&str> = version_part.split('.').collect();
    if parts.len() < 2 {
        return false;
    }
    let Ok(major) = parts[0].parse::<u32>() else { return false };
    let Ok(minor) = parts[1].parse::<u32>() else { return false };
    (major, minor) >= MIN_CLAUDE_VERSION
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

struct ClaudeCredentials {
    access_token: String,
    refresh_token: String,
    expires_at: u64,
    expires_display: String,
}

/// Detect existing Claude Code OAuth credentials.
///
/// Tries two sources:
/// 1. ~/.claude/.credentials.json (file cache, may not exist on all setups)
/// 2. `claude auth status --json` + keychain (Claude Code manages its own auth)
///
/// Returns the full credential set if found and not expired.
fn detect_claude_credentials() -> Option<ClaudeCredentials> {
    // Try 1: credentials file (fast, no subprocess)
    if let Some(creds) = detect_claude_credentials_file() {
        return Some(creds);
    }

    // Try 2: ask Claude CLI to export credentials via setup-token or auth status
    detect_claude_credentials_cli()
}

fn detect_claude_credentials_file() -> Option<ClaudeCredentials> {
    let home = std::env::var("HOME").ok()?;
    let path = std::path::PathBuf::from(home).join(".claude/.credentials.json");
    let data = std::fs::read_to_string(&path).ok()?;
    let json: serde_json::Value = serde_json::from_str(&data).ok()?;

    let oauth = json.get("claudeAiOauth")?;
    parse_claude_oauth(oauth)
}

fn detect_claude_credentials_cli() -> Option<ClaudeCredentials> {
    // On macOS, npm-installed Claude Code stores credentials in the Keychain
    // under service "Claude Code-credentials". Try reading it directly.
    #[cfg(target_os = "macos")]
    {
        if let Some(creds) = detect_claude_credentials_keychain() {
            return Some(creds);
        }
    }

    None
}

/// Read Claude Code credentials from macOS Keychain.
/// npm-installed Claude Code uses service name "Claude Code-credentials".
#[cfg(target_os = "macos")]
fn detect_claude_credentials_keychain() -> Option<ClaudeCredentials> {
    let output = std::process::Command::new("security")
        .args(["find-generic-password", "-s", "Claude Code-credentials", "-w"])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let json_str = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(json_str.trim()).ok()?;
    let oauth = json.get("claudeAiOauth")?;
    parse_claude_oauth(oauth)
}

fn parse_claude_oauth(oauth: &serde_json::Value) -> Option<ClaudeCredentials> {
    let access_token = oauth.get("accessToken")?.as_str()?.to_string();
    let refresh_token = oauth.get("refreshToken")?.as_str().unwrap_or("").to_string();
    let expires_at = oauth.get("expiresAt")?.as_u64()?;

    // Check if token is still valid (with 5 min buffer)
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_millis() as u64;

    if now_ms > expires_at.saturating_sub(300_000) {
        return None; // expired
    }

    let remaining_hours = (expires_at - now_ms) / 3_600_000;
    let expires_display = if remaining_hours > 24 {
        format!("in {} days", remaining_hours / 24)
    } else {
        format!("in {} hours", remaining_hours)
    };

    Some(ClaudeCredentials {
        access_token,
        refresh_token,
        expires_at,
        expires_display,
    })
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
