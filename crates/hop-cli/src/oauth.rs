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
/// 1. Detect local Claude Code credentials and copy them
/// 2. Prompt for an API key from console.anthropic.com
pub fn run_api_key_flow(provider: &ApiKeyProvider) -> Result<Vec<(String, String)>> {
    if provider.name == "anthropic" {
        // Check for existing Claude Code credentials
        if let Some(creds) = detect_claude_credentials() {
            eprintln!("  Found Claude Code credentials (expires {}).", creds.expires_display);
            eprint!("  Use Claude Code login? [Y/n]: ");
            std::io::stderr().flush()?;

            let mut answer = String::new();
            std::io::stdin().read_line(&mut answer)?;
            let answer = answer.trim().to_lowercase();

            if answer.is_empty() || answer == "y" || answer == "yes" {
                return Ok(vec![
                    ("ANTHROPIC_API_KEY".to_string(), creds.access_token),
                    ("anthropic_refresh_token".to_string(), creds.refresh_token),
                    ("anthropic_token_expiry".to_string(), creds.expires_at.to_string()),
                    ("anthropic_method".to_string(), "claude_oauth".to_string()),
                ]);
            }
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

struct ClaudeCredentials {
    access_token: String,
    refresh_token: String,
    expires_at: u64,
    expires_display: String,
}

/// Check for existing Claude Code OAuth credentials at ~/.claude/.credentials.json.
/// Returns the full credential set if found and not expired.
fn detect_claude_credentials() -> Option<ClaudeCredentials> {
    let home = std::env::var("HOME").ok()?;
    let path = std::path::PathBuf::from(home).join(".claude/.credentials.json");
    let data = std::fs::read_to_string(&path).ok()?;
    let json: serde_json::Value = serde_json::from_str(&data).ok()?;

    let oauth = json.get("claudeAiOauth")?;
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
