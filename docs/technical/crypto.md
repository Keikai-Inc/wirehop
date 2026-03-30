# Cryptography

## Ed25519 Identity

Each hop node (host or client) has a persistent Ed25519 keypair that serves as its identity. The keypair is used by iroh for QUIC/TLS 1.3 mutual authentication -- all connections are end-to-end encrypted.

### Generation and Storage

On first run, `load_or_generate_identity()` generates a new keypair and persists it to `identity.json`:

```rust
struct IdentityFile {
    secret_key: String,  // 32-byte Ed25519 secret, base64url-encoded (URL_SAFE_NO_PAD)
    node_id: String,     // Ed25519 public key, hex-encoded
}
```

Storage location:
- macOS system daemon: `/Library/Application Support/hop/identity.json`
- Linux system daemon: `/etc/hop/identity.json`
- User config: `~/.config/hop/identity.json` (via `directories::ProjectDirs`)

### File Permissions

`identity.json` is written with `write_secret_file()` which sets **mode 0600** (owner read/write only) on Unix. The containing config directory is set to **mode 0700** unless the setgid bit (0o2000) is set, which indicates shared daemon/CLI access configured by the macOS .pkg postinstall script.

### Resolution Priority

`resolve_host_config_dir()` resolves the config directory in order:
1. `--config` CLI override
2. System config dir if `identity.json` exists there
3. User config dir (`~/.config/hop/`)

### Read-Only Access

`load_identity()` reads an existing identity without generating one. Used by `hop invite` to read the daemon's identity. Errors if the file does not exist.

## Argon2 Invite Authentication

Invite tokens authenticate new peers to a host. The flow uses Argon2id to prevent offline brute-force attacks on stored invite hashes.

### Invite Generation

`generate_invite_with_role()` in `crates/hop-core/src/invite/mod.rs`:

1. Generate 32 bytes of random secret via `rand::rng().fill_bytes()`
2. Hex-encode the secret (64 hex characters)
3. Generate 16-byte random salt, base64-encode it
4. Hash the hex secret with `Argon2::default()` (Argon2id, default parameters)
5. Store `PendingInvite { secret_hash, created_at, username, role, sandbox }` in `pending_invites.json`
6. Build `InviteToken` struct, JSON-encode, base64url-encode

```rust
pub struct InviteToken {
    pub node_id: String,              // Host's public key (hex)
    pub secret: String,               // 32-byte random secret (hex)
    pub relay_url: Option<String>,    // Host's relay URL
    pub username: Option<String>,     // Unix username binding
    pub host_name: Option<String>,    // Human-readable hostname
    pub role: PeerRole,               // Peer | Creator
    pub sandbox: SandboxPolicy,       // Sandbox restrictions
}
```

### Verification

When a client connects with `ClientMessage::AuthResponse { secret }`:

1. `PendingInvitesStore::try_consume()` iterates all pending invites
2. For each invite, parses the stored `$argon2id$...` hash with `PasswordHash::new()`
3. Verifies `Argon2::default().verify_password(client_secret, stored_hash)`
4. On match: **removes** the invite from the store (single-use), returns `ConsumedInvite { username, role, sandbox }`

### TOCTOU Safety

The invite is atomically consumed -- `invites.remove(idx)` is called in the same operation as verification. The `PendingInvitesStore` is re-loaded from disk on each connection attempt, and saved after mutation. There is no window where two clients can consume the same invite.

### Expiry

`prune_expired(max_age_secs)` removes invites older than the threshold before checking. Default expiry:
- Regular invites: 15 minutes (900 seconds)
- Creator invites: 1 hour (3600 seconds)

### Transport Security

The invite secret is sent as plaintext in `AuthResponse` because the QUIC/TLS 1.3 transport is end-to-end encrypted. The secret never traverses the network in cleartext.

## ChaCha20-Poly1305 Secrets

The datastore's secrets subsystem provides at-rest encryption for sensitive values (API keys, tokens, credentials).

### SealedSecret Struct

```rust
pub struct SealedSecret {
    pub ciphertext: Vec<u8>,    // ChaCha20-Poly1305 ciphertext (plaintext + 16-byte auth tag)
    pub nonce: [u8; 12],        // 12-byte random nonce
    pub updated_at: u64,        // Unix timestamp in milliseconds
}
```

Stored in the redb `secrets` table as bincode-encoded bytes, keyed by secret name.

### Encryption

`encrypt(key, plaintext)` in `crates/hop-core/src/datastore/secrets.rs`:

1. Create `ChaCha20Poly1305` cipher from the 32-byte key
2. Generate 12 random bytes for the nonce via `rand::fill()`
3. Encrypt: `cipher.encrypt(nonce, plaintext)` -- produces ciphertext with appended 16-byte Poly1305 auth tag
4. Return `SealedSecret { ciphertext, nonce, updated_at: now_ms() }`

### Decryption

`decrypt(key, sealed)`:

1. Create `ChaCha20Poly1305` cipher from the 32-byte key
2. Decrypt: `cipher.decrypt(nonce, ciphertext)` -- verifies auth tag and returns plaintext
3. On auth tag mismatch (wrong key or tampered data): returns error

### Remote Mode

When the datastore is in Remote mode (MCP process connecting to daemon), secrets operations are proxied via `DsRequest::SecretsGet/Set/Delete/List` over the Unix domain socket. The daemon handles encryption/decryption locally -- plaintext secrets travel over the IPC socket but never leave the machine.

## Key Derivation

The AEAD encryption key is derived from the Ed25519 identity secret key using SHA-256 with a domain separator:

```rust
pub fn derive_secrets_key(identity_key: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"hop-secrets-v1");    // Domain separator
    hasher.update(identity_key);          // Ed25519 secret key bytes
    hasher.finalize().into()              // 32-byte SHA-256 output = AEAD key
}
```

### Design Rationale

- **Domain separator** (`"hop-secrets-v1"`): prevents cross-protocol key reuse. If the same Ed25519 key were used for a different purpose, the derived key would differ.
- **SHA-256 output**: 256 bits matches ChaCha20-Poly1305's key size exactly.
- **Deterministic**: the same identity always derives the same secrets key, so secrets survive daemon restarts without storing the AEAD key separately.
- **Version tag**: the `v1` suffix allows future key derivation scheme upgrades without breaking existing secrets.

### Key Lifecycle

1. Daemon starts, loads `identity.json` (Ed25519 secret key)
2. Calls `derive_secrets_key(&secret_key_bytes)` to get the 32-byte AEAD key
3. Opens datastore with `Datastore::open_with_secrets(path, secrets_key)`
4. All `secrets_get/set/delete/list` operations use this key for the session

*Last updated: v0.4.3*
