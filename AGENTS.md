# Agents Guide

## Project overview

hop is a secure P2P remote access tool (think SSH without a server). Single binary, no VPN, no port forwarding. Built on iroh (QUIC-based P2P networking).

**Workspace layout:**

```
crates/hop-cli/    # Binary crate (thin CLI wrapper, binary name: "hop")
crates/hop-core/   # Library crate (networking, PTY, auth, config, protocol)
pkg/               # macOS .pkg installer scripts and plists
scripts/           # AWS setup and release automation
install.sh         # curl|bash installer for end users
```

## Building

Requires Rust 2024 edition. No `rust-toolchain.toml` — uses the default toolchain.

```bash
# Local development build
cargo build -p hop-cli

# Release build
cargo build --release -p hop-cli
# Binary: target/release/hop
```

### Cross-compilation

**macOS targets** (native cargo, works on Apple Silicon via Rosetta/Xcode SDKs):

```bash
rustup target add x86_64-apple-darwin
cargo build --release --target aarch64-apple-darwin -p hop-cli
cargo build --release --target x86_64-apple-darwin -p hop-cli
```

**Linux targets** (requires [cross](https://github.com/cross-rs/cross) + Docker):

```bash
cargo install cross --git https://github.com/cross-rs/cross
AWS_LC_SYS_CMAKE_BUILDER=1 cross build --release --target x86_64-unknown-linux-gnu -p hop-cli
AWS_LC_SYS_CMAKE_BUILDER=1 cross build --release --target aarch64-unknown-linux-gnu -p hop-cli
```

`Cross.toml` installs cmake in the Docker containers and passes through `AWS_LC_SYS_CMAKE_BUILDER`. This is required because the default cross images have an old GCC that triggers a known `aws-lc-sys` bug.

### macOS .pkg installer

```bash
./pkg/build-pkg.sh                    # native arch
./pkg/build-pkg.sh --arch universal   # universal binary (arm64 + x86_64)
# Output: target/pkg-staging/output/hop-{VERSION}.pkg
```

The .pkg installs the binary to `/usr/local/bin/hop` and a LaunchDaemon (`com.hop.daemon`) that runs `hop host` at boot. Config lives at `/Library/Application Support/hop/`.

## Deploying / Releasing

### One-time AWS setup

```bash
./scripts/setup-aws.sh
```

Creates S3 bucket `hop-releases` (us-east-1), CloudFront distribution with OAC, and bucket policy. Prints the CloudFront domain and distribution ID to export.

**Current infrastructure:**
- CDN: `https://hop.keik.ai` (CloudFront: `d17l2ho600thzl.cloudfront.net`)
- Distribution ID: `E1SBRBZNSQX4WA`

### Publishing a release

```bash
# Release current version from Cargo.toml
./scripts/release.sh

# Bump version, commit, tag, build, and release in one step
./scripts/release.sh 0.3.0

# Redeploy website only (no builds)
./scripts/release.sh --site-only
```

The release script handles the full workflow:
1. Preflight checks (cargo, cross, aws, docker, rust targets)
2. Optional version bump (updates Cargo.toml, commits)
3. Runs tests
4. Builds all 4 targets (macOS via cargo, Linux via cross)
5. Strips binaries, generates `.sha256` sidecar files
6. Builds macOS universal `.pkg` installer
7. Uploads everything to `s3://hop-releases/v{VERSION}/`
8. Updates `latest` version marker, `install.sh`, and website
9. Tags the release in git and pushes (with tags)
10. Invalidates CloudFront cache

The CloudFront distribution ID defaults to `E1SBRBZNSQX4WA`. Override with `HOP_CF_DISTRIBUTION_ID` env var if needed.

**Prerequisites:** AWS credentials configured, Docker running, `cross` installed, `x86_64-apple-darwin` target added.

### S3 layout

```
s3://hop-releases/
  install.sh
  latest                          # plain text, e.g. "0.2.0"
  v0.2.0/
    hop-darwin-arm64
    hop-darwin-arm64.sha256
    hop-darwin-x86_64
    hop-darwin-x86_64.sha256
    hop-linux-arm64
    hop-linux-arm64.sha256
    hop-linux-x86_64
    hop-linux-x86_64.sha256
```

## Installation methods

```bash
# From CDN (recommended)
curl -fsSL https://hop.keik.ai/install.sh | bash

# Specific version
curl -fsSL https://hop.keik.ai/install.sh | bash -s -- --version 0.2.0

# Custom install directory
curl -fsSL https://hop.keik.ai/install.sh | bash -s -- --dir ~/.local/bin

# macOS .pkg
sudo installer -pkg hop-{VERSION}.pkg -target /
```

The installer detects OS/arch, downloads the binary with checksum verification, and installs to `/usr/local/bin` (with sudo if needed). Supports both curl and wget. Override the CDN URL with `HOP_CDN_URL` env var.

## Environment variables

| Variable | Used by | Purpose |
|---|---|---|
| `HOP_CF_DISTRIBUTION_ID` | `scripts/release.sh` | CloudFront distribution ID for cache invalidation |
| `HOP_CDN_URL` | `install.sh` | Override CDN base URL (default: `https://hop.keik.ai`) |
| `AWS_LC_SYS_CMAKE_BUILDER` | `cross` builds | Set to `1` to use cmake instead of cc for aws-lc-sys |

## Testing

```bash
cargo test                    # all workspace tests
cargo test -p hop-core        # core library tests only
cargo test -p hop-cli         # CLI tests only
```

## Code style

- Commit messages: imperative mood, 1-2 sentence summary of the "why"
- No `rust-toolchain.toml` — uses default stable toolchain
- Workspace dependencies defined in root `Cargo.toml`, crates use `.workspace = true`
