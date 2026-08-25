#!/usr/bin/env node
// Postinstall: fetch the platform's `hop` binary and verify it.
//
// WireHop ships a single Rust binary. npm is the distribution channel the MCP
// Registry supports (it has no Cargo type), so this package downloads the same
// signed artifact `install.sh` does — and applies the SAME two checks:
//
//   1. SHA-256 against the published .sha256 sidecar
//   2. RSA-SHA256 signature against the release public key embedded here
//
// Both must pass or installation fails: a compromised CDN or bucket must not
// be able to hand you a binary. Most npm binary wrappers verify neither.
//
// Offline/air-gapped or corp-proxy environments: set WIREHOP_SKIP_DOWNLOAD=1
// and put `hop` on PATH yourself; the bin shim will find it.

'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { pipeline } = require('stream/promises');

const VERSION = require('../package.json').version;
const BASE = process.env.WIREHOP_CDN_URL || 'https://hop.keikai.ai';
const BIN_DIR = path.join(__dirname, '..', 'bin');
const OUT = path.join(BIN_DIR, process.platform === 'win32' ? 'hop.exe' : 'hop');

/** Map Node's platform/arch onto published artifact names. */
function artifactName() {
  const { platform, arch } = process;
  const table = {
    'darwin:arm64': 'hop-darwin-arm64',
    'darwin:x64': 'hop-darwin-x86_64',
    'linux:arm64': 'hop-linux-arm64',
    'linux:x64': 'hop-linux-x86_64',
    'linux:arm': 'hop-linux-armv7',
  };
  return table[`${platform}:${arch}`] || null;
}

async function fetchBuffer(url) {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`${res.status} ${res.statusText} for ${url}`);
  return Buffer.from(await res.arrayBuffer());
}

async function main() {
  if (process.env.WIREHOP_SKIP_DOWNLOAD === '1') {
    console.log('[wirehop] WIREHOP_SKIP_DOWNLOAD=1 — skipping binary download.');
    return;
  }

  const name = artifactName();
  if (!name) {
    // Windows has no published build yet. Don't fail the install — WSL is the
    // supported path and a hard failure would break `npm i` in mixed repos.
    console.warn(
      `[wirehop] No prebuilt binary for ${process.platform}/${process.arch}.\n` +
        `[wirehop] On Windows, use WSL. Otherwise build from source:\n` +
        `[wirehop]   cargo install --git https://github.com/Keikai-Inc/wirehop hop-cli`
    );
    return;
  }

  const url = `${BASE}/v${VERSION}/${name}`;
  console.log(`[wirehop] Downloading ${name} v${VERSION}...`);

  const [bin, shaText, sig] = await Promise.all([
    fetchBuffer(url),
    fetchBuffer(`${url}.sha256`).then((b) => b.toString('utf8').trim().split(/\s+/)[0]),
    fetchBuffer(`${url}.sig`),
  ]);

  // 1. Checksum
  const actual = crypto.createHash('sha256').update(bin).digest('hex');
  if (actual !== shaText) {
    throw new Error(
      `checksum mismatch for ${name}\n  expected ${shaText}\n  actual   ${actual}`
    );
  }

  // 2. Signature — provenance, not just integrity. A compromised bucket can
  //    rewrite a binary AND its checksum; it cannot forge this.
  const pubkey = fs.readFileSync(path.join(__dirname, '..', 'release-pubkey.pem'), 'utf8');
  const ok = crypto.createVerify('RSA-SHA256').update(bin).verify(pubkey, sig);
  if (!ok) throw new Error(`signature verification FAILED for ${name} — refusing to install`);

  fs.mkdirSync(BIN_DIR, { recursive: true });
  fs.writeFileSync(OUT, bin, { mode: 0o755 });
  console.log(`[wirehop] Verified (sha256 + signature) and installed -> ${OUT}`);
}

main().catch((err) => {
  console.error(`[wirehop] Install failed: ${err.message}`);
  console.error('[wirehop] Set WIREHOP_SKIP_DOWNLOAD=1 to skip and supply `hop` on PATH yourself.');
  process.exit(1);
});
