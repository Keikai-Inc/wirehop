//! Hop extension system.
//!
//! Companion daemons that register with the hop daemon via TOML manifests
//! and serve peer requests for namespaced `ext_id` payloads. The extension
//! system is described in `docs/hop-tap-plan.md` (planning doc) and is
//! deliberately minimal in hop core: extensions handle their own auth
//! refinements, sub-protocols, and lifecycle.
//!
//! Components:
//!
//! - [`manifest`] — TOML schema and parser for extension manifests dropped
//!   into `~/.config/hop/extensions/` or `/etc/hop/extensions/`.
//! - (forthcoming) `registry` — runtime registry of active extensions,
//!   ipc-channel rendezvous, SO_PEERCRED checks, request dispatch.

pub mod manifest;

pub use manifest::ExtensionManifest;
