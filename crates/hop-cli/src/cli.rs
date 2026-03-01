use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "hop", about = "Secure P2P remote access")]
pub struct Cli {
    /// Override config directory
    #[arg(long, global = true)]
    pub config: Option<PathBuf>,

    /// Increase log verbosity
    #[arg(short, long, global = true, action = clap::ArgAction::Count)]
    pub verbose: u8,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Start hosting (listen for connections)
    Host {
        /// Suppress interactive output (for daemon/LaunchAgent use)
        #[arg(long)]
        quiet: bool,
    },

    /// Generate a one-time invite token/URL
    Invite,

    /// Connect to a host (NodeId or invite token)
    Connect {
        /// Host NodeId or invite token
        target: String,
    },

    /// List authorized peers or known hosts
    Peers {
        #[command(subcommand)]
        action: Option<PeersAction>,
    },

    /// Print this node's identity (NodeId)
    Id,
}

#[derive(Subcommand)]
pub enum PeersAction {
    /// Remove an authorized peer
    Remove {
        /// NodeId of the peer to remove
        id: String,
    },
}
