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
    Invite {
        /// Unix username the invited peer will log in as
        #[arg(long)]
        user: Option<String>,
        /// Human-readable name for this host (defaults to system hostname)
        #[arg(long)]
        name: Option<String>,
    },

    /// Connect to a host (NodeId, invite token, or known host alias)
    Connect {
        /// Host NodeId, invite token, or known host alias
        target: String,
        /// Override the name saved for this host in known_hosts
        #[arg(long)]
        name: Option<String>,
    },

    /// List authorized peers or known hosts
    Peers {
        #[command(subcommand)]
        action: Option<PeersAction>,
    },

    /// Copy files to/from a remote host
    Cp {
        /// Copy directories recursively
        #[arg(short, long)]
        recursive: bool,

        /// Source and destination paths (use host:path for remote)
        #[arg(required = true, num_args = 2..)]
        paths: Vec<String>,
    },

    /// Sync directories with a remote host
    Sync {
        /// Delete extraneous files from destination
        #[arg(long)]
        delete: bool,

        /// Show what would be transferred without doing it
        #[arg(short = 'n', long)]
        dry_run: bool,

        /// Verbose output (print each file)
        #[arg(short, long)]
        verbose: bool,

        /// Source path (use host:path for remote)
        source: String,

        /// Destination path (use host:path for remote)
        dest: String,
    },

    /// Execute a command on a remote host
    Exec {
        /// Host NodeId, invite token, or known host alias
        target: String,
        /// Command and arguments to execute
        #[arg(required = true, last = true)]
        command: Vec<String>,
    },

    /// Connect to a host (shorthand: "hop on <target>")
    On {
        /// Host NodeId, invite token, or known host alias
        target: String,
        /// Override the name saved for this host in known_hosts
        #[arg(long)]
        name: Option<String>,
    },

    /// Print this node's identity (NodeId)
    Id,

    /// Catch-all: treat unknown subcommands as connect targets (e.g. "hop myhost")
    #[command(external_subcommand)]
    External(Vec<String>),
}

#[derive(Subcommand)]
pub enum PeersAction {
    /// Remove an authorized peer
    Remove {
        /// NodeId of the peer to remove
        id: String,
    },

    /// Rename a peer or known host
    Rename {
        /// NodeId prefix or current alias
        id: String,
        /// New name
        name: String,
    },
}
