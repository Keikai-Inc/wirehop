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
        /// Restrict to read-only filesystem access
        #[arg(long)]
        read_only: bool,
        /// Block outbound network access
        #[arg(long)]
        no_network: bool,
        /// Restrict filesystem access to these paths (can be repeated)
        #[arg(long = "scope", value_name = "PATH")]
        scopes: Vec<std::path::PathBuf>,
        /// Only allow these commands (can be repeated)
        #[arg(long = "allow-command", value_name = "CMD")]
        allow_commands: Vec<String>,
        /// Use a sandbox preset (monitor, audit, deploy)
        #[arg(long)]
        preset: Option<String>,
    },

    /// Connect to a host (NodeId, invite token, or known host alias)
    Connect {
        /// Host NodeId, invite token, or known host alias
        target: String,
        /// Override the name saved for this host in known_hosts
        #[arg(long)]
        name: Option<String>,
        /// Request read-only filesystem access
        #[arg(long)]
        read_only: bool,
        /// Request blocking outbound network access
        #[arg(long)]
        no_network: bool,
        /// Restrict filesystem access to these paths (can be repeated)
        #[arg(long = "scope", value_name = "PATH")]
        scopes: Vec<std::path::PathBuf>,
        /// Only allow these commands (can be repeated)
        #[arg(long = "allow-command", value_name = "CMD")]
        allow_commands: Vec<String>,
        /// Use a sandbox preset (monitor, audit, deploy)
        #[arg(long)]
        preset: Option<String>,
    },

    /// View or update host configuration
    Config {
        #[command(subcommand)]
        action: Option<ConfigAction>,
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

        /// Show itemized list of changes per file
        #[arg(short = 'i', long = "itemize-changes", alias = "itemize")]
        itemize: bool,

        /// Show detailed transfer statistics
        #[arg(long)]
        stats: bool,

        /// Suppress per-file progress (show only filenames)
        #[arg(long)]
        no_progress: bool,

        // Compat no-ops (hidden from --help)
        #[arg(short = 'a', long, hide = true)]
        archive: bool,
        #[arg(short = 'z', long, hide = true)]
        compress: bool,
        #[arg(short = 'P', hide = true)]
        partial_progress: bool,
        #[arg(long, hide = true)]
        progress: bool,
        #[arg(short = 'H', long = "human-readable", hide = true)]
        human_readable: bool,

        /// Source path (use host:path for remote)
        source: String,

        /// Destination path (use host:path for remote)
        dest: String,
    },

    /// Execute a command on a remote host
    Exec {
        /// Host NodeId, invite token, or known host alias
        target: String,
        /// Request read-only filesystem access
        #[arg(long)]
        read_only: bool,
        /// Request blocking outbound network access
        #[arg(long)]
        no_network: bool,
        /// Restrict filesystem access to these paths (can be repeated)
        #[arg(long = "scope", value_name = "PATH")]
        scopes: Vec<std::path::PathBuf>,
        /// Only allow these commands (can be repeated)
        #[arg(long = "allow-command", value_name = "CMD")]
        allow_commands: Vec<String>,
        /// Use a sandbox preset (monitor, audit, deploy)
        #[arg(long)]
        preset: Option<String>,
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
        /// Request read-only filesystem access
        #[arg(long)]
        read_only: bool,
        /// Request blocking outbound network access
        #[arg(long)]
        no_network: bool,
        /// Restrict filesystem access to these paths (can be repeated)
        #[arg(long = "scope", value_name = "PATH")]
        scopes: Vec<std::path::PathBuf>,
        /// Only allow these commands (can be repeated)
        #[arg(long = "allow-command", value_name = "CMD")]
        allow_commands: Vec<String>,
        /// Use a sandbox preset (monitor, audit, deploy)
        #[arg(long)]
        preset: Option<String>,
    },

    /// Remote administration (requires creator role)
    Admin {
        /// Target host (alias, NodeId, or invite token)
        target: String,
        #[command(subcommand)]
        action: AdminAction,
    },

    /// Print the creator invite for this host (useful for headless/Docker)
    CreatorInvite,

    /// Fleet management (host-side)
    Fleet {
        #[command(subcommand)]
        action: FleetAction,
    },

    /// Manage cron jobs on the daemon
    Cron {
        #[command(subcommand)]
        action: CronAction,
    },

    /// Read/write key-value data from the daemon datastore
    Kv {
        #[command(subcommand)]
        action: KvAction,
    },

    /// Query time-series data from the daemon datastore
    Ts {
        #[command(subcommand)]
        action: TsAction,
    },

    /// Start MCP server (Model Context Protocol) for AI agent integration
    Mcp,

    /// Print this node's identity (NodeId)
    Id,

    /// Manage the connection multiplexer agent
    Agent {
        #[command(subcommand)]
        action: Option<AgentAction>,

        /// Start agent in daemon mode (background)
        #[arg(long)]
        daemon: bool,

        /// Override config directory
        #[arg(long)]
        config: Option<PathBuf>,
    },

    /// Internal: apply sandbox and exec a shell (used by Linux PTY sandboxing)
    #[command(name = "__sandbox-shell", hide = true)]
    SandboxShell {
        /// JSON-serialized SandboxPolicy
        #[arg(long)]
        policy: String,
        /// Shell binary and args to exec
        #[arg(required = true, last = true)]
        shell_args: Vec<String>,
    },

    /// Internal: list processes without setuid (works inside macOS sandbox)
    #[command(name = "__ps", hide = true)]
    Ps,

    /// Catch-all: treat unknown subcommands as connect targets (e.g. "hop myhost")
    #[command(external_subcommand)]
    External(Vec<String>),
}

#[derive(Subcommand)]
pub enum AgentAction {
    /// Stop the running agent
    Stop,
    /// Check agent status
    Status,
}

#[derive(Subcommand)]
pub enum ConfigAction {
    /// Set a configuration value
    Set {
        /// Configuration key (session_timeout, max_sessions)
        key: String,
        /// New value
        value: String,
    },
}

#[derive(Subcommand)]
pub enum AdminAction {
    /// Create an invite on the remote host
    Invite {
        /// Unix username for the invited peer
        #[arg(long)]
        user: Option<String>,
        /// Create a creator invite (admin access)
        #[arg(long)]
        creator: bool,
        /// Restrict to read-only filesystem access
        #[arg(long)]
        read_only: bool,
        /// Block outbound network access
        #[arg(long)]
        no_network: bool,
        /// Restrict filesystem access to these paths (can be repeated)
        #[arg(long = "scope", value_name = "PATH")]
        scopes: Vec<std::path::PathBuf>,
        /// Only allow these commands (can be repeated)
        #[arg(long = "allow-command", value_name = "CMD")]
        allow_commands: Vec<String>,
        /// Use a sandbox preset (monitor, audit, deploy)
        #[arg(long)]
        preset: Option<String>,
    },
    /// List authorized peers on the remote host
    Peers,
    /// Remove a peer from the remote host
    RemovePeer {
        /// NodeId prefix of the peer to remove
        id: String,
    },
    /// Create a Unix user on the remote host
    CreateUser {
        /// Username to create
        username: String,
        /// Grant sudo access
        #[arg(long)]
        sudo: bool,
        /// macOS admin group membership
        #[arg(long)]
        admin: bool,
        /// Extra Unix groups (comma-separated)
        #[arg(long, value_delimiter = ',')]
        groups: Vec<String>,
        /// Override default shell
        #[arg(long)]
        shell: Option<String>,
        /// Also generate an invite for this user
        #[arg(long)]
        invite: bool,
    },
    /// Get status of the remote host
    Status,
    /// Create a fleet invite token (orchestrator)
    FleetInvite {
        /// Tags for fleet members using this invite
        #[arg(long, value_delimiter = ',')]
        tags: Vec<String>,
        /// Maximum number of uses (0 = unlimited)
        #[arg(long, default_value = "0")]
        max_uses: u32,
        /// Expiry in seconds (default: 24h)
        #[arg(long, default_value = "86400")]
        expiry: u64,
    },
    /// List fleet members (orchestrator)
    FleetList {
        /// Filter by tag
        #[arg(long)]
        tag: Option<String>,
    },
    /// Remove a fleet member (orchestrator)
    FleetRemove {
        /// NodeId prefix of the member to remove
        id: String,
    },
    /// Update tags on a fleet member (orchestrator)
    FleetTag {
        /// NodeId prefix of the member
        id: String,
        /// Tags to add
        #[arg(long, value_delimiter = ',')]
        add: Vec<String>,
        /// Tags to remove
        #[arg(long, value_delimiter = ',')]
        remove: Vec<String>,
    },
    /// Create a role definition (orchestrator)
    #[command(subcommand)]
    Role(RoleAction),
}

#[derive(Subcommand)]
pub enum RoleAction {
    /// Create a new role
    Create {
        /// Role name
        name: String,
        /// Host tags this role can access (comma-separated)
        #[arg(long, value_delimiter = ',')]
        tags: Vec<String>,
        /// Use shared Unix accounts (default: individual)
        #[arg(long)]
        shared: bool,
        /// Grant sudo access
        #[arg(long)]
        sudo: bool,
        /// macOS admin group membership
        #[arg(long)]
        admin: bool,
        /// Extra Unix groups (comma-separated)
        #[arg(long, value_delimiter = ',')]
        groups: Vec<String>,
        /// Override default shell
        #[arg(long)]
        shell: Option<String>,
    },
    /// List all roles
    List,
    /// Update an existing role
    Update {
        /// Role name to update
        name: String,
        /// Tags to add
        #[arg(long, value_delimiter = ',')]
        add_tags: Vec<String>,
        /// Tags to remove
        #[arg(long, value_delimiter = ',')]
        remove_tags: Vec<String>,
        /// Set sudo access
        #[arg(long)]
        sudo: Option<bool>,
        /// Set macOS admin
        #[arg(long)]
        admin: Option<bool>,
    },
    /// Delete a role
    Delete {
        /// Role name to delete
        name: String,
    },
}

#[derive(Subcommand)]
pub enum FleetAction {
    /// Show fleet registration status
    Status {
        /// Fleet name (required only if registered with multiple fleets)
        #[arg(long)]
        fleet: Option<String>,
    },
    /// List hosts in a fleet group
    List {
        /// Group/role to filter by
        group: Option<String>,
    },
    /// Execute a command on all hosts in a group
    Exec {
        /// Group/role name
        group: String,
        /// Command and arguments
        #[arg(required = true, last = true)]
        command: Vec<String>,
    },
    /// Add a known host to the daemon's fleet store
    Add {
        /// Host alias from known_hosts
        name: String,
        /// Tags for this fleet member (comma-separated)
        #[arg(long, value_delimiter = ',')]
        tags: Vec<String>,
    },
}

#[derive(Subcommand)]
pub enum CronAction {
    /// List all cron jobs
    List,
    /// Show full details of a cron job
    Get {
        /// Job ID
        id: String,
    },
    /// Create a new cron job
    Create {
        /// Job name
        #[arg(long)]
        name: String,
        /// Cron schedule expression (e.g. "0 */5 * * * *")
        #[arg(long)]
        schedule: String,
        /// Inline JavaScript source
        #[arg(long, conflicts_with = "file")]
        script: Option<String>,
        /// Read script from a file
        #[arg(long, conflicts_with = "script")]
        file: Option<std::path::PathBuf>,
        /// Fleet target tag (hosts matching this tag get injected as hop.targets)
        #[arg(long)]
        targets: Option<String>,
        /// Tags for this job (comma-separated)
        #[arg(long, value_delimiter = ',')]
        tags: Vec<String>,
    },
    /// Delete a cron job
    Delete {
        /// Job ID
        id: String,
    },
    /// Enable a cron job
    Enable {
        /// Job ID
        id: String,
    },
    /// Disable a cron job
    Disable {
        /// Job ID
        id: String,
    },
    /// Trigger immediate execution of a cron job
    Run {
        /// Job ID
        id: String,
    },
}

#[derive(Subcommand)]
pub enum KvAction {
    /// Get a value by key
    Get {
        /// Key to look up
        key: String,
    },
    /// List keys matching an optional prefix
    List {
        /// Key prefix to filter by
        prefix: Option<String>,
    },
    /// Set a key-value pair
    Set {
        /// Key
        key: String,
        /// Value
        value: String,
    },
}

#[derive(Subcommand)]
pub enum TsAction {
    /// Get the most recent data point for a metric
    Latest {
        /// Metric name
        metric: String,
    },
    /// Query time-series data for a metric
    Query {
        /// Metric name
        metric: String,
        /// Time range to query (e.g. "1h", "30m", "7d"). Default: 1h
        #[arg(long, default_value = "1h")]
        last: String,
    },
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
