mod cli;

use anyhow::Result;
use clap::Parser;
use cli::{Cli, Command, PeersAction};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize tracing
    let filter = match cli.verbose {
        0 => "hop=info",
        1 => "hop=debug",
        _ => "hop=trace",
    };
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new(filter))
        .init();

    match cli.command {
        Command::Host => {
            tracing::info!("Starting host...");
            todo!("Implement host command")
        }
        Command::Invite => {
            tracing::info!("Generating invite...");
            todo!("Implement invite command")
        }
        Command::Connect { target } => {
            tracing::info!("Connecting to {target}...");
            todo!("Implement connect command")
        }
        Command::Peers { action } => match action {
            None => {
                todo!("Implement peers list")
            }
            Some(PeersAction::Remove { id }) => {
                tracing::info!("Removing peer {id}...");
                todo!("Implement peer removal")
            }
        },
        Command::Id => {
            todo!("Implement id command")
        }
    }
}
