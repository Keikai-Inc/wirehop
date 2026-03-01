use serde::{Deserialize, Serialize};

/// Messages sent from the host to the client.
#[derive(Debug, Serialize, Deserialize)]
pub enum HostMessage {
    /// Shell output data.
    Output(Vec<u8>),
    /// Shell exited with status code.
    Exit(i32),
    /// Terminal window size acknowledgement.
    WindowSizeAck,
    /// Auth challenge during invite flow.
    AuthChallenge(Vec<u8>),
    /// Auth result.
    AuthResult { authorized: bool },
}

/// Messages sent from the client to the host.
#[derive(Debug, Serialize, Deserialize)]
pub enum ClientMessage {
    /// Shell input data.
    Input(Vec<u8>),
    /// Terminal window size changed.
    WindowSize { cols: u16, rows: u16 },
    /// Auth response during invite flow.
    AuthResponse {
        secret_hash: Vec<u8>,
        client_public_key: Vec<u8>,
    },
    /// Request a shell session (after auth).
    RequestShell,
}
