use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FileInfo {
    pub enc_path: String,
    pub original_name: String,
    pub size_bytes: u64,
    pub encrypted_at: u64,
    /// New: which network does this file belong to. None = legacy/personal.
    #[serde(default)]
    pub network_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct NetworkInfo {
    pub id: String,
    pub name: String,
    pub region: Option<String>,
    /// Whether the daemon currently has the NK in its keychain (i.e. can
    /// decrypt files in this network).
    pub has_key: bool,
    pub key_version: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum IpcRequest {
    GetStatus,
    SyncKeys,
    AcceptInvite { target_user_id: String },
    RotatePnk,
    RotateHik,
    Login { user_id: String },
    StartOAuthFlow,
    GetNetworkDevices,
    GetConnections,
    GetFiles,
    OpenFile { enc_path: String },
    Logout,
    EncryptFile { file_path: String },

    // -------- Networks (Phase 4) --------
    /// List networks the signed-in user belongs to (with has_key state).
    ListNetworks,
    /// Encrypt a file into a specific network. The daemon must already
    /// have that network's NK in its keychain (else returns Error).
    EncryptFileToNetwork {
        file_path: String,
        network_id: String,
    },
    /// List files belonging to a single network.
    GetFilesInNetwork { network_id: String },
    /// Trigger the periodic network-sync loop manually (debug aid).
    SyncNetworks,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum IpcResponse {
    Success,
    Error(String),
    Status {
        hostname: String,
        is_active: bool,
        state: String,
        hik: String,
        email: Option<String>,
        name: Option<String>,
        image_url: Option<String>
    },
    NetworkDevices(Vec<String>),
    Connections(Vec<String>),
    Files(Vec<FileInfo>),
    OAuthUrl(String),
    EncryptedFile { path: String, manifest_entry: String },
    Networks(Vec<NetworkInfo>),
}
