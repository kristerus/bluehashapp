//! BlueHash client-side identity daemon — Windows port of `csid` from
//! tray-macos. Same IPC protocol, same Supabase broker, same X25519 +
//! ChaCha20-Poly1305 crypto. The two material differences:
//!
//!   * IPC transport: **Windows named pipe** (`\\.\pipe\csi`) instead of
//!     a Unix domain socket. Equivalent semantics — local-machine only,
//!     defaults to creator + LocalSystem access.
//!   * Lifecycle: the binary can run as a **Windows Service** (registered
//!     with SCM, auto-starts on boot) instead of a launchd LaunchDaemon.
//!     See `service.rs` for the install / uninstall / dispatch logic.

#![cfg_attr(
    all(target_os = "windows", not(debug_assertions)),
    windows_subsystem = "windows"
)]

use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as Base64, Engine};
use std::collections::{HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use tokio::sync::RwLock;
use tracing::{error, info};
use x25519_dalek::PublicKey as X25519PublicKey;

use csi_core::broker::SupabaseClient;
use csi_core::crypto::{HardwareIdentity, PersonalNetworkKey};
use csi_ipc::{IpcRequest, IpcResponse};

mod logging;
mod service;
mod watcher;

/// Named-pipe path. `\\.\pipe\` is the standard Windows local-machine
/// namespace. The pipe is created with default DACLs which grant access
/// to the creator (current user / LocalSystem when run as a service)
/// and the Administrators group.
const PIPE_NAME: &str = r"\\.\pipe\csi";

/// Global stop flag, flipped by the Windows Service control handler
/// (`service.rs::service_runner`) when SCM tells us to shut down.
static STOP: AtomicBool = AtomicBool::new(false);

pub fn request_stop() {
    STOP.store(true, Ordering::SeqCst);
}

pub fn should_stop() -> bool {
    STOP.load(Ordering::SeqCst)
}

// ---- Manifest -----------------------------------------------------------
// Tracks which encrypted files came from which plaintext originals so the
// tray can show a human-readable file list and "open" the right file.
// On Windows we drop the `inode` field that the macOS version stored —
// NTFS file indices aren't 1:1 with the Unix inode semantics and the
// field was never read by any consumer anyway.

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Default)]
pub struct ManifestEntry {
    pub original_name: String,
    pub original_path: String,
    pub sha256_original: String,
    pub encrypted_at: u64,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Default)]
pub struct Manifest {
    pub version: u32,
    pub files: std::collections::HashMap<String, ManifestEntry>,
}

fn get_hashnet_dir() -> Result<std::path::PathBuf> {
    // `dirs::home_dir()` returns %USERPROFILE% on Windows. When running
    // under LocalSystem it points at `C:\Windows\system32\config\
    // systemprofile`, which is appropriate for the service.
    let home = dirs::home_dir().ok_or_else(|| anyhow::anyhow!("Could not find home directory"))?;
    let hashnet_dir = home.join("Hashnet");
    std::fs::create_dir_all(&hashnet_dir)?;
    std::fs::create_dir_all(hashnet_dir.join("encrypted"))?;
    std::fs::create_dir_all(hashnet_dir.join(".hashnet"))?;
    let manifest_path = hashnet_dir.join(".hashnet/manifest.json");
    if !manifest_path.exists() {
        let blank = Manifest { version: 2, files: std::collections::HashMap::new() };
        std::fs::write(&manifest_path, serde_json::to_string_pretty(&blank)?)?;
    }
    Ok(hashnet_dir)
}

fn load_manifest(hashnet_dir: &std::path::Path) -> Manifest {
    let path = hashnet_dir.join(".hashnet/manifest.json");
    std::fs::read_to_string(&path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_else(|| Manifest { version: 2, files: std::collections::HashMap::new() })
}

pub struct DaemonState {
    pub identity: HardwareIdentity,
    pub pnk: Option<PersonalNetworkKey>,
    pub broker: Option<SupabaseClient>,
    pub logged_in_user: Option<String>,
    pub user_email: Option<String>,
    pub user_image: Option<String>,
    pub oauth_listening: bool,
    pub device_id: Option<uuid::Uuid>,
    pub key_version: u32,
    pub manifest: Manifest,
    pub in_flight: HashSet<std::path::PathBuf>,
    pub pending_encrypt: VecDeque<std::path::PathBuf>,
}

// ---- OS version (replaces `sw_vers -productVersion`) --------------------
//
// On Windows we shell out to `cmd /c ver` which returns
// "Microsoft Windows [Version 10.0.22631.4317]". The version number is
// extracted out so `register_device` records something useful.

fn detect_os_version() -> String {
    let output = std::process::Command::new("cmd").args(["/c", "ver"]).output();
    match output {
        Ok(o) => {
            let raw = String::from_utf8_lossy(&o.stdout);
            let version = raw
                .trim()
                .split_once("[Version ")
                .and_then(|(_, rest)| rest.strip_suffix(']'))
                .unwrap_or("");
            if version.is_empty() {
                "Windows".to_string()
            } else {
                format!("Windows {}", version)
            }
        }
        Err(_) => "Windows".to_string(),
    }
}

// ---- Entry point --------------------------------------------------------

fn main() -> Result<()> {
    dotenvy::dotenv().ok();

    // Subcommand handling, mirrors `hashednetworks-agent install/uninstall`
    // from hashednetworks-cli. We do this BEFORE the SCM dispatch so the
    // install command works when run from a normal console.
    let mut args = std::env::args().skip(1);
    if let Some(cmd) = args.next() {
        match cmd.as_str() {
            "install" => return service::install(),
            "uninstall" => return service::uninstall(),
            "version" | "--version" => {
                println!("csid {}", env!("CARGO_PKG_VERSION"));
                return Ok(());
            }
            _ => {} // fall through to normal startup
        }
    }

    // Try to run under SCM. If we're not under SCM, fall through to
    // console mode — useful for `cargo run` during development.
    match service::try_dispatch()? {
        true => Ok(()),
        false => {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(run_daemon())
        }
    }
}

/// The daemon's main async loop. Called by both the console-mode entry
/// in `main()` and the service-mode entry in `service::service_runner`.
pub async fn run_daemon() -> Result<()> {
    let _log_guard = match logging::init_logging() {
        Ok(g) => g,
        Err(e) => {
            eprintln!("Failed to initialize logging: {}", e);
            return Err(e);
        }
    };
    info!("Starting csid daemon ({})", detect_os_version());

    let hashnet_dir = get_hashnet_dir()?;
    let manifest = load_manifest(&hashnet_dir);

    let identity = HardwareIdentity::load_or_generate()
        .map_err(|e| anyhow::anyhow!("Failed to load hardware identity: {}", e))?;

    let broker = match SupabaseClient::new() {
        Ok(client) => Some(client),
        Err(e) => {
            error!("Warning: Failed to initialize Supabase client: {}", e);
            None
        }
    };

    let state = Arc::new(RwLock::new(DaemonState {
        identity,
        pnk: None,
        broker,
        logged_in_user: None,
        user_email: None,
        user_image: None,
        oauth_listening: false,
        device_id: None,
        key_version: 1,
        manifest,
        in_flight: HashSet::new(),
        pending_encrypt: VecDeque::new(),
    }));

    let _watcher = watcher::start(hashnet_dir.join("encrypted"), state.clone())
        .map_err(|e| anyhow::anyhow!("Failed to start file watcher: {}", e))?;

    // Heartbeat: refresh devices.last_seen_at every 60s while logged in.
    let state_heartbeat = state.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;
            if should_stop() {
                break;
            }
            let (broker, hik, logged_in) = {
                let s = state_heartbeat.read().await;
                (s.broker.clone(), s.identity.export_public_hik(), s.logged_in_user.is_some())
            };
            if logged_in {
                if let Some(client) = broker {
                    if let Err(e) = client.update_last_seen(hik).await {
                        error!("Heartbeat error updating last_seen_at: {}", e);
                    }
                }
            }
        }
    });

    // PNK auto-rotation every 24h.
    let state_rotation = state.clone();
    tokio::spawn(async move {
        const PNK_ROTATION_INTERVAL_SECS: u64 = 86_400;
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(PNK_ROTATION_INTERVAL_SECS)).await;
            if should_stop() {
                break;
            }
            let (broker, user_id, hik_secret, current_version) = {
                let s = state_rotation.read().await;
                (
                    s.broker.clone(),
                    s.logged_in_user.clone(),
                    s.identity.secret().clone(),
                    s.key_version,
                )
            };
            if let (Some(broker), Some(uid)) = (broker, user_id) {
                let new_pnk = PersonalNetworkKey::new_random();
                let new_version = current_version.saturating_add(1);
                if let Ok(devices) = broker.get_devices_for_key_distribution(&uid).await {
                    let mut ok = true;
                    for device in &devices {
                        if let Ok(target_pub) = parse_public_hik(&device.public_hik) {
                            if let Ok(wrapped) = new_pnk.wrap(&target_pub, &hik_secret) {
                                let b64 = Base64.encode(&wrapped);
                                if let Err(e) = broker
                                    .push_wrapped_pnk(
                                        device.id,
                                        uid.parse().unwrap_or_default(),
                                        b64,
                                        new_version,
                                    )
                                    .await
                                {
                                    error!("auto-rotation push error: {}", e);
                                    ok = false;
                                }
                            }
                        }
                    }
                    if ok {
                        let mut s = state_rotation.write().await;
                        s.pnk = Some(new_pnk);
                        s.key_version = new_version;
                    }
                }
            }
        }
    });

    // Named-pipe server loop. Windows requires us to construct a new
    // server instance for each incoming connection — the pattern is:
    // create a pending server, await connect(), then immediately create
    // the next pending server while we hand the connected one to a task.
    let mut server = ServerOptions::new()
        .first_pipe_instance(true)
        .create(PIPE_NAME)
        .with_context(|| format!("create named pipe {PIPE_NAME}"))?;

    info!("listening on {}", PIPE_NAME);

    loop {
        if should_stop() {
            info!("stop flag set, exiting accept loop");
            break;
        }

        server.connect().await.context("named pipe connect")?;
        let connected = server;

        // Create the next pending server instance before handling this
        // connection, so a fast subsequent client doesn't get refused.
        server = ServerOptions::new()
            .first_pipe_instance(false)
            .create(PIPE_NAME)
            .with_context(|| format!("create next named pipe {PIPE_NAME}"))?;

        let state_clone = state.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_client(connected, state_clone).await {
                error!("Client error: {}", e);
            }
        });
    }

    Ok(())
}

async fn handle_client(mut stream: NamedPipeServer, state: Arc<RwLock<DaemonState>>) -> Result<()> {
    let mut buf = vec![0u8; 4096];

    loop {
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            break; // Pipe closed by client (Disconnect).
        }

        let req_str = std::str::from_utf8(&buf[..n])?;

        for line in req_str.lines() {
            if line.trim().is_empty() {
                continue;
            }

            let response = if let Ok(req) = serde_json::from_str::<IpcRequest>(line) {
                process_request(req, &state).await
            } else {
                IpcResponse::Error("Failed to parse request JSON".into())
            };

            let mut resp_json = serde_json::to_string(&response)?;
            resp_json.push('\n');
            stream.write_all(resp_json.as_bytes()).await?;
        }
    }

    Ok(())
}

fn parse_public_hik(b64: &str) -> anyhow::Result<X25519PublicKey> {
    let bytes = Base64.decode(b64)?;
    if bytes.len() != 32 {
        anyhow::bail!("invalid HIK length: {}", bytes.len());
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(X25519PublicKey::from(arr))
}

async fn drain_pending(state: &Arc<RwLock<DaemonState>>) {
    let pending: Vec<std::path::PathBuf> = {
        let mut s = state.write().await;
        s.pending_encrypt.drain(..).collect()
    };
    for path in pending {
        watcher::encrypt_file_from_watcher_pub(path, state).await;
    }
}

async fn process_request(req: IpcRequest, state: &Arc<RwLock<DaemonState>>) -> IpcResponse {
    match req {
        IpcRequest::GetStatus => {
            let s = state.read().await;
            let status = if s.pnk.is_some() {
                "Ready (PNK loaded)"
            } else {
                "Waiting for PNK"
            };

            let hostname = gethostname::gethostname().to_string_lossy().to_string();
            let is_active = s.logged_in_user.is_some();

            IpcResponse::Status {
                hostname,
                is_active,
                state: status.to_string(),
                hik: s.identity.export_public_hik(),
                email: s.user_email.clone(),
                image_url: s.user_image.clone(),
            }
        }
        IpcRequest::StartOAuthFlow => {
            // === New flow: desktop-session pairing via Supabase ===
            // 1. Daemon creates a pending session row.
            // 2. Daemon opens https://bluehashsecurity.com/login?redirect_url=/desktop-link?session=<id>.
            // 3. After Clerk auth, /desktop-link claims the row with the user's info.
            // 4. Daemon polls the row, applies the user info, registers the device,
            //    and syncs the PNK. Same post-login machinery as the old OAuth path.

            {
                let mut s = state.write().await;
                if s.oauth_listening {
                    return IpcResponse::Error("Login already in progress. Check your browser.".into());
                }
                s.oauth_listening = true;
            }

            // We need the broker for both session creation and the poll loop.
            let broker = {
                let s = state.read().await;
                s.broker.clone()
            };
            let Some(broker) = broker else {
                let mut s = state.write().await;
                s.oauth_listening = false;
                return IpcResponse::Error("Supabase broker not configured (missing env vars)".into());
            };

            // Create the pending session row.
            let session_id = match broker.create_desktop_session().await {
                Ok(id) => id,
                Err(e) => {
                    let mut s = state.write().await;
                    s.oauth_listening = false;
                    return IpcResponse::Error(format!("Could not create desktop session: {e}"));
                }
            };
            info!("Created desktop session {session_id}");

            // Build the URL. We URL-encode the redirect_url so the inner
            // `?session=...` survives the outer query string.
            let inner = format!("/desktop-link?session={session_id}");
            let url = format!(
                "https://bluehashsecurity.com/login?redirect_url={}",
                urlencoding::encode(&inner)
            );

            if let Err(e) = open::that(&url) {
                let mut s = state.write().await;
                s.oauth_listening = false;
                return IpcResponse::Error(format!("Failed to open browser: {e}"));
            }

            // Spawn the polling task. ~5 min total (150 × 2s).
            let state_clone = state.clone();
            tokio::spawn(async move {
                const POLL_INTERVAL_SECS: u64 = 2;
                const MAX_POLLS: u32 = 150;
                let mut linked = None;

                for attempt in 1..=MAX_POLLS {
                    tokio::time::sleep(std::time::Duration::from_secs(POLL_INTERVAL_SECS)).await;
                    match broker.poll_desktop_session(session_id).await {
                        Ok(Some(info)) => {
                            info!("Desktop session linked on attempt {attempt}: user={}", info.user_id);
                            linked = Some(info);
                            break;
                        }
                        Ok(None) => { /* still pending */ }
                        Err(e) => {
                            error!("Poll error on attempt {attempt}: {e}");
                        }
                    }
                }

                let Some(linked) = linked else {
                    error!("Desktop session {session_id} timed out");
                    let mut s = state_clone.write().await;
                    s.oauth_listening = false;
                    return;
                };

                // Best-effort: mark session as consumed so it can't be replayed.
                if let Err(e) = broker.consume_desktop_session(session_id).await {
                    error!("consume_desktop_session: {e}");
                }

                // === Same post-login machinery as before ===
                {
                    let mut s = state_clone.write().await;
                    s.oauth_listening = false;
                    s.logged_in_user = Some(linked.user_id.clone());
                    s.user_email = linked.email.clone();
                    s.user_image = linked.image_url.clone();
                }

                let hostname = gethostname::gethostname().to_string_lossy().to_string();
                let hik = { let s = state_clone.read().await; s.identity.export_public_hik() };
                let os_version = detect_os_version();

                match broker.register_device(linked.user_id.clone(), hostname, hik, os_version).await {
                    Ok(device_id) => {
                        let pnk_result = if let Ok(key_bytes) = csi_core::keychain::load_pnk() {
                            info!("Loaded PNK from Credential Manager");
                            Ok(PersonalNetworkKey(key_bytes))
                        } else {
                            match broker.fetch_wrapped_pnks_for_device(device_id).await {
                                Ok(wrapped_pnks) if !wrapped_pnks.is_empty() => {
                                    let latest = &wrapped_pnks[0];
                                    let hik_id = { let s = state_clone.read().await; s.identity.clone() };
                                    PersonalNetworkKey::unwrap(
                                        Base64.decode(&latest.wrapped_pnk).unwrap_or_default().as_ref(),
                                        hik_id.public_key(),
                                        hik_id.secret(),
                                    ).map(|pnk| {
                                        let _ = csi_core::keychain::store_pnk(&pnk.0);
                                        info!("PNK synced from broker (version {})", latest.version);
                                        pnk
                                    })
                                }
                                _ => {
                                    info!("No PNK in Credential Manager or broker, generating new");
                                    let new_pnk = PersonalNetworkKey::new_random();
                                    let _ = csi_core::keychain::store_pnk(&new_pnk.0);
                                    let hik_secret = { let s = state_clone.read().await; s.identity.secret().clone() };
                                    if let Ok(devices) = broker.get_devices_for_key_distribution(&linked.user_id).await {
                                        for device in &devices {
                                            if let Ok(target_pub) = parse_public_hik(&device.public_hik) {
                                                if let Ok(wrapped) = new_pnk.wrap(&target_pub, &hik_secret) {
                                                    let b64 = Base64.encode(&wrapped);
                                                    let _ = broker.push_wrapped_pnk(device.id, linked.user_id.parse().unwrap_or_default(), b64, 1).await;
                                                }
                                            }
                                        }
                                    }
                                    Ok(new_pnk)
                                }
                            }
                        };

                        if let Ok(pnk) = pnk_result {
                            let mut s = state_clone.write().await;
                            s.pnk = Some(pnk);
                            s.device_id = Some(device_id);
                        }
                    }
                    Err(e) => {
                        error!("Failed to register device: {}", e);
                    }
                }

                drain_pending(&state_clone).await;
            });

            IpcResponse::Success
        }
        IpcRequest::SyncKeys => {
            let (broker, device_id) = {
                let s = state.read().await;
                (s.broker.clone(), s.device_id)
            };
            if broker.is_none() || device_id.is_none() {
                return IpcResponse::Error("Not ready for sync".into());
            }
            let broker = broker.unwrap();
            let device_id = device_id.unwrap();

            match broker.fetch_wrapped_pnks_for_device(device_id).await {
                Ok(wrapped_pnks) => {
                    if wrapped_pnks.is_empty() {
                        return IpcResponse::Error("No keys available for sync".into());
                    }
                    let latest = &wrapped_pnks[0];
                    let hik = { let s = state.read().await; s.identity.clone() };
                    match PersonalNetworkKey::unwrap(
                        Base64.decode(&latest.wrapped_pnk).unwrap_or_default().as_ref(),
                        hik.public_key(),
                        hik.secret(),
                    ) {
                        Ok(synced_key) => {
                            let mut s = state.write().await;
                            s.key_version = latest.version;
                            s.pnk = Some(synced_key);
                            IpcResponse::Success
                        }
                        Err(e) => {
                            error!("Failed to unwrap key: {}", e);
                            IpcResponse::Error("Key unwrap failed".into())
                        }
                    }
                }
                Err(e) => {
                    error!("Failed to fetch wrapped PNKs: {}", e);
                    IpcResponse::Error("Failed to fetch keys".into())
                }
            }
        }
        IpcRequest::AcceptInvite { target_user_id: _ } => {
            let s = state.read().await;
            if s.broker.is_none() { return IpcResponse::Error("Broker not initialized".into()); }
            if s.pnk.is_none() { return IpcResponse::Error("No PNK available to share".into()); }
            IpcResponse::Success
        }
        IpcRequest::RotatePnk => {
            let (broker, user_id, hik_secret, current_version) = {
                let s = state.read().await;
                (s.broker.clone(), s.logged_in_user.clone(), s.identity.secret().clone(), s.key_version)
            };
            if let (Some(broker), Some(uid)) = (broker, user_id) {
                let new_pnk = PersonalNetworkKey::new_random();
                let new_version = current_version.saturating_add(1);
                match broker.get_devices_for_key_distribution(&uid).await {
                    Ok(devices) => {
                        let mut push_errors = 0usize;
                        for device in &devices {
                            if let Ok(target_pub) = parse_public_hik(&device.public_hik) {
                                if let Ok(wrapped) = new_pnk.wrap(&target_pub, &hik_secret) {
                                    let b64 = Base64.encode(&wrapped);
                                    if let Err(e) = broker.push_wrapped_pnk(
                                        device.id, uid.parse().unwrap_or_default(), b64, new_version,
                                    ).await {
                                        error!("push_wrapped_pnk error for {}: {}", device.id, e);
                                        push_errors += 1;
                                    }
                                }
                            }
                        }
                        if push_errors > 0 {
                            return IpcResponse::Error(format!("PNK rotated but {} device(s) failed", push_errors));
                        }
                        let mut s = state.write().await;
                        s.pnk = Some(new_pnk);
                        s.key_version = new_version;
                        IpcResponse::Success
                    }
                    Err(e) => {
                        error!("Failed to fetch devices for PNK rotation: {}", e);
                        IpcResponse::Error("Failed to fetch devices for rotation".into())
                    }
                }
            } else { IpcResponse::Error("Not logged in".into()) }
        }
        IpcRequest::RotateHik => {
            let (broker, user_id) = {
                let s = state.read().await;
                (s.broker.clone(), s.logged_in_user.clone())
            };
            if let (Some(broker), Some(uid)) = (broker, user_id) {
                let (_new_hik_pub, new_hik_secret, hik_version) = {
                    let mut s = state.write().await;
                    match s.identity.rotate() {
                        Ok(_old_pub) => {
                            let pub_key = *s.identity.public_key();
                            let sec_key = s.identity.secret().clone();
                            let ver = s.identity.version;
                            (pub_key, sec_key, ver)
                        }
                        Err(e) => {
                            error!("HIK rotation failed: {}", e);
                            return IpcResponse::Error(format!("HIK rotation failed: {}", e));
                        }
                    }
                };
                let new_hik_b64 = {
                    let s = state.read().await;
                    s.identity.export_public_hik()
                };
                if let Some(device_id) = { state.read().await.device_id } {
                    if let Err(e) = broker.update_device_hik(device_id, &new_hik_b64, hik_version).await {
                        error!("Failed to update HIK in DB: {}", e);
                        return IpcResponse::Error("DB update for HIK failed".into());
                    }
                }
                let pnk_version = state.read().await.key_version;
                let pnk_bytes = { let s = state.read().await; s.pnk.as_ref().map(|p| p.0) };
                if let Some(bytes) = pnk_bytes {
                    let current_pnk = PersonalNetworkKey(bytes);
                    if let Ok(devices) = broker.get_devices_for_key_distribution(&uid).await {
                        for device in &devices {
                            if let Ok(target_pub) = parse_public_hik(&device.public_hik) {
                                if let Ok(wrapped) = current_pnk.wrap(&target_pub, &new_hik_secret) {
                                    let b64 = Base64.encode(&wrapped);
                                    let _ = broker.push_wrapped_pnk(
                                        device.id, uid.parse().unwrap_or_default(), b64, pnk_version,
                                    ).await;
                                }
                            }
                        }
                    }
                }
                IpcResponse::Success
            } else { IpcResponse::Error("Not logged in".into()) }
        }
        IpcRequest::Login { user_id } => {
            let (broker, _key_version) = {
                let mut s = state.write().await;
                s.logged_in_user = Some(user_id.clone());
                (s.broker.clone(), s.key_version)
            };
            if let Some(broker) = broker {
                let hostname = gethostname::gethostname().to_string_lossy().to_string();
                let hik = { let s = state.read().await; s.identity.export_public_hik() };
                let os_version = detect_os_version();
                match broker.register_device(user_id.clone(), hostname, hik, os_version).await {
                    Ok(device_id) => {
                        let pnk_result = if let Ok(key_bytes) = csi_core::keychain::load_pnk() {
                            Ok(PersonalNetworkKey(key_bytes))
                        } else {
                            match broker.fetch_wrapped_pnks_for_device(device_id).await {
                                Ok(wrapped_pnks) if !wrapped_pnks.is_empty() => {
                                    let latest = &wrapped_pnks[0];
                                    let hik_id = { let s = state.read().await; s.identity.clone() };
                                    PersonalNetworkKey::unwrap(
                                        Base64.decode(&latest.wrapped_pnk).unwrap_or_default().as_ref(),
                                        hik_id.public_key(),
                                        hik_id.secret(),
                                    )
                                    .map(|pnk| {
                                        let _ = csi_core::keychain::store_pnk(&pnk.0);
                                        pnk
                                    })
                                }
                                _ => {
                                    let new_pnk = PersonalNetworkKey::new_random();
                                    let _ = csi_core::keychain::store_pnk(&new_pnk.0);
                                    let hik_secret = { let s = state.read().await; s.identity.secret().clone() };
                                    if let Ok(devices) = broker.get_devices_for_key_distribution(&user_id).await {
                                        for device in &devices {
                                            if let Ok(target_pub) = parse_public_hik(&device.public_hik) {
                                                if let Ok(wrapped) = new_pnk.wrap(&target_pub, &hik_secret) {
                                                    let b64 = Base64.encode(&wrapped);
                                                    let _ = broker.push_wrapped_pnk(device.id, user_id.parse().unwrap_or_default(), b64, 1).await;
                                                }
                                            }
                                        }
                                    }
                                    Ok(new_pnk)
                                }
                            }
                        };
                        if let Ok(pnk) = pnk_result {
                            let mut s = state.write().await;
                            s.pnk = Some(pnk);
                            s.device_id = Some(device_id);
                        }
                    }
                    Err(e) => { error!("Failed to register device: {}", e); }
                }
            }
            drain_pending(state).await;
            IpcResponse::Success
        }
        IpcRequest::GetNetworkDevices => {
            let s = state.read().await;
            if let (Some(broker), Some(uid)) = (&s.broker, s.logged_in_user.clone()) {
                if let Ok(devs) = broker.get_active_devices(uid).await {
                    return IpcResponse::NetworkDevices(devs);
                }
            }
            IpcResponse::Error("Failed to fetch devices".into())
        }
        IpcRequest::GetConnections => {
            let s = state.read().await;
            if let (Some(broker), Some(uid)) = (&s.broker, s.logged_in_user.clone()) {
                if let Ok(conns) = broker.get_connections(uid).await {
                    return IpcResponse::Connections(conns);
                }
            }
            IpcResponse::Error("Failed to fetch connections".into())
        }
        IpcRequest::Logout => {
            let mut s = state.write().await;
            if let Some(broker) = &s.broker {
                let hik = s.identity.export_public_hik();
                let _ = broker.set_device_status(hik, false).await;
            }
            s.logged_in_user = None;
            s.user_email = None;
            s.user_image = None;
            s.pnk = None;
            s.device_id = None;
            IpcResponse::Success
        }
        IpcRequest::GetFiles => {
            let s = state.read().await;
            let files: Vec<csi_ipc::FileInfo> = s.manifest.files.iter().map(|(enc_path, entry)| {
                csi_ipc::FileInfo {
                    enc_path: enc_path.clone(),
                    original_name: entry.original_name.clone(),
                    size_bytes: entry.size_bytes,
                    encrypted_at: entry.encrypted_at,
                }
            }).collect();
            IpcResponse::Files(files)
        }
        IpcRequest::OpenFile { enc_path } => {
            let pnk_bytes = { let s = state.read().await; s.pnk.as_ref().map(|p| p.0) };
            let Some(key_bytes) = pnk_bytes else {
                return IpcResponse::Error("Not logged in — cannot decrypt".into());
            };
            let enc = std::path::PathBuf::from(&enc_path);
            let original_name = {
                let s = state.read().await;
                s.manifest.files.get(&enc_path)
                    .map(|e| e.original_name.clone())
                    .unwrap_or_else(|| enc.file_stem().unwrap_or_default().to_string_lossy().to_string())
            };
            match watcher::do_decrypt(&enc, &key_bytes, &original_name).await {
                Ok(tmp_path) => {
                    if let Err(e) = open::that(&tmp_path) {
                        error!("Failed to open decrypted file: {}", e);
                        return IpcResponse::Error(format!("Decrypted but could not open: {}", e));
                    }
                    IpcResponse::Success
                }
                Err(e) => {
                    error!("Decryption failed for {:?}: {}", enc_path, e);
                    IpcResponse::Error(format!("Decryption failed: {}", e))
                }
            }
        }
        IpcRequest::EncryptFile { file_path } => {
            let path = std::path::PathBuf::from(&file_path);
            watcher::encrypt_file_from_watcher_pub(path, state).await;
            IpcResponse::Success
        }
    }
}
