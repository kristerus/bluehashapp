//! BlueHash desktop tray — Windows port of csi-tray from tray-macos.
//! Same UI shape, same IPC protocol, same Tauri 1.6 commands. The single
//! Windows-specific change is the IPC transport: instead of connecting
//! to a `/tmp/csi.sock` Unix domain socket, we open `\\.\pipe\csi` named
//! pipe via tokio.

#![cfg_attr(
    all(target_os = "windows", not(debug_assertions)),
    windows_subsystem = "windows"
)]

use anyhow::{Context, Result};
use csi_ipc::{IpcRequest, IpcResponse};
use tauri::{Manager, PhysicalPosition, SystemTray, SystemTrayEvent};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeClient};

/// Same pipe name the daemon publishes in `csid/src/main.rs`. Both ends
/// hard-code this — for v1 we don't try to make the pipe path
/// configurable per-user, since the daemon is shipped per-machine.
const PIPE_NAME: &str = r"\\.\pipe\csi";

#[tauri::command]
async fn send_ipc_command(req: IpcRequest) -> Result<IpcResponse, String> {
    send_ipc_command_inner(req).await.map_err(|e| e.to_string())
}

/// Open `%USERPROFILE%\Hashnet` in Explorer. Lives in the tray (not the
/// daemon) because it's a UX shortcut, not part of the agent protocol.
#[tauri::command]
fn open_hashnet_folder() -> Result<(), String> {
    let profile = std::env::var("USERPROFILE")
        .map_err(|_| "USERPROFILE not set".to_string())?;
    let path = std::path::Path::new(&profile).join("Hashnet");
    if !path.exists() {
        std::fs::create_dir_all(&path).map_err(|e| format!("create {path:?}: {e}"))?;
    }
    std::process::Command::new("explorer.exe")
        .arg(&path)
        .spawn()
        .map_err(|e| format!("explorer.exe {path:?}: {e}"))?;
    Ok(())
}

async fn send_ipc_command_inner(req: IpcRequest) -> Result<IpcResponse> {
    // Named pipes on Windows can be "busy" right after a previous client
    // disconnects — the server is recreating the pending instance. Retry
    // a few times with a short sleep before bailing.
    let mut client = open_pipe_with_retry().await.context("Failed to connect to csid daemon")?;

    let mut req_json = serde_json::to_string(&req)?;
    req_json.push('\n');

    client.write_all(req_json.as_bytes()).await?;

    let mut buf = vec![0u8; 4096];
    let n = client.read(&mut buf).await?;

    let resp_str = std::str::from_utf8(&buf[..n])?.trim();
    let resp: IpcResponse = serde_json::from_str(resp_str)?;
    Ok(resp)
}

async fn open_pipe_with_retry() -> Result<NamedPipeClient> {
    use std::time::Duration;
    let mut last_err: Option<anyhow::Error> = None;
    for attempt in 0..10 {
        match ClientOptions::new().open(PIPE_NAME) {
            Ok(client) => return Ok(client),
            Err(e) => {
                // ERROR_PIPE_BUSY (231) or ERROR_FILE_NOT_FOUND (2) → retry
                last_err = Some(anyhow::anyhow!("open {PIPE_NAME} attempt {attempt}: {e}"));
                tokio::time::sleep(Duration::from_millis(150)).await;
            }
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow::anyhow!("named pipe unreachable")))
}

/// On launch, make sure `csid.exe` (the daemon) is already running. If
/// not, spawn it from the same directory as our own exe — that's where
/// the installer drops it via Tauri's `externalBin` config. Detached so
/// it survives when the tray exits; the user can re-open the tray later
/// without restarting the daemon.
fn ensure_daemon_running() {
    // Cheap, blocking probe — if the pipe is reachable, daemon is up.
    if std::fs::metadata(r"\\.\pipe\csi").is_ok() {
        eprintln!("Daemon already running (pipe exists).");
        return;
    }

    let exe_path = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("current_exe failed: {e}");
            return;
        }
    };
    let exe_dir = match exe_path.parent() {
        Some(d) => d.to_path_buf(),
        None => return,
    };
    let csid_path = exe_dir.join("csid.exe");
    if !csid_path.exists() {
        eprintln!("csid.exe not found next to tray at {csid_path:?}");
        return;
    }

    eprintln!("Spawning daemon: {csid_path:?}");
    // CREATE_NO_WINDOW (0x08000000) keeps the daemon from flashing a
    // console window when the user double-clicks the tray.
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let _ = std::process::Command::new(&csid_path)
        .creation_flags(CREATE_NO_WINDOW)
        .spawn();
}

fn main() {
    // Ensure the daemon is up before the tray boots its IPC probe —
    // gives the named pipe time to come alive in the 10s window.
    ensure_daemon_running();

    let system_tray = SystemTray::new();

    tauri::Builder::default()
        .setup(|_app| {
            tauri::async_runtime::spawn(async move {
                // Same retry/probe pattern as the macOS version — the
                // tray comes up before the service is necessarily ready
                // to accept on the pipe, so poll for ~10s before giving
                // up the startup check.
                for attempt in 1..=20 {
                    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
                    match send_ipc_command_inner(IpcRequest::GetStatus).await {
                        Ok(resp) => {
                            eprintln!("Startup IPC connected (attempt {}): {:?}", attempt, resp);
                            break;
                        }
                        Err(e) => {
                            if attempt == 20 {
                                eprintln!("Startup IPC failed after 20 attempts: {}", e);
                            }
                        }
                    }
                }
            });
            Ok(())
        })
        .system_tray(system_tray)
        .on_system_tray_event(|app, event| match event {
            SystemTrayEvent::LeftClick { position, .. } => {
                // Anchor the popover at the right edge of the monitor
                // containing the tray icon, vertically centred. Works
                // on any laptop resolution because we read the monitor
                // bounds at click time. The user can still drag the
                // window to a different spot — next open re-anchors.
                if let Some(window) = app.get_window("main") {
                    if window.is_visible().unwrap_or(false) {
                        let _ = window.hide();
                        return;
                    }

                    // Pick the monitor that contains the tray click. On
                    // multi-monitor setups this puts the popover on the
                    // same screen the user is interacting with.
                    let monitors = window.available_monitors().unwrap_or_default();
                    let tray_x = position.x as i32;
                    let tray_y = position.y as i32;
                    let target = monitors.iter().find(|m| {
                        let mp = m.position();
                        let ms = m.size();
                        tray_x >= mp.x
                            && tray_x < mp.x + ms.width as i32
                            && tray_y >= mp.y
                            && tray_y < mp.y + ms.height as i32
                    }).or_else(|| monitors.first());

                    if let (Some(monitor), Ok(window_size)) = (target, window.outer_size()) {
                        let mp = monitor.position();
                        let ms = monitor.size();
                        let scale = monitor.scale_factor();
                        let margin_right = (16.0 * scale) as i32;
                        let x = mp.x + ms.width as i32 - window_size.width as i32 - margin_right;
                        let y = mp.y + ((ms.height as i32 - window_size.height as i32) / 2);
                        let _ = window.set_position(tauri::Position::Physical(
                            PhysicalPosition { x, y },
                        ));
                    }
                    let _ = window.show();
                    let _ = window.set_focus();
                }
            }
            SystemTrayEvent::RightClick { .. } | SystemTrayEvent::DoubleClick { .. } => {
                // No right-click menu in v1 — matches macOS behaviour.
            }
            _ => {}
        })
        // NOTE: auto-hide-on-blur intentionally disabled. The popover
        // was closing the instant the user clicked a button that
        // shifted focus (e.g. "Log in" opening the browser), making
        // the UI feel broken. To re-enable once the IPC plumbing is
        // proven, copy the focus-loss handler from the macOS version
        // and gate it behind a "Hide on blur" preference.
        .on_window_event(|_event| {
            // intentionally empty — popover stays until user hides it
        })
        .invoke_handler(tauri::generate_handler![
            send_ipc_command,
            open_hashnet_folder
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
