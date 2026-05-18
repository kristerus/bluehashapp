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

fn main() {
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
            SystemTrayEvent::LeftClick { position, size, .. } => {
                // Windows tray sits at the bottom-right by default. Pop
                // the window above-and-centred on the tray icon. The
                // macOS version anchored under the menu bar at the top;
                // the +height offset here flips that direction.
                if let Some(window) = app.get_window("main") {
                    if window.is_visible().unwrap_or(false) {
                        let _ = window.hide();
                    } else {
                        if let Ok(window_size) = window.outer_size() {
                            let x = position.x as i32 - (window_size.width as i32 / 2);
                            // Anchor ABOVE the tray on Windows (negative y offset).
                            let y = position.y as i32 - window_size.height as i32 - size.height as i32;
                            let _ = window.set_position(tauri::Position::Physical(
                                PhysicalPosition { x, y },
                            ));
                        }
                        let _ = window.show();
                        let _ = window.set_focus();
                    }
                }
            }
            SystemTrayEvent::RightClick { .. } | SystemTrayEvent::DoubleClick { .. } => {
                // No right-click menu in v1 — matches macOS behaviour.
            }
            _ => {}
        })
        .on_window_event(|event| match event.event() {
            tauri::WindowEvent::Focused(is_focused) => {
                if !is_focused {
                    let window = event.window().clone();
                    tauri::async_runtime::spawn(async move {
                        tokio::time::sleep(tokio::time::Duration::from_millis(150)).await;
                        let _ = window.hide();
                    });
                }
            }
            _ => {}
        })
        .invoke_handler(tauri::generate_handler![send_ipc_command])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
