//! Windows port of the macOS logging module. Mac wrote to
//! `~/Library/Logs/Hashnet/csid.log`; on Windows the equivalent location
//! that survives across user sessions is `%LOCALAPPDATA%\Hashnet\Logs\`
//! when running as a user, or `%PROGRAMDATA%\Hashnet\Logs\` when running
//! under LocalSystem as a Windows Service.

use std::path::PathBuf;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

/// Pick the log directory based on whether we're running as a service
/// (LocalSystem → %PROGRAMDATA%\Hashnet\Logs) or a normal user session
/// (%LOCALAPPDATA%\Hashnet\Logs). Falls back to CWD if neither var is
/// set, which only happens in weird CI environments.
fn log_dir() -> PathBuf {
    // LocalSystem (running as a Service) has %LOCALAPPDATA% pointing at
    // `C:\Windows\system32\config\systemprofile\AppData\Local`, which is
    // hidden and a pain to inspect, so prefer %PROGRAMDATA% in that case.
    let prefer_programdata = std::env::var_os("USERNAME")
        .map(|u| u.to_string_lossy().to_lowercase().contains("system"))
        .unwrap_or(false);

    let base = if prefer_programdata {
        std::env::var_os("ProgramData")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
    } else {
        std::env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .or_else(|| dirs::data_local_dir())
            .unwrap_or_else(|| PathBuf::from("."))
    };

    base.join("Hashnet").join("Logs")
}

pub fn init_logging() -> anyhow::Result<tracing_appender::non_blocking::WorkerGuard> {
    let log_dir = log_dir();
    std::fs::create_dir_all(&log_dir)?;

    let file_appender = tracing_appender::rolling::daily(&log_dir, "csid.log");
    let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);

    let fmt_layer = fmt::layer()
        .with_writer(non_blocking)
        .with_target(true)
        .with_level(true)
        // ANSI off on Windows by default - services have no terminal,
        // and the log file goes through editors that don't render ANSI.
        .with_ansi(false);

    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("csid=info,csi_core=info,warn"));

    tracing_subscriber::registry()
        .with(env_filter)
        .with(fmt_layer)
        .init();

    Ok(guard)
}
