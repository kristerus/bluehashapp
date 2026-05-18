//! Windows Service integration - the equivalent of the macOS launchd
//! plist (`scripts/com.hashnet.csid.plist` in tray-macos). Handles:
//!
//!   * `csid install`   - register with the Service Control Manager
//!   * `csid uninstall` - remove the service
//!   * `csid start`     - start the installed service (one-shot wrapper)
//!   * `csid stop`      - stop the installed service
//!   * Running under SCM - when SCM launches `csid.exe` it expects the
//!     service control dispatcher to take over; we detect that case in
//!     `main.rs` and route here.

use anyhow::{anyhow, Context, Result};
use std::ffi::OsString;
use std::time::Duration;
use tracing::info;
use windows_service::service::{
    ServiceAccess, ServiceErrorControl, ServiceInfo, ServiceStartType, ServiceState, ServiceStatus,
    ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_service::{define_windows_service, service::ServiceControl, service_dispatcher};

pub const SERVICE_NAME: &str = "BlueHashAgent";
pub const DISPLAY_NAME: &str = "BlueHash Identity Agent";
pub const DESCRIPTION: &str = "Hardware-bound identity agent for BlueHash. Manages encryption keys, file watching, and broker sync.";

const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;
/// Returned by `service_dispatcher::start` when the binary wasn't
/// launched from the SCM - we use this to detect "running standalone".
pub const ERROR_NOT_UNDER_SCM: i32 = 1063;

/// Attempt to start service-mode. Returns:
///   * `Ok(true)`  - we ran as a service and it's done (caller should exit 0)
///   * `Ok(false)` - not running under SCM, caller should run console mode
///   * `Err(...)`  - something went wrong in the dispatcher itself
pub fn try_dispatch() -> Result<bool> {
    match service_dispatcher::start(SERVICE_NAME, ffi_service_main) {
        Ok(()) => Ok(true),
        Err(windows_service::Error::Winapi(io_err))
            if io_err.raw_os_error() == Some(ERROR_NOT_UNDER_SCM) =>
        {
            Ok(false)
        }
        Err(e) => Err(anyhow!("service_dispatcher::start failed: {e}")),
    }
}

define_windows_service!(ffi_service_main, service_main);

fn service_main(_args: Vec<OsString>) {
    if let Err(e) = service_runner() {
        tracing::error!(error = %e, "service runner exited with error");
    }
}

fn service_runner() -> windows_service::Result<()> {
    let status_handle = service_control_handler::register(SERVICE_NAME, |control| match control {
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        ServiceControl::Stop | ServiceControl::Shutdown => {
            crate::request_stop();
            ServiceControlHandlerResult::NoError
        }
        _ => ServiceControlHandlerResult::NotImplemented,
    })?;

    let running = ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state: ServiceState::Running,
        controls_accepted: windows_service::service::ServiceControlAccept::STOP
            | windows_service::service::ServiceControlAccept::SHUTDOWN,
        exit_code: windows_service::service::ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    };
    status_handle.set_service_status(running.clone())?;

    // Build a single-threaded tokio runtime and drive the daemon main
    // loop until the service-control handler flips the stop flag.
    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            tracing::error!(error = %e, "failed to build tokio runtime");
            return Ok(());
        }
    };
    if let Err(e) = rt.block_on(crate::run_daemon()) {
        tracing::error!(error = %e, "daemon exited with error");
    }

    let stopped = ServiceStatus {
        current_state: ServiceState::Stopped,
        ..running
    };
    status_handle.set_service_status(stopped)?;
    Ok(())
}

pub fn install() -> Result<()> {
    let manager_access = ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE;
    let manager = ServiceManager::local_computer(None::<&str>, manager_access)
        .context("open SCM (do you have admin?)")?;

    let exe = std::env::current_exe().context("locate current exe")?;
    let info = ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from(DISPLAY_NAME),
        service_type: SERVICE_TYPE,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: exe,
        launch_arguments: vec![],
        dependencies: vec![],
        account_name: None, // LocalSystem - matches launchd UserName=root on macOS
        account_password: None,
    };
    let service = manager
        .create_service(&info, ServiceAccess::CHANGE_CONFIG | ServiceAccess::START)
        .context("create service")?;
    service.set_description(DESCRIPTION).context("set description")?;

    info!("✓ installed: {SERVICE_NAME} (auto-start, LocalSystem)");
    println!("✓ installed: {SERVICE_NAME} (auto-start, LocalSystem)");
    println!("  start now with: sc start {SERVICE_NAME}");
    println!("  or reboot to start automatically");
    Ok(())
}

pub fn uninstall() -> Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .context("open SCM")?;
    let service = manager
        .open_service(
            SERVICE_NAME,
            ServiceAccess::STOP | ServiceAccess::DELETE | ServiceAccess::QUERY_STATUS,
        )
        .context("open service (already uninstalled?)")?;
    let _ = service.stop();
    service.delete().context("delete service")?;
    println!("✓ uninstalled: {SERVICE_NAME}");
    Ok(())
}
