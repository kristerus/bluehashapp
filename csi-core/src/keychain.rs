//! Windows secure-storage backend, mirroring the macOS Keychain interface
//! that `crypto.rs` expects. Same function signatures as the macOS version
//! (`store_device_secret`, `load_device_secret`, `delete_device_secret`,
//! `store_pnk`, `load_pnk`, `delete_pnk`) so the cross-platform call sites
//! don't need any cfg-gating.
//!
//! Storage backend: **Windows Credential Manager** via `CredWriteW` /
//! `CredReadW` / `CredDeleteW`. Credentials are persisted with
//! `CRED_PERSIST_LOCAL_MACHINE` so the daemon (running as LocalSystem)
//! can read them across user sessions. Each credential's `TargetName` is
//! `com.hashnet.csid:<account>` to match the macOS Keychain service key.
//!
//! Cred Manager already encrypts at rest (DPAPI-backed) and ACL-restricts
//! to the storing principal; we deliberately use it instead of writing
//! our own DPAPI-encrypted files because it gives us audit-trail visibility
//! in Credential Manager and works with Windows account migration.

use anyhow::{anyhow, bail, Result};
use std::ffi::OsString;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use windows::core::PWSTR;
use windows::Win32::Foundation::FILETIME;
use windows::Win32::Security::Credentials::{
    CredDeleteW, CredFree, CredReadW, CredWriteW, CREDENTIALW, CRED_FLAGS, CRED_PERSIST_LOCAL_MACHINE,
    CRED_TYPE_GENERIC,
};

/// Mirrors `SERVICE` constant on the macOS side. Used as the prefix of the
/// `TargetName` so all our credentials cluster together in the Cred
/// Manager UI under one logical service.
const SERVICE: &str = "com.hashnet.csid";

/// Build a wide-string that the Win32 W-suffixed APIs expect. Returns
/// the Vec<u16> (must outlive the PWSTR) and a non-owning PWSTR into it.
fn to_wide(s: &str) -> Vec<u16> {
    OsString::from(s).encode_wide().chain(std::iter::once(0)).collect()
}

/// `TargetName = "<SERVICE>:<account>"`. Matches the macOS layout where
/// service+account combine to identify a row.
fn target_name(account: &str) -> Vec<u16> {
    to_wide(&format!("{SERVICE}:{account}"))
}

pub fn store_device_secret(account: &str, secret: &[u8]) -> Result<()> {
    // Cred Manager rejects credentials > 5 * 512 bytes (CRED_MAX_CREDENTIAL_BLOB_SIZE
    // is 2560 since Vista, 5120 since 7). 32-byte X25519 secrets are fine.
    if secret.len() > 5120 {
        bail!("secret too large for Credential Manager ({} bytes > 5120)", secret.len());
    }

    // Overwrite the existing entry first so CredWrite doesn't fail when
    // the credential already exists with different flags. Equivalent to
    // the `delete_device_secret(account)` line on macOS.
    let _ = delete_device_secret(account);

    let mut target = target_name(account);
    let mut user = to_wide(account);
    let mut comment = to_wide(&format!("BlueHash {} key", account));
    // CredWriteW reads the blob as a contiguous byte buffer; we make a
    // mutable copy because the struct holds a non-const pointer.
    let mut blob: Vec<u8> = secret.to_vec();

    let cred = CREDENTIALW {
        Flags: CRED_FLAGS(0),
        Type: CRED_TYPE_GENERIC,
        TargetName: PWSTR(target.as_mut_ptr()),
        Comment: PWSTR(comment.as_mut_ptr()),
        LastWritten: FILETIME::default(),
        CredentialBlobSize: blob.len() as u32,
        CredentialBlob: blob.as_mut_ptr(),
        Persist: CRED_PERSIST_LOCAL_MACHINE,
        AttributeCount: 0,
        Attributes: std::ptr::null_mut(),
        TargetAlias: PWSTR::null(),
        UserName: PWSTR(user.as_mut_ptr()),
    };

    unsafe {
        CredWriteW(&cred, 0).map_err(|e| anyhow!("CredWriteW failed: {e}"))?;
    }
    Ok(())
}

pub fn load_device_secret(account: &str) -> Result<Vec<u8>> {
    let target = target_name(account);
    let mut credential_ptr: *mut CREDENTIALW = std::ptr::null_mut();

    let result = unsafe {
        // 3rd arg is `flags: u32`; 0 = no special flags. windows 0.58
        // doesn't accept `Option` here even though some earlier crate
        // versions did.
        CredReadW(
            PWSTR(target.as_ptr() as *mut u16),
            CRED_TYPE_GENERIC,
            0,
            &mut credential_ptr,
        )
    };

    // `CredReadW` returns Err(ERROR_NOT_FOUND) when the credential
    // doesn't exist — map to a typed error so the crypto layer can
    // distinguish "no key yet" from "real failure".
    if let Err(e) = result {
        return Err(anyhow!("credential not found for {account}: {e}"));
    }
    if credential_ptr.is_null() {
        bail!("CredReadW returned null pointer for {account}");
    }

    // Copy the blob out before freeing the Cred Manager allocation.
    let bytes = unsafe {
        let cred = &*credential_ptr;
        let len = cred.CredentialBlobSize as usize;
        let slice = std::slice::from_raw_parts(cred.CredentialBlob, len);
        let copy = slice.to_vec();
        CredFree(credential_ptr as *const _);
        copy
    };

    Ok(bytes)
}

pub fn delete_device_secret(account: &str) -> Result<()> {
    let target = target_name(account);
    let result = unsafe {
        CredDeleteW(PWSTR(target.as_ptr() as *mut u16), CRED_TYPE_GENERIC, 0)
    };
    // ERROR_NOT_FOUND (1168) is fine — we're idempotent like the macOS
    // version (which treats OSStatus -25300 as "already gone").
    if let Err(e) = result {
        let msg = format!("{e}");
        if msg.contains("0x80070490") || msg.contains("(1168)") {
            return Ok(());
        }
        bail!("CredDeleteW failed: {e}");
    }
    Ok(())
}

// ---- PNK helpers (per-user 32-byte ChaCha20-Poly1305 key) --------------

/// Store PersonalNetworkKey (32-byte key material) in Credential Manager.
pub fn store_pnk(key_bytes: &[u8; 32]) -> Result<()> {
    store_device_secret("pnk", key_bytes)
}

/// Load PersonalNetworkKey from Credential Manager.
pub fn load_pnk() -> Result<[u8; 32]> {
    let bytes = load_device_secret("pnk")?;
    if bytes.len() != 32 {
        bail!("PNK must be 32 bytes, got {}", bytes.len());
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

/// Delete PersonalNetworkKey from Credential Manager.
pub fn delete_pnk() -> Result<()> {
    delete_device_secret("pnk")
}

// Allow OsString round-trip for debug builds without a "unused import"
// warning on the encode-only path.
#[allow(dead_code)]
fn from_wide_lossy(bytes: &[u16]) -> String {
    OsString::from_wide(bytes).to_string_lossy().into_owned()
}
