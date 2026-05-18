# bluehashapp — BlueHash Windows agent + tray

Windows port of [`tray-macos`](https://github.com/JanosMozer/tray-macos).
Same architecture, same Supabase broker, same IPC protocol — different
host OS plumbing.

| Crate | Role | Cross-platform? |
|---|---|---|
| `csi-core`  | Crypto (X25519 + ChaCha20-Poly1305), Supabase HTTP client, secure-storage keychain. | crypto/broker yes; **keychain rewritten for Windows Credential Manager** |
| `csi-ipc`   | Request/Response types shared between the daemon and the tray. | yes (copied verbatim) |
| `csid`      | The agent daemon. Owns the hardware identity key (HIK) + the per-user Personal Network Key (PNK), watches `~/Hashnet/encrypted/`, runs the OAuth callback at `127.0.0.1:14555`. | **named-pipe IPC + Windows Service integration** |
| `csi-tray`  | Tauri 1.6 system-tray UI. | **named-pipe IPC client** |

## Build

Requires Rust 1.78+, MSVC toolchain, WebView2 runtime.

```powershell
git clone https://github.com/kristerus/bluehashapp
cd bluehashapp
Copy-Item .env.example .env
cargo build --release
```

Outputs:
* `target\release\csid.exe`     — the daemon
* `target\release\csi-tray.exe` — the tray app

## Run for development

In two terminals (so you can see daemon logs):

```powershell
# Terminal 1 — daemon
cargo run -p csid

# Terminal 2 — tray
cargo run -p csi-tray
```

The tray connects to the daemon over `\\.\pipe\csi`. The daemon listens
for the OAuth callback on `127.0.0.1:14555` — make sure nothing else is
bound to that port.

## Install as a Windows Service

Run an **elevated** PowerShell:

```powershell
.\scripts\install-service.ps1 -Start
```

This calls `csid.exe install` under the hood (which uses
`windows-service` to register with the SCM as `BlueHashAgent`,
auto-start, LocalSystem) and then `sc start BlueHashAgent`. Logs land
in `%ProgramData%\Hashnet\Logs\csid.log` when the service is running
under LocalSystem, or `%LOCALAPPDATA%\Hashnet\Logs\csid.log` when run
from a normal user terminal.

To uninstall:

```powershell
.\scripts\install-service.ps1 -Uninstall
```

## Differences from `tray-macos`

| Concern | macOS (`tray-macos`) | Windows (`bluehashapp`) |
|---|---|---|
| Secure storage | macOS Keychain via `security-framework` | Windows Credential Manager via `windows-rs` |
| IPC transport | Unix domain socket at `/tmp/csi.sock` | Named pipe at `\\.\pipe\csi` |
| Daemon supervisor | launchd via `com.hashnet.csid.plist` | Windows Service via `windows-service` crate + `BlueHashAgent` SCM entry |
| OS version detection | `sw_vers -productVersion` | `cmd /c ver` |
| Log directory | `~/Library/Logs/Hashnet/` | `%LOCALAPPDATA%\Hashnet\Logs\` (user) or `%ProgramData%\Hashnet\Logs\` (LocalSystem service) |
| File watcher | `notify` (FSEvents) | `notify` (ReadDirectoryChangesW) — same crate, same API |
| Manifest `inode` field | NTFS doesn't expose Unix-style inode 1:1 | Dropped (was never read) |

Everything else — the Supabase schema, the X25519 ECDH key wrapping
under the HIK, the PNK rotation cadence, the OAuth PKCE flow, the
file-watcher encrypt/decrypt loop — is byte-identical between the two
ports. Both daemons can be members of the same hashnet and share
files via the same broker.

## Repo layout

```
bluehashapp/
├── Cargo.toml             # workspace
├── .env.example
├── .gitignore
├── README.md
├── csi-core/              # shared crypto / broker / keychain
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs
│       ├── crypto.rs      # X25519 + ChaCha20-Poly1305 (= macOS)
│       ├── broker.rs      # Supabase HTTP client    (= macOS)
│       └── keychain.rs    # Windows Credential Manager
├── csi-ipc/               # request/response types (= macOS)
├── csid/                  # daemon
│   ├── Cargo.toml
│   └── src/
│       ├── main.rs        # named-pipe IPC + OAuth + state machine
│       ├── watcher.rs     # ~/Hashnet/encrypted/ watcher
│       ├── logging.rs     # rotating file logger
│       └── service.rs     # Windows Service registration / dispatch
├── csi-tray/              # Tauri 1.6 tray UI
│   ├── Cargo.toml
│   ├── build.rs           # generates icon.ico + icon.png placeholders
│   ├── tauri.conf.json
│   ├── index.html         # tray UI (placeholder; swap in Janos's HTML)
│   ├── icons/             # generated at build time if absent
│   └── src/
│       └── main.rs
├── scripts/
│   └── install-service.ps1   # elevated-PS installer + start helper
├── supabase_phase2_schema.sql
└── supabase_rls_policies.sql
```

## Status

Compiles cleanly via `cargo check` on Windows. The functional
end-to-end test (OAuth login → device registration → file
encryption → cross-device decryption) needs an integration run
against the live Supabase project + a paired Mac instance.

Known gaps vs. the macOS repo:
* The tray UI in `csi-tray/index.html` is a stub — the macOS repo's
  `index.html` (containing the editorial-styled tray layout) should be
  vendored once Janos confirms which version is canonical.
* Windows-specific code-signing for the produced `.exe`s is not yet
  wired into CI.

## License

Apache-2.0 (same as `tray-macos`).
