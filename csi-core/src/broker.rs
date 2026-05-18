use anyhow::{Context, Result};
use reqwest::{header, Client};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::Utc;

#[derive(Debug, Serialize, Deserialize)]
pub struct WrappedPnk {
    pub id: Option<Uuid>,
    pub target_device_id: Uuid,
    pub wrapped_pnk: String,
    pub version: u32,
    pub created_at: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct DeviceKeyInfo {
    pub id: Uuid,
    pub public_hik: String,
}

// Fallback Supabase coordinates for production installer builds where
// no `.env` file is present. The anon key is, by Supabase design, safe
// to embed in client binaries — Row-Level Security on the DB side is
// what protects data, not key secrecy. Override either via env var
// (e.g. for a staging project) without rebuilding.
const DEFAULT_SUPABASE_URL: &str = "https://mxgffpaxfjphoxnmvjqn.supabase.co";
const DEFAULT_SUPABASE_ANON_KEY: &str = "sb_publishable_fNY6vIb2dOyowKu0sxYx3w_JvxKQFLB";

#[derive(Clone)]
pub struct SupabaseClient {
    client: Client,
    url: String,
}

impl SupabaseClient {
    pub fn new() -> Result<Self> {
        let url = std::env::var("SUPABASE_PROJECT_URL")
            .unwrap_or_else(|_| DEFAULT_SUPABASE_URL.to_string());
        let anon_key = std::env::var("SUPABASE_ANON_KEY")
            .unwrap_or_else(|_| DEFAULT_SUPABASE_ANON_KEY.to_string());

        let mut headers = header::HeaderMap::new();
        headers.insert(
            "apikey",
            header::HeaderValue::from_str(&anon_key).context("Invalid anon key format")?,
        );
        headers.insert(
            header::AUTHORIZATION,
            header::HeaderValue::from_str(&format!("Bearer {}", anon_key))
                .context("Invalid anon key format for bearer")?,
        );

        let client = Client::builder().default_headers(headers).build()?;

        Ok(Self { client, url })
    }

    pub async fn get_active_devices(&self, user_id: String) -> Result<Vec<String>> {
        let endpoint = format!("{}/rest/v1/devices", self.url);

        let response = self
            .client
            .get(&endpoint)
            .query(&[
                ("user_id", format!("eq.{}", user_id)),
                ("select", "device_name".to_string()),
            ])
            .send()
            .await?
            .error_for_status()?;

        #[derive(Deserialize)]
        struct DeviceRecord {
            device_name: String,
        }

        let records: Vec<DeviceRecord> = response.json().await?;
        Ok(records.into_iter().map(|r| r.device_name).collect())
    }

    /// Returns all device UUIDs and public HIKs for a user — used when
    /// re-wrapping keys during PNK or HIK rotation.
    pub async fn get_devices_for_key_distribution(&self, user_id: &str) -> Result<Vec<DeviceKeyInfo>> {
        let endpoint = format!("{}/rest/v1/devices", self.url);

        let response = self
            .client
            .get(&endpoint)
            .query(&[
                ("user_id", format!("eq.{}", user_id)),
                ("select", "id,public_hik".to_string()),
            ])
            .send()
            .await?
            .error_for_status()?;

        let records: Vec<DeviceKeyInfo> = response.json().await?;
        Ok(records)
    }

    pub async fn push_wrapped_pnk(
        &self,
        target_device_id: Uuid,
        owner_user_id: Uuid,
        wrapped_pnk: String,
        version: u32,
    ) -> Result<()> {
        let endpoint = format!("{}/rest/v1/key_broker", self.url);
        let payload = serde_json::json!({
            "target_device_id": target_device_id,
            "owner_user_id": owner_user_id,
            "wrapped_pnk": wrapped_pnk,
            "version": version
        });
        self.client.post(&endpoint)
            .header("Prefer", "return=minimal")
            .json(&payload).send().await?.error_for_status()?;
        Ok(())
    }

    pub async fn fetch_my_wrapped_pnks(&self, my_device_id: Uuid) -> Result<Vec<WrappedPnk>> {
        let endpoint = format!("{}/rest/v1/key_broker", self.url);

        let response = self
            .client
            .get(&endpoint)
            .query(&[("target_device_id", format!("eq.{}", my_device_id))])
            .send()
            .await?
            .error_for_status()?;

        let pnks: Vec<WrappedPnk> = response.json().await?;

        Ok(pnks)
    }

    pub async fn register_device(&self, user_id: String, device_name: String, public_hik: String, os_version: String) -> Result<Uuid> {
        let endpoint = format!("{}/rest/v1/devices", self.url);

        let check_resp = self.client.get(&endpoint)
            .query(&[("public_hik", format!("eq.{}", public_hik))])
            .send().await?.error_for_status()?;

        #[derive(Deserialize)]
        struct DeviceRecord {
            id: Uuid,
        }

        let existing: Vec<DeviceRecord> = check_resp.json().await?;
        if !existing.is_empty() {
            let device_id = existing[0].id;
            let patch_url = format!("{}?id=eq.{}", endpoint, device_id);
            self.client.patch(&patch_url)
                .json(&serde_json::json!({
                    "is_active": true,
                    "os_version": os_version,
                    "last_seen_at": Utc::now().to_rfc3339(),
                    "disconnected_at": serde_json::Value::Null
                }))
                .send().await?.error_for_status()?;
            return Ok(device_id);
        }

        let payload = serde_json::json!({
            "user_id": user_id,
            "device_name": device_name,
            "public_hik": public_hik,
            "os_version": os_version,
            "is_active": true
        });
        let resp = self.client.post(&endpoint)
            .header("Prefer", "return=representation")
            .json(&payload).send().await?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("register_device failed {}: {}", status, body);
        }

        let records: Vec<DeviceRecord> = resp.json().await?;
        let device_id = records.first()
            .ok_or_else(|| anyhow::anyhow!("No device returned from register_device"))?
            .id;
        Ok(device_id)
    }

    pub async fn set_device_status(&self, public_hik: String, is_active: bool) -> Result<()> {
        let endpoint = format!("{}/rest/v1/devices", self.url);
        let patch_url = format!("{}?public_hik=eq.{}", endpoint, public_hik);

        let payload = if is_active {
            serde_json::json!({
                "is_active": true,
                "last_seen_at": Utc::now().to_rfc3339(),
                "disconnected_at": serde_json::Value::Null
            })
        } else {
            serde_json::json!({
                "is_active": false,
                "disconnected_at": Utc::now().to_rfc3339()
            })
        };

        self.client.patch(&patch_url)
            .json(&payload)
            .send().await?.error_for_status()?;
        Ok(())
    }

    pub async fn update_last_seen(&self, public_hik: String) -> Result<()> {
        let endpoint = format!("{}/rest/v1/devices", self.url);
        let patch_url = format!("{}?public_hik=eq.{}", endpoint, public_hik);

        self.client.patch(&patch_url)
            .json(&serde_json::json!({
                "last_seen_at": Utc::now().to_rfc3339()
            }))
            .send().await?.error_for_status()?;
        Ok(())
    }

    pub async fn get_connections(&self, user_id: String) -> Result<Vec<String>> {
        let endpoint = format!("{}/rest/v1/connections", self.url);
        let or_filter = format!("(initiator_user_id.eq.{},target_user_id.eq.{})", user_id, user_id);

        let response = self.client.get(&endpoint)
            .query(&[
                ("or", or_filter),
                ("status", "eq.accepted".to_string()),
                ("select", "id".to_string()),
            ])
            .send().await?.error_for_status()?;

        #[derive(Deserialize)]
        struct ConnRecord {
            id: Uuid
        }
        let records: Vec<ConnRecord> = response.json().await?;
        Ok(records.into_iter().map(|r| r.id.to_string()).collect())
    }

    pub async fn get_latest_key_version(&self, device_id: Uuid) -> Result<Option<u32>> {
        let endpoint = format!("{}/rest/v1/key_broker", self.url);

        let response = self.client.get(&endpoint)
            .query(&[
                ("target_device_id", format!("eq.{}", device_id)),
                ("select", "version".to_string()),
                ("order", "version.desc".to_string()),
                ("limit", "1".to_string()),
            ])
            .send().await?.error_for_status()?;

        #[derive(Deserialize)]
        struct VersionRecord {
            version: u32,
        }

        let records: Vec<VersionRecord> = response.json().await?;
        Ok(records.first().map(|r| r.version))
    }

    pub async fn check_key_sync_needed(&self, device_id: Uuid, local_version: u32) -> Result<bool> {
        match self.get_latest_key_version(device_id).await? {
            Some(latest) => Ok(latest > local_version),
            None => Ok(false),
        }
    }

    pub async fn update_device_hik(&self, device_id: Uuid, new_public_hik: &str, hik_version: u32) -> Result<()> {
        let endpoint = format!("{}/rest/v1/devices", self.url);
        let patch_url = format!("{}?id=eq.{}", endpoint, device_id);

        self.client.patch(&patch_url)
            .json(&serde_json::json!({
                "public_hik": new_public_hik,
                "hik_version": hik_version,
                "last_seen_at": Utc::now().to_rfc3339()
            }))
            .send().await?.error_for_status()?;
        Ok(())
    }

    pub async fn fetch_wrapped_pnks_for_device(&self, device_id: Uuid) -> Result<Vec<WrappedPnk>> {
        let endpoint = format!("{}/rest/v1/key_broker", self.url);

        let response = self.client.get(&endpoint)
            .query(&[
                ("target_device_id", format!("eq.{}", device_id)),
                ("order", "version.desc".to_string()),
            ])
            .send().await?.error_for_status()?;

        let pnks: Vec<WrappedPnk> = response.json().await?;
        Ok(pnks)
    }

    // ============================================================
    // Desktop pairing flow (see supabase_phase3_desktop_link.sql).
    // ============================================================

    /// Create a new pending desktop session. Returns the session UUID
    /// that the daemon then embeds in the browser URL and polls.
    pub async fn create_desktop_session(&self) -> Result<Uuid> {
        let endpoint = format!("{}/rest/v1/desktop_sessions", self.url);
        let resp = self.client.post(&endpoint)
            .header("Prefer", "return=representation")
            .json(&serde_json::json!({}))
            .send().await?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("create_desktop_session failed {}: {}", status, body);
        }
        #[derive(Deserialize)]
        struct R { id: Uuid }
        let records: Vec<R> = resp.json().await?;
        records.first().map(|r| r.id)
            .ok_or_else(|| anyhow::anyhow!("create_desktop_session: empty response"))
    }

    /// One-shot poll: returns Some(linked info) when the marketing site
    /// has filled in the session, otherwise None. The daemon loops over
    /// this every 2 seconds.
    pub async fn poll_desktop_session(&self, session_id: Uuid) -> Result<Option<LinkedDesktopSession>> {
        let endpoint = format!("{}/rest/v1/desktop_sessions", self.url);
        let response = self.client.get(&endpoint)
            .query(&[
                ("id", format!("eq.{}", session_id)),
                ("select", "status,user_id,email,name,image_url".to_string()),
            ])
            .send().await?.error_for_status()?;

        #[derive(Deserialize)]
        struct R {
            status: String,
            user_id: Option<String>,
            email: Option<String>,
            name: Option<String>,
            image_url: Option<String>,
        }
        let records: Vec<R> = response.json().await?;
        let Some(rec) = records.into_iter().next() else { return Ok(None); };
        if rec.status != "linked" { return Ok(None); }
        let Some(user_id) = rec.user_id else { return Ok(None); };
        Ok(Some(LinkedDesktopSession {
            user_id,
            email: rec.email,
            name: rec.name,
            image_url: rec.image_url,
        }))
    }

    /// Mark a session as consumed so the same row can't be re-claimed.
    pub async fn consume_desktop_session(&self, session_id: Uuid) -> Result<()> {
        let endpoint = format!("{}/rest/v1/desktop_sessions", self.url);
        let patch_url = format!("{}?id=eq.{}", endpoint, session_id);
        self.client.patch(&patch_url)
            .header("Prefer", "return=minimal")
            .json(&serde_json::json!({ "status": "consumed" }))
            .send().await?.error_for_status()?;
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct LinkedDesktopSession {
    pub user_id: String,
    pub email: Option<String>,
    pub name: Option<String>,
    pub image_url: Option<String>,
}
