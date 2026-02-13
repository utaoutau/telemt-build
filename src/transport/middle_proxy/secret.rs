use std::time::Duration;

use tracing::{debug, info, warn};

use crate::error::{ProxyError, Result};

/// Fetch Telegram proxy-secret binary.
pub async fn fetch_proxy_secret(cache_path: Option<&str>) -> Result<Vec<u8>> {
    let cache = cache_path.unwrap_or("proxy-secret");

    if let Ok(metadata) = tokio::fs::metadata(cache).await {
        if let Ok(modified) = metadata.modified() {
            let age = std::time::SystemTime::now()
                .duration_since(modified)
                .unwrap_or(Duration::from_secs(u64::MAX));
            if age < Duration::from_secs(86_400) {
                if let Ok(data) = tokio::fs::read(cache).await {
                    if data.len() >= 32 {
                        info!(
                            path = cache,
                            len = data.len(),
                            age_hours = age.as_secs() / 3600,
                            "Loaded proxy-secret from cache"
                        );
                        return Ok(data);
                    }
                    warn!(
                        path = cache,
                        len = data.len(),
                        "Cached proxy-secret too short"
                    );
                }
            }
        }
    }

    info!("Downloading proxy-secret from core.telegram.org...");
    let data = download_proxy_secret().await?;

    if let Err(e) = tokio::fs::write(cache, &data).await {
        warn!(error = %e, "Failed to cache proxy-secret (non-fatal)");
    } else {
        debug!(path = cache, len = data.len(), "Cached proxy-secret");
    }

    Ok(data)
}

async fn download_proxy_secret() -> Result<Vec<u8>> {
    let resp = reqwest::get("https://core.telegram.org/getProxySecret")
        .await
        .map_err(|e| ProxyError::Proxy(format!("Failed to download proxy-secret: {e}")))?;

    if !resp.status().is_success() {
        return Err(ProxyError::Proxy(format!(
            "proxy-secret download HTTP {}",
            resp.status()
        )));
    }

    let data = resp
        .bytes()
        .await
        .map_err(|e| ProxyError::Proxy(format!("Read proxy-secret body: {e}")))?
        .to_vec();

    if data.len() < 32 {
        return Err(ProxyError::Proxy(format!(
            "proxy-secret too short: {} bytes (need >= 32)",
            data.len()
        )));
    }

    info!(len = data.len(), "Downloaded proxy-secret OK");
    Ok(data)
}
