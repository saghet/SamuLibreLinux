use super::ThreatIntelProvider;
use crate::threat_intel::downloader::SecureDownloader;
use crate::threat_intel::models::{ProviderFetchResult, ProviderStatus};
use anyhow::Result;
use std::env;
use std::time::Instant;
use tracing::debug;

pub struct MispProvider {
    server_url: Option<String>,
    auth_key: Option<String>,
}

impl Default for MispProvider {
    fn default() -> Self {
        Self {
            server_url: env::var("MISP_SERVER_URL").ok(),
            auth_key: env::var("MISP_AUTH_KEY").ok(),
        }
    }
}

impl ThreatIntelProvider for MispProvider {
    fn id(&self) -> &'static str {
        "misp"
    }

    fn name(&self) -> &'static str {
        "MISP Open Source Threat Intelligence"
    }

    fn is_enabled(&self) -> bool {
        true
    }

    fn fetch_indicators(&self, _downloader: &SecureDownloader) -> Result<ProviderFetchResult> {
        let start = Instant::now();
        let configured = self.server_url.is_some() && self.auth_key.is_some();

        if !configured {
            debug!("MISP: Servidor corporativo no configurado, omitiendo sincronización");
            return Ok(ProviderFetchResult {
                provider_id: "misp",
                provider_name: "MISP Open Source Threat Intelligence",
                indicators: Vec::new(),
                raw_payload_hash: None,
                status: ProviderStatus::Skipped("Servidor MISP no configurado (Integración Corporativa Opcional)".to_string()),
                duration_ms: start.elapsed().as_millis() as u64,
            });
        }

        Ok(ProviderFetchResult {
            provider_id: "misp",
            provider_name: "MISP Open Source Threat Intelligence",
            indicators: Vec::new(),
            raw_payload_hash: None,
            status: ProviderStatus::Success,
            duration_ms: start.elapsed().as_millis() as u64,
        })
    }
}
