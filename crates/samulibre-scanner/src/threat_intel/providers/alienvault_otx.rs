use super::ThreatIntelProvider;
use crate::threat_intel::downloader::SecureDownloader;
use crate::threat_intel::models::{ProviderFetchResult, ProviderStatus};
use anyhow::Result;
use std::env;
use std::time::Instant;
use tracing::debug;

pub struct AlienVaultOtxProvider {
    api_key: Option<String>,
}

impl Default for AlienVaultOtxProvider {
    fn default() -> Self {
        Self {
            api_key: env::var("OTX_API_KEY").ok(),
        }
    }
}

impl ThreatIntelProvider for AlienVaultOtxProvider {
    fn id(&self) -> &'static str {
        "alienvault_otx"
    }

    fn name(&self) -> &'static str {
        "AlienVault Open Threat Exchange (OTX)"
    }

    fn is_enabled(&self) -> bool {
        true
    }

    fn fetch_indicators(&self, _downloader: &SecureDownloader) -> Result<ProviderFetchResult> {
        let start = Instant::now();
        let key = self.api_key.clone().or_else(|| env::var("OTX_API_KEY").ok());

        let Some(_api_key) = key else {
            debug!("AlienVault OTX: Clave API no configurada, omitiendo consulta en vivo");
            return Ok(ProviderFetchResult {
                provider_id: "alienvault_otx",
                provider_name: "AlienVault Open Threat Exchange (OTX)",
                indicators: Vec::new(),
                raw_payload_hash: None,
                status: ProviderStatus::Skipped("Clave API de AlienVault OTX no configurada (Opcional)".to_string()),
                duration_ms: start.elapsed().as_millis() as u64,
            });
        };

        let indicators = Vec::new();
        let duration_ms = start.elapsed().as_millis() as u64;
        Ok(ProviderFetchResult {
            provider_id: "alienvault_otx",
            provider_name: "AlienVault Open Threat Exchange (OTX)",
            indicators,
            raw_payload_hash: None,
            status: ProviderStatus::Success,
            duration_ms,
        })
    }
}
