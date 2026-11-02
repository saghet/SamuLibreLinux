use super::ThreatIntelProvider;
use crate::threat_intel::downloader::SecureDownloader;
use crate::threat_intel::models::{ProviderFetchResult, ProviderStatus};
use anyhow::Result;
use std::env;
use std::time::Instant;
use tracing::debug;

pub struct VirusTotalProvider {
    api_key: Option<String>,
}

impl Default for VirusTotalProvider {
    fn default() -> Self {
        Self {
            api_key: env::var("VT_API_KEY").ok(),
        }
    }
}

impl ThreatIntelProvider for VirusTotalProvider {
    fn id(&self) -> &'static str {
        "virustotal"
    }

    fn name(&self) -> &'static str {
        "VirusTotal Threat Reputation (v3 API)"
    }

    fn is_enabled(&self) -> bool {
        true
    }

    fn fetch_indicators(&self, _downloader: &SecureDownloader) -> Result<ProviderFetchResult> {
        let start = Instant::now();
        let key = self.api_key.clone().or_else(|| env::var("VT_API_KEY").ok());

        let Some(_api_key) = key else {
            debug!("VirusTotal: Clave API no configurada, omitiendo consulta");
            return Ok(ProviderFetchResult {
                provider_id: "virustotal",
                provider_name: "VirusTotal Threat Reputation (v3 API)",
                indicators: Vec::new(),
                raw_payload_hash: None,
                status: ProviderStatus::Skipped(
                    "Clave API de VirusTotal no configurada (Modo Enriquecimiento Forense Opcional)".to_string(),
                ),
                duration_ms: start.elapsed().as_millis() as u64,
            });
        };

        // En VirusTotal no se descargan listas masivas por términos de servicio de Google/VT,
        // sino que se realizan consultas de reputación puntuales
        Ok(ProviderFetchResult {
            provider_id: "virustotal",
            provider_name: "VirusTotal Threat Reputation (v3 API)",
            indicators: Vec::new(),
            raw_payload_hash: None,
            status: ProviderStatus::Success,
            duration_ms: start.elapsed().as_millis() as u64,
        })
    }
}
