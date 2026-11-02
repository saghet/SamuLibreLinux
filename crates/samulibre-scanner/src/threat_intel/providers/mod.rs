use super::downloader::SecureDownloader;
use super::models::ProviderFetchResult;
use anyhow::Result;

pub mod alienvault_otx;
pub mod clamav;
pub mod malware_bazaar;
pub mod misp;
pub mod threatfox;
pub mod urlhaus;
pub mod virustotal;
pub mod yara_rules;

/// Contrato universal para cada conector de fuente de inteligencia de amenazas
pub trait ThreatIntelProvider: Send + Sync {
    /// Identificador canónico del proveedor (ej. "malwarebazaar", "threatfox")
    fn id(&self) -> &'static str;

    /// Nombre legible para auditoría y visualización
    fn name(&self) -> &'static str;

    /// Indica si el proveedor está habilitado en la configuración actual
    fn is_enabled(&self) -> bool;

    /// Obtiene y extrae los indicadores desde la fuente de inteligencia
    fn fetch_indicators(&self, downloader: &SecureDownloader) -> Result<ProviderFetchResult>;
}
