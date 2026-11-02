use serde::{Deserialize, Serialize};

/// Tipo de indicador de compromiso o detección
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IndicatorType {
    /// Hash criptográfico de archivo (SHA-256 canónico)
    FileHashSha256,
    /// Hash de archivo MD5 (legado)
    FileHashMd5,
    /// Dirección IP maliciosa o C2
    NetworkIp,
    /// Nombre de dominio malicioso / C2
    NetworkDomain,
    /// URL de distribución de malware o phishing
    MaliciousUrl,
    /// Regla YARA sintácticamente validada
    YaraRule,
}

impl std::fmt::Display for IndicatorType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IndicatorType::FileHashSha256 => write!(f, "SHA-256"),
            IndicatorType::FileHashMd5 => write!(f, "MD5"),
            IndicatorType::NetworkIp => write!(f, "IP_C2"),
            IndicatorType::NetworkDomain => write!(f, "DOMINIO_C2"),
            IndicatorType::MaliciousUrl => write!(f, "URL_MALICIOSA"),
            IndicatorType::YaraRule => write!(f, "REGLA_YARA"),
        }
    }
}

/// Nivel de severidad de la amenaza
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ThreatSeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for ThreatSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ThreatSeverity::Low => write!(f, "Baja"),
            ThreatSeverity::Medium => write!(f, "Media"),
            ThreatSeverity::High => write!(f, "Alta"),
            ThreatSeverity::Critical => write!(f, "Crítica"),
        }
    }
}

/// Registro de evidencia de una fuente que reportó el indicador
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceEvidence {
    pub provider_id: String,
    pub provider_name: String,
    pub report_date: String,
    pub confidence: u32,
    pub reference_url: Option<String>,
    pub tags: Vec<String>,
}

/// Indicador de amenaza normalizado y consolidado
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIndicator {
    pub id: String,
    pub indicator_type: IndicatorType,
    pub value: String,
    pub malware_family: String,
    pub severity: ThreatSeverity,
    pub confidence_score: u32,
    pub sources: Vec<SourceEvidence>,
    pub description: String,
    pub first_seen: String,
    pub last_updated: String,
    pub is_active: bool,
}

/// Perfiles de actualización automática e inteligente
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UpdateProfile {
    /// Actualizaciones periódicas equilibradas (cada 4h, feeds comunitarios principales)
    Normal,
    /// Mayor frecuencia y análisis exhaustivo de todas las fuentes disponibles
    HighProtection,
    /// Optimizado para servidores o portátiles: firmas esenciales y menor consumo de red
    LowResource,
    /// Solo bajo demanda explícita del usuario o administrador
    Manual,
}

impl std::fmt::Display for UpdateProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UpdateProfile::Normal => write!(f, "MODO NORMAL (Equilibrado)"),
            UpdateProfile::HighProtection => write!(f, "MODO ALTA PROTECCIÓN (Frecuente)"),
            UpdateProfile::LowResource => write!(f, "MODO BAJO CONSUMO (Esencial)"),
            UpdateProfile::Manual => write!(f, "MODO MANUAL (Bajo demanda)"),
        }
    }
}

/// Estados formales de una operación de actualización
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum UpdateStatus {
    Completada,
    CompletadaParcialmente,
    EnProceso,
    SinCambios,
    Fallida,
    Revertida,
}

impl std::fmt::Display for UpdateStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UpdateStatus::Completada => write!(f, "COMPLETADA"),
            UpdateStatus::CompletadaParcialmente => write!(f, "COMPLETADA PARCIALMENTE"),
            UpdateStatus::EnProceso => write!(f, "EN PROCESO"),
            UpdateStatus::SinCambios => write!(f, "SIN CAMBIOS"),
            UpdateStatus::Fallida => write!(f, "FALLIDA"),
            UpdateStatus::Revertida => write!(f, "REVERTIDA"),
        }
    }
}

/// Estado individual de un proveedor en una operación de actualización
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProviderStatus {
    Success,
    Failed(String),
    Skipped(String),
    RateLimited,
}

/// Evidencia individual de un proveedor dentro de la auditoría
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderEvidence {
    pub provider_id: String,
    pub provider_name: String,
    pub status: ProviderStatus,
    pub indicators_fetched: usize,
    pub indicators_accepted: usize,
    pub payload_sha256: Option<String>,
    pub duration_ms: u64,
    pub error_message: Option<String>,
}

/// Resultado retornado por la ejecución de un conector de proveedor
#[derive(Debug, Clone)]
pub struct ProviderFetchResult {
    pub provider_id: &'static str,
    pub provider_name: &'static str,
    pub indicators: Vec<ThreatIndicator>,
    pub raw_payload_hash: Option<String>,
    pub status: ProviderStatus,
    pub duration_ms: u64,
}

/// Evidencia técnica e inmutable de una operación de actualización (Audit Trail)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateEvidence {
    pub operation_id: String,
    pub started_at: String,
    pub completed_at: String,
    pub duration_ms: u64,
    pub linux_distro: String,
    pub antivirus_version: String,
    pub previous_db_version: String,
    pub new_db_version: String,
    pub profile: UpdateProfile,
    pub providers: Vec<ProviderEvidence>,
    pub total_indicators_downloaded: usize,
    pub new_indicators_added: usize,
    pub duplicate_indicators_merged: usize,
    pub rejected_indicators_count: usize,
    pub yara_rules_updated: usize,
    pub signatures_updated: usize,
    pub status: UpdateStatus,
    pub verification_summary: String,
    pub evidence_hash_sha256: String,
}
