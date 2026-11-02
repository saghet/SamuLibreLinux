use chrono::Utc;
use serde::{Deserialize, Serialize};

/// Modos de operación y postura de defensa del EDR
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProtectionMode {
    /// Modo Pasivo: Observación, auditoría forense y registro sin interferir con procesos o archivos
    Passive,
    /// Modo Activo (Recomendado): Aislamiento automático en cuarentena y alertas en tiempo real ante amenazas confirmadas
    Active,
    /// Modo Estricto: Bloqueo preventivo de procesos anómalos, intercepción en VFS y cuarentena agresiva
    Strict,
}

impl std::fmt::Display for ProtectionMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProtectionMode::Passive => write!(f, "PASIVO (Auditoría Forense)"),
            ProtectionMode::Active => write!(f, "ACTIVO (Respuesta y Cuarentena)"),
            ProtectionMode::Strict => write!(f, "ESTRICTO (Prevención Preventiva VFS)"),
        }
    }
}

/// Estado global de los subsistemas del motor de protección continua EDR
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdrProtectionStatus {
    pub is_active: bool,
    pub protection_mode: ProtectionMode,
    pub fanotify_active: bool,
    pub inotify_active: bool,
    pub process_sensor_active: bool,
    pub ebpf_sensor_active: bool,
    pub fim_active: bool,
    pub behavioral_active: bool,
    pub reconciliation_active: bool,
    pub kernel_version: String,
    pub linux_distro: String,
    pub uptime_secs: u64,
}

/// Métricas de cobertura del sistema de archivos y procesos
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CoverageMetrics {
    pub watch_dirs: Vec<String>,
    pub excluded_paths: Vec<String>,
    pub filesystems_monitored: Vec<String>,
    pub total_dirs_watched: usize,
    pub total_files_indexed: usize,
    pub active_processes_monitored: usize,
}

/// Métricas de actividad, colas y rendimiento del motor de inspección
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ActivityMetrics {
    pub events_received: u64,
    pub events_processed: u64,
    pub events_dropped_saturation: u64,
    pub queue_pending: usize,
    pub files_inspected: u64,
    pub files_clean_cached: u64,
    pub threats_detected: u64,
    pub threats_blocked_isolated: u64,
    pub processes_suspended: u64,
    pub avg_inspection_time_ms: f64,
}

/// Tipos de eventos interceptados por los diferentes sensores
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EdrEventType {
    FileCreate,
    FileModify,
    FileCloseWrite,
    FileOpenExec,
    ProcessSpawn,
    ProcessExec,
    ProcessTamper,
    FimIntegrityViolation,
    RansomwareBurst,
    CanaryTripped,
}

impl std::fmt::Display for EdrEventType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EdrEventType::FileCreate => write!(f, "FILE_CREATE"),
            EdrEventType::FileModify => write!(f, "FILE_MODIFY"),
            EdrEventType::FileCloseWrite => write!(f, "FILE_CLOSE_WRITE"),
            EdrEventType::FileOpenExec => write!(f, "FILE_OPEN_EXEC"),
            EdrEventType::ProcessSpawn => write!(f, "PROCESS_SPAWN"),
            EdrEventType::ProcessExec => write!(f, "PROCESS_EXEC"),
            EdrEventType::ProcessTamper => write!(f, "PROCESS_TAMPER"),
            EdrEventType::FimIntegrityViolation => write!(f, "FIM_VIOLATION"),
            EdrEventType::RansomwareBurst => write!(f, "RANSOMWARE_BURST"),
            EdrEventType::CanaryTripped => write!(f, "CANARY_TRIPPED"),
        }
    }
}

/// Evento forense y de telemetría registrado en la línea de tiempo del EDR
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdrEvent {
    pub id: String,
    pub timestamp: String,
    pub event_type: EdrEventType,
    pub severity: String,
    pub file_path: Option<String>,
    pub sha256: Option<String>,
    pub pid: Option<u32>,
    pub ppid: Option<u32>,
    pub process_name: Option<String>,
    pub user: Option<String>,
    pub sensor: String,
    pub verdict: String,
    pub confidence_score: u32,
    pub action_taken: String,
    pub details: String,
}

impl EdrEvent {
    pub fn new(
        event_type: EdrEventType,
        severity: impl Into<String>,
        sensor: impl Into<String>,
        verdict: impl Into<String>,
        confidence_score: u32,
        action_taken: impl Into<String>,
        details: impl Into<String>,
    ) -> Self {
        Self {
            id: format!("EDR-{}", uuid::Uuid::new_v4().to_string().to_uppercase()),
            timestamp: Utc::now().to_rfc3339(),
            event_type,
            severity: severity.into(),
            file_path: None,
            sha256: None,
            pid: None,
            ppid: None,
            process_name: None,
            user: None,
            sensor: sensor.into(),
            verdict: verdict.into(),
            confidence_score,
            action_taken: action_taken.into(),
            details: details.into(),
        }
    }
}
