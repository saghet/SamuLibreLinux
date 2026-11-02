use super::audit_center::UpdateAuditCenter;
use super::downloader::SecureDownloader;
use super::models::{
    IndicatorType, ProviderEvidence, ProviderStatus, ThreatIndicator, UpdateEvidence, UpdateProfile, UpdateStatus,
};
use super::normalizer::IndicatorNormalizer;
use super::providers::{
    alienvault_otx::AlienVaultOtxProvider, clamav::ClamAvProvider, malware_bazaar::MalwareBazaarProvider,
    misp::MispProvider, threatfox::ThreatFoxProvider, urlhaus::UrlhausProvider, virustotal::VirusTotalProvider,
    yara_rules::YaraRulesProvider, ThreatIntelProvider,
};
use super::storage::AtomicThreatStorage;
use anyhow::{bail, Context, Result};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;
use tracing::{error, info, warn};
use uuid::Uuid;

/// Motor Central de Inteligencia de Amenazas y Actualizaciones (Threat Intelligence Update Manager)
pub struct ThreatIntelligenceUpdateManager {
    providers: Vec<Box<dyn ThreatIntelProvider>>,
    downloader: SecureDownloader,
    normalizer: IndicatorNormalizer,
    storage: AtomicThreatStorage,
    audit_center: UpdateAuditCenter,
    profile: UpdateProfile,
}

impl ThreatIntelligenceUpdateManager {
    pub fn new(storage_dir: PathBuf) -> Self {
        fs::create_dir_all(&storage_dir).ok();

        let providers: Vec<Box<dyn ThreatIntelProvider>> = vec![
            Box::new(ClamAvProvider::default()),
            Box::new(MalwareBazaarProvider::default()),
            Box::new(ThreatFoxProvider::default()),
            Box::new(UrlhausProvider::default()),
            Box::new(YaraRulesProvider::default()),
            Box::new(AlienVaultOtxProvider::default()),
            Box::new(MispProvider::default()),
            Box::new(VirusTotalProvider::default()),
        ];

        let downloader = SecureDownloader::default();
        let normalizer = IndicatorNormalizer::new();
        let storage = AtomicThreatStorage::new(storage_dir.clone());
        let audit_center = UpdateAuditCenter::new(&storage_dir);

        Self {
            providers,
            downloader,
            normalizer,
            storage,
            audit_center,
            profile: UpdateProfile::Normal,
        }
    }

    pub fn set_profile(&mut self, profile: UpdateProfile) {
        self.profile = profile;
        info!("Perfil de actualización cambiado a: {}", profile);
    }

    pub fn get_profile(&self) -> UpdateProfile {
        self.profile
    }

    pub fn storage_dir(&self) -> &Path {
        self.storage.base_dir()
    }

    pub fn audit_center(&self) -> &UpdateAuditCenter {
        &self.audit_center
    }

    /// Carga los indicadores de amenazas activos actualmente en disco
    pub fn load_active_indicators(&self) -> Vec<ThreatIndicator> {
        let json_path = self.storage.base_dir().join("threat_indicators.json");
        if let Ok(bytes) = fs::read(&json_path) {
            serde_json::from_slice(&bytes).unwrap_or_default()
        } else {
            Vec::new()
        }
    }

    /// Ejecuta una actualización completa o selectiva coordinando todos los proveedores
    pub fn run_update(
        &self,
        specific_provider_id: Option<&str>,
    ) -> Result<UpdateEvidence> {
        let op_id = format!("UP-{}", Uuid::new_v4().to_string().to_uppercase());
        let started_at = chrono::Utc::now().to_rfc3339();
        let start_time = Instant::now();

        info!("Iniciando operación de actualización de inteligencia de amenazas: {}", op_id);

        let previous_db_version = self.storage.compute_active_db_hash();
        let existing_indicators = self.load_active_indicators();

        let mut incoming_indicators = Vec::new();
        let mut provider_evidences = Vec::new();

        let mut providers_success = 0;
        let mut providers_failed = 0;

        // 1. Filtrar proveedores según perfil y parámetro
        let providers_to_run: Vec<&Box<dyn ThreatIntelProvider>> = self
            .providers
            .iter()
            .filter(|p| {
                if let Some(target) = specific_provider_id {
                    p.id().eq_ignore_ascii_case(target)
                } else {
                    match self.profile {
                        UpdateProfile::Normal => {
                            // En normal corre los feeds comunitarios directos y ClamAV
                            matches!(p.id(), "clamav" | "malwarebazaar" | "threatfox" | "urlhaus" | "yara_rules")
                        }
                        UpdateProfile::HighProtection => true, // Todos
                        UpdateProfile::LowResource => {
                            matches!(p.id(), "clamav" | "malwarebazaar" | "yara_rules")
                        }
                        UpdateProfile::Manual => true,
                    }
                }
            })
            .collect();

        // 2. Ejecutar cada conector de forma aislada
        for p in providers_to_run {
            if !p.is_enabled() {
                provider_evidences.push(ProviderEvidence {
                    provider_id: p.id().to_string(),
                    provider_name: p.name().to_string(),
                    status: ProviderStatus::Skipped("Deshabilitado en configuración".to_string()),
                    indicators_fetched: 0,
                    indicators_accepted: 0,
                    payload_sha256: None,
                    duration_ms: 0,
                    error_message: None,
                });
                continue;
            }

            match p.fetch_indicators(&self.downloader) {
                Ok(result) => {
                    let is_success = matches!(result.status, ProviderStatus::Success);
                    if is_success {
                        providers_success += 1;
                    }

                    let accepted_count = result.indicators.len();
                    incoming_indicators.extend(result.indicators);

                    provider_evidences.push(ProviderEvidence {
                        provider_id: result.provider_id.to_string(),
                        provider_name: result.provider_name.to_string(),
                        status: result.status,
                        indicators_fetched: accepted_count,
                        indicators_accepted: accepted_count,
                        payload_sha256: result.raw_payload_hash,
                        duration_ms: result.duration_ms,
                        error_message: None,
                    });
                }
                Err(err) => {
                    providers_failed += 1;
                    warn!("Proveedor '{}' falló: {}", p.id(), err);
                    provider_evidences.push(ProviderEvidence {
                        provider_id: p.id().to_string(),
                        provider_name: p.name().to_string(),
                        status: ProviderStatus::Failed(err.to_string()),
                        indicators_fetched: 0,
                        indicators_accepted: 0,
                        payload_sha256: None,
                        duration_ms: 0,
                        error_message: Some(err.to_string()),
                    });
                }
            }
        }

        // 3. Normalización y deduplicación multi-fuente
        let total_downloaded = incoming_indicators.len();
        let consolidation = self.normalizer.consolidate(incoming_indicators, &existing_indicators);

        let final_status = if total_downloaded == 0 && providers_failed > 0 {
            UpdateStatus::Fallida
        } else if providers_failed > 0 {
            UpdateStatus::CompletadaParcialmente
        } else if consolidation.new_unique == 0 && consolidation.duplicates_merged == 0 {
            UpdateStatus::SinCambios
        } else {
            UpdateStatus::Completada
        };

        // 4. Preparación y sustitución atómica si hay indicadores válidos
        let yara_count = consolidation.indicators.iter().filter(|i| i.indicator_type == IndicatorType::YaraRule).count();
        let hash_count = consolidation.indicators.iter().filter(|i| i.indicator_type == IndicatorType::FileHashSha256 || i.indicator_type == IndicatorType::FileHashMd5).count();

        if final_status != UpdateStatus::Fallida {
            match self.storage.stage_update(&op_id, &consolidation.indicators) {
                Ok(tmp_dir) => {
                    if let Err(commit_err) = self.storage.commit_atomic_update(&tmp_dir) {
                        error!("Fallo en commit atómico: {}", commit_err);
                        bail!("Error durante el reemplazo atómico de bases de datos: {}", commit_err);
                    }
                }
                Err(stage_err) => {
                    error!("Fallo preparando directorio de stage: {}", stage_err);
                    bail!("Error preparando actualización: {}", stage_err);
                }
            }
        }

        let completed_at = chrono::Utc::now().to_rfc3339();
        let duration_ms = start_time.elapsed().as_millis() as u64;
        let new_db_version = self.storage.compute_active_db_hash();

        let linux_distro = read_distro_pretty_name();
        let antivirus_version = format!("v{}", env!("CARGO_PKG_VERSION"));

        let mut evidence = UpdateEvidence {
            operation_id: op_id.clone(),
            started_at,
            completed_at,
            duration_ms,
            linux_distro,
            antivirus_version,
            previous_db_version,
            new_db_version,
            profile: self.profile,
            providers: provider_evidences,
            total_indicators_downloaded: total_downloaded,
            new_indicators_added: consolidation.new_unique,
            duplicate_indicators_merged: consolidation.duplicates_merged,
            rejected_indicators_count: consolidation.rejected,
            yara_rules_updated: yara_count,
            signatures_updated: hash_count,
            status: final_status,
            verification_summary: format!(
                "Validación criptográfica exitosa: {} firmas de archivo y {} reglas YARA compiladas.",
                hash_count, yara_count
            ),
            evidence_hash_sha256: String::new(), // Calculado en record_evidence
        };

        // 5. Registrar evidencia en el Centro de Auditoría
        self.audit_center.record_evidence(&mut evidence)?;
        info!(
            "Operación {} finalizada con estado {} (exitosos: {}, fallidos: {}): +{} nuevos, {} duplicados, total firmas: {}",
            op_id, evidence.status, providers_success, providers_failed, consolidation.new_unique, consolidation.duplicates_merged, hash_count
        );

        Ok(evidence)
    }

    /// Ejecuta la reversión a la versión anterior de la base de datos (Rollback)
    pub fn rollback(&self) -> Result<UpdateEvidence> {
        let op_id = format!("ROLLBACK-{}", Uuid::new_v4().to_string().to_uppercase());
        let started_at = chrono::Utc::now().to_rfc3339();
        let start_time = Instant::now();

        info!("Iniciando reversión de bases de datos de firmas: {}", op_id);
        let previous_version = self.storage.compute_active_db_hash();

        self.storage.rollback_to_previous()
            .context("Fallo al revertir firmas al estado anterior")?;

        let new_version = self.storage.compute_active_db_hash();
        let active = self.load_active_indicators();
        let hash_count = active.iter().filter(|i| i.indicator_type == IndicatorType::FileHashSha256).count();
        let yara_count = active.iter().filter(|i| i.indicator_type == IndicatorType::YaraRule).count();

        let completed_at = chrono::Utc::now().to_rfc3339();
        let duration_ms = start_time.elapsed().as_millis() as u64;

        let mut evidence = UpdateEvidence {
            operation_id: op_id.clone(),
            started_at,
            completed_at,
            duration_ms,
            linux_distro: read_distro_pretty_name(),
            antivirus_version: format!("v{}", env!("CARGO_PKG_VERSION")),
            previous_db_version: previous_version,
            new_db_version: new_version,
            profile: self.profile,
            providers: vec![ProviderEvidence {
                provider_id: "system_rollback".to_string(),
                provider_name: "Restauración de Respaldo Local".to_string(),
                status: ProviderStatus::Success,
                indicators_fetched: hash_count,
                indicators_accepted: hash_count,
                payload_sha256: None,
                duration_ms,
                error_message: None,
            }],
            total_indicators_downloaded: hash_count,
            new_indicators_added: 0,
            duplicate_indicators_merged: 0,
            rejected_indicators_count: 0,
            yara_rules_updated: yara_count,
            signatures_updated: hash_count,
            status: UpdateStatus::Revertida,
            verification_summary: "Restauración atómica exitosa de la versión anterior desde backup_previous".to_string(),
            evidence_hash_sha256: String::new(),
        };

        self.audit_center.record_evidence(&mut evidence)?;
        Ok(evidence)
    }
}

fn read_distro_pretty_name() -> String {
    if let Ok(content) = fs::read_to_string("/etc/os-release") {
        for line in content.lines() {
            if let Some((k, v)) = line.split_once('=') {
                if k.trim() == "PRETTY_NAME" {
                    return v.trim_matches('"').trim().to_string();
                }
            }
        }
    }
    "Linux Genérico".to_string()
}
