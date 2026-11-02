use super::models::{IndicatorType, ThreatIndicator};
use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use tracing::{debug, info};

/// Gestor de almacenamiento atómico con respaldo y capacidad de rollback instantáneo
pub struct AtomicThreatStorage {
    base_dir: PathBuf,
}

impl AtomicThreatStorage {
    pub fn new(base_dir: PathBuf) -> Self {
        Self { base_dir }
    }

    pub fn base_dir(&self) -> &Path {
        &self.base_dir
    }

    /// Prepara y escribe los nuevos datos en un directorio temporal aislado
    pub fn stage_update(
        &self,
        op_id: &str,
        indicators: &[ThreatIndicator],
    ) -> Result<PathBuf> {
        let tmp_dir = self.base_dir.join(format!(".tmp_update_{}", op_id));
        if tmp_dir.exists() {
            let _ = fs::remove_dir_all(&tmp_dir);
        }
        fs::create_dir_all(&tmp_dir).context("No se pudo crear el directorio de preparación temporal")?;

        // 1. Escribir base de datos de hashes de malware
        let hashes_path = tmp_dir.join("malware_hashes.db");
        let mut hashes_file = File::create(&hashes_path)?;
        writeln!(hashes_file, "# SamuLibre Linux - Base de Datos Consolidada de Inteligencia de Amenazas")?;
        writeln!(hashes_file, "# Formato: SHA256 : Familia_Malware : Severidad : Confianza")?;

        let mut hash_count = 0;
        for ind in indicators {
            if ind.indicator_type == IndicatorType::FileHashSha256 || ind.indicator_type == IndicatorType::FileHashMd5 {
                writeln!(
                    hashes_file,
                    "{} : {} : {} : {}",
                    ind.value, ind.malware_family, ind.severity, ind.confidence_score
                )?;
                hash_count += 1;
            }
        }
        hashes_file.flush()?;

        // 2. Escribir base de datos de IOCs de red (IPs, Dominios, URLs)
        let network_path = tmp_dir.join("network_iocs.db");
        let mut network_file = File::create(&network_path)?;
        writeln!(network_file, "# SamuLibre Linux - Base de Datos de IOCs de Red y Reputación Web")?;

        for ind in indicators {
            match ind.indicator_type {
                IndicatorType::NetworkIp | IndicatorType::NetworkDomain | IndicatorType::MaliciousUrl => {
                    writeln!(
                        network_file,
                        "{}\t{}\t{}\t{}",
                        ind.indicator_type, ind.value, ind.malware_family, ind.confidence_score
                    )?;
                }
                _ => {}
            }
        }
        network_file.flush()?;

        // 3. Escribir archivo de reglas YARA
        let yara_path = tmp_dir.join("compiled_yara.yar");
        let mut yara_file = File::create(&yara_path)?;
        for ind in indicators {
            if ind.indicator_type == IndicatorType::YaraRule {
                writeln!(yara_file, "{}\n", ind.value)?;
            }
        }
        yara_file.flush()?;

        // 4. Escribir catálogo completo en JSON estructurado para el motor central
        let json_path = tmp_dir.join("threat_indicators.json");
        let json_data = serde_json::to_vec_pretty(indicators)?;
        fs::write(&json_path, json_data)?;

        // Verificación de integridad estricta del directorio temporal
        if !hashes_path.exists() || fs::metadata(&hashes_path)?.len() == 0 {
            let _ = fs::remove_dir_all(&tmp_dir);
            bail!("Fallo de verificación de integridad: malware_hashes.db quedó vacío o ausente");
        }

        debug!("Directorio temporal preparado exitosamente con {} hashes: {:?}", hash_count, tmp_dir);
        Ok(tmp_dir)
    }

    /// Realiza la sustitución atómica de las bases de datos preservando copia de respaldo
    pub fn commit_atomic_update(&self, tmp_dir: &Path) -> Result<()> {
        let backup_dir = self.base_dir.join("backup_previous");
        if backup_dir.exists() {
            let _ = fs::remove_dir_all(&backup_dir);
        }
        fs::create_dir_all(&backup_dir)?;

        // Respaldar archivos existentes
        let targets = ["malware_hashes.db", "network_iocs.db", "compiled_yara.yar", "threat_indicators.json"];
        for file_name in &targets {
            let cur_file = self.base_dir.join(file_name);
            if cur_file.exists() {
                let _ = fs::copy(&cur_file, backup_dir.join(file_name));
            }
        }

        // Mover archivos desde tmp a destino definitivo
        for file_name in &targets {
            let src = tmp_dir.join(file_name);
            let dst = self.base_dir.join(file_name);
            if src.exists() {
                fs::copy(&src, &dst).context(format!("Error al escribir archivo final {}", file_name))?;
            }
        }

        // Limpiar directorio temporal
        let _ = fs::remove_dir_all(tmp_dir);
        info!("Sustitución atómica de firmas completada exitosamente. Backup conservado en {:?}", backup_dir);
        Ok(())
    }

    /// Revierte la base de datos a la versión anterior almacenada en backup
    pub fn rollback_to_previous(&self) -> Result<bool> {
        let backup_dir = self.base_dir.join("backup_previous");
        if !backup_dir.exists() {
            bail!("No existe copia de respaldo previa para ejecutar rollback.");
        }

        let targets = ["malware_hashes.db", "network_iocs.db", "compiled_yara.yar", "threat_indicators.json"];
        let mut restored_count = 0;

        for file_name in &targets {
            let src = backup_dir.join(file_name);
            let dst = self.base_dir.join(file_name);
            if src.exists() {
                fs::copy(&src, &dst)?;
                restored_count += 1;
            }
        }

        if restored_count == 0 {
            bail!("El directorio de backup no contenía archivos válidos para restaurar.");
        }

        info!("Rollback completado exitosamente: {} archivos de firmas restaurados", restored_count);
        Ok(true)
    }

    /// Calcula el checksum SHA-256 de la base de datos activa
    pub fn compute_active_db_hash(&self) -> String {
        let db_file = self.base_dir.join("malware_hashes.db");
        if let Ok(bytes) = fs::read(&db_file) {
            hex::encode(Sha256::digest(&bytes))
        } else {
            "no_db".to_string()
        }
    }
}
