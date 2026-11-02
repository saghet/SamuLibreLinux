use super::models::{ProviderStatus, UpdateEvidence, UpdateStatus};
use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use tracing::info;

/// Centro de Auditoría y Evidencias Técnicas de Actualización (Update Evidence & Audit Center)
pub struct UpdateAuditCenter {
    evidence_file: PathBuf,
}

impl UpdateAuditCenter {
    pub fn new(storage_dir: &Path) -> Self {
        Self {
            evidence_file: storage_dir.join("update_evidence.json"),
        }
    }

    /// Registra permanentemente una evidencia de actualización con firma criptográfica
    pub fn record_evidence(&self, evidence: &mut UpdateEvidence) -> Result<String> {
        // 1. Calcular hash criptográfico de integridad de la evidencia completa
        let serialized_core = format!(
            "{}:{}:{}:{}:{}:{:?}:{}",
            evidence.operation_id,
            evidence.started_at,
            evidence.completed_at,
            evidence.total_indicators_downloaded,
            evidence.new_indicators_added,
            evidence.status,
            evidence.new_db_version
        );
        evidence.evidence_hash_sha256 = hex::encode(Sha256::digest(serialized_core.as_bytes()));

        // 2. Cargar historial existente
        let mut history = self.get_all_evidence()?;
        // Evitar duplicados del mismo ID de operación
        history.retain(|e| e.operation_id != evidence.operation_id);
        history.insert(0, evidence.clone());

        // Mantener hasta 250 operaciones en el historial persistente
        if history.len() > 250 {
            history.truncate(250);
        }

        let json_bytes = serde_json::to_vec_pretty(&history)
            .context("Error serializando historial de evidencias")?;
        fs::write(&self.evidence_file, json_bytes)
            .context("Error escribiendo archivo de evidencias de actualización")?;

        info!("Evidencia registrada con éxito en el Centro de Auditoría: {}", evidence.operation_id);
        Ok(evidence.operation_id.clone())
    }

    /// Obtiene todas las evidencias registradas
    pub fn get_all_evidence(&self) -> Result<Vec<UpdateEvidence>> {
        if !self.evidence_file.exists() {
            return Ok(Vec::new());
        }
        let data = fs::read(&self.evidence_file)
            .context("Error leyendo archivo update_evidence.json")?;
        let list: Vec<UpdateEvidence> = serde_json::from_slice(&data).unwrap_or_default();
        Ok(list)
    }

    /// Obtiene una evidencia específica por su ID de operación
    pub fn get_evidence(&self, operation_id: &str) -> Result<Option<UpdateEvidence>> {
        let all = self.get_all_evidence()?;
        Ok(all.into_iter().find(|e| e.operation_id == operation_id))
    }

    /// Obtiene la última evidencia registrada
    pub fn get_latest_evidence(&self) -> Result<Option<UpdateEvidence>> {
        let all = self.get_all_evidence()?;
        Ok(all.into_iter().next())
    }

    /// Exporta una evidencia en formato JSON estructurado
    pub fn export_json(&self, operation_id: &str) -> Result<String> {
        let ev = self.get_evidence(operation_id)?
            .ok_or_else(|| anyhow::anyhow!("Operación de actualización no encontrada: {}", operation_id))?;
        Ok(serde_json::to_string_pretty(&ev)?)
    }

    /// Exporta una evidencia en formato CSV delimitado
    pub fn export_csv(&self, operation_id: &str) -> Result<String> {
        let ev = self.get_evidence(operation_id)?
            .ok_or_else(|| anyhow::anyhow!("Operación no encontrada: {}", operation_id))?;

        let mut csv = String::new();
        csv.push_str("operation_id,started_at,completed_at,duration_ms,status,profile,provider_id,provider_name,provider_status,fetched,accepted,payload_sha256\n");

        for p in &ev.providers {
            let status_str = match &p.status {
                ProviderStatus::Success => "SUCCESS".to_string(),
                ProviderStatus::Failed(e) => format!("FAILED: {}", e.replace(',', ";")),
                ProviderStatus::Skipped(r) => format!("SKIPPED: {}", r.replace(',', ";")),
                ProviderStatus::RateLimited => "RATE_LIMITED".to_string(),
            };
            csv.push_str(&format!(
                "{},{},{},{},{},{},{},{},{},{},{},{}\n",
                ev.operation_id,
                ev.started_at,
                ev.completed_at,
                ev.duration_ms,
                ev.status,
                ev.profile,
                p.provider_id,
                p.provider_name,
                status_str,
                p.indicators_fetched,
                p.indicators_accepted,
                p.payload_sha256.as_deref().unwrap_or("N/A")
            ));
        }

        Ok(csv)
    }

    /// Exporta un informe forense formal e inmutable en HTML5 auto-contenido
    pub fn export_html_report(&self, operation_id: &str) -> Result<String> {
        let ev = self.get_evidence(operation_id)?
            .ok_or_else(|| anyhow::anyhow!("Operación no encontrada: {}", operation_id))?;

        let status_color = match ev.status {
            UpdateStatus::Completada => "#10b981",
            UpdateStatus::CompletadaParcialmente => "#f59e0b",
            UpdateStatus::SinCambios => "#3b82f6",
            UpdateStatus::Fallida => "#ef4444",
            UpdateStatus::Revertida => "#8b5cf6",
            UpdateStatus::EnProceso => "#06b6d4",
        };

        let mut providers_rows = String::new();
        for p in &ev.providers {
            let (status_badge, row_bg): (String, &str) = match &p.status {
                ProviderStatus::Success => (
                    r#"<span style="color:#10b981;font-weight:600;">✔ COMPLETADO</span>"#.to_string(),
                    "rgba(16, 185, 129, 0.05)",
                ),
                ProviderStatus::Failed(err) => (
                    format!(r#"<span style="color:#ef4444;font-weight:600;">✘ ERROR: {}</span>"#, err),
                    "rgba(239, 68, 68, 0.05)",
                ),
                ProviderStatus::Skipped(reason) => (
                    format!(r#"<span style="color:#94a3b8;font-weight:500;">⏸ OMITIDO: {}</span>"#, reason),
                    "transparent",
                ),
                ProviderStatus::RateLimited => (
                    r#"<span style="color:#f59e0b;font-weight:600;">⏳ RATE LIMIT</span>"#.to_string(),
                    "rgba(245, 158, 11, 0.05)",
                ),
            };

            providers_rows.push_str(&format!(
                r#"<tr style="background:{};border-bottom:1px solid #334155;">
                    <td style="padding:12px;font-family:monospace;font-weight:600;color:#f8fafc;">{}</td>
                    <td style="padding:12px;color:#cbd5e1;">{}</td>
                    <td style="padding:12px;">{}</td>
                    <td style="padding:12px;text-align:right;font-family:monospace;color:#38bdf8;">{}</td>
                    <td style="padding:12px;text-align:right;font-family:monospace;color:#10b981;">{}</td>
                    <td style="padding:12px;text-align:right;font-family:monospace;color:#94a3b8;">{} ms</td>
                </tr>"#,
                row_bg, p.provider_id, p.provider_name, status_badge, p.indicators_fetched, p.indicators_accepted, p.duration_ms
            ));
        }

        let html = format!(
            r#"<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>Informe de Actualización - SamuLibre Threat Intel ({op_id})</title>
    <style>
        body {{ background-color: #0b0f17; color: #f8fafc; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; margin: 0; padding: 40px; }}
        .container {{ max-width: 900px; margin: 0 auto; background: #111827; border: 1px solid #1e293b; border-radius: 20px; padding: 32px; box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5); }}
        .header {{ display: flex; justify-content: space-between; align-items: flex-start; border-bottom: 1px solid #1e293b; padding-bottom: 24px; margin-bottom: 24px; }}
        .badge {{ background: {status_color}22; color: {status_color}; border: 1px solid {status_color}55; padding: 6px 14px; border-radius: 9999px; font-weight: 700; font-size: 13px; text-transform: uppercase; font-family: monospace; }}
        .metrics-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 28px; }}
        .card {{ background: rgba(255, 255, 255, 0.02); border: 1px solid #1e293b; border-radius: 14px; padding: 16px; }}
        .card-label {{ font-size: 12px; color: #94a3b8; font-weight: 500; text-transform: uppercase; }}
        .card-val {{ font-size: 24px; font-weight: 700; color: #ffffff; font-family: monospace; margin-top: 6px; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 12px; font-size: 13px; }}
        th {{ text-align: left; padding: 12px; background: #0f172a; color: #94a3b8; font-weight: 600; text-transform: uppercase; font-size: 11px; letter-spacing: 0.05em; }}
        .footer {{ margin-top: 32px; padding-top: 20px; border-top: 1px solid #1e293b; font-size: 11px; color: #64748b; display: flex; justify-content: space-between; font-family: monospace; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div>
                <h1 style="margin:0 0 6px 0; font-size: 22px; color: #ffffff;">Certificado de Auditoría de Actualización</h1>
                <p style="margin:0; font-size: 13px; color: #94a3b8;">SamuLibre Linux Threat Intelligence Center • Operación: <code style="color:#38bdf8;">{op_id}</code></p>
            </div>
            <div class="badge">{status_str}</div>
        </div>

        <div class="metrics-grid">
            <div class="card">
                <div class="card-label">Indicadores Totales</div>
                <div class="card-val" style="color:#38bdf8;">{total_downloaded}</div>
            </div>
            <div class="card">
                <div class="card-label">Nuevas Firmas</div>
                <div class="card-val" style="color:#10b981;">{new_added}</div>
            </div>
            <div class="card">
                <div class="card-label">Duplicados Fusionados</div>
                <div class="card-val" style="color:#f59e0b;">{duplicates}</div>
            </div>
            <div class="card">
                <div class="card-label">Duración Operación</div>
                <div class="card-val" style="color:#a855f7;">{duration} ms</div>
            </div>
        </div>

        <h3 style="font-size: 15px; margin: 0 0 8px 0; color: #f8fafc;">Desglose por Proveedor de Inteligencia</h3>
        <table>
            <thead>
                <tr>
                    <th>Proveedor</th>
                    <th>Fuente</th>
                    <th>Resultado</th>
                    <th style="text-align:right;">Recibidos</th>
                    <th style="text-align:right;">Aceptados</th>
                    <th style="text-align:right;">Latencia</th>
                </tr>
            </thead>
            <tbody>
                {providers_rows}
            </tbody>
        </table>

        <div style="margin-top: 24px; padding: 16px; background: rgba(56, 189, 248, 0.03); border: 1px solid rgba(56, 189, 248, 0.15); border-radius: 14px;">
            <p style="margin:0 0 6px 0; font-size: 12px; font-weight: 600; color: #38bdf8;">Sello de Verificación Criptográfica</p>
            <p style="margin:0; font-family: monospace; font-size: 11px; color: #94a3b8; word-break: break-all;">SHA-256: {evidence_hash}</p>
        </div>

        <div class="footer">
            <span>Sistema: {distro} | SamuLibre {version}</span>
            <span>Fecha de emisión: {completed_at}</span>
        </div>
    </div>
</body>
</html>"#,
            op_id = ev.operation_id,
            status_color = status_color,
            status_str = ev.status,
            total_downloaded = ev.total_indicators_downloaded,
            new_added = ev.new_indicators_added,
            duplicates = ev.duplicate_indicators_merged,
            duration = ev.duration_ms,
            providers_rows = providers_rows,
            evidence_hash = ev.evidence_hash_sha256,
            distro = ev.linux_distro,
            version = ev.antivirus_version,
            completed_at = ev.completed_at
        );

        Ok(html)
    }
}
