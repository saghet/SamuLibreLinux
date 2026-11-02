use anyhow::Result;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostSystemInfo {
    pub hostname: String,
    pub os_name: String,
    pub kernel_version: String,
    pub architecture: String,
    pub generated_at: String,
    pub samulibre_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportThreatItem {
    pub id: String,
    pub timestamp: String,
    pub file_path: String,
    pub threat_name: String,
    pub severity: String,
    pub engine: String,
    pub action_taken: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportSocketItem {
    pub protocol: String,
    pub local_address: String,
    pub local_port: u16,
    pub remote_address: String,
    pub state: String,
    pub pid: Option<u32>,
    pub process_name: Option<String>,
    pub is_suspicious: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportCveItem {
    pub cve: String,
    pub title: String,
    pub component: String,
    pub severity: String,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForensicReportData {
    pub system_info: HostSystemInfo,
    pub daemon_active: bool,
    pub daemon_socket: String,
    pub total_threats: usize,
    pub neutralized_threats: usize,
    pub pending_threats: usize,
    pub canaries_deployed: usize,
    pub canaries_intact: bool,
    pub active_virtual_patches: usize,
    pub native_repaired_cves: usize,
    pub cve_list: Vec<ReportCveItem>,
    pub threats: Vec<ReportThreatItem>,
    pub sockets: Vec<ReportSocketItem>,
}

impl ForensicReportData {
    pub fn collect_current(
        core: &samulibre_core::SamuLibreCore,
        db_path: &Path,
        daemon_active: bool,
        daemon_socket: &str,
    ) -> Self {
        let hostname = std::env::var("HOSTNAME")
            .or_else(|_| std::env::var("HOST"))
            .unwrap_or_else(|_| {
                fs::read_to_string("/etc/hostname")
                    .map(|s| s.trim().to_string())
                    .unwrap_or_else(|_| "localhost".to_string())
            });

        let kernel_version = fs::read_to_string("/proc/sys/kernel/osrelease")
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|_| "Linux Unknown".to_string());

        let os_name = fs::read_to_string("/etc/os-release")
            .ok()
            .and_then(|content| {
                for line in content.lines() {
                    if let Some(val) = line.strip_prefix("PRETTY_NAME=") {
                        return Some(val.trim_matches('"').to_string());
                    }
                }
                None
            })
            .unwrap_or_else(|| "Linux (GNU/Linux)".to_string());

        let arch = std::env::consts::ARCH.to_string();

        let system_info = HostSystemInfo {
            hostname,
            os_name,
            kernel_version,
            architecture: arch,
            generated_at: Utc::now().to_rfc3339(),
            samulibre_version: "2.0.32".to_string(),
        };

        // Estado del núcleo y canarios
        let status = core.get_status();
        let canaries_intact = {
            let shield = core.shield.lock().unwrap();
            shield.check_canary_integrity().is_empty()
        };

        // Parches virtuales
        let cve_list = {
            let mut patcher = core.patcher.lock().unwrap();
            let (_, _, _) = patcher.scan_and_evaluate(None);
            let mut list = Vec::new();
            for r in patcher.get_rules() {
                list.push(ReportCveItem {
                    cve: r.cve.clone(),
                    title: r.title.clone(),
                    component: r.target_component.clone(),
                    severity: r.severity.to_string(),
                    status: format!("{:?}", r.status),
                });
            }
            list
        };

        // Historial de amenazas desde SQLite
        let mut threats = Vec::new();
        let mut total_threats = 0;
        let mut neutralized_threats = 0;
        let mut pending_threats = 0;

        if let Ok(db) = samulibre_core::SecurityEventDatabase::new(db_path) {
            if let Ok(stats) = db.get_summary_stats() {
                total_threats = stats.total_threats;
                neutralized_threats = stats.neutralized_threats;
                pending_threats = stats.pending_threats;
            }
            if let Ok(th_list) = db.list_threats(50) {
                for t in th_list {
                    threats.push(ReportThreatItem {
                        id: t.id,
                        timestamp: t.timestamp,
                        file_path: t.file_path,
                        threat_name: t.threat_name,
                        severity: t.severity,
                        engine: t.engine,
                        action_taken: t.action_taken,
                    });
                }
            }
        }

        // Sockets de red
        let sockets_raw = core.get_network_sockets();
        let mut sockets = Vec::new();
        for s in sockets_raw.iter().take(35) {
            sockets.push(ReportSocketItem {
                protocol: s.protocol.clone(),
                local_address: s.local_address.clone(),
                local_port: s.local_port,
                remote_address: s.remote_address.clone(),
                state: s.state.clone(),
                pid: Some(s.pid),
                process_name: Some(s.process_name.clone()),
                is_suspicious: s.is_risk_port,
            });
        }

        Self {
            system_info,
            daemon_active,
            daemon_socket: daemon_socket.to_string(),
            total_threats,
            neutralized_threats,
            pending_threats,
            canaries_deployed: status.canaries_deployed_count,
            canaries_intact,
            active_virtual_patches: status.active_virtual_patches_count,
            native_repaired_cves: status.native_repaired_cves_count,
            cve_list,
            threats,
            sockets,
        }
    }

    pub fn to_json(&self) -> Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    pub fn to_markdown(&self) -> String {
        let mut md = String::new();
        md.push_str(&format!("# Informe Forense y de Auditoría de Seguridad SamuLibre\n\n"));
        md.push_str(&format!("* **Host:** {}\n", self.system_info.hostname));
        md.push_str(&format!("* **SO:** {} ({})\n", self.system_info.os_name, self.system_info.architecture));
        md.push_str(&format!("* **Kernel:** {}\n", self.system_info.kernel_version));
        md.push_str(&format!("* **Fecha:** {}\n", self.system_info.generated_at));
        md.push_str(&format!("* **Versión Suite:** SamuLibre {}\n", self.system_info.samulibre_version));
        md.push_str(&format!("* **Demonio samulibred:** {}\n\n", if self.daemon_active { "Activo (Conectado)" } else { "Inactivo (Modo Local)" }));

        md.push_str("## Resumen Ejecutivo de Métricas\n\n");
        md.push_str(&format!("| Métrica | Valor |\n|---|---|\n"));
        md.push_str(&format!("| Amenazas Neutralizadas | {} |\n", self.neutralized_threats));
        md.push_str(&format!("| Amenazas Pendientes | {} |\n", self.pending_threats));
        md.push_str(&format!("| Canarios Anti-Ransomware | {} (Estado: {}) |\n", self.canaries_deployed, if self.canaries_intact { "Intactos" } else { "ALERTA" }));
        md.push_str(&format!("| Parches Virtuales Activos | {} |\n", self.active_virtual_patches));
        md.push_str(&format!("| CVEs Mitigados Nativamente | {} |\n\n", self.native_repaired_cves));

        md.push_str("## Vulnerabilidades y Cumplimiento de Kernel\n\n");
        md.push_str("| CVE | Componente | Severidad | Estado |\n|---|---|---|---|\n");
        for cve in &self.cve_list {
            md.push_str(&format!("| {} | {} | {} | {} |\n", cve.cve, cve.component, cve.severity, cve.status));
        }

        md.push_str("\n## Historial de Amenazas Recientes (SQLite WAL)\n\n");
        if self.threats.is_empty() {
            md.push_str("*No hay amenazas registradas en la base de datos.*\n");
        } else {
            md.push_str("| Fecha | Archivo | Amenaza | Severidad | Acción |\n|---|---|---|---|---|\n");
            for t in &self.threats {
                md.push_str(&format!("| {} | `{}` | {} | {} | {} |\n", t.timestamp, t.file_path, t.threat_name, t.severity, t.action_taken));
            }
        }

        md.push_str("\n## Sockets de Red y Puertos Abiertos\n\n");
        md.push_str("| Protocolo | Puerto Local | Estado | PID | Proceso | ¿Sospechoso? |\n|---|---|---|---|---|:---:|\n");
        for s in &self.sockets {
            let pid_str = s.pid.map(|p| p.to_string()).unwrap_or_else(|| "-".to_string());
            let proc_str = s.process_name.as_deref().unwrap_or("-");
            let susp = if s.is_suspicious { "⚠️ SÍ" } else { "No" };
            md.push_str(&format!("| {} | {} | {} | {} | {} | {} |\n", s.protocol, s.local_port, s.state, pid_str, proc_str, susp));
        }

        md
    }

    pub fn to_html(&self) -> String {
        let status_color = if self.pending_threats > 0 || !self.canaries_intact {
            "#ef4444"
        } else {
            "#10b981"
        };
        let status_text = if self.pending_threats > 0 {
            "ATENCIÓN REQUERIDA"
        } else if !self.canaries_intact {
            "ALERTA RANSOMWARE"
        } else {
            "ENDPOINT PROTEGIDO Y CUMPLIENDO"
        };

        let mut cve_rows = String::new();
        for cve in &self.cve_list {
            let badge_class = match cve.status.as_str() {
                "NativePatchInstalled" => "badge-success",
                "VirtualPatchActive" => "badge-warning",
                _ => "badge-danger",
            };
            cve_rows.push_str(&format!(
                "<tr><td><strong>{}</strong></td><td>{}</td><td><span class=\"badge {}\">{}</span></td><td><span class=\"badge {}\">{}</span></td></tr>",
                cve.cve, cve.component, if cve.severity == "Critical" { "badge-danger" } else { "badge-warning" }, cve.severity, badge_class, cve.status
            ));
        }

        let mut threat_rows = String::new();
        if self.threats.is_empty() {
            threat_rows.push_str("<tr><td colspan=\"5\" style=\"text-align:center; color:#9ca3af;\">No hay incidentes o amenazas registrados en la base de datos.</td></tr>");
        } else {
            for t in &self.threats {
                threat_rows.push_str(&format!(
                    "<tr><td>{}</td><td><code>{}</code></td><td><strong>{}</strong></td><td><span class=\"badge badge-danger\">{}</span></td><td><span class=\"badge badge-success\">{}</span></td></tr>",
                    t.timestamp, t.file_path, t.threat_name, t.severity, t.action_taken
                ));
            }
        }

        let mut socket_rows = String::new();
        for s in &self.sockets {
            let susp_badge = if s.is_suspicious {
                "<span class=\"badge badge-danger\">Sospechoso</span>"
            } else {
                "<span class=\"badge badge-info\">Normal</span>"
            };
            let pid_str = s.pid.map(|p| p.to_string()).unwrap_or_else(|| "-".to_string());
            let proc_str = s.process_name.as_deref().unwrap_or("-");
            socket_rows.push_str(&format!(
                "<tr><td>{}</td><td><strong>:{}</strong></td><td>{}</td><td>{}</td><td><code>{}</code></td><td>{}</td></tr>",
                s.protocol, s.local_port, s.state, pid_str, proc_str, susp_badge
            ));
        }

        format!(
            r#"<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SamuLibre Linux - Informe Forense de Cumplimiento</title>
    <style>
        :root {{
            --bg: #0b0f19;
            --card-bg: #111827;
            --border: #1f2937;
            --text: #f9fafb;
            --text-muted: #9ca3af;
            --cyan: #06b6d4;
            --emerald: #10b981;
            --amber: #f59e0b;
            --rose: #f43f5e;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            background-color: var(--bg);
            color: var(--text);
            line-height: 1.6;
            padding: 30px 20px;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 2px solid var(--border);
            padding-bottom: 20px;
            margin-bottom: 30px;
            flex-wrap: wrap;
            gap: 15px;
        }}
        .logo-title h1 {{ font-size: 24px; color: var(--cyan); letter-spacing: -0.5px; display: flex; align-items: center; gap: 10px; }}
        .logo-title p {{ color: var(--text-muted); font-size: 13px; margin-top: 4px; }}
        .status-pill {{
            background: rgba(16, 185, 129, 0.1);
            color: {status_color};
            border: 1px solid {status_color};
            padding: 6px 16px;
            border-radius: 9999px;
            font-weight: 700;
            font-size: 13px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        .grid-metrics {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        .card {{
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 20px;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.3);
        }}
        .card h3 {{ font-size: 12px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.8px; margin-bottom: 8px; }}
        .card .value {{ font-size: 28px; font-weight: 800; color: #fff; }}
        .card .sub {{ font-size: 12px; color: var(--text-muted); margin-top: 4px; }}
        .section-title {{
            font-size: 18px;
            color: var(--cyan);
            margin: 30px 0 15px 0;
            display: flex;
            align-items: center;
            gap: 8px;
            border-left: 4px solid var(--cyan);
            padding-left: 10px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            background: var(--card-bg);
            border-radius: 8px;
            overflow: hidden;
            border: 1px solid var(--border);
            margin-bottom: 25px;
        }}
        th, td {{ padding: 12px 16px; text-align: left; font-size: 13px; }}
        th {{ background: #1f2937; color: #d1d5db; text-transform: uppercase; font-size: 11px; letter-spacing: 0.5px; }}
        tr:not(:last-child) td {{ border-bottom: 1px solid var(--border); }}
        tr:hover td {{ background: rgba(255, 255, 255, 0.02); }}
        code {{ background: #1e293b; color: #38bdf8; padding: 2px 6px; border-radius: 4px; font-size: 12px; font-family: monospace; }}
        .badge {{
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 600;
            display: inline-block;
        }}
        .badge-success {{ background: rgba(16, 185, 129, 0.15); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.3); }}
        .badge-warning {{ background: rgba(245, 158, 11, 0.15); color: #fbbf24; border: 1px solid rgba(245, 158, 11, 0.3); }}
        .badge-danger {{ background: rgba(244, 63, 94, 0.15); color: #fb7185; border: 1px solid rgba(244, 63, 94, 0.3); }}
        .badge-info {{ background: rgba(6, 182, 212, 0.15); color: #22d3ee; border: 1px solid rgba(6, 182, 212, 0.3); }}
        footer {{
            border-top: 1px solid var(--border);
            padding-top: 20px;
            margin-top: 40px;
            color: var(--text-muted);
            font-size: 12px;
            display: flex;
            justify-content: space-between;
            flex-wrap: wrap;
            gap: 10px;
        }}
        @media print {{
            body {{ background: #fff; color: #000; padding: 0; }}
            .card, table {{ background: #fff; border-color: #ccc; box-shadow: none; }}
            th {{ background: #f0f0f0; color: #000; }}
            td {{ color: #000; }}
            code {{ background: #eee; color: #000; }}
            .status-pill {{ border-color: #000; color: #000; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="logo-title">
                <h1>🛡️ SamuLibre Linux Security Suite</h1>
                <p>Auditoría Forense de Endpoint, Conformidad de Kernel y Telemetría de Red Local</p>
            </div>
            <div class="status-pill">{status_text}</div>
        </header>

        <!-- Métricas Principales -->
        <div class="grid-metrics">
            <div class="card">
                <h3>Amenazas Neutralizadas</h3>
                <div class="value" style="color:var(--emerald);">{neutralized_threats}</div>
                <div class="sub">Total en SQLite: {total_threats} ({pending_threats} pendientes)</div>
            </div>
            <div class="card">
                <h3>Mitigaciones de Kernel</h3>
                <div class="value" style="color:var(--cyan);">{active_virtual_patches}</div>
                <div class="sub">{native_repaired_cves} CVEs nativos en kernel</div>
            </div>
            <div class="card">
                <h3>Trampas Anti-Ransomware</h3>
                <div class="value" style="color:var(--amber);">{canaries_deployed}</div>
                <div class="sub">{canary_status_str}</div>
            </div>
            <div class="card">
                <h3>Demonio samulibred</h3>
                <div class="value" style="font-size:20px; color:{daemon_color};">{daemon_label}</div>
                <div class="sub">Socket: <code>{daemon_socket}</code></div>
            </div>
        </div>

        <!-- Telemetría del Sistema Operativo -->
        <h2 class="section-title">Información del Host y Entorno</h2>
        <table>
            <tr><th style="width:25%;">Parámetro</th><th>Valor del Sistema</th></tr>
            <tr><td>Nombre de Host</td><td><strong>{hostname}</strong></td></tr>
            <tr><td>Distribución del Sistema Operativo</td><td>{os_name} ({arch})</td></tr>
            <tr><td>Versión del Kernel Linux</td><td><code>{kernel_version}</code></td></tr>
            <tr><td>Versión de SamuLibre Suite</td><td>v{samulibre_version} (Open Source, Zero-Cloud)</td></tr>
            <tr><td>Fecha y Hora de Generación</td><td>{generated_at}</td></tr>
        </table>

        <!-- Tabla de CVEs -->
        <h2 class="section-title">Cumplimiento y Diagnóstico de Vulnerabilidades CVE</h2>
        <table>
            <thead>
                <tr>
                    <th>Identificador</th>
                    <th>Componente Protegido</th>
                    <th>Severidad</th>
                    <th>Estado de Mitigación</th>
                </tr>
            </thead>
            <tbody>
                {cve_rows}
            </tbody>
        </table>

        <!-- Historial Forense -->
        <h2 class="section-title">Historial Forense de Amenazas (SQLite WAL)</h2>
        <table>
            <thead>
                <tr>
                    <th>Fecha / Hora</th>
                    <th>Ruta del Archivo</th>
                    <th>Amenaza Detectada</th>
                    <th>Severidad</th>
                    <th>Acción Aplicada</th>
                </tr>
            </thead>
            <tbody>
                {threat_rows}
            </tbody>
        </table>

        <!-- Sockets Activos -->
        <h2 class="section-title">Inspección de Conexiones de Red y Procesos Vinculados</h2>
        <table>
            <thead>
                <tr>
                    <th>Protocolo</th>
                    <th>Puerto Local</th>
                    <th>Estado TCP</th>
                    <th>PID</th>
                    <th>Nombre del Proceso</th>
                    <th>Evaluación</th>
                </tr>
            </thead>
            <tbody>
                {socket_rows}
            </tbody>
        </table>

        <footer>
            <div>SamuLibre Linux Security Suite &copy; 2026 SamuLibre Security Community. Licencia GPL-3.0.</div>
            <div>Zero-Cloud Mandate: 100% Procesado y Almacenado Localmente sin Telemetría Externa.</div>
        </footer>
    </div>
</body>
</html>"#,
            status_color = status_color,
            status_text = status_text,
            neutralized_threats = self.neutralized_threats,
            total_threats = self.total_threats,
            pending_threats = self.pending_threats,
            active_virtual_patches = self.active_virtual_patches,
            native_repaired_cves = self.native_repaired_cves,
            canaries_deployed = self.canaries_deployed,
            canary_status_str = if self.canaries_intact { "Canarios 100% Intactos" } else { "Trampa detonada" },
            daemon_color = if self.daemon_active { "var(--emerald)" } else { "var(--amber)" },
            daemon_label = if self.daemon_active { "CONECTADO" } else { "MODO LOCAL" },
            daemon_socket = self.daemon_socket,
            hostname = self.system_info.hostname,
            os_name = self.system_info.os_name,
            arch = self.system_info.architecture,
            kernel_version = self.system_info.kernel_version,
            samulibre_version = self.system_info.samulibre_version,
            generated_at = self.system_info.generated_at,
            cve_rows = cve_rows,
            threat_rows = threat_rows,
            socket_rows = socket_rows
        )
    }
}
