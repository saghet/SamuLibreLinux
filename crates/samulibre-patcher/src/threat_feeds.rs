use crate::package_inventory::{compare_package_versions, PackageInventory};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use tracing::{info, warn};

pub const DEFAULT_CISA_KEV_PATH: &str = "data/vulnerability_feeds/cisa_kev.json";

/// Entrada individual de vulnerabilidad explotada activamente según el catálogo oficial CISA KEV
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CisaKevEntry {
    pub cve_id: String,
    pub vendor_project: String,
    pub product: String,
    pub vulnerability_name: String,
    pub date_added: String,
    pub short_description: String,
    pub required_action: String,
    pub known_ransomware_campaign_use: bool,
    pub affected_package: Option<String>,
    pub min_fixed_version: Option<String>,
}

/// Catálogo CISA KEV estructurado
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CisaKevCatalog {
    pub title: String,
    pub catalog_version: String,
    pub date_released: String,
    pub count: usize,
    pub vulnerabilities: Vec<CisaKevEntry>,
}

/// Entrada de vulnerabilidad según el estándar Open Source Vulnerabilities (OSV)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsvVulnerability {
    pub id: String,
    pub published: Option<String>,
    pub aliases: Vec<String>,
    pub summary: Option<String>,
    pub details: Option<String>,
    pub package_name: String,
    pub ecosystem: String,
    pub fixed_version: Option<String>,
}

/// Hallazgo formal resultante de la correlación entre feeds de amenazas y el inventario del host
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VulnerabilityFinding {
    pub cve: String,
    pub advisory_id: String,
    pub source: String,
    pub package_name: String,
    pub installed_version: String,
    pub fixed_version: String,
    pub title: String,
    pub description: String,
    pub actively_exploited: bool,
    pub ransomware_use: bool,
    pub severity: String,
    pub mitigation_available: bool,
}

/// Motor de feeds de inteligencia de vulnerabilidades y correlación en tiempo de ejecución
pub struct ThreatFeedEngine {
    cisa_kev: HashMap<String, CisaKevEntry>,
    pub osv_entries: Vec<OsvVulnerability>,
    local_storage_dir: PathBuf,
}

impl Default for ThreatFeedEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl ThreatFeedEngine {
    pub fn new() -> Self {
        let mut engine = Self {
            cisa_kev: HashMap::new(),
            osv_entries: Vec::new(),
            local_storage_dir: PathBuf::from("data/vulnerability_feeds"),
        };
        engine.init_default_feeds();
        engine
    }

    pub fn with_storage_dir(dir: impl Into<PathBuf>) -> Self {
        let mut engine = Self {
            cisa_kev: HashMap::new(),
            osv_entries: Vec::new(),
            local_storage_dir: dir.into(),
        };
        engine.init_default_feeds();
        engine
    }

    /// Inicializa los feeds cargando el catálogo CISA KEV local (100% offline / Air-Gapped Ready)
    fn init_default_feeds(&mut self) {
        let primary_path = self.local_storage_dir.join("cisa_kev.json");
        let fallback_path = Path::new(DEFAULT_CISA_KEV_PATH);

        if primary_path.exists() {
            let _ = self.load_cisa_kev_file(&primary_path);
        } else if fallback_path.exists() {
            let _ = self.load_cisa_kev_file(fallback_path);
        } else {
            self.load_embedded_kev_baseline();
        }
    }

    /// Carga el catálogo CISA KEV desde un archivo JSON local validando integridad
    pub fn load_cisa_kev_file(&mut self, path: &Path) -> Result<usize> {
        let content = fs::read_to_string(path)
            .with_context(|| format!("No se pudo leer archivo de feed KEV: {}", path.display()))?;

        let catalog: CisaKevCatalog = serde_json::from_str(&content)
            .with_context(|| "Formato JSON de CISA KEV inválido")?;

        let loaded = catalog.vulnerabilities.len();
        for entry in catalog.vulnerabilities {
            self.cisa_kev.insert(entry.cve_id.clone(), entry);
        }

        info!("Catálogo CISA KEV cargado exitosamente: {} vulnerabilidades activas registradas", loaded);
        Ok(loaded)
    }

    /// Carga catálogo de respaldo embebido si no existen archivos en disco
    fn load_embedded_kev_baseline(&mut self) {
        let baseline = vec![
            CisaKevEntry {
                cve_id: "CVE-2021-4034".to_string(),
                vendor_project: "Polkit".to_string(),
                product: "pkexec".to_string(),
                vulnerability_name: "Polkit pkexec Local Privilege Escalation (PwnKit)".to_string(),
                date_added: "2022-01-26".to_string(),
                short_description: "Local root escalation in pkexec".to_string(),
                required_action: "Update polkit or remove SUID bit".to_string(),
                known_ransomware_campaign_use: true,
                affected_package: Some("polkit".to_string()),
                min_fixed_version: Some("0.120-1".to_string()),
            },
            CisaKevEntry {
                cve_id: "CVE-2024-6387".to_string(),
                vendor_project: "OpenSSH".to_string(),
                product: "sshd".to_string(),
                vulnerability_name: "OpenSSH Server regreSSHion Remote Code Execution".to_string(),
                date_added: "2024-07-08".to_string(),
                short_description: "Signal handler race condition in sshd".to_string(),
                required_action: "Upgrade OpenSSH to 9.8p1".to_string(),
                known_ransomware_campaign_use: false,
                affected_package: Some("openssh".to_string()),
                min_fixed_version: Some("9.8p1-1".to_string()),
            },
            CisaKevEntry {
                cve_id: "CVE-2022-0847".to_string(),
                vendor_project: "Linux Kernel".to_string(),
                product: "splice/pipe".to_string(),
                vulnerability_name: "Dirty Pipe: Linux Kernel Arbitrary File Overwrite".to_string(),
                date_added: "2022-03-10".to_string(),
                short_description: "Arbitrary write in read-only files".to_string(),
                required_action: "Upgrade kernel >= 5.16.11 / 5.15.25".to_string(),
                known_ransomware_campaign_use: true,
                affected_package: Some("linux".to_string()),
                min_fixed_version: Some("5.16.11-1".to_string()),
            },
        ];

        for entry in baseline {
            self.cisa_kev.insert(entry.cve_id.clone(), entry);
        }
    }

    /// Correlaciona el catálogo CISA KEV con el inventario real de paquetes del equipo
    /// Genera hallazgos únicamente cuando el software afectado está físicamente instalado
    /// y su versión es vulnerable.
    pub fn correlate_with_inventory(&self, inventory: &PackageInventory) -> Vec<VulnerabilityFinding> {
        let mut findings = Vec::new();

        for entry in self.cisa_kev.values() {
            let pkg_name = match &entry.affected_package {
                Some(p) => p.as_str(),
                None => continue,
            };

            // Comprobar si el paquete está instalado en el sistema
            let installed_pkg = match inventory.get_package(pkg_name) {
                Some(p) => p,
                None => {
                    // Verificación de nombres alternativos comunes (ej. openssh-server, libc6, policykit-1)
                    let alt_name = match pkg_name {
                        "openssh" => "openssh-server",
                        "glibc" => "libc6",
                        "polkit" => "policykit-1",
                        _ => continue,
                    };
                    match inventory.get_package(alt_name) {
                        Some(alt) => alt,
                        None => continue, // El paquete no está instalado: inmune
                    }
                }
            };

            let min_fixed = match &entry.min_fixed_version {
                Some(v) => v.as_str(),
                None => continue,
            };

            let full_installed_version = match &installed_pkg.release {
                Some(rel) => format!("{}-{}", installed_pkg.version, rel),
                None => installed_pkg.version.clone(),
            };

            // Comparar versiones determinísticamente
            let is_vulnerable = compare_package_versions(&full_installed_version, min_fixed) == std::cmp::Ordering::Less;

            if is_vulnerable {
                warn!(
                    "HALLAZGO DE AMENAZA CISA KEV: Paquete '{}' ({}) es vulnerable a {} ({})",
                    installed_pkg.name, full_installed_version, entry.cve_id, entry.vulnerability_name
                );

                findings.push(VulnerabilityFinding {
                    cve: entry.cve_id.clone(),
                    advisory_id: format!("CISA-KEV-{}", entry.cve_id),
                    source: "CISA KEV (Known Exploited Vulnerabilities)".to_string(),
                    package_name: installed_pkg.name.clone(),
                    installed_version: full_installed_version,
                    fixed_version: min_fixed.to_string(),
                    title: entry.vulnerability_name.clone(),
                    description: entry.short_description.clone(),
                    actively_exploited: true,
                    ransomware_use: entry.known_ransomware_campaign_use,
                    severity: "Crítica (Explotada activamente en la naturaleza)".to_string(),
                    mitigation_available: true,
                });
            }
        }

        findings
    }

    pub fn get_total_cisa_kev_count(&self) -> usize {
        self.cisa_kev.len()
    }

    pub fn get_entry(&self, cve: &str) -> Option<&CisaKevEntry> {
        self.cisa_kev.get(cve)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::package_inventory::InstalledPackage;

    #[test]
    fn test_cisa_kev_loading() {
        let engine = ThreatFeedEngine::new();
        assert!(engine.get_total_cisa_kev_count() >= 3);
        assert!(engine.get_entry("CVE-2021-4034").is_some());
        assert!(engine.get_entry("CVE-2024-6387").is_some());
    }

    #[test]
    fn test_correlation_vulnerable_package() {
        let engine = ThreatFeedEngine::new();

        // Crear inventario simulado con un polkit vulnerable (versión 0.105-1 antigua)
        let mut inv = PackageInventory::empty();
        inv.packages.insert("polkit".to_string(), InstalledPackage {
            name: "polkit".to_string(),
            version: "0.105".to_string(),
            release: Some("1".to_string()),
            arch: Some("x86_64".to_string()),
            package_manager: "pacman".to_string(),
        });

        let findings = engine.correlate_with_inventory(&inv);
        assert!(!findings.is_empty(), "Debería detectar que polkit 0.105 es vulnerable");
        assert_eq!(findings[0].cve, "CVE-2021-4034");
        assert!(findings[0].actively_exploited);
        assert!(findings[0].ransomware_use);
    }

    #[test]
    fn test_correlation_patched_package() {
        let engine = ThreatFeedEngine::new();

        // Crear inventario simulado con un polkit actualizado (versión 128-1 actual de Garuda)
        let mut inv = PackageInventory::empty();
        inv.packages.insert("polkit".to_string(), InstalledPackage {
            name: "polkit".to_string(),
            version: "128".to_string(),
            release: Some("1".to_string()),
            arch: Some("x86_64".to_string()),
            package_manager: "pacman".to_string(),
        });

        let findings = engine.correlate_with_inventory(&inv);
        assert!(findings.is_empty(), "Polkit 128-1 no debe generar hallazgo vulnerable");
    }
}
