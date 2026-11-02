use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::process::Command;
use std::time::Instant;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InstalledPackage {
    pub name: String,
    pub version: String,
    pub release: Option<String>,
    pub arch: Option<String>,
    pub package_manager: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageInventory {
    pub packages: HashMap<String, InstalledPackage>,
    pub package_manager: String,
    pub scan_duration_ms: u64,
    pub total_packages: usize,
}

impl Default for PackageInventory {
    fn default() -> Self {
        Self::empty()
    }
}

impl PackageInventory {
    pub fn empty() -> Self {
        Self {
            packages: HashMap::new(),
            package_manager: "none".to_string(),
            scan_duration_ms: 0,
            total_packages: 0,
        }
    }

    /// Autodetecta el gestor de paquetes de la distribución Linux actual
    /// e indexa todos los paquetes instalados en memoria.
    pub fn autodetect() -> Self {
        let start = Instant::now();

        // 1. Intentar Arch Linux / Garuda / Manjaro (Pacman)
        if Path::new("/var/lib/pacman/local").is_dir() {
            if let Some(pkgs) = Self::load_from_pacman_db() {
                let duration = start.elapsed().as_millis() as u64;
                info!("Inventario de paquetes cargado desde Pacman DB: {} paquetes en {} ms", pkgs.len(), duration);
                return Self {
                    total_packages: pkgs.len(),
                    packages: pkgs,
                    package_manager: "pacman".to_string(),
                    scan_duration_ms: duration,
                };
            }
        }

        // 2. Intentar Debian / Ubuntu / Linux Mint (dpkg)
        if Path::new("/var/lib/dpkg/status").is_file() {
            if let Some(pkgs) = Self::load_from_dpkg_status() {
                let duration = start.elapsed().as_millis() as u64;
                info!("Inventario de paquetes cargado desde dpkg status: {} paquetes en {} ms", pkgs.len(), duration);
                return Self {
                    total_packages: pkgs.len(),
                    packages: pkgs,
                    package_manager: "dpkg".to_string(),
                    scan_duration_ms: duration,
                };
            }
        }

        // 3. Intentar Red Hat / Fedora / CentOS / Rocky (rpm)
        if let Some(pkgs) = Self::load_from_rpm() {
            let duration = start.elapsed().as_millis() as u64;
            info!("Inventario de paquetes cargado desde RPM: {} paquetes en {} ms", pkgs.len(), duration);
            return Self {
                total_packages: pkgs.len(),
                packages: pkgs,
                package_manager: "rpm".to_string(),
                scan_duration_ms: duration,
            };
        }

        // 4. Fallback a comandos CLI si las lecturas de sistema de archivos no fueron posibles
        if let Some(pkgs) = Self::load_from_pacman_cli() {
            let duration = start.elapsed().as_millis() as u64;
            return Self {
                total_packages: pkgs.len(),
                packages: pkgs,
                package_manager: "pacman_cli".to_string(),
                scan_duration_ms: duration,
            };
        }

        if let Some(pkgs) = Self::load_from_dpkg_cli() {
            let duration = start.elapsed().as_millis() as u64;
            return Self {
                total_packages: pkgs.len(),
                packages: pkgs,
                package_manager: "dpkg_cli".to_string(),
                scan_duration_ms: duration,
            };
        }

        warn!("No se pudo detectar un gestor de paquetes soportado (dpkg, rpm, pacman)");
        Self {
            packages: HashMap::new(),
            package_manager: "unknown".to_string(),
            scan_duration_ms: start.elapsed().as_millis() as u64,
            total_packages: 0,
        }
    }

    /// Lectura directa de `/var/lib/pacman/local/*/desc` (sin crear subprocesos, ultra rápido < 30ms)
    fn load_from_pacman_db() -> Option<HashMap<String, InstalledPackage>> {
        let local_dir = Path::new("/var/lib/pacman/local");
        let entries = fs::read_dir(local_dir).ok()?;
        let mut packages = HashMap::new();

        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                let desc_file = path.join("desc");
                if desc_file.is_file() {
                    if let Ok(content) = fs::read_to_string(&desc_file) {
                        let mut name: Option<String> = None;
                        let mut version: Option<String> = None;
                        let mut arch: Option<String> = None;

                        let mut lines = content.lines();
                        while let Some(line) = lines.next() {
                            match line.trim() {
                                "%NAME%" => {
                                    if let Some(val) = lines.next() {
                                        name = Some(val.trim().to_string());
                                    }
                                }
                                "%VERSION%" => {
                                    if let Some(val) = lines.next() {
                                        version = Some(val.trim().to_string());
                                    }
                                }
                                "%ARCH%" => {
                                    if let Some(val) = lines.next() {
                                        arch = Some(val.trim().to_string());
                                    }
                                }
                                _ => {}
                            }
                        }

                        if let (Some(pkg_name), Some(pkg_ver)) = (name, version) {
                            let (ver_clean, rel) = match pkg_ver.split_once('-') {
                                Some((v, r)) => (v.to_string(), Some(r.to_string())),
                                None => (pkg_ver.clone(), None),
                            };

                            packages.insert(pkg_name.clone(), InstalledPackage {
                                name: pkg_name,
                                version: ver_clean,
                                release: rel,
                                arch,
                                package_manager: "pacman".to_string(),
                            });
                        }
                    }
                }
            }
        }

        if packages.is_empty() {
            None
        } else {
            Some(packages)
        }
    }

    /// Lectura directa de `/var/lib/dpkg/status` (sin crear subprocesos, < 25ms)
    fn load_from_dpkg_status() -> Option<HashMap<String, InstalledPackage>> {
        let status_path = Path::new("/var/lib/dpkg/status");
        let content = fs::read_to_string(status_path).ok()?;
        let mut packages = HashMap::new();

        let mut current_name: Option<String> = None;
        let mut current_version: Option<String> = None;
        let mut current_arch: Option<String> = None;
        let mut is_installed = false;

        for line in content.lines() {
            if line.is_empty() {
                if is_installed {
                    if let (Some(name), Some(ver)) = (current_name.take(), current_version.take()) {
                        let (ver_clean, rel) = match ver.split_once('-') {
                            Some((v, r)) => (v.to_string(), Some(r.to_string())),
                            None => (ver.clone(), None),
                        };
                        packages.insert(name.clone(), InstalledPackage {
                            name,
                            version: ver_clean,
                            release: rel,
                            arch: current_arch.take(),
                            package_manager: "dpkg".to_string(),
                        });
                    }
                }
                current_name = None;
                current_version = None;
                current_arch = None;
                is_installed = false;
                continue;
            }

            if let Some(pkg) = line.strip_prefix("Package: ") {
                current_name = Some(pkg.trim().to_string());
            } else if let Some(ver) = line.strip_prefix("Version: ") {
                current_version = Some(ver.trim().to_string());
            } else if let Some(arch) = line.strip_prefix("Architecture: ") {
                current_arch = Some(arch.trim().to_string());
            } else if let Some(status) = line.strip_prefix("Status: ") {
                if status.contains("installed") && !status.contains("not-installed") {
                    is_installed = true;
                }
            }
        }

        if packages.is_empty() {
            None
        } else {
            Some(packages)
        }
    }

    /// Consulta paquetes instalados mediante `rpm`
    fn load_from_rpm() -> Option<HashMap<String, InstalledPackage>> {
        let out = Command::new("rpm")
            .args(["-qa", "--qf", "%{NAME}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\n"])
            .output()
            .ok()?;

        if !out.status.success() {
            return None;
        }

        let stdout = String::from_utf8_lossy(&out.stdout);
        let mut packages = HashMap::new();

        for line in stdout.lines() {
            let parts: Vec<&str> = line.split('\t').collect();
            if parts.len() >= 3 {
                let name = parts[0].trim().to_string();
                let version = parts[1].trim().to_string();
                let release = Some(parts[2].trim().to_string());
                let arch = parts.get(3).map(|s| s.trim().to_string());

                packages.insert(name.clone(), InstalledPackage {
                    name,
                    version,
                    release,
                    arch,
                    package_manager: "rpm".to_string(),
                });
            }
        }

        if packages.is_empty() {
            None
        } else {
            Some(packages)
        }
    }

    /// Fallback CLI: `pacman -Q`
    fn load_from_pacman_cli() -> Option<HashMap<String, InstalledPackage>> {
        let out = Command::new("pacman").arg("-Q").output().ok()?;
        if !out.status.success() {
            return None;
        }

        let stdout = String::from_utf8_lossy(&out.stdout);
        let mut packages = HashMap::new();

        for line in stdout.lines() {
            if let Some((name, ver)) = line.split_once(' ') {
                let name = name.trim().to_string();
                let ver = ver.trim();
                let (ver_clean, rel) = match ver.split_once('-') {
                    Some((v, r)) => (v.to_string(), Some(r.to_string())),
                    None => (ver.to_string(), None),
                };

                packages.insert(name.clone(), InstalledPackage {
                    name,
                    version: ver_clean,
                    release: rel,
                    arch: None,
                    package_manager: "pacman".to_string(),
                });
            }
        }

        Some(packages)
    }

    /// Fallback CLI: `dpkg-query`
    fn load_from_dpkg_cli() -> Option<HashMap<String, InstalledPackage>> {
        let out = Command::new("dpkg-query")
            .args(["-W", "-f=${Package}\t${Version}\t${Architecture}\n"])
            .output()
            .ok()?;

        if !out.status.success() {
            return None;
        }

        let stdout = String::from_utf8_lossy(&out.stdout);
        let mut packages = HashMap::new();

        for line in stdout.lines() {
            let parts: Vec<&str> = line.split('\t').collect();
            if parts.len() >= 2 {
                let name = parts[0].trim().to_string();
                let ver = parts[1].trim();
                let arch = parts.get(2).map(|s| s.trim().to_string());
                let (ver_clean, rel) = match ver.split_once('-') {
                    Some((v, r)) => (v.to_string(), Some(r.to_string())),
                    None => (ver.to_string(), None),
                };

                packages.insert(name.clone(), InstalledPackage {
                    name,
                    version: ver_clean,
                    release: rel,
                    arch,
                    package_manager: "dpkg".to_string(),
                });
            }
        }

        Some(packages)
    }

    /// Obtiene información de un paquete instalado si existe
    pub fn get_package(&self, name: &str) -> Option<&InstalledPackage> {
        self.packages.get(name)
    }

    /// Verifica si un paquete específico está instalado en el sistema
    pub fn has_package(&self, name: &str) -> bool {
        self.packages.contains_key(name)
    }

    /// Evalúa si el paquete instalado es vulnerable frente a una versión corregida (`min_fixed_version`).
    /// - Retorna `Some(true)` si el paquete está instalado y su versión es estrictamente MENOR que `min_fixed_version` (Vulnerable).
    /// - Retorna `Some(false)` si el paquete está instalado y su versión es MAYOR o IGUAL (Mitigado nativamente).
    /// - Retorna `None` si el paquete NO está instalado en el equipo (Inmune / No aplicable).
    pub fn is_package_vulnerable(&self, package_name: &str, min_fixed_version: &str) -> Option<bool> {
        let pkg = self.get_package(package_name)?;
        let full_installed_version = match &pkg.release {
            Some(rel) => format!("{}-{}", pkg.version, rel),
            None => pkg.version.clone(),
        };

        let ordering = compare_package_versions(&full_installed_version, min_fixed_version);
        debug!(
            "Comparación de paquete '{}': instalada='{}', corregida='{}' -> {:?}",
            package_name, full_installed_version, min_fixed_version, ordering
        );

        Some(ordering == std::cmp::Ordering::Less)
    }
}

/// Comparador determinista de versiones de paquetes Linux (conforme a especificaciones Debian/RPM/Pacman)
pub fn compare_package_versions(v1: &str, v2: &str) -> std::cmp::Ordering {
    // 1. Quitar épocas (ej. "1:2.0" -> epoch 1, ver "2.0")
    let (epoch1, clean_v1) = extract_epoch(v1);
    let (epoch2, clean_v2) = extract_epoch(v2);

    match epoch1.cmp(&epoch2) {
        std::cmp::Ordering::Equal => {}
        diff => return diff,
    }

    // 2. Comparar segmentos recursivamente
    compare_version_segments(clean_v1, clean_v2)
}

fn extract_epoch(v: &str) -> (u32, &str) {
    if let Some((e, rest)) = v.split_once(':') {
        if let Ok(num) = e.parse::<u32>() {
            return (num, rest);
        }
    }
    (0, v)
}

fn compare_version_segments(mut a: &str, mut b: &str) -> std::cmp::Ordering {
    while !a.is_empty() || !b.is_empty() {
        // Manejo especial de tilde '~' (en Debian/RPM, ~ es menor que vacío o cualquier caracter)
        let a_tilde = a.starts_with('~');
        let b_tilde = b.starts_with('~');
        if a_tilde || b_tilde {
            if a_tilde && !b_tilde {
                return std::cmp::Ordering::Less;
            }
            if !a_tilde && b_tilde {
                return std::cmp::Ordering::Greater;
            }
            // Ambos inician con ~: consumir y continuar
            a = &a[1..];
            b = &b[1..];
            continue;
        }

        // Si uno de los dos terminó
        if a.is_empty() {
            return std::cmp::Ordering::Less;
        }
        if b.is_empty() {
            return std::cmp::Ordering::Greater;
        }

        // Extraer siguiente bloque numérico o no-numérico
        let (is_a_digit, a_seg, a_rem) = next_segment(a);
        let (is_b_digit, b_seg, b_rem) = next_segment(b);

        if is_a_digit && is_b_digit {
            // Comparación numérica
            let a_num = a_seg.parse::<u64>().unwrap_or(0);
            let b_num = b_seg.parse::<u64>().unwrap_or(0);
            match a_num.cmp(&b_num) {
                std::cmp::Ordering::Equal => {}
                diff => return diff,
            }
        } else if !is_a_digit && !is_b_digit {
            // Comparación léxica de delimitadores/letras
            match a_seg.cmp(b_seg) {
                std::cmp::Ordering::Equal => {}
                diff => return diff,
            }
        } else {
            // Un dígito es mayor que un no-dígito (ej: "1" > ".alpha")
            return if is_a_digit {
                std::cmp::Ordering::Greater
            } else {
                std::cmp::Ordering::Less
            };
        }

        a = a_rem;
        b = b_rem;
    }

    std::cmp::Ordering::Equal
}

fn next_segment(s: &str) -> (bool, &str, &str) {
    let first_char = s.chars().next().unwrap();
    let is_digit = first_char.is_ascii_digit();

    let split_pos = s.char_indices()
        .find(|&(_, c)| c.is_ascii_digit() != is_digit || c == '~')
        .map(|(idx, _)| idx)
        .unwrap_or(s.len());

    (is_digit, &s[..split_pos], &s[split_pos..])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_comparisons() {
        assert_eq!(compare_package_versions("1.0", "1.0"), std::cmp::Ordering::Equal);
        assert_eq!(compare_package_versions("1.0-1", "1.0-2"), std::cmp::Ordering::Less);
        assert_eq!(compare_package_versions("1.1", "1.0.9"), std::cmp::Ordering::Greater);
        assert_eq!(compare_package_versions("0.120-1", "128-1"), std::cmp::Ordering::Less);
        assert_eq!(compare_package_versions("1:2.0", "2.0"), std::cmp::Ordering::Greater);
        assert_eq!(compare_package_versions("1.0~rc1", "1.0"), std::cmp::Ordering::Less);
        assert_eq!(compare_package_versions("9.8p1", "8.5p1"), std::cmp::Ordering::Greater);
    }

    #[test]
    fn test_package_inventory_autodetect() {
        let inv = PackageInventory::autodetect();
        println!("Gestor detectado: {}, Paquetes: {}, Tiempo: {} ms", inv.package_manager, inv.total_packages, inv.scan_duration_ms);
        assert!(inv.total_packages > 0, "Debería haber indexado paquetes del sistema");
        assert!(inv.scan_duration_ms < 500, "La indexación debe completarse en menos de 500 ms");

        // En Garuda/Arch 'polkit' o 'systemd' deben estar presentes
        if inv.package_manager == "pacman" {
            assert!(inv.has_package("systemd") || inv.has_package("polkit") || inv.has_package("glibc"));
            if let Some(vuln) = inv.is_package_vulnerable("polkit", "0.120-1") {
                assert!(!vuln, "Polkit en sistema actual debe ser >= 0.120-1");
            }
        }
    }
}
