use anyhow::{bail, Result};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use tracing::info;

/// Ruta estándar de persistencia sysctl para SamuLibre
pub const SAMULIBRE_SYSCTL_CONF: &str = "/etc/sysctl.d/99-samulibre-vpatch.conf";
pub const SAMULIBRE_SYSCTL_BACKUP: &str = "/etc/sysctl.d/.samulibre-backup.conf";

/// Entrada individual de parámetro de kernel con su valor de mitigación y valor previo
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SysctlEntry {
    pub parameter: String,
    pub safe_value: String,
    pub original_value: Option<String>,
}

/// Motor de endurecimiento y persistencia sysctl para Linux
pub struct SysctlEngine {
    conf_path: PathBuf,
    backup_path: PathBuf,
    dry_run: bool,
}

impl SysctlEngine {
    pub fn new(dry_run: bool) -> Self {
        Self {
            conf_path: PathBuf::from(SAMULIBRE_SYSCTL_CONF),
            backup_path: PathBuf::from(SAMULIBRE_SYSCTL_BACKUP),
            dry_run,
        }
    }

    #[cfg(test)]
    pub fn new_with_paths(conf: impl Into<PathBuf>, backup: impl Into<PathBuf>, dry_run: bool) -> Self {
        Self {
            conf_path: conf.into(),
            backup_path: backup.into(),
            dry_run,
        }
    }

    /// Lee el valor actual de un parámetro sysctl directamente desde `/proc/sys`
    pub fn read_current_value(&self, parameter: &str) -> Option<String> {
        let proc_path = format!("/proc/sys/{}", parameter.replace('.', "/"));
        fs::read_to_string(&proc_path).ok().map(|s| s.trim().to_string())
    }

    /// Aplica un parámetro sysctl de forma inmediata en `/proc/sys` y asegura persistencia en `/etc/sysctl.d/`
    pub fn apply_parameter(&self, parameter: &str, safe_value: &str) -> Result<()> {
        let is_root = unsafe { libc::geteuid() == 0 };
        if !is_root && !self.dry_run {
            bail!("Permisos insuficientes: aplicar parámetros de kernel en sysctl requiere privilegios de root (UID 0 o CAP_SYS_ADMIN)");
        }

        info!("Aplicando parámetro sysctl '{}={}' (dry_run: {})", parameter, safe_value, self.dry_run);

        // 1. Respaldar valor actual si no existe respaldo previo
        if let Some(current) = self.read_current_value(parameter) {
            let _ = self.save_backup_entry(parameter, &current);
        }

        if self.dry_run {
            info!("[Dry-Run] Parámetro sysctl '{}={}' simulado con éxito.", parameter, safe_value);
            return Ok(());
        }

        // 2. Aplicar inmediatamente en memoria viva (/proc/sys/<param>)
        let proc_path = format!("/proc/sys/{}", parameter.replace('.', "/"));
        if Path::new(&proc_path).exists() {
            fs::write(&proc_path, safe_value.as_bytes())
                .map_err(|e| anyhow::anyhow!("Fallo al escribir en {}: {}", proc_path, e))?;
        } else {
            // Intentar comando sysctl -w
            let out = Command::new("sysctl")
                .args(["-w", &format!("{}={}", parameter, safe_value)])
                .output()?;
            if !out.status.success() {
                let stderr = String::from_utf8_lossy(&out.stderr);
                bail!("Error ejecutando sysctl -w {}={}: {}", parameter, safe_value, stderr.trim());
            }
        }

        // 3. Escribir configuración persistente en /etc/sysctl.d/99-samulibre-vpatch.conf
        self.persist_parameter(parameter, safe_value)?;

        // 4. Recargar el archivo persistente mediante `sysctl -p` si está disponible
        let _ = Command::new("sysctl").args(["-p", self.conf_path.to_str().unwrap_or(SAMULIBRE_SYSCTL_CONF)]).output();

        info!("Parámetro sysctl '{}={}' aplicado y persistido.", parameter, safe_value);
        Ok(())
    }

    /// Revierte un parámetro a su valor de respaldo original
    pub fn revert_parameter(&self, parameter: &str, default_fallback: &str) -> Result<()> {
        let is_root = unsafe { libc::geteuid() == 0 };
        if !is_root && !self.dry_run {
            bail!("Permisos insuficientes: restaurar parámetros sysctl requiere privilegios de root");
        }

        let restore_val = self.get_backup_entry(parameter).unwrap_or_else(|| default_fallback.to_string());
        info!("Restaurando parámetro sysctl '{}={}' (dry_run: {})", parameter, restore_val, self.dry_run);

        if self.dry_run {
            info!("[Dry-Run] Reversión de '{}={}' simulada.", parameter, restore_val);
            return Ok(());
        }

        // 1. Restaurar en /proc/sys
        let proc_path = format!("/proc/sys/{}", parameter.replace('.', "/"));
        if Path::new(&proc_path).exists() {
            let _ = fs::write(&proc_path, restore_val.as_bytes());
        } else {
            let _ = Command::new("sysctl")
                .args(["-w", &format!("{}={}", parameter, restore_val)])
                .output();
        }

        // 2. Eliminar del archivo persistente
        self.remove_persistent_parameter(parameter)?;

        info!("Parámetro sysctl '{}' revertido a '{}'.", parameter, restore_val);
        Ok(())
    }

    /// Guarda una entrada en el archivo de respaldo
    fn save_backup_entry(&self, parameter: &str, current_val: &str) -> Result<()> {
        let mut map = self.load_key_value_file(&self.backup_path);
        if !map.contains_key(parameter) {
            map.insert(parameter.to_string(), current_val.to_string());
            self.write_key_value_file(&self.backup_path, &map, "# Respaldos automáticos de parámetros originales sysctl SamuLibre")?;
        }
        Ok(())
    }

    /// Lee un valor de respaldo previo
    fn get_backup_entry(&self, parameter: &str) -> Option<String> {
        let map = self.load_key_value_file(&self.backup_path);
        map.get(parameter).cloned()
    }

    /// Persiste un parámetro en el archivo de configuración 99-samulibre-vpatch.conf
    fn persist_parameter(&self, parameter: &str, value: &str) -> Result<()> {
        let mut map = self.load_key_value_file(&self.conf_path);
        map.insert(parameter.to_string(), value.to_string());
        self.write_key_value_file(&self.conf_path, &map, "# Generado automáticamente por SamuLibre Virtual Patching Shield")
    }

    /// Elimina un parámetro del archivo persistente
    fn remove_persistent_parameter(&self, parameter: &str) -> Result<()> {
        let mut map = self.load_key_value_file(&self.conf_path);
        map.remove(parameter);
        if map.is_empty() {
            if self.conf_path.exists() {
                let _ = fs::remove_file(&self.conf_path);
            }
        } else {
            self.write_key_value_file(&self.conf_path, &map, "# Generado automáticamente por SamuLibre Virtual Patching Shield")?;
        }
        Ok(())
    }

    fn load_key_value_file(&self, path: &Path) -> HashMap<String, String> {
        let mut map = HashMap::new();
        if let Ok(content) = fs::read_to_string(path) {
            for line in content.lines() {
                let trimmed = line.trim();
                if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
                    continue;
                }
                if let Some((k, v)) = trimmed.split_once('=') {
                    map.insert(k.trim().to_string(), v.trim().to_string());
                }
            }
        }
        map
    }

    fn write_key_value_file(&self, path: &Path, map: &HashMap<String, String>, header: &str) -> Result<()> {
        if let Some(parent) = path.parent() {
            if !parent.exists() {
                let _ = fs::create_dir_all(parent);
            }
        }
        let mut content = format!("{}\n", header);
        let mut sorted_keys: Vec<_> = map.keys().collect();
        sorted_keys.sort();
        for k in sorted_keys {
            content.push_str(&format!("{} = {}\n", k, map[k]));
        }
        fs::write(path, content)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sysctl_engine_persistence_cycle() {
        let temp_dir = std::env::temp_dir().join("samulibre_sysctl_test");
        let _ = fs::create_dir_all(&temp_dir);
        let conf_file = temp_dir.join("99-samulibre-vpatch.conf");
        let backup_file = temp_dir.join(".samulibre-backup.conf");

        let engine = SysctlEngine::new_with_paths(&conf_file, &backup_file, true);

        // Prueba en modo Dry-Run
        assert!(engine.apply_parameter("kernel.yama.ptrace_scope", "2").is_ok());
        assert!(engine.revert_parameter("kernel.yama.ptrace_scope", "0").is_ok());

        // Prueba de lectura y persistencia de archivo
        let mut map = HashMap::new();
        map.insert("fs.protected_fifos".to_string(), "2".to_string());
        engine.write_key_value_file(&conf_file, &map, "# Test").unwrap();

        let loaded = engine.load_key_value_file(&conf_file);
        assert_eq!(loaded.get("fs.protected_fifos"), Some(&"2".to_string()));

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_read_real_sysctl_proc() {
        let engine = SysctlEngine::new(true);
        // /proc/sys/kernel/pid_max o /proc/sys/fs/file-max existen en todo Linux
        let val = engine.read_current_value("kernel.pid_max");
        assert!(val.is_some(), "Debería poder leer kernel.pid_max en Linux");
    }
}
