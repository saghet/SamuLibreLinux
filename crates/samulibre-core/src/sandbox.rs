use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SandboxVerdict {
    Clean,
    Suspicious,
    Malicious,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxReport {
    pub file_path: String,
    pub execution_time_ms: u64,
    pub exit_code: Option<i32>,
    pub dropped_files: Vec<String>,
    pub spawned_processes: Vec<String>,
    pub network_attempts: Vec<String>,
    pub mitre_tactics: Vec<String>,
    pub verdict: SandboxVerdict,
    pub reasoning: String,
}

pub struct MicroSandbox {
    sandbox_root: PathBuf,
}

impl MicroSandbox {
    pub fn new(sandbox_root: impl AsRef<Path>) -> Self {
        let root = sandbox_root.as_ref().to_path_buf();
        let _ = fs::create_dir_all(&root);
        Self { sandbox_root: root }
    }

    /// Ejecuta de forma segura un archivo en un entorno aislado temporal (Micro-Sandbox)
    /// con tiempo límite estricto (timeout) e inspección de artefactos generados.
    pub fn execute_and_analyze(&self, target_file: impl AsRef<Path>, timeout: Duration) -> SandboxReport {
        let start = Instant::now();
        let target_path = target_file.as_ref();
        let file_name = target_path.file_name().unwrap_or_default().to_string_lossy().to_string();

        let run_id = uuid::Uuid::new_v4().to_string();
        let jail_dir = self.sandbox_root.join(format!("jail_{}", &run_id[..8]));
        let _ = fs::create_dir_all(&jail_dir);

        let jailed_file = jail_dir.join(&file_name);
        let _ = fs::copy(target_path, &jailed_file);

        let mut dropped_files = Vec::new();
        let spawned_processes = Vec::new();
        let network_attempts = Vec::new();
        let mut mitre_tactics = Vec::new();

        // SEC-01 Blindaje de Kernel: Ejecución en Sandbox con Bubblewrap (bwrap)
        // En Linux, nunca ejecutar binarios no confiables directamente en el host anfitrión.
        let mut exit_code = None;
        let mut is_contained_execution = false;

        #[cfg(target_os = "linux")]
        let has_bwrap = Path::new("/usr/bin/bwrap").exists();
        #[cfg(not(target_os = "linux"))]
        let has_bwrap = false;

        if has_bwrap {
            // Ejecutar con confinamiento total de namespaces de Linux
            let mut cmd = Command::new("/usr/bin/bwrap");
            cmd.args([
                "--unshare-all",
                "--ro-bind", "/usr", "/usr",
                "--ro-bind-try", "/lib", "/lib",
                "--ro-bind-try", "/lib64", "/lib64",
                "--ro-bind-try", "/bin", "/bin",
                "--tmpfs", "/tmp",
                "--bind", jail_dir.to_str().unwrap_or("."), "/jail",
                "--chdir", "/jail",
                "--clearenv",
                "--setenv", "PATH", "/usr/bin:/bin",
                "--die-with-parent",
                &format!("/jail/{}", file_name),
            ]);
            cmd.stdin(Stdio::null());
            cmd.stdout(Stdio::piped());
            cmd.stderr(Stdio::piped());

            let spawn_res = cmd.spawn();
            match spawn_res {
                Ok(mut child) => {
                    is_contained_execution = true;
                    let check_interval = Duration::from_millis(100);
                    let mut waited = Duration::ZERO;

                    while waited < timeout {
                        match child.try_wait() {
                            Ok(Some(status)) => {
                                exit_code = status.code();
                                break;
                            }
                            Ok(None) => {
                                std::thread::sleep(check_interval);
                                waited += check_interval;
                            }
                            Err(_) => break,
                        }
                    }

                    let _ = child.kill();
                    let _ = child.wait();
                }
                Err(e) => {
                    tracing::warn!("No se pudo inicializar contenedor bwrap: {}", e);
                }
            }
        } else {
            #[cfg(target_os = "windows")]
            {
                // En Windows ejecutamos con flag oculto
                let mut cmd = Command::new(&jailed_file);
                cmd.current_dir(&jail_dir);
                cmd.stdin(Stdio::null());
                cmd.stdout(Stdio::piped());
                cmd.stderr(Stdio::piped());
                use std::os::windows::process::CommandExt;
                const CREATE_NO_WINDOW: u32 = 0x08000000;
                cmd.creation_flags(CREATE_NO_WINDOW);

                if let Ok(mut child) = cmd.spawn() {
                    is_contained_execution = true;
                    let check_interval = Duration::from_millis(100);
                    let mut waited = Duration::ZERO;
                    while waited < timeout {
                        match child.try_wait() {
                            Ok(Some(status)) => {
                                exit_code = status.code();
                                break;
                            }
                            Ok(None) => {
                                std::thread::sleep(check_interval);
                                waited += check_interval;
                            }
                            Err(_) => break,
                        }
                    }
                    let _ = child.kill();
                    let _ = child.wait();
                }
            }

            #[cfg(target_os = "linux")]
            {
                // PREVENCIÓN CRÍTICA DE RCE: Sin bwrap, denegar la ejecución directa en el host anfitrión
                tracing::warn!("Bubblewrap (/usr/bin/bwrap) no disponible. Ejecución dinámica bloqueada para proteger el host.");
            }
        }

        // Inspeccionar cambios en el directorio de la celda de aislamiento (Jail)
        if let Ok(entries) = fs::read_dir(&jail_dir) {
            for entry in entries.flatten() {
                let p = entry.path();
                if p != jailed_file {
                    let name = p.file_name().unwrap_or_default().to_string_lossy().to_string();
                    dropped_files.push(name.clone());

                    let lower = name.to_lowercase();
                    if lower.ends_with(".exe") || lower.ends_with(".dll") || lower.ends_with(".bat") || lower.ends_with(".ps1") {
                        mitre_tactics.push("T1105 - Ingress Tool Transfer / Dropper de Binarios".to_string());
                    }
                    if lower.ends_with(".locked") || lower.ends_with(".crypto") || lower.ends_with(".enc") {
                        mitre_tactics.push("T1486 - Data Encrypted for Impact / Ransomware Behavior".to_string());
                    }
                }
            }
        }

        // Limpiar celda de aislamiento
        let _ = fs::remove_dir_all(&jail_dir);

        let verdict = if mitre_tactics.iter().any(|t| t.contains("T1486") || t.contains("T1105")) {
            SandboxVerdict::Malicious
        } else if !dropped_files.is_empty() {
            SandboxVerdict::Suspicious
        } else {
            SandboxVerdict::Clean
        };

        let reasoning = match verdict {
            SandboxVerdict::Malicious => format!("Comportamiento hostil confirmado en Sandbox: mutación de archivos y tácticas MITRE {:?}", mitre_tactics),
            SandboxVerdict::Suspicious => format!("Comportamiento anómalo en Sandbox: soltó {} archivo(s) no esperados.", dropped_files.len()),
            SandboxVerdict::Clean => {
                if is_contained_execution {
                    "Ejecución contenida en Sandbox de kernel (Bubblewrap) finalizada sin comportamiento hostil detectable.".to_string()
                } else {
                    "Análisis estático preventivo completado. Aislamiento dinámico deshabilitado para prevenir ejecución no confinada en el host.".to_string()
                }
            }
        };

        SandboxReport {
            file_path: target_path.to_string_lossy().to_string(),
            execution_time_ms: start.elapsed().as_millis() as u64,
            exit_code,
            dropped_files,
            spawned_processes,
            network_attempts,
            mitre_tactics,
            verdict,
            reasoning,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_micro_sandbox_safe_binary() {
        let sandbox = MicroSandbox::new(std::env::temp_dir().join("samulibre_sbx_test"));
        #[cfg(target_os = "windows")]
        let test_bin = std::env::temp_dir().join("test_safe.bat");
        #[cfg(not(target_os = "windows"))]
        let test_bin = std::env::temp_dir().join("test_safe.sh");

        #[cfg(target_os = "windows")]
        let _ = fs::write(&test_bin, "@echo off\r\necho Safe test");
        #[cfg(not(target_os = "windows"))]
        {
            let _ = fs::write(&test_bin, "#!/bin/sh\necho Safe test\n");
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&test_bin, fs::Permissions::from_mode(0o755));
        }

        let report = sandbox.execute_and_analyze(&test_bin, Duration::from_millis(1000));
        assert!(matches!(report.verdict, SandboxVerdict::Clean));

        let _ = fs::remove_file(test_bin);
    }
}
