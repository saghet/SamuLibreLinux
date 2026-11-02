use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{info, warn};

/// Veredicto de la evaluación eBPF en tiempo real
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VpatchVerdict {
    Allow,
    Block {
        rule_id: String,
        cve: String,
        reason: String,
        action: String,
    },
}

/// Definición de una regla de comportamiento activo de parchado virtual
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehavioralVpatchRule {
    pub id: String,
    pub cve: String,
    pub target_process: String,
    pub forbidden_patterns: Vec<String>,
    pub check_empty_argv: bool,
    pub check_environment: bool,
    pub action: String,
}

/// Motor de parchado virtual en tiempo de ejecución asistido por eBPF / EDR
pub struct EbpfVpatchEngine {
    rules: HashMap<String, BehavioralVpatchRule>,
    active: bool,
    total_intercepted: usize,
    total_blocked: usize,
}

impl Default for EbpfVpatchEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl EbpfVpatchEngine {
    pub fn new() -> Self {
        let mut engine = Self {
            rules: HashMap::new(),
            active: true,
            total_intercepted: 0,
            total_blocked: 0,
        };
        engine.load_builtin_rules();
        engine
    }

    /// Carga las reglas predeterminadas de mitigación de exploits locales en Linux
    fn load_builtin_rules(&mut self) {
        // Regla 1: PwnKit (CVE-2021-4034) - Polkit pkexec Local Privilege Escalation
        self.register_rule(BehavioralVpatchRule {
            id: "VP-EBPF-PWNKIT".to_string(),
            cve: "CVE-2021-4034".to_string(),
            target_process: "pkexec".to_string(),
            forbidden_patterns: vec![
                "GCONV_PATH=".to_string(),
                "CHARSET=".to_string(),
                "SHELL=pwnkit".to_string(),
            ],
            check_empty_argv: true,
            check_environment: true,
            action: "SIGKILL".to_string(),
        });

        // Regla 2: Looney Tunables (CVE-2023-4911) - glibc ld.so Buffer Overflow
        self.register_rule(BehavioralVpatchRule {
            id: "VP-EBPF-LOONEY-TUNABLES".to_string(),
            cve: "CVE-2023-4911".to_string(),
            target_process: "*".to_string(),
            forbidden_patterns: vec![
                "GLIBC_TUNABLES=glibc.pthread.rseq".to_string(),
                "GLIBC_TUNABLES=glibc.malloc.mxfast".to_string(),
                "GLIBC_TUNABLES=glibc.cpu.hwcap_mask".to_string(),
            ],
            check_empty_argv: false,
            check_environment: true,
            action: "SIGKILL".to_string(),
        });

        // Regla 3: Sudo Baron Samedit (CVE-2021-3156) - Heap-based Buffer Overflow en sudoedit
        self.register_rule(BehavioralVpatchRule {
            id: "VP-EBPF-SUDO-BARON".to_string(),
            cve: "CVE-2021-3156".to_string(),
            target_process: "sudoedit".to_string(),
            forbidden_patterns: vec!["sudoedit -s \\".to_string()],
            check_empty_argv: false,
            check_environment: false,
            action: "SIGKILL".to_string(),
        });
    }

    pub fn register_rule(&mut self, rule: BehavioralVpatchRule) {
        info!("Regla de mitigación activa registrada: {} ({}) para '{}'", rule.id, rule.cve, rule.target_process);
        self.rules.insert(rule.id.clone(), rule);
    }

    /// Evalúa una llamada al sistema `sys_enter_execve` frente al conjunto de reglas de mitigación
    pub fn evaluate_execve(
        &mut self,
        pid: u32,
        comm: &str,
        argv: &[String],
        envp: &[String],
    ) -> VpatchVerdict {
        self.total_intercepted += 1;
        if !self.active {
            return VpatchVerdict::Allow;
        }

        let comm_lower = comm.to_lowercase();

        for rule in self.rules.values() {
            let process_matches = rule.target_process == "*"
                || comm_lower.ends_with(&rule.target_process.to_lowercase())
                || argv.first().map(|a| a.to_lowercase().ends_with(&rule.target_process.to_lowercase())).unwrap_or(false);

            if !process_matches {
                continue;
            }

            // 1. Detección de argv vacío (Vector crítico de PwnKit CVE-2021-4034)
            if rule.check_empty_argv && argv.is_empty() {
                self.total_blocked += 1;
                warn!("ALERTA MITIGACIÓN LPE: Intento de invocación de '{}' con argv vacío (PID {}) neutralizado [{} - {}]",
                    comm, pid, rule.id, rule.cve);
                return VpatchVerdict::Block {
                    rule_id: rule.id.clone(),
                    cve: rule.cve.clone(),
                    reason: format!("Ejecución sospechosa de '{}' sin argumentos (técnica PwnKit)", comm),
                    action: rule.action.clone(),
                };
            }

            // 2. Detección de patrones maliciosos en variables de entorno
            if rule.check_environment {
                for env in envp {
                    for pat in &rule.forbidden_patterns {
                        if env.starts_with(pat) {
                            self.total_blocked += 1;
                            warn!("ALERTA MITIGACIÓN LPE: Variable maliciosa '{}' detectada en '{}' (PID {}) [{} - {}]",
                                env, comm, pid, rule.id, rule.cve);
                            return VpatchVerdict::Block {
                                rule_id: rule.id.clone(),
                                cve: rule.cve.clone(),
                                reason: format!("Variable de entorno peligrosa '{}' bloqueada por regla de parchado virtual", pat),
                                action: rule.action.clone(),
                            };
                        }
                    }
                }
            }

            // 3. Detección de patrones maliciosos en la línea de comandos
            let full_cmdline = argv.join(" ");
            for pat in &rule.forbidden_patterns {
                if full_cmdline.contains(pat) {
                    self.total_blocked += 1;
                    warn!("ALERTA MITIGACIÓN LPE: Patrón de explotación '{}' detectado en línea de comandos de '{}' (PID {})",
                        pat, comm, pid);
                    return VpatchVerdict::Block {
                        rule_id: rule.id.clone(),
                        cve: rule.cve.clone(),
                        reason: format!("Parámetro de línea de comandos peligroso detectado: '{}'", pat),
                        action: rule.action.clone(),
                    };
                }
            }
        }

        VpatchVerdict::Allow
    }

    /// Ejecuta la acción de mitigación (SIGKILL) si se determina un bloqueo
    pub fn enforce_verdict(&self, pid: u32, verdict: &VpatchVerdict) -> bool {
        match verdict {
            VpatchVerdict::Allow => false,
            VpatchVerdict::Block { action, rule_id, cve, .. } => {
                if action == "SIGKILL" {
                    #[cfg(target_os = "linux")]
                    {
                        let is_root = unsafe { libc::geteuid() == 0 };
                        if is_root && pid > 1 {
                            unsafe {
                                libc::kill(pid as i32, libc::SIGKILL);
                            }
                            info!("Proceso atacante PID {} neutralizado mediante SIGKILL por regla {} ({})", pid, rule_id, cve);
                            return true;
                        }
                    }
                }
                false
            }
        }
    }

    pub fn get_metrics(&self) -> (usize, usize, usize) {
        (self.rules.len(), self.total_intercepted, self.total_blocked)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ebpf_vpatch_pwnkit_detection() {
        let mut engine = EbpfVpatchEngine::new();

        // 1. Caso legítimo
        let v1 = engine.evaluate_execve(
            1001,
            "pkexec",
            &["pkexec".to_string(), "/usr/bin/whoami".to_string()],
            &["USER=usuario".to_string(), "PATH=/usr/bin".to_string()],
        );
        assert_eq!(v1, VpatchVerdict::Allow);

        // 2. Caso PwnKit con argv vacío
        let v2 = engine.evaluate_execve(
            1002,
            "pkexec",
            &[],
            &["GCONV_PATH=./pwn".to_string()],
        );
        assert!(matches!(v2, VpatchVerdict::Block { .. }));
        if let VpatchVerdict::Block { cve, .. } = v2 {
            assert_eq!(cve, "CVE-2021-4034");
        }

        // 3. Caso Looney Tunables
        let v3 = engine.evaluate_execve(
            1003,
            "su",
            &["su".to_string()],
            &["GLIBC_TUNABLES=glibc.pthread.rseq=123".to_string()],
        );
        assert!(matches!(v3, VpatchVerdict::Block { .. }));
        if let VpatchVerdict::Block { cve, .. } = v3 {
            assert_eq!(cve, "CVE-2023-4911");
        }
    }
}
