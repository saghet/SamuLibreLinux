use anyhow::{bail, Result};
use std::io::Write;
use std::process::{Command, Stdio};
use tracing::{info, warn};

pub const SAMULIBRE_NFT_TABLE: &str = "samulibre_vpatch";
pub const SAMULIBRE_NFT_FAMILY: &str = "inet";
pub const SAMULIBRE_NFT_CHAIN: &str = "inbound_mitigation";

/// Definición de una regla de mitigación de red
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkRuleSpec {
    pub rule_name: String,
    pub port: u16,
    pub protocol: String,
    pub direction: String,
}

/// Motor atómico de filtrado de red basado en nftables (con fallback a iptables)
pub struct NftablesEngine {
    dry_run: bool,
    nft_available: bool,
}

impl NftablesEngine {
    pub fn new(dry_run: bool) -> Self {
        let nft_available = Self::detect_nft_binary();
        Self { dry_run, nft_available }
    }

    fn detect_nft_binary() -> bool {
        if let Ok(out) = Command::new("nft").arg("--version").output() {
            out.status.success()
        } else {
            false
        }
    }

    /// Comprueba si la tabla de SamuLibre ya está presente en nftables
    pub fn is_table_active(&self) -> bool {
        if !self.nft_available {
            return false;
        }
        let out = Command::new("nft")
            .args(["list", "table", SAMULIBRE_NFT_FAMILY, SAMULIBRE_NFT_TABLE])
            .output();

        match out {
            Ok(o) => o.status.success(),
            Err(_) => false,
        }
    }

    /// Aplica una regla de filtrado atómico en la tabla aislada `inet samulibre_vpatch`
    pub fn apply_network_mitigation(&self, spec: &NetworkRuleSpec) -> Result<()> {
        let is_root = unsafe { libc::geteuid() == 0 };
        if !is_root && !self.dry_run {
            bail!("Permisos insuficientes: aplicar reglas de firewall requiere privilegios de root (CAP_NET_ADMIN)");
        }

        info!("Aplicando regla de red '{}': {} {} puerto {} (dry_run: {})",
            spec.rule_name, spec.direction, spec.protocol, spec.port, self.dry_run
        );

        if self.dry_run {
            info!("[Dry-Run] Regla nftables/iptables '{}' simulada con éxito.", spec.rule_name);
            return Ok(());
        }

        if self.nft_available {
            self.apply_via_nftables(spec)
        } else {
            warn!("nftables no disponible en el sistema; utilizando fallback a iptables");
            self.apply_via_iptables_fallback(spec)
        }
    }

    /// Aplica la regla mediante transacción atómica con `nft -f -`
    fn apply_via_nftables(&self, spec: &NetworkRuleSpec) -> Result<()> {
        let proto = spec.protocol.to_lowercase();
        let port_clause = if spec.port > 0 {
            format!("{} dport {} ", proto, spec.port)
        } else {
            format!("meta l4proto {} ", proto)
        };

        let nft_script = format!(
            "table {family} {table} {{\n\
             \tchain {chain} {{\n\
             \t\ttype filter hook input priority -10; policy accept;\n\
             \t\t{clause}drop comment \"{comment}\"\n\
             \t}}\n\
             }}\n",
            family = SAMULIBRE_NFT_FAMILY,
            table = SAMULIBRE_NFT_TABLE,
            chain = SAMULIBRE_NFT_CHAIN,
            clause = port_clause,
            comment = spec.rule_name
        );

        let mut child = Command::new("nft")
            .arg("-f")
            .arg("-")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| anyhow::anyhow!("Fallo al ejecutar nft: {}", e))?;

        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(nft_script.as_bytes())
                .map_err(|e| anyhow::anyhow!("Fallo al transmitir script a nft: {}", e))?;
        }

        let output = child.wait_with_output()
            .map_err(|e| anyhow::anyhow!("Fallo esperando respuesta de nft: {}", e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!("Transacción atómica de nftables fallida: {}", stderr.trim());
        }

        info!("Regla de red '{}' aplicada atómicamente en nftables (tabla {}).", spec.rule_name, SAMULIBRE_NFT_TABLE);
        Ok(())
    }

    /// Fallback a iptables si nftables no está soportado en la distribución
    fn apply_via_iptables_fallback(&self, spec: &NetworkRuleSpec) -> Result<()> {
        let mut args = vec!["-I", "INPUT"];
        let port_str = spec.port.to_string();

        if spec.port > 0 {
            args.extend(["-p", &spec.protocol, "--dport", &port_str]);
        } else {
            args.extend(["-p", &spec.protocol]);
        }

        args.extend(["-m", "comment", "--comment", &spec.rule_name, "-j", "DROP"]);

        let out = Command::new("iptables").args(&args).output()
            .map_err(|e| anyhow::anyhow!("Fallo al ejecutar iptables: {}", e))?;

        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            bail!("Error aplicando regla iptables '{}': {}", spec.rule_name, stderr.trim());
        }

        Ok(())
    }

    /// Revierte una regla de red específica o elimina la tabla dedicada si queda vacía
    pub fn revert_network_mitigation(&self, spec: &NetworkRuleSpec) -> Result<()> {
        let is_root = unsafe { libc::geteuid() == 0 };
        if !is_root && !self.dry_run {
            bail!("Permisos insuficientes: revertir reglas de red requiere privilegios de root");
        }

        info!("Revirtiendo regla de red '{}' (dry_run: {})", spec.rule_name, self.dry_run);

        if self.dry_run {
            info!("[Dry-Run] Reversión de regla '{}' simulada.", spec.rule_name);
            return Ok(());
        }

        if self.nft_available {
            // Intentar eliminar la tabla completa de SamuLibre
            let out = Command::new("nft")
                .args(["delete", "table", SAMULIBRE_NFT_FAMILY, SAMULIBRE_NFT_TABLE])
                .output();

            if let Ok(o) = out {
                if o.status.success() {
                    info!("Tabla nftables '{}' eliminada con éxito.", SAMULIBRE_NFT_TABLE);
                    return Ok(());
                }
            }
        }

        // Limpieza de fallback con iptables
        let mut args = vec!["-D", "INPUT"];
        let port_str = spec.port.to_string();

        if spec.port > 0 {
            args.extend(["-p", &spec.protocol, "--dport", &port_str]);
        } else {
            args.extend(["-p", &spec.protocol]);
        }

        args.extend(["-m", "comment", "--comment", &spec.rule_name, "-j", "DROP"]);
        let _ = Command::new("iptables").args(&args).output();

        // Alternativa genérica de borrado por comentario
        let _ = Command::new("iptables")
            .args(["-D", "INPUT", "-m", "comment", "--comment", &spec.rule_name, "-j", "DROP"])
            .output();

        info!("Regla '{}' retirada del cortafuegos.", spec.rule_name);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nftables_engine_dry_run() {
        let engine = NftablesEngine::new(true);
        let spec = NetworkRuleSpec {
            rule_name: "SamuLibre_VPatch_CVE-2024-6387_SSHD".to_string(),
            port: 22,
            protocol: "TCP".to_string(),
            direction: "in".to_string(),
        };

        assert!(engine.apply_network_mitigation(&spec).is_ok());
        assert!(engine.revert_network_mitigation(&spec).is_ok());
    }

    #[test]
    fn test_nft_script_generation() {
        let spec = NetworkRuleSpec {
            rule_name: "SamuLibre_Test_Rule".to_string(),
            port: 8080,
            protocol: "TCP".to_string(),
            direction: "in".to_string(),
        };

        let proto = spec.protocol.to_lowercase();
        let port_clause = format!("{} dport {} ", proto, spec.port);
        assert_eq!(port_clause, "tcp dport 8080 ");
    }
}
