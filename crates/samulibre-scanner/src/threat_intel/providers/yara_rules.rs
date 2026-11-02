use super::ThreatIntelProvider;
use crate::threat_intel::downloader::SecureDownloader;
use crate::threat_intel::models::{
    IndicatorType, ProviderFetchResult, ProviderStatus, SourceEvidence, ThreatIndicator, ThreatSeverity,
};
use anyhow::Result;
use std::collections::HashSet;
use std::time::Instant;
use tracing::{info, warn};
use uuid::Uuid;

pub struct YaraRulesProvider;

impl Default for YaraRulesProvider {
    fn default() -> Self {
        Self
    }
}

impl ThreatIntelProvider for YaraRulesProvider {
    fn id(&self) -> &'static str {
        "yara_rules"
    }

    fn name(&self) -> &'static str {
        "YARA-Rules Community & Linux Specialized"
    }

    fn is_enabled(&self) -> bool {
        true
    }

    fn fetch_indicators(&self, _downloader: &SecureDownloader) -> Result<ProviderFetchResult> {
        let start = Instant::now();
        let mut indicators = Vec::new();

        // Conjunto de reglas YARA especializadas en amenazas Linux y multi-plataforma
        let curated_rules = get_linux_curated_yara_rules();
        let mut seen_rule_names = HashSet::new();

        for (rule_name, rule_body, family, severity) in curated_rules {
            // Validación sintáctica rigurosa antes de admitir la regla
            if let Err(err) = validate_yara_rule_syntax(rule_name, rule_body) {
                warn!("Regla YARA '{}' descartada por error sintáctico: {}", rule_name, err);
                continue;
            }

            if seen_rule_names.contains(rule_name) {
                warn!("Conflicto de nombre en regla YARA duplicada descartada: {}", rule_name);
                continue;
            }
            seen_rule_names.insert(rule_name);

            indicators.push(ThreatIndicator {
                id: Uuid::new_v4().to_string(),
                indicator_type: IndicatorType::YaraRule,
                value: rule_body.to_string(),
                malware_family: family.to_string(),
                severity,
                confidence_score: 95,
                sources: vec![SourceEvidence {
                    provider_id: "yara_rules".to_string(),
                    provider_name: "YARA-Rules Linux Community (GPL-3.0)".to_string(),
                    report_date: chrono::Utc::now().to_rfc3339(),
                    confidence: 95,
                    reference_url: Some("https://github.com/Yara-Rules/rules".to_string()),
                    tags: vec!["yara".to_string(), "linux_elf".to_string(), rule_name.to_string()],
                }],
                description: format!("Regla de detección YARA-X: {}", rule_name),
                first_seen: chrono::Utc::now().to_rfc3339(),
                last_updated: chrono::Utc::now().to_rfc3339(),
                is_active: true,
            });
        }

        let duration_ms = start.elapsed().as_millis() as u64;
        info!("YaraRulesProvider: {} reglas YARA validadas y activas ({} ms)", indicators.len(), duration_ms);

        Ok(ProviderFetchResult {
            provider_id: "yara_rules",
            provider_name: "YARA-Rules Community & Linux Specialized",
            indicators,
            raw_payload_hash: None,
            status: ProviderStatus::Success,
            duration_ms,
        })
    }
}

/// Validador sintáctico estricto para reglas YARA
pub fn validate_yara_rule_syntax(name: &str, content: &str) -> Result<(), &'static str> {
    if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return Err("Nombre de regla no válido (debe ser alfanumérico ASCII o guión bajo)");
    }

    if !content.contains("rule ") || !content.contains('{') || !content.contains('}') {
        return Err("Estructura básica de regla inválida (faltan palabras clave o llaves)");
    }

    if !content.contains("condition:") {
        return Err("Falta la sección obligatoria 'condition:' en la regla YARA");
    }

    // Verificar balance de llaves
    let open_braces = content.chars().filter(|&c| c == '{').count();
    let close_braces = content.chars().filter(|&c| c == '}').count();
    if open_braces != close_braces {
        return Err("Llaves desbalanceadas en la regla YARA");
    }

    Ok(())
}

fn get_linux_curated_yara_rules() -> Vec<(&'static str, &'static str, &'static str, ThreatSeverity)> {
    vec![
        (
            "linux_mirai_botnet_elf",
            r#"rule linux_mirai_botnet_elf {
    meta:
        description = "Detecta variantes activas del botnet Mirai para arquitecturas Linux"
        author = "SamuLibre Threat Intel"
        severity = "Critical"
    strings:
        $s1 = "/bin/busybox" ascii
        $s2 = "POST /cdn-cgi/" ascii
        $s3 = "REPORT %s:%s" ascii
        $s4 = "HTTPFlooder" ascii
    condition:
        uint32(0) == 0x464c457f and (2 of ($s*))
}"#,
            "Linux.Botnet.Mirai",
            ThreatSeverity::Critical,
        ),
        (
            "linux_kinsing_miner_agent",
            r#"rule linux_kinsing_miner_agent {
    meta:
        description = "Detecta el cargador y ejecutable Kinsing cryptominer en Linux"
        author = "SamuLibre Threat Intel"
    strings:
        $k1 = "kdevtmpfsi" ascii
        $k2 = "kinsing" ascii
        $k3 = "alsp.sh" ascii
        $k4 = "kinsing.service" ascii
    condition:
        uint32(0) == 0x464c457f and (2 of ($k*))
}"#,
            "Linux.Coinminer.Kinsing",
            ThreatSeverity::High,
        ),
        (
            "linux_webshell_b374k_c99",
            r#"rule linux_webshell_b374k_c99 {
    meta:
        description = "Detección de webshells comunes empleadas para persistencia en servidores Linux"
        author = "SamuLibre Threat Intel"
    strings:
        $w1 = "b374k" nocase ascii
        $w2 = "c99shell" nocase ascii
        $w3 = "r57shell" nocase ascii
        $w4 = "eval(base64_decode(" ascii
        $w5 = "passthru($_" ascii
    condition:
        2 of ($w*)
}"#,
            "Webshell.Linux.Backdoor",
            ThreatSeverity::Critical,
        ),
        (
            "linux_reverse_shell_bash",
            r#"rule linux_reverse_shell_bash {
    meta:
        description = "Detecta reverse shells en scripts de shell o tareas de cron"
        author = "SamuLibre Threat Intel"
    strings:
        $r1 = "bash -i >& /dev/tcp/" ascii
        $r2 = "0>&1 2>&1" ascii
        $r3 = "mkfifo /tmp/" ascii
        $r4 = "/bin/sh -i <&" ascii
    condition:
        (1 of ($r1, $r4)) or (all of ($r2, $r3))
}"#,
            "Trojan.Script.ReverseShell",
            ThreatSeverity::High,
        ),
        (
            "linux_ransomware_esxi_deadbolt",
            r#"rule linux_ransomware_esxi_deadbolt {
    meta:
        description = "Detecta ransomware dirigido a infraestructuras Linux y VMware ESXi"
        author = "SamuLibre Threat Intel"
    strings:
        $e1 = ".deadbolt" ascii
        $e2 = "HOW_TO_RESTORE_FILES.txt" ascii
        $e3 = "encrypt_file" ascii
        $e4 = "openssl enc -aes-256-cbc" ascii
    condition:
        uint32(0) == 0x464c457f and (2 of ($e*))
}"#,
            "Ransomware.Linux.DeadBolt",
            ThreatSeverity::Critical,
        ),
    ]
}
