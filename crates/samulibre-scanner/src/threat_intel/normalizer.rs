use super::models::{IndicatorType, ThreatIndicator};
use super::whitelist::ThreatWhitelist;
use std::collections::HashMap;
use tracing::warn;
use uuid::Uuid;

/// Normalizador, clasificador y motor de deduplicación de inteligencia de amenazas
pub struct IndicatorNormalizer {
    whitelist: ThreatWhitelist,
}

impl Default for IndicatorNormalizer {
    fn default() -> Self {
        Self {
            whitelist: ThreatWhitelist::default(),
        }
    }
}

pub struct ConsolidationResult {
    pub indicators: Vec<ThreatIndicator>,
    pub total_processed: usize,
    pub new_unique: usize,
    pub duplicates_merged: usize,
    pub rejected: usize,
}

impl IndicatorNormalizer {
    pub fn new() -> Self {
        Self::default()
    }

    /// Valida un hash hexadecimal y determina su tipo
    pub fn validate_and_normalize_hash(&self, raw_hash: &str) -> Option<(String, IndicatorType)> {
        let clean = raw_hash.trim().to_lowercase();
        if self.whitelist.is_hash_whitelisted(&clean) {
            warn!("Hash protegido por lista blanca descartado: {}", clean);
            return None;
        }

        if clean.len() == 64 && clean.chars().all(|c| c.is_ascii_hexdigit()) {
            Some((clean, IndicatorType::FileHashSha256))
        } else if clean.len() == 32 && clean.chars().all(|c| c.is_ascii_hexdigit()) {
            Some((clean, IndicatorType::FileHashMd5))
        } else {
            None
        }
    }

    /// Valida y normaliza un dominio
    pub fn validate_domain(&self, raw_domain: &str) -> Option<String> {
        let clean = raw_domain.trim().to_lowercase();
        if clean.is_empty() || clean.len() > 253 || self.whitelist.is_domain_whitelisted(&clean) {
            return None;
        }
        if clean.contains('/') || clean.contains(':') || clean.contains(' ') {
            return None;
        }
        Some(clean)
    }

    /// Valida y normaliza una IP
    pub fn validate_ip(&self, raw_ip: &str) -> Option<String> {
        let clean = raw_ip.trim();
        if self.whitelist.is_ip_whitelisted(clean) {
            return None;
        }
        if clean.parse::<std::net::IpAddr>().is_ok() {
            Some(clean.to_string())
        } else {
            None
        }
    }

    /// Consolida y deduplica una colección de indicadores provenientes de múltiples proveedores
    pub fn consolidate(
        &self,
        incoming: Vec<ThreatIndicator>,
        existing: &[ThreatIndicator],
    ) -> ConsolidationResult {
        let total_processed = incoming.len();
        let mut map: HashMap<String, ThreatIndicator> = HashMap::new();

        // 1. Cargar existentes en el mapa de deduplicación
        for item in existing {
            map.insert(format!("{}:{}", item.indicator_type, item.value), item.clone());
        }

        let mut duplicates_merged = 0;
        let mut rejected = 0;
        let mut new_unique = 0;

        // 2. Procesar entrantes
        for mut inc in incoming {
            // Validación previa contra lista blanca
            let is_whitelisted = match inc.indicator_type {
                IndicatorType::FileHashSha256 | IndicatorType::FileHashMd5 => {
                    self.whitelist.is_hash_whitelisted(&inc.value)
                }
                IndicatorType::NetworkDomain => self.whitelist.is_domain_whitelisted(&inc.value),
                IndicatorType::NetworkIp => self.whitelist.is_ip_whitelisted(&inc.value),
                _ => false,
            };

            if is_whitelisted {
                rejected += 1;
                continue;
            }

            let key = format!("{}:{}", inc.indicator_type, inc.value);

            if let Some(existing_entry) = map.get_mut(&key) {
                // Deduplicación inteligente: Fusionar fuentes y reforzar nivel de confianza
                duplicates_merged += 1;
                existing_entry.last_updated = chrono::Utc::now().to_rfc3339();

                // Fusión de evidencias de fuentes
                for s in inc.sources {
                    if !existing_entry.sources.iter().any(|cur| cur.provider_id == s.provider_id) {
                        existing_entry.sources.push(s);
                        // Aumentar nivel de confianza por confirmación multi-fuente
                        existing_entry.confidence_score = (existing_entry.confidence_score + 15).min(99);
                    }
                }

                // Ajustar severidad a la más restrictiva
                if inc.severity > existing_entry.severity {
                    existing_entry.severity = inc.severity;
                }

                // Enriquecer nombre de familia si la existente era genérica
                if existing_entry.malware_family.contains("Generic") && !inc.malware_family.contains("Generic") {
                    existing_entry.malware_family = inc.malware_family;
                }
            } else {
                // Nuevo indicador único
                new_unique += 1;
                if inc.id.is_empty() {
                    inc.id = Uuid::new_v4().to_string();
                }
                map.insert(key, inc);
            }
        }

        let consolidated: Vec<ThreatIndicator> = map.into_values().collect();

        ConsolidationResult {
            indicators: consolidated,
            total_processed,
            new_unique,
            duplicates_merged,
            rejected,
        }
    }
}
