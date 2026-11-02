pub mod audit_center;
pub mod downloader;
pub mod manager;
pub mod models;
pub mod normalizer;
pub mod providers;
pub mod storage;
pub mod whitelist;

pub use audit_center::UpdateAuditCenter;
pub use downloader::SecureDownloader;
pub use manager::ThreatIntelligenceUpdateManager;
pub use models::{
    IndicatorType, ProviderEvidence, ProviderFetchResult, ProviderStatus, SourceEvidence, ThreatIndicator,
    ThreatSeverity, UpdateEvidence, UpdateProfile, UpdateStatus,
};
pub use normalizer::IndicatorNormalizer;
pub use providers::ThreatIntelProvider;
pub use storage::AtomicThreatStorage;
pub use whitelist::ThreatWhitelist;

#[cfg(test)]
mod tests {
    use super::*;
    use models::*;
    use std::fs;
    use std::path::PathBuf;

    struct TestDir(PathBuf);
    impl TestDir {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("samulibre_test_{}", uuid::Uuid::new_v4()));
            fs::create_dir_all(&path).unwrap();
            TestDir(path)
        }
        fn path(&self) -> &std::path::Path {
            &self.0
        }
    }
    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn test_normalizer_whitelist_and_deduplication() {
        let normalizer = IndicatorNormalizer::new();

        // 1. Hashes protegidos por lista blanca deben ser rechazados
        let empty_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        assert!(normalizer.validate_and_normalize_hash(empty_hash).is_none());

        // 2. Hash válido SHA-256
        let valid_hash = "3395856ce81f2d7382dee72602f798b642f14140024b934b82670273a6543632";
        let res = normalizer.validate_and_normalize_hash(valid_hash);
        assert!(res.is_some());
        assert_eq!(res.unwrap().1, IndicatorType::FileHashSha256);

        // 3. Fusión y deduplicación multi-fuente
        let ind1 = ThreatIndicator {
            id: "ind-1".to_string(),
            indicator_type: IndicatorType::FileHashSha256,
            value: valid_hash.to_string(),
            malware_family: "Trojan.Generic".to_string(),
            severity: ThreatSeverity::Medium,
            confidence_score: 70,
            sources: vec![SourceEvidence {
                provider_id: "source_a".to_string(),
                provider_name: "Source A".to_string(),
                report_date: "2026-11-02T10:00:00Z".to_string(),
                confidence: 70,
                reference_url: None,
                tags: vec!["trojan".to_string()],
            }],
            description: "Test sample A".to_string(),
            first_seen: "2026-11-02T10:00:00Z".to_string(),
            last_updated: "2026-11-02T10:00:00Z".to_string(),
            is_active: true,
        };

        let ind2 = ThreatIndicator {
            id: "ind-2".to_string(),
            indicator_type: IndicatorType::FileHashSha256,
            value: valid_hash.to_string(),
            malware_family: "Ransomware.Conti.Gen".to_string(),
            severity: ThreatSeverity::Critical,
            confidence_score: 85,
            sources: vec![SourceEvidence {
                provider_id: "source_b".to_string(),
                provider_name: "Source B".to_string(),
                report_date: "2026-11-02T10:05:00Z".to_string(),
                confidence: 85,
                reference_url: None,
                tags: vec!["conti".to_string()],
            }],
            description: "Test sample B".to_string(),
            first_seen: "2026-11-02T10:05:00Z".to_string(),
            last_updated: "2026-11-02T10:05:00Z".to_string(),
            is_active: true,
        };

        let consolidation = normalizer.consolidate(vec![ind1, ind2], &[]);
        assert_eq!(consolidation.total_processed, 2);
        assert_eq!(consolidation.new_unique, 1);
        assert_eq!(consolidation.duplicates_merged, 1);
        assert_eq!(consolidation.indicators.len(), 1);

        let merged = &consolidation.indicators[0];
        assert_eq!(merged.sources.len(), 2);
        assert_eq!(merged.severity, ThreatSeverity::Critical);
        assert_eq!(merged.malware_family, "Ransomware.Conti.Gen");
        assert!(merged.confidence_score >= 85);
    }

    #[test]
    fn test_yara_syntax_validator() {
        use providers::yara_rules::validate_yara_rule_syntax;

        let valid_rule = r#"rule test_rule {
            strings: $a = "malicious"
            condition: $a
        }"#;
        assert!(validate_yara_rule_syntax("test_rule", valid_rule).is_ok());

        let unclosed = r#"rule broken_rule {
            strings: $a = "malicious"
            condition: $a
        "#;
        assert!(validate_yara_rule_syntax("broken_rule", unclosed).is_err());

        let missing_condition = r#"rule no_condition {
            strings: $a = "malicious"
        }"#;
        assert!(validate_yara_rule_syntax("no_condition", missing_condition).is_err());
    }

    #[test]
    fn test_atomic_storage_and_rollback() {
        let temp_dir = TestDir::new();
        let storage = AtomicThreatStorage::new(temp_dir.path().to_path_buf());

        let initial_ind = vec![ThreatIndicator {
            id: "init-1".to_string(),
            indicator_type: IndicatorType::FileHashSha256,
            value: "1111111111111111111111111111111111111111111111111111111111111111".to_string(),
            malware_family: "Trojan.Initial".to_string(),
            severity: ThreatSeverity::Medium,
            confidence_score: 80,
            sources: vec![],
            description: "Initial db".to_string(),
            first_seen: "2026-11-02".to_string(),
            last_updated: "2026-11-02".to_string(),
            is_active: true,
        }];

        // Fase 1: Commit inicial
        let stage1 = storage.stage_update("OP-01", &initial_ind).unwrap();
        storage.commit_atomic_update(&stage1).unwrap();
        let hash_v1 = storage.compute_active_db_hash();
        assert_ne!(hash_v1, "no_db");

        // Fase 2: Segundo commit con más firmas
        let updated_ind = vec![
            initial_ind[0].clone(),
            ThreatIndicator {
                id: "init-2".to_string(),
                indicator_type: IndicatorType::FileHashSha256,
                value: "2222222222222222222222222222222222222222222222222222222222222222".to_string(),
                malware_family: "Trojan.Second".to_string(),
                severity: ThreatSeverity::High,
                confidence_score: 90,
                sources: vec![],
                description: "Second db".to_string(),
                first_seen: "2026-11-02".to_string(),
                last_updated: "2026-11-02".to_string(),
                is_active: true,
            },
        ];

        let stage2 = storage.stage_update("OP-02", &updated_ind).unwrap();
        storage.commit_atomic_update(&stage2).unwrap();
        let hash_v2 = storage.compute_active_db_hash();
        assert_ne!(hash_v1, hash_v2);

        // Fase 3: Rollback
        let rolled_back = storage.rollback_to_previous().unwrap();
        assert!(rolled_back);
        let hash_after_rollback = storage.compute_active_db_hash();
        assert_eq!(hash_after_rollback, hash_v1);
    }

    #[test]
    fn test_audit_center_evidence_and_exports() {
        let temp_dir = TestDir::new();
        let audit_center = UpdateAuditCenter::new(temp_dir.path());

        let mut evidence = UpdateEvidence {
            operation_id: "UP-TEST-AUDIT-001".to_string(),
            started_at: "2026-11-02T10:00:00Z".to_string(),
            completed_at: "2026-11-02T10:00:02Z".to_string(),
            duration_ms: 2000,
            linux_distro: "Garuda Linux".to_string(),
            antivirus_version: "v2.0.32".to_string(),
            previous_db_version: "v1_hash".to_string(),
            new_db_version: "v2_hash".to_string(),
            profile: UpdateProfile::Normal,
            providers: vec![ProviderEvidence {
                provider_id: "threatfox".to_string(),
                provider_name: "ThreatFox IOC Feed".to_string(),
                status: ProviderStatus::Success,
                indicators_fetched: 50,
                indicators_accepted: 48,
                payload_sha256: Some("payload_hash_123".to_string()),
                duration_ms: 450,
                error_message: None,
            }],
            total_indicators_downloaded: 50,
            new_indicators_added: 48,
            duplicate_indicators_merged: 2,
            rejected_indicators_count: 0,
            yara_rules_updated: 5,
            signatures_updated: 48,
            status: UpdateStatus::Completada,
            verification_summary: "Verificación de firmas y reglas exitosa.".to_string(),
            evidence_hash_sha256: String::new(),
        };

        let op_id = audit_center.record_evidence(&mut evidence).unwrap();
        assert_eq!(op_id, "UP-TEST-AUDIT-001");

        // Validar consulta
        let fetched = audit_center.get_evidence("UP-TEST-AUDIT-001").unwrap();
        assert!(fetched.is_some());
        let ev = fetched.unwrap();
        assert_eq!(ev.status, UpdateStatus::Completada);
        assert!(!ev.evidence_hash_sha256.is_empty());

        // Validar exportadores JSON, CSV, HTML
        let json_exp = audit_center.export_json("UP-TEST-AUDIT-001").unwrap();
        assert!(json_exp.contains("UP-TEST-AUDIT-001"));

        let csv_exp = audit_center.export_csv("UP-TEST-AUDIT-001").unwrap();
        assert!(csv_exp.contains("threatfox"));
        assert!(csv_exp.contains("SUCCESS"));

        let html_exp = audit_center.export_html_report("UP-TEST-AUDIT-001").unwrap();
        assert!(html_exp.contains("Certificado de Auditoría de Actualización"));
        assert!(html_exp.contains("COMPLETADO"));
    }

    #[test]
    fn test_update_manager_lifecycle() {
        let temp_dir = TestDir::new();
        let manager = ThreatIntelligenceUpdateManager::new(temp_dir.path().to_path_buf());

        let evidence = manager.run_update(None).unwrap();
        assert!(matches!(evidence.status, UpdateStatus::Completada | UpdateStatus::CompletadaParcialmente));
        assert!(evidence.total_indicators_downloaded > 0);
        assert!(evidence.signatures_updated > 0);

        let latest = manager.audit_center().get_latest_evidence().unwrap();
        assert!(latest.is_some());
        assert_eq!(latest.unwrap().operation_id, evidence.operation_id);
    }
}
