use anyhow::Result;
use chrono::Utc;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tracing::info;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub id: String,
    pub timestamp: String,
    pub event_type: String,
    pub severity: String,
    pub source: String,
    pub description: String,
    pub payload_json: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EventSummaryStats {
    pub total_threats: usize,
    pub neutralized_threats: usize,
    pub pending_threats: usize,
    pub isolated_quarantines: usize,
    pub total_audit_events: usize,
}

/// Base de Datos de Eventos de Seguridad y Telemetría Local basada en SQLite (WAL Mode)
#[derive(Clone)]
pub struct SecurityEventDatabase {
    conn: Arc<Mutex<Connection>>,
    db_path: PathBuf,
}

impl SecurityEventDatabase {
    /// Inicializa o abre la base de datos de eventos en la ruta especificada
    pub fn new(db_path: impl AsRef<Path>) -> Result<Self> {
        let path = db_path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            let _ = fs::create_dir_all(parent);
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(parent, fs::Permissions::from_mode(0o750));
            }
        }

        let conn = Connection::open(&path)?;

        // Optimización WAL (Write-Ahead Logging) y contención ACID
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             PRAGMA temp_store = MEMORY;
             PRAGMA cache_size = -2000;
             PRAGMA foreign_keys = ON;",
        )?;

        // Creación de tablas de auditoría
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS threat_events (
                id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                file_path TEXT NOT NULL,
                threat_name TEXT NOT NULL,
                severity TEXT NOT NULL,
                engine TEXT NOT NULL,
                sha256 TEXT NOT NULL,
                action_taken TEXT NOT NULL,
                details TEXT
            );

            CREATE TABLE IF NOT EXISTS audit_events (
                id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                event_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                source TEXT NOT NULL,
                description TEXT NOT NULL,
                payload_json TEXT
            );

            CREATE TABLE IF NOT EXISTS exclusions (
                path TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                is_directory INTEGER NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_threat_timestamp ON threat_events(timestamp);
            CREATE INDEX IF NOT EXISTS idx_threat_sha256 ON threat_events(sha256);
            CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_events(timestamp);
            CREATE INDEX IF NOT EXISTS idx_audit_type ON audit_events(event_type);",
        )?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o640));
        }

        info!("Base de datos de eventos de seguridad SQLite inicializada en: {}", path.display());

        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
            db_path: path,
        })
    }

    /// Registra una amenaza detectada en la base de datos relacional
    pub fn log_threat(&self, record: &samulibre_types::ThreatRecord) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO threat_events (id, timestamp, file_path, threat_name, severity, engine, sha256, action_taken, details)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
             ON CONFLICT(id) DO UPDATE SET action_taken = excluded.action_taken, details = excluded.details",
            params![
                record.id,
                record.timestamp,
                record.file_path,
                record.threat_name,
                record.severity,
                record.engine,
                record.sha256,
                record.action_taken,
                record.human_explanation.as_deref().unwrap_or("")
            ],
        )?;
        Ok(())
    }

    /// Actualiza el estado o acción tomada sobre una amenaza
    pub fn update_threat_action(&self, id: &str, action: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE threat_events SET action_taken = ?1 WHERE id = ?2",
            params![action, id],
        )?;
        Ok(())
    }

    /// Retorna el historial de amenazas ordenado por fecha descendente
    pub fn list_threats(&self, limit: usize) -> Result<Vec<samulibre_types::ThreatRecord>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, timestamp, file_path, threat_name, severity, engine, sha256, action_taken, details
             FROM threat_events ORDER BY timestamp DESC LIMIT ?1",
        )?;

        let rows = stmt.query_map(params![limit as i64], |row| {
            let details: String = row.get(8)?;
            Ok(samulibre_types::ThreatRecord {
                id: row.get(0)?,
                timestamp: row.get(1)?,
                file_path: row.get(2)?,
                threat_name: row.get(3)?,
                severity: row.get(4)?,
                engine: row.get(5)?,
                sha256: row.get(6)?,
                action_taken: row.get(7)?,
                human_explanation: Some(details),
                quarantine_id: None,
                origin_source: None,
                origin_url: None,
                suggested_action: None,
            })
        })?;

        let mut list = Vec::new();
        for r in rows.flatten() {
            list.push(r);
        }
        Ok(list)
    }

    /// Registra un evento de auditoría general (aislamiento, firewall, canarios, persistencia)
    pub fn log_audit_event(
        &self,
        event_type: &str,
        severity: &str,
        source: &str,
        description: &str,
        payload: Option<&str>,
    ) -> Result<String> {
        let id = uuid::Uuid::new_v4().to_string();
        let timestamp = Utc::now().to_rfc3339();

        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO audit_events (id, timestamp, event_type, severity, source, description, payload_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![id, timestamp, event_type, severity, source, description, payload],
        )?;

        Ok(id)
    }

    /// Consulta eventos de auditoría recientes
    pub fn list_audit_events(&self, limit: usize) -> Result<Vec<AuditEvent>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, timestamp, event_type, severity, source, description, payload_json
             FROM audit_events ORDER BY timestamp DESC LIMIT ?1",
        )?;

        let rows = stmt.query_map(params![limit as i64], |row| {
            Ok(AuditEvent {
                id: row.get(0)?,
                timestamp: row.get(1)?,
                event_type: row.get(2)?,
                severity: row.get(3)?,
                source: row.get(4)?,
                description: row.get(5)?,
                payload_json: row.get(6)?,
            })
        })?;

        let mut list = Vec::new();
        for r in rows.flatten() {
            list.push(r);
        }
        Ok(list)
    }

    /// Obtiene estadísticas agregadas de la base de datos
    pub fn get_summary_stats(&self) -> Result<EventSummaryStats> {
        let conn = self.conn.lock().unwrap();

        let total_threats: i64 = conn.query_row(
            "SELECT COUNT(*) FROM threat_events",
            [],
            |r| r.get(0),
        )?;

        let neutralized_threats: i64 = conn.query_row(
            "SELECT COUNT(*) FROM threat_events WHERE action_taken IN ('Eliminado', 'En Cuarentena', 'Neutralizado')",
            [],
            |r| r.get(0),
        )?;

        let pending_threats: i64 = conn.query_row(
            "SELECT COUNT(*) FROM threat_events WHERE action_taken = 'Pendiente'",
            [],
            |r| r.get(0),
        )?;

        let total_audit_events: i64 = conn.query_row(
            "SELECT COUNT(*) FROM audit_events",
            [],
            |r| r.get(0),
        )?;

        Ok(EventSummaryStats {
            total_threats: total_threats as usize,
            neutralized_threats: neutralized_threats as usize,
            pending_threats: pending_threats as usize,
            isolated_quarantines: 0,
            total_audit_events: total_audit_events as usize,
        })
    }

    pub fn get_path(&self) -> &Path {
        &self.db_path
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_database_lifecycle() {
        let temp_dir = std::env::temp_dir().join(format!("samu_db_test_{}", std::process::id()));
        let db_file = temp_dir.join("test_events.db");

        let db = SecurityEventDatabase::new(&db_file).expect("Failed to create test db");

        // Registrar amenaza
        let threat = samulibre_types::ThreatRecord {
            id: "threat-uuid-001".to_string(),
            timestamp: Utc::now().to_rfc3339(),
            file_path: "/tmp/sample.elf".to_string(),
            threat_name: "Trojan.Linux.Base64Shell".to_string(),
            severity: "Critical".to_string(),
            engine: "SamuLibre Heuristic".to_string(),
            sha256: "aabbcc112233".to_string(),
            action_taken: "Pendiente".to_string(),
            human_explanation: Some("Sample detection test".to_string()),
            quarantine_id: None,
            origin_source: None,
            origin_url: None,
            suggested_action: None,
        };

        db.log_threat(&threat).expect("Failed to log threat");

        // Actualizar acción
        db.update_threat_action("threat-uuid-001", "Eliminado").expect("Failed to update");

        // Consultar
        let threats = db.list_threats(10).expect("Failed to list threats");
        assert_eq!(threats.len(), 1);
        assert_eq!(threats[0].action_taken, "Eliminado");

        // Registrar evento de auditoría
        let audit_id = db.log_audit_event(
            "FIREWALL_ISOLATE",
            "High",
            "linux_monitor",
            "PID 1234 aislado de la red por Netfilter",
            Some("{\"pid\": 1234}"),
        ).expect("Failed to log audit event");

        let audits = db.list_audit_events(10).expect("Failed to list audit events");
        assert_eq!(audits.len(), 1);
        assert_eq!(audits[0].id, audit_id);
        assert_eq!(audits[0].event_type, "FIREWALL_ISOLATE");

        let stats = db.get_summary_stats().expect("Failed to get stats");
        assert_eq!(stats.total_threats, 1);
        assert_eq!(stats.neutralized_threats, 1);
        assert_eq!(stats.pending_threats, 0);

        let _ = fs::remove_dir_all(&temp_dir);
    }
}
