use anyhow::Result;
use clap::Parser;
use colored::Colorize;
use samulibre_core::event_db::SecurityEventDatabase;
use samulibre_core::ipc::{resolve_ipc_socket_path, IpcRequest, IpcResponse, UnixSocketServer};
use samulibre_core::SamuLibreCore;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{error, info, warn};

#[derive(Parser, Debug)]
#[command(name = "samulibred", about = "Demonio de Seguridad del Sistema SamuLibre (Systemd Daemon)")]
struct Args {
    #[arg(short, long, help = "Ruta personalizada del UNIX Domain Socket")]
    socket: Option<PathBuf>,

    #[arg(short, long, help = "Ruta a la base de datos de eventos SQLite")]
    db: Option<PathBuf>,

    #[arg(long, help = "Ejecutar en modo foreground (no demonizar)")]
    foreground: bool,

    #[arg(long, help = "Modo dry-run (no aplicar cambios reales en el kernel)")]
    dry_run: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let args = Args::parse();

    println!("{}", "══════════════════════════════════════════════════════════".cyan());
    println!("{}", "      SamuLibre Security Daemon (samulibred v2.0.32)      ".bold().green());
    println!("{}", "    Demonio de Seguridad del Sistema y EDR para Linux    ".cyan());
    println!("{}", "══════════════════════════════════════════════════════════".cyan());

    // 1. Endurecimiento Anti-Tamper a nivel de Kernel (PR_SET_DUMPABLE = 0)
    #[cfg(target_os = "linux")]
    {
        let res = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) };
        if res == 0 {
            info!("Autoprotección del Demonio activa: PR_SET_DUMPABLE=0 habilitado.");
        } else {
            warn!("No se pudo configurar PR_SET_DUMPABLE=0 en el proceso del demonio.");
        }
    }

    // 2. Determinar rutas del sistema
    let is_root = unsafe { libc::geteuid() == 0 };
    let (data_dir, default_sock, default_db) = if is_root {
        (
            PathBuf::from("/var/lib/samulibre"),
            PathBuf::from("/run/samulibre/samulibre.sock"),
            PathBuf::from("/var/lib/samulibre/events.db"),
        )
    } else {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
        let user_base = PathBuf::from(home).join(".local/share/samulibre");
        (
            user_base.clone(),
            resolve_ipc_socket_path(),
            user_base.join("data").join("events.db"),
        )
    };

    let sock_path = args.socket.unwrap_or(default_sock);
    let db_path = args.db.unwrap_or(default_db);

    info!("Iniciando samulibred con socket: {}", sock_path.display());
    info!("Base de datos de eventos SQLite: {}", db_path.display());

    // 3. Inicializar Base de Datos SQLite (WAL Mode)
    let event_db = match SecurityEventDatabase::new(&db_path) {
        Ok(db) => {
            info!("Base de datos de eventos conectada exitosamente.");
            Arc::new(Mutex::new(Some(db)))
        }
        Err(e) => {
            warn!("No se pudo abrir base de datos SQLite ({}), continuando sin persistencia relacional.", e);
            Arc::new(Mutex::new(None))
        }
    };

    // 4. Inicializar SamuLibreCore
    let canary_dir = data_dir.join("canaries");
    let vpn_dir = data_dir.join("vpn");
    let core = Arc::new(Mutex::new(SamuLibreCore::new(&canary_dir, &vpn_dir, args.dry_run)));

    // 5. Iniciar Servidor UNIX Domain Socket
    let mut server = match UnixSocketServer::bind(&sock_path) {
        Ok(s) => s,
        Err(e) => {
            error!("Error fatal iniciando servidor UNIX socket en {}: {}", sock_path.display(), e);
            return Err(e);
        }
    };

    println!("{} Socket IPC listo en: {}", "✔".green(), sock_path.display());
    println!("{} Demonio operando activamente en segundo plano.", "✔".green());

    let core_for_handler = Arc::clone(&core);
    let db_for_handler = Arc::clone(&event_db);

    let handler = move |req: IpcRequest| {
        let core = Arc::clone(&core_for_handler);
        let db = Arc::clone(&db_for_handler);

        async move {
            match req.action.as_str() {
                "ping" => {
                    IpcResponse::ok(&req.id, serde_json::json!({
                        "daemon": "samulibred",
                        "version": "2.0.32",
                        "status": "online",
                        "timestamp": chrono::Utc::now().to_rfc3339()
                    }))
                }

                "get_status" => {
                    let c = core.lock().await;
                    let status = c.get_status();
                    IpcResponse::ok(&req.id, serde_json::to_value(&status).unwrap_or_default())
                }

                "scan_file" => {
                    let path_str = req.payload
                        .and_then(|p| p.get("path").and_then(|v| v.as_str()).map(|s| s.to_string()))
                        .unwrap_or_default();

                    if path_str.is_empty() {
                        return IpcResponse::err(&req.id, "Ruta de archivo vacía");
                    }

                    let p = Path::new(&path_str);
                    let c = core.lock().await;
                    match c.scan_file_path(p) {
                        Ok(result) => {
                            if result.status == samulibre_types::FileScanStatus::Infected {
                                let d_guard = db.lock().await;
                                if let Some(ref d) = *d_guard {
                                    let record = samulibre_types::ThreatRecord {
                                        id: uuid::Uuid::new_v4().to_string(),
                                        timestamp: chrono::Utc::now().to_rfc3339(),
                                        file_path: result.file_path.clone(),
                                        threat_name: result.detection_name.clone().unwrap_or_else(|| "Generic.Threat".to_string()),
                                        severity: "High".to_string(),
                                        engine: result.engine.clone(),
                                        sha256: result.sha256.clone(),
                                        action_taken: "Detectado".to_string(),
                                        human_explanation: result.detection_name.clone(),
                                        quarantine_id: None,
                                        origin_source: None,
                                        origin_url: None,
                                        suggested_action: None,
                                    };
                                    let _ = d.log_threat(&record);
                                }
                            }
                            IpcResponse::ok(&req.id, serde_json::to_value(&result).unwrap_or_default())
                        }
                        Err(e) => IpcResponse::err(&req.id, format!("Error en escaneo: {}", e)),
                    }
                }

                "isolate_process_network" => {
                    let pid = req.payload
                        .and_then(|p| p.get("pid").and_then(|v| v.as_u64()).map(|n| n as u32))
                        .unwrap_or(0);

                    if pid == 0 {
                        return IpcResponse::err(&req.id, "PID de proceso inválido");
                    }

                    let c = core.lock().await;
                    match c.isolate_process_network(pid, true) {
                        Ok(msg) => {
                            let d_guard = db.lock().await;
                            if let Some(ref d) = *d_guard {
                                let _ = d.log_audit_event(
                                    "PROCESS_ISOLATE",
                                    "High",
                                    "samulibred",
                                    &format!("PID {} aislado de la red mediante Netfilter/iptables: {}", pid, msg),
                                    Some(&format!("{{\"pid\": {}}}", pid)),
                                );
                            }
                            IpcResponse::ok(&req.id, serde_json::json!({"result": msg}))
                        }
                        Err(e) => IpcResponse::err(&req.id, format!("Fallo al aislar proceso {}: {}", pid, e)),
                    }
                }

                "get_threat_history" => {
                    let limit = req.payload
                        .and_then(|p| p.get("limit").and_then(|v| v.as_u64()).map(|n| n as usize))
                        .unwrap_or(50);

                    let d_guard = db.lock().await;
                    if let Some(ref d) = *d_guard {
                        match d.list_threats(limit) {
                            Ok(threats) => IpcResponse::ok(&req.id, serde_json::to_value(&threats).unwrap_or_default()),
                            Err(e) => IpcResponse::err(&req.id, format!("Error en SQLite: {}", e)),
                        }
                    } else {
                        IpcResponse::ok(&req.id, serde_json::json!([]))
                    }
                }

                "get_audit_events" => {
                    let limit = req.payload
                        .and_then(|p| p.get("limit").and_then(|v| v.as_u64()).map(|n| n as usize))
                        .unwrap_or(50);

                    let d_guard = db.lock().await;
                    if let Some(ref d) = *d_guard {
                        match d.list_audit_events(limit) {
                            Ok(events) => IpcResponse::ok(&req.id, serde_json::to_value(&events).unwrap_or_default()),
                            Err(e) => IpcResponse::err(&req.id, format!("Error en SQLite: {}", e)),
                        }
                    } else {
                        IpcResponse::ok(&req.id, serde_json::json!([]))
                    }
                }

                "get_persistence_entries" => {
                    let c = core.lock().await;
                    let entries = c.get_persistence_entries();
                    IpcResponse::ok(&req.id, serde_json::to_value(&entries).unwrap_or_default())
                }

                "get_network_sockets" => {
                    let c = core.lock().await;
                    let sockets = c.get_network_sockets();
                    IpcResponse::ok(&req.id, serde_json::to_value(&sockets).unwrap_or_default())
                }

                _ => IpcResponse::err(&req.id, format!("Acción '{}' no implementada en el daemon", req.action)),
            }
        }
    };

    // 6. Ejecutar servidor y escuchar señales de parada (SIGINT / SIGTERM)
    tokio::select! {
        res = server.run_server(handler) => {
            if let Err(e) = res {
                error!("Servidor IPC terminado con error: {}", e);
            }
        }
        _ = tokio::signal::ctrl_c() => {
            info!("Señal de apagado recibida (Ctrl+C). Apagando samulibred de forma ordenada...");
        }
    }

    println!("{}", "Demonio samulibred apagado de forma segura.".green());
    Ok(())
}
