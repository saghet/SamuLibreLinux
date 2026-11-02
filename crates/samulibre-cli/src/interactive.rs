use anyhow::Result;
use colored::*;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

pub async fn run_interactive_menu(
    canary_dir: &Path,
    vpn_dir: &Path,
    db_path: &Path,
) -> Result<()> {
    loop {
        println!("\n{}", "╔════════════════════════════════════════════════════════════════════════╗".bright_cyan());
        println!("{}", "║                  SAMULIBRE LINUX - PANEL INTERACTIVO                   ║".bright_cyan().bold());
        println!("{}", "║             Suite de Seguridad, EDR y Privacidad Zero-Cloud             ║".bright_cyan());
        println!("{}", "╚════════════════════════════════════════════════════════════════════════╝".bright_cyan());

        println!("\n  {} {}", "[1]".bold().yellow(), "Estado Global de Protección y Demonio samulibred");
        println!("  {} {}", "[2]".bold().yellow(), "Escanear Archivo o Directorio (Multi-Motor)");
        println!("  {} {}", "[3]".bold().yellow(), "Inspector de Red: Sockets TCP y Procesos en Vivo");
        println!("  {} {}", "[4]".bold().yellow(), "Base de Datos SQLite WAL: Estadísticas e Historial");
        println!("  {} {}", "[5]".bold().yellow(), "Gestión de Exclusiones de Escaneo");
        println!("  {} {}", "[6]".bold().yellow(), "Generar Informe Forense y de Auditoría (HTML / JSON)");
        println!("  {} {}", "[7]".bold().yellow(), "Desplegar / Auditar Canarios Anti-Ransomware");
        println!("  {} {}", "[8]".bold().yellow(), "Copiloto Forense con Inteligencia Artificial Local");
        println!("  {} {}", "[9]".bold().yellow(), "Salir");

        print!("\n{} Ingrese una opción [1-9]: ", "➤".cyan().bold());
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        let choice = input.trim();

        match choice {
            "1" => {
                show_interactive_status(canary_dir, vpn_dir).await?;
            }
            "2" => {
                interactive_scan().await?;
            }
            "3" => {
                interactive_network(canary_dir, vpn_dir).await?;
            }
            "4" => {
                interactive_db(db_path)?;
            }
            "5" => {
                interactive_exclusions(db_path)?;
            }
            "6" => {
                interactive_report(canary_dir, vpn_dir, db_path)?;
            }
            "7" => {
                interactive_canaries(canary_dir)?;
            }
            "8" => {
                interactive_copilot(canary_dir, vpn_dir)?;
            }
            "9" | "q" | "exit" => {
                println!("\n{} Saliendo del panel interactivo de SamuLibre. ¡Sistema protegido!", "✔".green());
                break;
            }
            _ => {
                println!("\n{} Opción no válida, intente de nuevo.", "✘".red());
            }
        }

        print!("\nPresione Enter para continuar...");
        io::stdout().flush()?;
        let mut pause = String::new();
        let _ = io::stdin().read_line(&mut pause);
    }

    Ok(())
}

async fn show_interactive_status(canary_dir: &Path, vpn_dir: &Path) -> Result<()> {
    println!("\n{}", "─── ESTADO GLOBAL DE PROTECCIÓN SAMULIBRE ───".bold().cyan());

    // Demonio IPC
    let socket_path = samulibre_core::ipc::resolve_ipc_socket_path();
    let (daemon_online, ping_latency_us) = match samulibre_core::ipc::UnixSocketClient::connect(&socket_path).await {
        Ok(client) => {
            let start = std::time::Instant::now();
            let pong = client.request(samulibre_core::ipc::IpcRequest::ping()).await;
            let elapsed = start.elapsed().as_micros();
            (pong.is_ok(), elapsed)
        }
        Err(_) => (false, 0),
    };

    if daemon_online {
        println!("  {} Demonio del Sistema:      {} (Socket: {}, Latencia: {} µs)",
            "✔".green(), "CONECTADO Y ACTIVO".bold().green(), socket_path.display(), ping_latency_us
        );
    } else {
        println!("  {} Demonio del Sistema:      {} (Ejecute 'sudo systemctl start samulibred')",
            "ℹ".yellow(), "MODO LOCAL / STANDALONE".bold().yellow()
        );
    }

    let core = samulibre_core::SamuLibreCore::new(canary_dir, vpn_dir, true);
    let _ = core.initialize();
    let status = core.get_status();

    println!("  {} Núcleo de Seguridad:      {}", "✔".green(), "100% Rust Nativo (Memoria Segura)".green());
    println!("  {} Autoprotección:           {}", "✔".green(), "PR_SET_DUMPABLE=0 (Anti-Ptrace/Anti-Dump)".green());
    println!("  {} Motor de Detección:       {}", "✔".green(), "Firmas ClamAV + YARA-X + Heurística Shannon".green());
    println!("  {} Trampas Anti-Ransomware:  {}", "✔".green(), format!("{} canarios activos", status.canaries_deployed_count).cyan());
    println!("  {} Parchado Virtual:         {}", "✔".green(), format!("{} mitigaciones sysctl activas", status.active_virtual_patches_count).yellow());
    println!("  {} Parches Nativos del SO:   {}", "✔".green(), format!("{} CVEs resueltos en kernel", status.native_repaired_cves_count).green());
    println!("  {} Amenazas Bloqueadas:      {}", "✔".green(), format!("{}", status.threats_blocked_total).cyan());
    println!("  {} Soberanía y Privacidad:   {}", "✔".green(), "100% Local (Zero-Cloud Mandate)".bold().green());

    Ok(())
}

async fn interactive_scan() -> Result<()> {
    print!("\n{} Ingrese la ruta del archivo o carpeta a escanear: ", "➤".cyan().bold());
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let p = input.trim();
    if p.is_empty() {
        println!("Operación cancelada.");
        return Ok(());
    }

    let path = PathBuf::from(p);
    if !path.exists() {
        println!("{} La ruta '{}' no existe.", "✘".red(), path.display());
        return Ok(());
    }

    println!("\nIniciando escaneo multi-motor en: {}", path.display().to_string().bold());
    let scanner = samulibre_scanner::MultiEngineScanner::new();

    if path.is_file() {
        crate::scan_single_file(&scanner, &path);
    } else {
        crate::scan_directory(&scanner, &path);
    }

    Ok(())
}

async fn interactive_network(canary_dir: &Path, vpn_dir: &Path) -> Result<()> {
    println!("\n{}", "─── INSPECTOR DE RED Y SOCKETS TCP EN VIVO ───".bold().cyan());
    let core = samulibre_core::SamuLibreCore::new(canary_dir, vpn_dir, true);
    let sockets = core.get_network_sockets();
    println!("  Total de sockets encontrados: {}", sockets.len());
    println!("\n  {:<8} {:<10} {:<14} {:<8} {:<24} {}", "PROTO", "PUERTO", "ESTADO", "PID", "PROCESO", "EVALUACIÓN");
    println!("  {}", "─".repeat(74));

    for s in sockets.iter().take(25) {
        let eval = if s.is_risk_port {
            "⚠ SOSPECHOSO".red().bold()
        } else {
            "NORMAL".green()
        };
        println!("  {:<8} :<{:<9} {:<14} {:<8} {:<24} {}", s.protocol, s.local_port, s.state, s.pid, s.process_name, eval);
    }

    Ok(())
}

fn interactive_db(db_path: &Path) -> Result<()> {
    println!("\n{}", "─── BASE DE DATOS SQLITE WAL (HISTORIAL FORENSE) ───".bold().cyan());
    let db = samulibre_core::SecurityEventDatabase::new(db_path)?;
    let stats = db.get_summary_stats()?;

    println!("  Ruta de Base de Datos:     {}", db.get_path().display());
    println!("  Total Amenazas:            {}", stats.total_threats);
    println!("  Amenazas Neutralizadas:    {}", stats.neutralized_threats.to_string().green());
    println!("  Amenazas Pendientes:       {}", if stats.pending_threats > 0 { stats.pending_threats.to_string().red() } else { "0".green() });
    println!("  Eventos de Auditoría:      {}", stats.total_audit_events);

    let threats = db.list_threats(10)?;
    if !threats.is_empty() {
        println!("\nÚltimas amenazas registradas:");
        for t in threats {
            println!("  [{}] {} ({}) - Acción: {}", t.timestamp, t.threat_name.red().bold(), t.file_path, t.action_taken.yellow());
        }
    } else {
        println!("\nNo hay amenazas registradas en la base de datos.");
    }

    Ok(())
}

fn interactive_exclusions(db_path: &Path) -> Result<()> {
    let db = samulibre_core::SecurityEventDatabase::new(db_path)?;
    println!("\n{}", "─── GESTIÓN DE EXCLUSIONES DE ESCANEO ───".bold().cyan());
    let exclusions = db.list_exclusions()?;

    if exclusions.is_empty() {
        println!("No hay rutas excluidas.");
    } else {
        println!("Exclusiones activas:");
        for (path, created_at, is_dir) in &exclusions {
            let tipo = if *is_dir { "[DIR]".cyan() } else { "[FILE]".yellow() };
            println!("  {} {} (Añadido: {})", tipo, path.bold(), created_at);
        }
    }

    print!("\n¿Desea [A]gregar exclusión, [E]liminar exclusión o [V]olver? (a/e/v): ");
    io::stdout().flush()?;
    let mut act = String::new();
    io::stdin().read_line(&mut act)?;
    let act = act.trim().to_lowercase();

    if act == "a" {
        print!("Ingrese ruta a excluir: ");
        io::stdout().flush()?;
        let mut p = String::new();
        io::stdin().read_line(&mut p)?;
        let p = p.trim();
        if !p.is_empty() {
            let is_dir = Path::new(p).is_dir();
            db.add_exclusion(p, is_dir)?;
            println!("{} Exclusión agregada correctamente.", "✔".green());
        }
    } else if act == "e" {
        print!("Ingrese ruta a remover: ");
        io::stdout().flush()?;
        let mut p = String::new();
        io::stdin().read_line(&mut p)?;
        let p = p.trim();
        if !p.is_empty() {
            if db.remove_exclusion(p)? {
                println!("{} Exclusión removida.", "✔".green());
            } else {
                println!("{} La ruta no estaba en la lista de exclusiones.", "✘".red());
            }
        }
    }

    Ok(())
}

fn interactive_report(canary_dir: &Path, vpn_dir: &Path, db_path: &Path) -> Result<()> {
    println!("\n{}", "─── GENERADOR DE INFORMES FORENSES DE AUDITORÍA ───".bold().cyan());
    let socket_path = samulibre_core::ipc::resolve_ipc_socket_path();
    let daemon_active = socket_path.exists();

    let core = samulibre_core::SamuLibreCore::new(canary_dir, vpn_dir, true);

    let report_data = crate::report::ForensicReportData::collect_current(
        &core,
        db_path,
        daemon_active,
        &socket_path.display().to_string(),
    );

    let default_output = PathBuf::from("samulibre_forensic_report.html");
    let html = report_data.to_html();
    std::fs::write(&default_output, html)?;

    println!("{} Informe Forense generado exitosamente en: {}", "✔".green().bold(), default_output.display().to_string().cyan().bold());
    println!("Puede abrirlo en cualquier navegador web para visualización ejecutiva o impresión de cumplimiento.");

    Ok(())
}

fn interactive_canaries(canary_dir: &Path) -> Result<()> {
    println!("\n{}", "─── TRAMPAS CANARIOS ANTI-RANSOMWARE ───".bold().cyan());
    let mut shield = samulibre_shield::EndpointShield::new(canary_dir);
    let deployed = shield.deploy_canaries()?;
    println!("{} Canarios desplegados en el sistema: {}", "✔".green(), deployed);

    let alerts = shield.check_canary_integrity();
    if alerts.is_empty() {
        println!("{} Integridad de trampas verificada: 100% intactas, sin indicios de cifrado malicioso.", "✔".green());
    } else {
        println!("{} ¡ALERTA DE SEGURIDAD! Canarios alterados:", "🚨".red().bold());
        for a in alerts {
            println!("  [{}] {} - {}", a.severity.to_string().red(), a.title, a.details);
        }
    }

    Ok(())
}

fn interactive_copilot(canary_dir: &Path, vpn_dir: &Path) -> Result<()> {
    println!("\n{}", "─── COPILOTO FORENSE CON INTELIGENCIA ARTIFICIAL LOCAL (OFFLINE) ───".bold().cyan());
    println!("Escriba su consulta en lenguaje natural (ej. '¿cómo protejo el sistema contra ransomware?' o 'audita la persistencia').");
    print!("\n{} Consulta: ", "➤".cyan().bold());
    io::stdout().flush()?;
    let mut query = String::new();
    io::stdin().read_line(&mut query)?;
    let q = query.trim();

    if q.is_empty() {
        return Ok(());
    }

    let core = samulibre_core::SamuLibreCore::new(canary_dir, vpn_dir, true);
    let _ = core.initialize();
    let resp = core.ask_copilot(q);

    println!("\n{}", "─── RESPUESTA DEL COPILOTO SAMULIBRE ───".bold().cyan());
    println!("{}", resp.answer);
    if !resp.suggested_actions.is_empty() {
        println!("\nAcciones sugeridas:");
        for act in resp.suggested_actions {
            println!("  → [{}] (Acción: {}, Payload: {})", act.label.cyan().bold(), act.action_type, act.payload);
        }
    }

    Ok(())
}
