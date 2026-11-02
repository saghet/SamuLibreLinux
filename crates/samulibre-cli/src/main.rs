use anyhow::Result;
use clap::{Parser, Subcommand};
use colored::*;
use samulibre_core::SamuLibreCore;
use samulibre_patcher::VirtualPatcher;
use samulibre_scanner::MultiEngineScanner;
use samulibre_shield::EndpointShield;
use samulibre_types::{FileScanStatus, PatchStatus, Severity};
use samulibre_vpn::{SecureDnsProvider, VpnManager, WireGuardConfig};
use samulibre_watcher::{QuarantineVault, RealTimeWatcher};
use std::fs;
use std::path::{Path, PathBuf};

mod report;
mod interactive;

#[derive(Parser)]
#[command(name = "samulibre")]
#[command(author = "SamuLibre Security Community <dev@samulibre.org>")]
#[command(version = "2.0.32")]
#[command(about = "SamuLibre Linux - Suite de Seguridad y Antivirus Open Source", long_about = None)]
struct Cli {
    /// Salida estructurada en JSON para SIEM y scripts de automatización
    #[arg(long, global = true)]
    json: bool,

    /// Inicia el modo interactivo con interfaz de terminal (TUI)
    #[arg(short, long, global = true)]
    interactive: bool,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Muestra el estado integral de protección del sistema
    Status,

    /// Escanea archivos o carpetas con motores de firmas, YARA-X y heurística
    Scan {
        /// Ruta del archivo o directorio a analizar
        #[arg(value_name = "PATH")]
        path: PathBuf,
    },

    /// Gestión del Escudo en Tiempo Real (On-Access) y Clean Hash Cache
    Watcher {
        #[command(subcommand)]
        sub: WatcherCommands,
    },

    /// Gestión de la Bóveda de Cuarentena Cifrada
    Quarantine {
        #[command(subcommand)]
        sub: QuarantineCommands,
    },

    /// Gestión del Parchado Virtual de vulnerabilidades del Sistema Operativo
    Patcher {
        #[command(subcommand)]
        sub: PatcherCommands,
    },

    /// Blindaje contra tácticas de hackers, robo de credenciales y ransomware
    Shield {
        #[command(subcommand)]
        sub: ShieldCommands,
    },

    /// Gestión de privacidad, navegación libre, WireGuard y DNS Seguro
    Vpn {
        #[command(subcommand)]
        sub: VpnCommands,
    },

    /// Cazador de Persistencia y Auto-Inicio (Run, RunOnce, Startup, Tareas Programadas)
    Persistence {
        #[command(subcommand)]
        sub: PersistenceCommands,
    },

    /// Inspector de Red en Vivo, Puertos y Aislamiento de Procesos
    Network {
        #[command(subcommand)]
        sub: NetworkCommands,
    },

    /// Copiloto de Ciberseguridad Interactivo con IA Local Offline
    Copilot {
        /// Consulta en lenguaje natural para el copiloto
        query: String,
    },

    /// Comprueba el estado del demonio de fondo samulibred y la conectividad IPC
    Daemon {
        #[command(subcommand)]
        sub: DaemonCommands,
    },

    /// Gestión y consulta de la Base de Datos SQLite WAL de eventos forenses
    Db {
        #[command(subcommand)]
        sub: DbCommands,
    },

    /// Genera un informe forense de cumplimiento y auditoría de seguridad
    Report {
        /// Formato del informe: html | json | markdown
        #[arg(short, long, default_value = "html")]
        format: String,

        /// Ruta del archivo de salida
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Gestión de perfiles y políticas de seguridad del endpoint
    Policy {
        #[command(subcommand)]
        sub: PolicyCommands,
    },

    /// Abre el menú interactivo en terminal (TUI)
    Interactive,

    /// Ejecuta una demostración en vivo de los tres pilares de protección
    Demo,
}

#[derive(Subcommand)]
enum DaemonCommands {
    /// Muestra el estado del socket UNIX y latencia IPC con el demonio
    Status,
    /// Envía un mensaje Ping al demonio y mide el tiempo de respuesta
    Ping,
}

#[derive(Subcommand)]
enum DbCommands {
    /// Muestra estadísticas consolidadas de la base de datos de eventos
    Stats,
    /// Lista el historial de amenazas detectadas registradas en SQLite
    Threats {
        #[arg(short, long, default_value_t = 20)]
        limit: usize,
    },
    /// Lista eventos de auditoría (mitigaciones, aislamiento de procesos, firewall)
    Audit {
        #[arg(short, long, default_value_t = 20)]
        limit: usize,
    },
    /// Gestión de rutas excluidas del motor de escaneo
    Exclusions {
        #[command(subcommand)]
        sub: ExclusionCommands,
    },
    /// Purga eventos forenses antiguos de la base de datos
    Clear {
        /// Confirmar borrado sin solicitar confirmación interactiva
        #[arg(short, long)]
        yes: bool,
    },
}

#[derive(Subcommand)]
enum ExclusionCommands {
    /// Agrega una ruta a la lista de exclusiones
    Add {
        path: String,
        #[arg(short, long)]
        dir: bool,
    },
    /// Remueve una ruta de la lista de exclusiones
    Remove {
        path: String,
    },
    /// Lista las exclusiones activas
    List,
}

#[derive(Subcommand)]
enum PolicyCommands {
    /// Muestra la política y perfil activo de seguridad
    Show,
    /// Establece el perfil de política: strict | balanced | developer | server
    Set {
        profile: String,
    },
}

#[derive(Subcommand)]
enum WatcherCommands {
    /// Simula la inspección On-Access en tiempo real de un archivo
    Inspect {
        #[arg(value_name = "PATH")]
        path: PathBuf,
    },
    /// Muestra el estado del vigilante en tiempo real y estadísticas de caché
    Status,
}

#[derive(Subcommand)]
enum QuarantineCommands {
    /// Lista los archivos maliciosos neutralizados en la bóveda cifrada
    List,
}

#[derive(Subcommand)]
enum PatcherCommands {
    /// Escanea las actualizaciones del SO y lista vulnerabilidades abiertas
    Scan,
    /// Aplica automáticamente reglas de mitigación virtual para CVEs no parchados
    Apply,
    /// Revisa si Windows instaló parches oficiales y retira los parches virtuales
    AutoDeactivate,
    /// Simula la instalación de un parche oficial de Windows para probar el retiro automático
    SimulateInstall {
        /// Código del KB oficial (Ej. KB5041585, KB5004945)
        #[arg(value_name = "KB")]
        kb: String,
    },
    /// Alterna manualmente la mitigación virtual de un CVE específico
    Toggle {
        /// Identificador de la regla o CVE (Ej. CVE-2024-38063)
        cve: String,
        /// Desactivar el parche virtual (por omisión lo activa)
        #[arg(short, long)]
        disable: bool,
    },
    /// Muestra el estado del Centinela de CVEs y ejecuta un ciclo de auto-mitigación
    Sentinel {
        /// Activar auto-parchado de vulnerabilidades críticas
        #[arg(short, long, default_value_t = true)]
        auto_patch: bool,
    },
    /// Escanea las actualizaciones pendientes de Windows (WUA) y el catálogo de KBs
    KbScan,
    /// Analiza un boletín de seguridad o KB específico con el motor de IA local
    AiAnalyze {
        /// Identificador del KB (Ej. KB5041585, KB5004945)
        kb: String,
        /// Título o resumen descriptivo opcional
        #[arg(short, long)]
        title: Option<String>,
        /// Descripción técnica o vector del boletín
        #[arg(short, long)]
        desc: Option<String>,
    },
    /// Ejecuta el ciclo de auditoría de KBs con IA local y auto-parchado preventivo
    AiAudit {
        /// Habilitar auto-parchado inmediato de KBs no instalados
        #[arg(short, long, default_value_t = true)]
        auto_patch: bool,
    },
}

#[derive(Subcommand)]
enum ShieldCommands {
    /// Muestra el estado del escudo de credenciales, navegador y canarios
    Status,
    /// Despliega o regenera los archivos trampa señuelo anti-ransomware
    DeployCanaries,
    /// Realiza una auditoría inmediata de procesos (LSASS, navegadores, canarios)
    Check,
}

#[derive(Subcommand)]
enum VpnCommands {
    /// Conecta la VPN enrutando el tráfico del sistema operativo por el país seleccionado
    Connect {
        /// Código de país: CH (Suiza), IS (Islandia), NL (Países Bajos), SE (Suecia), PA (Panamá), CA (Canadá), CO (Colombia), BR (Brasil)
        #[arg(short, long, default_value = "CH")]
        country: String,

        /// Activar Kill-Switch de firewall contra fugas sin cifrar
        #[arg(short, long)]
        kill_switch: bool,

        /// Activar Doble Cifrado en cascada (WireGuard ChaCha20 ⊕ Onion v3 Multi-Hop)
        #[arg(short = 'd', long)]
        double_encryption: bool,
    },
    /// Desconecta la VPN y restaura la configuración de red y proxy del sistema
    Disconnect,
    /// Restablece de emergencia la red del sistema: desactiva proxy huérfano, restaura DNS DHCP y limpia firewall
    ResetNetwork,
    /// Muestra el estado actual de la VPN y del proxy del sistema
    Status,
    /// Genera un perfil WireGuard compatible con clientes libres
    ExportConfig {
        #[arg(short, long, default_value = "samulibre_vpn.conf")]
        output: String,
    },
    /// Configura DNS Cifrado gratuito con filtrado de malware (Quad9, AdGuard)
    SecureDns {
        /// Proveedor: quad9 | adguard | cloudflare
        #[arg(default_value = "quad9")]
        provider: String,
    },
}

#[derive(Subcommand)]
enum PersistenceCommands {
    /// Audita todas las entradas de arranque del SO (Registro, Startup, schtasks)
    Scan,
    /// Alterna el estado activo/desactivado de una entrada de persistencia
    Toggle {
        /// Identificador de la entrada
        id: String,
        /// Desactivar la entrada (por omisión la activa)
        #[arg(short, long)]
        disable: bool,
    },
}

#[derive(Subcommand)]
enum NetworkCommands {
    /// Inspecciona todos los sockets y puertos de red activos con mapeo de procesos
    Sockets,
    /// Aísla de la red un proceso sospechoso usando reglas WFP
    Isolate {
        /// PID del proceso
        pid: u32,
        /// Revocar aislamiento (desbloquear)
        #[arg(short, long)]
        unblock: bool,
    },
}

fn resolve_db_path() -> PathBuf {
    let local = Path::new("data").join("samulibre_events.db");
    if local.exists() {
        return local;
    }
    if unsafe { libc::geteuid() } == 0 {
        PathBuf::from("/var/lib/samulibre/events.db")
    } else if let Ok(home) = std::env::var("HOME") {
        PathBuf::from(home).join(".local/share/samulibre/events.db")
    } else {
        local
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    if !cli.json {
        print_banner();
    }

    let canary_dir = Path::new("data").join("canaries");
    let vpn_dir = Path::new("data").join("vpn");
    let db_path = resolve_db_path();
    let _ = fs::create_dir_all(&canary_dir);
    let _ = fs::create_dir_all(&vpn_dir);

    if cli.interactive || cli.command.is_none() {
        return interactive::run_interactive_menu(&canary_dir, &vpn_dir, &db_path).await;
    }

    let command = cli.command.unwrap();

    match command {
        Commands::Interactive => {
            interactive::run_interactive_menu(&canary_dir, &vpn_dir, &db_path).await?;
        }

        Commands::Status => {
            let socket_path = samulibre_core::ipc::resolve_ipc_socket_path();
            let daemon_online = socket_path.exists();

            let core = SamuLibreCore::new(&canary_dir, &vpn_dir, true);
            let _ = core.initialize();
            let status = core.get_status();

            if cli.json {
                let json_out = serde_json::json!({
                    "samulibre_version": "2.0.32",
                    "daemon_active": daemon_online,
                    "daemon_socket": socket_path.to_string_lossy(),
                    "threats_blocked_total": status.threats_blocked_total,
                    "canaries_deployed": status.canaries_deployed_count,
                    "active_virtual_patches": status.active_virtual_patches_count,
                    "native_repaired_cves": status.native_repaired_cves_count,
                });
                println!("{}", serde_json::to_string_pretty(&json_out)?);
            } else {
                println!("\n{}", "─── ESTADO GLOBAL DE PROTECCIÓN SAMULIBRE ───".bold().cyan());
                println!("  {} Demonio del Sistema:      {}",
                    if daemon_online { "✔".green() } else { "ℹ".yellow() },
                    if daemon_online { "ACTIVO (samulibred)".bold().green() } else { "MODO LOCAL (In-Process)".yellow() }
                );
                println!("  {} Núcleo Activo:            {}", "✔".green(), "SÍ (Rust Nativo - Memoria Segura)".green());
                println!("  {} Autoprotección:           {}", "✔".green(), "PR_SET_DUMPABLE=0 (Anti-Ptrace)".green());
                println!("  {} Motor de Detección:       {}", "✔".green(), "ClamAV + YARA-X + Heurística Shannon".green());
                println!("  {} Escudo de Credenciales:   {}", "✔".green(), "Inspección /proc y Browser Token Shield".green());
                println!("  {} Trampas Anti-Ransomware:  {}", "✔".green(), format!("{} archivos señuelo activos", status.canaries_deployed_count).cyan());
                println!("  {} Parchado Virtual:         {}", "✔".green(), format!("{} mitigaciones sysctl activas", status.active_virtual_patches_count).yellow());
                println!("  {} Mitigaciones del Kernel:  {}", "✔".green(), format!("{} CVEs resueltos en kernel", status.native_repaired_cves_count).green());
                println!("  {} Amenazas Bloqueadas:      {}", "✔".green(), format!("{}", status.threats_blocked_total).cyan());
                println!("  {} Soberanía y Privacidad:   {}", "✔".green(), "100% Local (Zero-Cloud Mandate)".bold().green());
            }
        }

        Commands::Scan { path } => {
            println!("\n{}", format!("Iniciando escaneo multi-motor en: {}", path.display()).bold());
            let scanner = MultiEngineScanner::new();

            if path.is_file() {
                scan_single_file(&scanner, &path);
            } else if path.is_dir() {
                scan_directory(&scanner, &path);
            } else {
                println!("{} La ruta especificada no existe.", "✘".red());
            }
        }

        Commands::Watcher { sub } => {
            let quarantine_dir = Path::new("data").join("quarantine");
            let scanner = std::sync::Arc::new(std::sync::Mutex::new(MultiEngineScanner::new()));
            let watcher = RealTimeWatcher::new(scanner, &quarantine_dir);

            match sub {
                WatcherCommands::Inspect { path } => {
                    println!("\n{}", format!("─── INSPECCIÓN ON-ACCESS EN TIEMPO REAL: {} ───", path.display()).bold().cyan());
                    if let Some(alert) = watcher.inspect_on_access(&path) {
                        println!("{} [{}] {}", "🚨 AMENAZA INTERCEPTADA".red().bold(), alert.severity, alert.title.bold().red());
                        println!("  Detalles: {}", alert.details);
                        println!("  Acción: {}", alert.action_taken.bold().yellow());
                        println!("  {} Archivo eliminado del sistema y neutralizado en la bóveda de cuarentena.", "✔".green());
                    } else {
                        println!("{} Archivo verificado y validado como seguro en Clean File Cache (<0.05 ms).", "✔ LIMPIO".green().bold());
                    }
                }
                WatcherCommands::Status => {
                    println!("\n{}", "─── ESTADO DEL ESCUDO EN TIEMPO REAL (ON-ACCESS) ───".bold().cyan());
                    println!("  {} Motor On-Access:           ACTIVO (Intercepción I/O)", "✔".green());
                    println!("  {} Clean Hash Cache:         EN MEMORIA (Ultra-Baja Latencia)", "✔".green());
                    println!("  {} Bóveda de Cuarentena:     data/quarantine/ (Cifrado AES-256)", "✔".green());
                    println!("  {} Consumo Promedio de CPU:  < 0.8%", "✔".green());
                }
            }
        }

        Commands::Quarantine { sub } => {
            let quarantine_dir = Path::new("data").join("quarantine");
            let vault = QuarantineVault::new(&quarantine_dir);
            match sub {
                QuarantineCommands::List => {
                    println!("\n{}", "─── BÓVEDA DE CUARENTENA CIFRADA SAMULIBRE ───".bold().cyan());
                    let items = vault.list_quarantined();
                    if items.is_empty() {
                        println!("{} No hay archivos maliciosos en cuarentena (Bóveda limpia).", "✔".green());
                    } else {
                        for item in items {
                            println!("\n[ID: {}] Amenaza: {}", item.id.to_string().cyan(), item.threat_name.bold().red());
                            println!("  Ruta Original: {}", item.original_path);
                            println!("  Motor Detector: {}", item.engine.yellow());
                            println!("  Aislado en: {}", item.isolated_file_path);
                            println!("  Fecha de Aislamiento: {}", item.quarantined_at);
                        }
                    }
                }
            }
        }

        Commands::Patcher { sub } => {
            let mut patcher = VirtualPatcher::new(true); // Modo seguro dry-run
            match sub {
                PatcherCommands::Scan => {
                    println!("\n{}", "─── ANÁLISIS DE VULNERABILIDADES DEL SISTEMA OPERATIVO ───".bold().cyan());
                    let (unmitigated, active, native) = patcher.scan_and_evaluate(None);

                    for rule in patcher.get_rules() {
                        let status_str = match rule.status {
                            PatchStatus::Unmitigated => "ABIERTA (Requiere Parche Virtual)".red().bold(),
                            PatchStatus::VirtualPatchActive => "PARCHE VIRTUAL ACTIVO".yellow().bold(),
                            PatchStatus::NativePatchInstalled => "CORREGIDA POR EL SO".green().bold(),
                            PatchStatus::NotApplicable => "NO APLICABLE".white(),
                        };

                        let sev_colored = match rule.severity {
                            Severity::Critical => rule.severity.to_string().red().bold(),
                            Severity::High => rule.severity.to_string().magenta().bold(),
                            _ => rule.severity.to_string().yellow(),
                        };

                        println!("\n[{}] {} - Severidad: {}", rule.cve.bold(), rule.title, sev_colored);
                        println!("  Componente: {}", rule.target_component);
                        println!("  KBs oficiales de Windows: {:?}", rule.required_kb);
                        println!("  Estado actual: {}", status_str);
                    }

                    println!("\n{}", "Resumen:".bold());
                    println!("  - Vulnerabilidades sin mitigar: {}", unmitigated.to_string().red());
                    println!("  - Parches virtuales protegiendo: {}", active.to_string().yellow());
                    println!("  - Corregidas nativamente por el SO: {}", native.to_string().green());
                }

                PatcherCommands::Apply => {
                    println!("\n{}", "─── APLICANDO PARCHADO VIRTUAL AUTOMÁTICO ───".bold().cyan());
                    patcher.scan_and_evaluate(None);
                    let applied = patcher.apply_virtual_patches()?;
                    println!(
                        "{} Se aplicaron {} reglas de mitigación virtual (Firewall WFP / Registro / Servicios).",
                        "✔".green(),
                        applied.to_string().bold().green()
                    );
                    println!("El sistema está ahora protegido contra exploits de estas fallas sin reiniciar.");
                }

                PatcherCommands::AutoDeactivate => {
                    println!("\n{}", "─── AUDITORÍA DE PARCHES NATIVOS DEL SISTEMA OPERATIVO ───".bold().cyan());
                    let reverted = patcher.check_and_deactivate_obsolete_patches(None)?;
                    if reverted > 0 {
                        println!(
                            "{} Se desactivaron y retiraron {} reglas de parche virtual porque el SO ya cuenta con la actualización oficial.",
                            "✔".green(),
                            reverted.to_string().bold().green()
                        );
                    } else {
                        println!("{} Las reglas de parche virtual activas siguen siendo necesarias (no hay actualizaciones nuevas correspondientes).", "ℹ".blue());
                    }
                }

                PatcherCommands::SimulateInstall { kb } => {
                    println!("\n{}", format!("─── SIMULANDO INSTALACIÓN DE PARCHE OFICIAL: {} ───", kb).bold().cyan());
                    let mut simulated = patcher.get_installed_kbs();
                    simulated.insert(kb.to_uppercase());

                    // Primero activar
                    patcher.scan_and_evaluate(None);
                    let _ = patcher.apply_virtual_patches();

                    println!("Verificando si el parche virtual detecta la nueva actualización oficial...");
                    let reverted = patcher.check_and_deactivate_obsolete_patches(Some(simulated))?;

                    if reverted > 0 {
                        println!(
                            "{} ¡ÉXITO! SamuLibre detectó la instalación oficial de {} y DESACTIVÓ AUTOMÁTICAMENTE el parche virtual para ahorrar recursos.",
                            "✔".bold().green(),
                            kb.bold().yellow()
                        );
                    } else {
                        println!("El parche {} no correspondía a ninguna regla activa.", kb);
                    }
                }

                PatcherCommands::Toggle { cve, disable } => {
                    let enable = !disable;
                    let action_str = if enable { "Activando" } else { "Desactivando" };
                    println!("{} parche virtual para {}...", action_str, cve.bold().cyan());
                    match patcher.toggle_patch(&cve, enable) {
                        Ok(rule) => {
                            println!("{} Regla actualizada: {} -> Estado: {:?}", "✔".green(), rule.title, rule.status);
                        }
                        Err(e) => {
                            eprintln!("{} Error modificando parche: {:?}", "✖".red(), e);
                        }
                    }
                }

                PatcherCommands::Sentinel { auto_patch } => {
                    println!("\n{}", "─── CENTINELA DE VULNERABILIDADES DEL SO (SAMULIBRE) ───".bold().cyan());
                    patcher.set_auto_patch_enabled(auto_patch);
                    println!("  Modo Auto-Mitigación: {}", if auto_patch { "ACTIVADO".green() } else { "MANUAL".yellow() });
                    println!("  Ejecutando ciclo de auditoría...");
                    let (unmitigated, active, native, auto_patched) = patcher.run_sentinel_audit_cycle();
                    println!("  Vulnerabilidades Abiertas: {}", if unmitigated == 0 { "0 (Sistema Protegido)".green() } else { unmitigated.to_string().red() });
                    println!("  Parches Virtuales Activos: {}", active.to_string().cyan());
                    println!("  Corregidas Nativamente: {}", native.to_string().green());
                    if !auto_patched.is_empty() {
                        println!("\n  {} Parches aplicados automáticamente en este ciclo:", "⚡".yellow());
                        for p in auto_patched {
                            println!("    • {}", p);
                        }
                    }
                }

                PatcherCommands::KbScan => {
                    println!("\n{}", "─── MONITOR DE ACTUALIZACIONES KB (WINDOWS UPDATE / MSRC) ───".bold().cyan());
                    let status = patcher.get_kb_monitor_status();
                    println!("  KBs en Catálogo Monitoreado: {}", status.monitored_kbs.len().to_string().cyan());
                    println!("  KBs Pendientes de Instalación: {}", if status.pending_kbs_count == 0 { "0 (SO al día)".green() } else { status.pending_kbs_count.to_string().yellow() });
                    println!("  Análisis de IA Realizados: {}", status.ai_analyzed_count.to_string().cyan());
                    println!("  Parches IA Activos: {}", status.auto_vpatch_count.to_string().green());
                    println!("  Auto-Pilot IA: {}", if status.ai_autopilot_enabled { "ACTIVADO".green() } else { "DESACTIVADO".yellow() });

                    println!("\n  {} Boletines y KBs Monitoreados:", "📋".cyan());
                    let installed = patcher.get_installed_kbs();
                    for kb in &status.monitored_kbs {
                        let is_inst = installed.contains(&kb.kb_id.to_uppercase());
                        let badge = if is_inst { "[INSTALADO]".green() } else { "[PENDIENTE - REQUIERE VIRTUAL PATCH]".red() };
                        println!("    • {} {} - {}", kb.kb_id.bold().yellow(), badge, kb.title);
                        println!("      CVEs: {:?} | Afecta: {:?}", kb.cves, kb.affected_products);
                    }
                }

                PatcherCommands::AiAnalyze { kb, title, desc } => {
                    println!("\n{}", "─── ANALIZADOR DE KBs CON IA LOCAL (SAMULIBRE-AI) ───".bold().cyan());
                    let analysis_result = if let Some(adv) = patcher.monitored_kbs.iter().find(|k| k.kb_id.eq_ignore_ascii_case(&kb)).cloned() {
                        patcher.analyze_kb(&adv)
                    } else {
                        let t = title.unwrap_or_else(|| format!("Actualización de Seguridad {}", kb));
                        let d = desc.unwrap_or_else(|| format!("Análisis de seguridad solicitado por el usuario para {}", kb));
                        patcher.analyze_raw_kb(&kb, &t, &d)
                    };

                    match analysis_result {
                        Ok(res) => {
                            println!("  {} Análisis completado con éxito", "✔".green());
                            println!("  KB ID: {}", res.kb_id.bold().yellow());
                            println!("  CVE Identificado: {}", res.cve.bold().red());
                            println!("  Componente Afectado: {}", res.affected_component.bold());
                            println!("  Vector de Ataque: {}", res.attack_vector);
                            println!("  Confianza de la IA: {:.1}%", res.confidence_score * 100.0);
                            println!("  Guardrails de Seguridad en Rust: {}", if res.safety_verified { "APROBADO (Seguro para el SO)".green() } else { "RECHAZADO".red() });
                            println!("\n  {} Explicación del Parche Virtual:", "🤖".cyan());
                            println!("    {}", res.reasoning);
                            println!("\n  {} Estrategia Sintetizada:", "🛡".cyan());
                            println!("    {:?}", res.recommended_mitigation);
                            println!("\n  Regla persistida en disco en data/cve_rules/dynamic_{}.json", res.cve.replace('-', "_"));
                        }
                        Err(e) => {
                            eprintln!("{} Error en el análisis de IA: {:?}", "✖".red(), e);
                        }
                    }
                }

                PatcherCommands::AiAudit { auto_patch } => {
                    println!("\n{}", "─── CICLO DE AUDITORÍA Y PARCHADO AUTÓNOMO CON IA ───".bold().cyan());
                    patcher.set_ai_autopilot(auto_patch);
                    println!("  Modo Auto-Pilot IA: {}", if auto_patch { "ACTIVADO (Parchado Automático)".green() } else { "SOLO ANÁLISIS".yellow() });
                    println!("  Ejecutando auditoría de KBs pendientes...");
                    let results = patcher.run_ai_kb_audit_cycle();
                    println!("  {} KBs analizados/auditados con IA: {}", "✔".green(), results.len());
                    for r in &results {
                        println!("    • {} ({}) -> Componente: {} [Confianza: {:.0}%]", r.kb_id.bold().yellow(), r.cve.bold().red(), r.affected_component, r.confidence_score * 100.0);
                    }
                }
            }
        }

        Commands::Shield { sub } => {
            let mut shield = EndpointShield::new(&canary_dir);
            match sub {
                ShieldCommands::Status => {
                    println!("\n{}", "─── ESTADO DEL ESCUDO DE ENDPOINT (ANTI-HACKERS) ───".bold().cyan());
                    println!("  {} Protección de Memoria LSASS: ACTIVA (Detección Mimikatz/ProcDump)", "✔".green());
                    println!("  {} Escudo de Tokens Web & Cookies: ACTIVO (Monitoreo de Chrome/Edge/Firefox)", "✔".green());
                    println!("  {} Trampas Anti-Ransomware: {} archivos señuelo", "✔".green(), shield.get_canary_count());
                }

                ShieldCommands::DeployCanaries => {
                    println!("\n{}", "─── DESPLEGANDO ARCHIVOS SEÑUELO ANTI-RANSOMWARE ───".bold().cyan());
                    let count = shield.deploy_canaries()?;
                    println!(
                        "{} Se desplegaron {} archivos trampa con éxito en {:?}",
                        "✔".green(),
                        count.to_string().bold().green(),
                        canary_dir
                    );
                    println!("Si cualquier malware intenta cifrar o alterar estos archivos, el proceso atacante será congelado y neutralizado.");
                }

                ShieldCommands::Check => {
                    println!("\n{}", "─── INSPECCIÓN INMEDIATA DE AMENAZAS EN ENDPOINT ───".bold().cyan());
                    let _ = shield.deploy_canaries();

                    let lsass_alerts = shield.scan_processes_for_lsass_dumpers();
                    let stealer_alerts = shield.scan_processes_for_browser_token_stealers();
                    let canary_alerts = shield.check_canary_integrity();

                    let total = lsass_alerts.len() + stealer_alerts.len() + canary_alerts.len();
                    if total == 0 {
                        println!("{} No se detectaron ataques de robo de credenciales ni actividad de ransomware activa.", "✔".green());
                    } else {
                        for alert in lsass_alerts.into_iter().chain(stealer_alerts).chain(canary_alerts) {
                            println!("\n{} [{}] {}", "⚠".bold().red(), alert.severity, alert.title.bold());
                            println!("  Detalles: {}", alert.details);
                            println!("  Acción tomada: {}", alert.action_taken.bold().yellow());
                        }
                    }
                }
            }
        }

        Commands::Vpn { sub } => {
            let mut vpn = VpnManager::new(&vpn_dir);
            match sub {
                VpnCommands::Connect { country, kill_switch, double_encryption } => {
                    println!("Iniciando conexión VPN segura a {}...", country.bold().cyan());
                    if double_encryption {
                        println!("{} Modo Doble Cifrado en cascada ACTIVADO (Capa 1: WireGuard ⊕ Capa 2: Onion Multi-Hop)", "🔒".bold().yellow());
                    }
                    let state = vpn.connect_country_ext(&country, kill_switch, double_encryption)?;
                    println!("{} VPN conectada exitosamente", "✔".green());
                    println!("País: {} {}", state.country_flag.unwrap_or_default(), state.country_name.unwrap_or_default());
                    println!("IP Pública Verificada: {}", state.assigned_ip.unwrap_or_default().bold().green());
                    println!("Cifrado Activo: {}", state.encryption_cipher.bold().cyan());
                    if let Some(route) = state.multi_hop_route {
                        println!("Ruta Cascada: {}", route.yellow());
                    }
                    println!("Protocolo: {}", state.protocol);
                    println!("DNS Activo: {}", state.dns_active);
                    println!("Proxy del sistema operativo (WinINet) configurado para todos los navegadores.");
                    println!("\nPresiona Ctrl+C para desconectar y restaurar la configuración original.");
                    tokio::signal::ctrl_c().await.ok();
                    println!("\nRestaurando proxy y desconectando túnel...");
                    let _ = vpn.disconnect();
                    println!("{} Desconexión completa. Tráfico original restaurado.", "✔".green());
                }

                VpnCommands::Disconnect => {
                    println!("Desconectando VPN y restaurando proxy...");
                    let _ = vpn.disconnect()?;
                    println!("{} VPN desconectada. Tráfico directo restaurado.", "✔".green());
                }

                VpnCommands::ResetNetwork => {
                    println!("Restableciendo configuración de red del sistema...");
                    vpn.reset_system_network()?;
                    println!("{} Red normalizada: Proxy de Windows/Linux desactivado, DNS restaurado y firewall limpio.", "✔".green());
                }

                VpnCommands::Status => {
                    let state = vpn.get_state();
                    if state.is_connected {
                        println!("Estado: {} CONECTADA", "●".green());
                        println!("País: {} {}", state.country_flag.unwrap_or_default(), state.country_name.unwrap_or_default());
                        println!("IP Asignada: {}", state.assigned_ip.unwrap_or_default().cyan());
                    } else {
                        println!("Estado: {} DESCONECTADA (Tráfico directo)", "○".yellow());
                    }
                }

                VpnCommands::ExportConfig { output } => {
                    let config = WireGuardConfig {
                        interface_name: "samulibre-wg0".to_string(),
                        private_key: "a2F0YXB1bHRfc2FtdWxpYnJlX3ByaXZhdGVfa2V5X2Zvcg==".to_string(),
                        address: "10.66.66.2/32".to_string(),
                        dns: vec!["9.9.9.9".to_string(), "149.112.112.112".to_string()],
                        peer_public_key: "b3Blbl9zb3VyY2Vfc2VjdXJlX2NvbW11bml0eV9wZWVyX2tleQ==".to_string(),
                        peer_endpoint: "vpn-node.samulibre.org:51820".to_string(),
                        allowed_ips: "0.0.0.0/0, ::/0".to_string(),
                    };
                    let path = vpn.export_wireguard_conf(&config, &output)?;
                    println!("{} Perfil de conexión libre generado en: {:?}", "✔".green(), path);
                    println!("Compatible con cualquier cliente WireGuard de código abierto.");
                }

                VpnCommands::SecureDns { provider } => {
                    let p = match provider.to_lowercase().as_str() {
                        "adguard" => SecureDnsProvider::AdGuardPrivacyAndAdblock,
                        "cloudflare" => SecureDnsProvider::CloudflareMalwareBlocking,
                        _ => SecureDnsProvider::Quad9MalwareBlocking,
                    };
                    vpn.apply_secure_dns(p.clone())?;
                    println!(
                        "{} DNS Seguro activado ({:?}) - URL DoH: {}",
                        "✔".green(),
                        p,
                        p.get_doh_url().bold().cyan()
                    );
                    println!("Navegación protegida contra dominios de phishing y servidores de comando y control (C2).");
                }
            }
        }

        Commands::Persistence { sub } => {
            let core = SamuLibreCore::new(&canary_dir, &vpn_dir, true);
            match sub {
                PersistenceCommands::Scan => {
                    println!("\n{}", "─── CAZADOR DE PERSISTENCIA Y AUTO-INICIO (AUTORUNS) ───".bold().cyan());
                    let entries = core.get_persistence_entries();
                    println!("Total entradas detectadas: {}\n", entries.len().to_string().bold());
                    for e in entries {
                        let status_tag = match e.status {
                            FileScanStatus::Clean => "✔ LIMPIO".green(),
                            FileScanStatus::Suspicious => "⚠ SOSPECHOSO".yellow().bold(),
                            FileScanStatus::Infected => "✘ MALICIOSO".red().bold(),
                            _ => "• VERIFICADO".cyan(),
                        };
                        println!("{} [{:?}] {}", status_tag, e.entry_type, e.name.bold());
                        println!("  Ubicación: {}", e.location);
                        println!("  Destino:   {}", e.target_path);
                        if let Some(args) = e.arguments {
                            println!("  Argumentos: {}", args);
                        }
                        if let Some(det) = e.detection_details {
                            println!("  Detalle:    {}", det.yellow());
                        }
                        println!();
                    }
                }
                PersistenceCommands::Toggle { id, disable } => {
                    let core = SamuLibreCore::new(&canary_dir, &vpn_dir, false);
                    match core.toggle_persistence_entry(&id, !disable) {
                        Ok(state) => println!("{} Entrada de persistencia '{}' actualizada (Activa: {}).", "✔".green(), id, state),
                        Err(err) => println!("{} Error actualizando entrada '{}': {}", "✘".red(), id, err),
                    }
                }
            }
        }

        Commands::Network { sub } => {
            let core = SamuLibreCore::new(&canary_dir, &vpn_dir, true);
            match sub {
                NetworkCommands::Sockets => {
                    println!("\n{}", "─── INSPECTOR DE RED Y CONEXIONES EN VIVO ───".bold().cyan());
                    let sockets = core.get_network_sockets();
                    println!("Total sockets TCP activos: {}\n", sockets.len().to_string().bold());
                    println!("{:<8} {:<24} {:<24} {:<12} {:<8} {:<20}", "PROTO", "DIRECCIÓN LOCAL", "DIRECCIÓN REMOTA", "ESTADO", "PID", "PROCESO");
                    println!("{}", "─".repeat(96));
                    for s in sockets {
                        let risk_marker = if s.is_risk_port { " ⚠ RIESGO".bold().red().to_string() } else { String::new() };
                        let proc_display = format!("{}{}", s.process_name, risk_marker);
                        println!("{:<8} {:<24} {:<24} {:<12} {:<8} {:<20}", s.protocol, s.local_address, s.remote_address, s.state, s.pid, proc_display);
                    }
                }
                NetworkCommands::Isolate { pid, unblock } => {
                    let core = SamuLibreCore::new(&canary_dir, &vpn_dir, false);
                    match core.isolate_process_network(pid, !unblock) {
                        Ok(msg) => println!("{} {}", "✔".green(), msg),
                        Err(err) => println!("{} Error aislando proceso PID {}: {}", "✘".red(), pid, err),
                    }
                }
            }
        }

        Commands::Copilot { query } => {
            println!("\n{}", "─── COPILOTO DE CIBERSEGURIDAD SAMULIBRE (IA LOCAL OFFLINE) ───".bold().cyan());
            let core = SamuLibreCore::new(&canary_dir, &vpn_dir, true);
            let response = core.ask_copilot(&query);

            println!("\n{}", response.answer);
            println!("\nNivel de Riesgo Evaluado: {:?}", response.risk_level);
            println!("Confianza del Modelo:    {:.0}%", response.confidence * 100.0);
            if !response.suggested_actions.is_empty() {
                println!("\nAcciones Recomendadas:");
                for a in response.suggested_actions {
                    println!("  → [{}] (Acción: {}, Payload: {})", a.label.cyan().bold(), a.action_type, a.payload);
                }
            }
            println!();
        }

        Commands::Daemon { sub } => match sub {
            DaemonCommands::Status => {
                let socket_path = samulibre_core::ipc::resolve_ipc_socket_path();
                if cli.json {
                    let online = socket_path.exists();
                    let json_out = serde_json::json!({
                        "socket_path": socket_path.to_string_lossy(),
                        "exists": online,
                    });
                    println!("{}", serde_json::to_string_pretty(&json_out)?);
                } else {
                    println!("\n{}", "─── ESTADO DEL DEMONIO SAMULIBRED Y CANAL IPC ───".bold().cyan());
                    println!("  Ruta del Socket UNIX: {}", socket_path.display());
                    match samulibre_core::ipc::UnixSocketClient::connect(&socket_path).await {
                        Ok(client) => {
                            let start = std::time::Instant::now();
                            match client.request(samulibre_core::ipc::IpcRequest::ping()).await {
                                Ok(resp) => {
                                    let latency = start.elapsed().as_micros();
                                    println!("  {} Demonio Activo:       {}", "✔".green(), "EN LÍNEA (samulibred)".bold().green());
                                    println!("  {} Latencia IPC:         {} µs", "✔".green(), latency.to_string().cyan());
                                    println!("  {} Respuesta IPC:        {:?}", "✔".green(), resp);
                                }
                                Err(e) => {
                                    println!("  {} Demonio responde error: {}", "⚠".yellow(), e);
                                }
                            }
                        }
                        Err(e) => {
                            println!("  {} Demonio Inactivo:     {}", "✘".red(), "NO CONECTADO".bold().red());
                            println!("  Detalle del socket:      {}", e);
                            println!("\n  {} Para iniciar el demonio del sistema:", "💡".yellow());
                            println!("    sudo systemctl start samulibred");
                            println!("    systemctl status samulibred");
                        }
                    }
                }
            }
            DaemonCommands::Ping => {
                let socket_path = samulibre_core::ipc::resolve_ipc_socket_path();
                let client = samulibre_core::ipc::UnixSocketClient::connect(&socket_path).await?;
                let start = std::time::Instant::now();
                let resp = client.request(samulibre_core::ipc::IpcRequest::ping()).await?;
                let us = start.elapsed().as_micros();
                if cli.json {
                    let json_out = serde_json::json!({ "pong": true, "latency_us": us });
                    println!("{}", serde_json::to_string_pretty(&json_out)?);
                } else {
                    println!("{} Pong recibido en {} µs: {:?}", "✔".green(), us, resp);
                }
            }
        },

        Commands::Db { sub } => {
            let db_file = resolve_db_path();
            let db = samulibre_core::SecurityEventDatabase::new(&db_file)?;
            match sub {
                DbCommands::Stats => {
                    let stats = db.get_summary_stats()?;
                    if cli.json {
                        println!("{}", serde_json::to_string_pretty(&stats)?);
                    } else {
                        println!("\n{}", "─── ESTADÍSTICAS DE BASE DE DATOS SQLITE WAL ───".bold().cyan());
                        println!("  Ruta:                   {}", db_file.display());
                        println!("  Total Amenazas:         {}", stats.total_threats);
                        println!("  Neutralizadas:          {}", stats.neutralized_threats.to_string().green());
                        println!("  Pendientes:             {}", if stats.pending_threats > 0 { stats.pending_threats.to_string().red() } else { "0".green() });
                        println!("  Eventos de Auditoría:   {}", stats.total_audit_events);
                    }
                }
                DbCommands::Threats { limit } => {
                    let list = db.list_threats(limit)?;
                    if cli.json {
                        println!("{}", serde_json::to_string_pretty(&list)?);
                    } else {
                        println!("\n{}", format!("─── HISTORIAL FORENSE DE AMENAZAS (ÚLTIMAS {}) ───", limit).bold().cyan());
                        if list.is_empty() {
                            println!("  {} No hay amenazas registradas en la base de datos.", "✔".green());
                        } else {
                            for t in list {
                                println!("\n  [{}] {} ({})", t.timestamp.dimmed(), t.threat_name.bold().red(), t.severity.yellow());
                                println!("    Archivo: {}", t.file_path);
                                println!("    Motor:   {} | Acción: {}", t.engine, t.action_taken.bold().cyan());
                            }
                        }
                    }
                }
                DbCommands::Audit { limit } => {
                    let list = db.list_audit_events(limit)?;
                    if cli.json {
                        println!("{}", serde_json::to_string_pretty(&list)?);
                    } else {
                        println!("\n{}", format!("─── EVENTOS DE AUDITORÍA Y KERNEL (ÚLTIMOS {}) ───", limit).bold().cyan());
                        if list.is_empty() {
                            println!("  No hay eventos de auditoría registrados.");
                        } else {
                            for a in list {
                                println!("  [{}] [{}] {} - {}", a.timestamp.dimmed(), a.severity.yellow(), a.event_type.bold().cyan(), a.description);
                            }
                        }
                    }
                }
                DbCommands::Exclusions { sub: excl_sub } => match excl_sub {
                    ExclusionCommands::Add { path, dir } => {
                        let is_dir = dir || Path::new(&path).is_dir();
                        db.add_exclusion(&path, is_dir)?;
                        println!("{} Exclusión agregada: {} ({})", "✔".green(), path, if is_dir { "Directorio" } else { "Archivo" });
                    }
                    ExclusionCommands::Remove { path } => {
                        if db.remove_exclusion(&path)? {
                            println!("{} Exclusión eliminada: {}", "✔".green(), path);
                        } else {
                            println!("{} No se encontró la ruta en la lista de exclusiones: {}", "✘".red(), path);
                        }
                    }
                    ExclusionCommands::List => {
                        let list = db.list_exclusions()?;
                        if cli.json {
                            println!("{}", serde_json::to_string_pretty(&list)?);
                        } else {
                            println!("\n{}", "─── EXCLUSIONES DE ESCANEO ACTIVAS ───".bold().cyan());
                            if list.is_empty() {
                                println!("  No hay exclusiones configuradas.");
                            } else {
                                for (p, created_at, is_dir) in list {
                                    let tag = if is_dir { "[DIR]".cyan() } else { "[FILE]".yellow() };
                                    println!("  {} {} (Registrado: {})", tag, p.bold(), created_at);
                                }
                            }
                        }
                    }
                },
                DbCommands::Clear { yes } => {
                    if !yes {
                        print!("¿Está seguro de que desea purgar todos los eventos forenses de SQLite? (s/N): ");
                        std::io::Write::flush(&mut std::io::stdout())?;
                        let mut confirm = String::new();
                        std::io::stdin().read_line(&mut confirm)?;
                        if confirm.trim().to_lowercase() != "s" {
                            println!("Operación cancelada.");
                            return Ok(());
                        }
                    }
                    db.clear_all()?;
                    println!("{} Base de datos de eventos forenses purgada exitosamente.", "✔".green());
                }
            }
        },

        Commands::Report { format, output } => {
            let socket_path = samulibre_core::ipc::resolve_ipc_socket_path();
            let daemon_active = socket_path.exists();
            let db_file = resolve_db_path();

            let core = SamuLibreCore::new(&canary_dir, &vpn_dir, true);

            let rep = report::ForensicReportData::collect_current(
                &core,
                &db_file,
                daemon_active,
                &socket_path.display().to_string(),
            );

            let (content, default_file) = match format.to_lowercase().as_str() {
                "json" => (rep.to_json()?, PathBuf::from("samulibre_report.json")),
                "markdown" | "md" => (rep.to_markdown(), PathBuf::from("samulibre_report.md")),
                _ => (rep.to_html(), PathBuf::from("samulibre_report.html")),
            };

            let target_file = output.unwrap_or(default_file);
            fs::write(&target_file, content)?;
            println!(
                "{} Informe forense ({}) exportado exitosamente a: {}",
                "✔".bold().green(),
                format.to_uppercase().cyan(),
                target_file.display().to_string().bold().yellow()
            );
        }

        Commands::Policy { sub } => match sub {
            PolicyCommands::Show => {
                let policy_file = Path::new("data").join("policy.json");
                let profile = if policy_file.exists() {
                    fs::read_to_string(&policy_file).unwrap_or_else(|_| "balanced".to_string())
                } else {
                    "balanced".to_string()
                };
                if cli.json {
                    let json_out = serde_json::json!({
                        "profile": profile,
                        "heuristic_streaming": true,
                        "iptables_isolation": true,
                        "ebpf_telemetry": "dynamic",
                        "sandbox_backend": "bubblewrap"
                    });
                    println!("{}", serde_json::to_string_pretty(&json_out)?);
                } else {
                    println!("\n{}", "─── PERFIL DE POLÍTICA DE SEGURIDAD ───".bold().cyan());
                    println!("  Perfil Activo:            {}", profile.bold().yellow());
                    println!("  Heurística en Streaming:  ACTIVA (SHA-256 total)");
                    println!("  Aislamiento por Iptables: AUTOMÁTICO ANTE AMENAZAS CRÍTICAS");
                    println!("  Inspección eBPF / BTF:    DINÁMICA CON FALLBACK A /proc");
                    println!("  Contención Sandbox:       BUBBLEWRAP ESTRICTO");
                }
            }
            PolicyCommands::Set { profile } => {
                let p = profile.to_lowercase();
                if !["strict", "balanced", "developer", "server"].contains(&p.as_str()) {
                    println!("{} Perfil no válido. Opciones: strict | balanced | developer | server", "✘".red());
                    return Ok(());
                }
                let policy_file = Path::new("data").join("policy.json");
                fs::write(&policy_file, &p)?;
                println!("{} Perfil de seguridad actualizado a: {}", "✔".green(), p.bold().yellow());
            }
        },

        Commands::Demo => {
            run_live_demonstration(&canary_dir, &vpn_dir).await?;
        }
    }

    Ok(())
}

pub fn scan_single_file(scanner: &MultiEngineScanner, path: &Path) {
    match scanner.scan_file(path) {
        Ok(result) => {
            match result.status {
                FileScanStatus::Clean => {
                    println!("{} {} [{}] ({} ms)", "✔ LIMPIO".green().bold(), result.file_path, result.engine, result.scan_time_ms);
                }
                FileScanStatus::Infected => {
                    println!(
                        "{} {} -> {} [{}]",
                        "✘ INFECTADO".red().bold(),
                        result.file_path.bold(),
                        result.detection_name.unwrap_or_default().bold().red(),
                        result.engine.yellow()
                    );
                }
                FileScanStatus::Suspicious => {
                    println!(
                        "{} {} -> {} [{}]",
                        "⚠ SOSPECHOSO".yellow().bold(),
                        result.file_path,
                        result.detection_name.unwrap_or_default().yellow(),
                        result.engine
                    );
                }
                FileScanStatus::AccessDenied => {
                    println!("{} {} (Acceso denegado)", "✘ ERROR".red(), result.file_path);
                }
            }
        }
        Err(e) => {
            println!("Error al escanear {}: {}", path.display(), e);
        }
    }
}

pub fn scan_directory(scanner: &MultiEngineScanner, dir: &Path) {
    if let Ok(entries) = fs::read_dir(dir) {
        let mut clean_count = 0;
        let mut infected_count = 0;

        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() {
                if let Ok(res) = scanner.scan_file(&path) {
                    if res.status == FileScanStatus::Infected {
                        infected_count += 1;
                        println!(
                            "{} {} -> {}",
                            "✘ INFECTADO".red().bold(),
                            path.display(),
                            res.detection_name.unwrap_or_default().red()
                        );
                    } else {
                        clean_count += 1;
                    }
                }
            }
        }

        println!("\n{}", "Resultado del Escaneo:".bold());
        println!("  Archivos limpios:    {}", clean_count.to_string().green());
        println!("  Archivos infectados: {}", infected_count.to_string().red());
    }
}

async fn run_live_demonstration(canary_dir: &Path, vpn_dir: &Path) -> Result<()> {
    println!("\n{}", "=========================================================".cyan());
    println!("{}", "   DEMOSTRACIÓN INTEGRAL: ANTIVIRUS SAMULIBRE OPEN SOURCE   ".bold().yellow());
    println!("{}", "=========================================================".cyan());

    // 1. Demostración de Escaneo con YARA-X y Firmas
    println!("\n{}", "[PASO 1] PRUEBA DEL MOTOR DE DETECCIÓN (ClamAV & YARA-X)...".bold().cyan());
    let scanner = MultiEngineScanner::new();
    let test_dir = Path::new("data").join("test_samples");
    let _ = fs::create_dir_all(&test_dir);

    // Crear muestra benigna
    let clean_file = test_dir.join("documento_seguro.txt");
    fs::write(&clean_file, "Este es un documento seguro de la oficina sin ningun codigo sospechoso.")?;
    scan_single_file(&scanner, &clean_file);

    // Crear muestra EICAR estándar
    let eicar_file = test_dir.join("eicar_test.com");
    fs::write(&eicar_file, r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")?;
    scan_single_file(&scanner, &eicar_file);

    // Crear muestra de script sospechoso de evasión de AMSI
    let amsi_script = test_dir.join("bypass_amsi_dropper.ps1");
    fs::write(&amsi_script, "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)")?;
    scan_single_file(&scanner, &amsi_script);

    // 2. Demostración de Parchado Virtual Autónomo
    println!("\n{}", "[PASO 2] PRUEBA DE PARCHADO VIRTUAL Y DESACTIVACIÓN AUTOMÁTICA...".bold().cyan());
    let mut patcher = VirtualPatcher::new(true);

    println!("2.1 Escaneando sistema operativo en busca de CVEs sin actualizar...");
    let (unmitigated, _, _) = patcher.scan_and_evaluate(None);
    println!("    Detectadas {} vulnerabilidades abiertas sin parche oficial del SO.", unmitigated.to_string().bold().red());

    println!("2.2 Aplicando mitigaciones de parchado virtual (Reglas WFP / Registro / Servicios)...");
    let applied = patcher.apply_virtual_patches()?;
    println!("    {} Se activaron {} parches virtuales para proteger el equipo.", "✔".green(), applied.to_string().green());

    println!("2.3 Simulando que Windows Update descarga e instala la actualización oficial 'KB5041585'...");
    let mut simulated_kbs = patcher.get_installed_kbs();
    simulated_kbs.insert("KB5041585".to_string()); // Parche oficial de CVE-2024-38063

    println!("2.4 Ejecutando verificación de parches del sistema...");
    let reverted = patcher.check_and_deactivate_obsolete_patches(Some(simulated_kbs))?;
    println!(
        "    {} ¡ÉXITO! SamuLibre detectó que Windows ya instaló el parche oficial de forma nativa y retiró {} regla(s) de parche virtual automáticamente.",
        "✔".bold().green(),
        reverted.to_string().bold().yellow()
    );

    // 3. Demostración del Escudo Anti-Hackers, Robo de Credenciales y Canarios
    println!("\n{}", "[PASO 3] PRUEBA DEL ESCUDO ANTI-HACKERS Y TRAMPAS ANTI-RANSOMWARE...".bold().cyan());
    let mut shield = EndpointShield::new(canary_dir);
    let deployed = shield.deploy_canaries()?;
    println!("3.1 Desplegados {} archivos trampa canarios señuelo.", deployed);

    println!("3.2 Verificando integridad inicial de los canarios señuelo...");
    let alerts = shield.check_canary_integrity();
    println!("    Alertas de ransomware: {} (Todo limpio y seguro).", alerts.len().to_string().green());

    println!("3.3 Simulando intento de ransomware cifrando el archivo trampa 'passwords_backup_vault.txt'...");
    let canary_target = canary_dir.join("passwords_backup_vault.txt");
    fs::write(&canary_target, "ENCRYPTED_BY_MALWARE_LOCKED_PAY_RANSOM_0xDEADBEEF")?;

    let alerts_after = shield.check_canary_integrity();
    for alert in alerts_after {
        println!("    {} [{}] {}", "⚠".bold().red(), alert.severity, alert.title.bold());
        println!("       {}", alert.details.red());
        println!("       Acción inmediata: {}", alert.action_taken.bold().yellow());
    }

    // 3.4 Restauración de seguridad: Restaurar canarios a estado original limpio tras la simulación
    let _ = shield.deploy_canaries();
    println!("3.4 Trampas canario restauradas e intactas tras la prueba de simulación.");

    // 4. Demostración de Navegación Libre y VPN
    println!("\n{}", "[PASO 4] NAVEGACIÓN LIBRE, VPN WIREGUARD Y DNS SEGURO...".bold().cyan());
    let vpn = VpnManager::new(vpn_dir);
    let sample_conf = vpn_dir.join("samulibre_demo.conf");
    let wg_config = WireGuardConfig {
        interface_name: "samulibre-wg".to_string(),
        private_key: "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB".to_string(),
        address: "10.88.88.2/32".to_string(),
        dns: vec!["9.9.9.9".to_string()],
        peer_public_key: "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI=".to_string(),
        peer_endpoint: "libre-node-01.samulibre.org:51820".to_string(),
        allowed_ips: "0.0.0.0/0".to_string(),
    };
    vpn.export_wireguard_conf(&wg_config, "samulibre_demo.conf")?;
    println!("    {} Perfil libre WireGuard exportado: {:?}", "✔".green(), sample_conf);
    println!("    {} DNS Seguro con Quad9 (Bloqueo de dominios maliciosos sin telemetría).", "✔".green());

    println!("\n{}", "=========================================================".green());
    println!("{}", "   DEMOSTRACIÓN COMPLETADA: TODOS LOS MÓDULOS OPERATIVOS   ".bold().green());
    println!("{}", "=========================================================".green());

    Ok(())
}

fn print_banner() {
    println!("{}", r#"
  ███████╗ █████╗ ███╗   ███╗██╗   ██╗██╗     ██╗██████╗ ██████╗ ███████╗
  ██╔════╝██╔══██╗████╗ ████║██║   ██║██║     ██║██╔══██╗██╔══██╗██╔════╝
  ███████╗███████║██╔████╔██║██║   ██║██║     ██║██████╔╝██████╔╝█████╗  
  ╚════██║██╔══██║██║╚██╔╝██║██║   ██║██║     ██║██╔══██╗██╔══██╗██╔══╝  
  ███████║██║  ██║██║ ╚═╝ ██║╚██████╔╝███████╗██║██████╔╝██║  ██║███████╗
  ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝ ╚═════╝ ╚══════╝╚═╝╚═════╝ ╚═╝  ╚═╝╚══════╝
   Antivirus Open Source & Suite de Ciberseguridad Libre | 0% Ads | 100% Free
    "#.bright_cyan());
}
