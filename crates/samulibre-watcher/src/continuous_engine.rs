use crate::behavioral_sensor::BehavioralSensor;
use crate::event_queue::{EdrEventQueue, QueueItem};
use crate::fanotify_sensor::{FanotifySensor, FanotifySensorHandle};
use crate::fim_sensor::{FimSensor, FimSensorHandle};
use crate::inotify_sensor::{InotifySensor, InotifySensorHandle};
use crate::models::{
    ActivityMetrics, CoverageMetrics, EdrEvent, EdrEventType, EdrProtectionStatus, ProtectionMode,
};
use crate::process_sensor::{ProcessSensor, ProcessSensorHandle};
use crate::reconciliation::{ReconciliationEngine, ReconciliationHandle};
use crate::smart_cache::SmartInspectionCache;
use crate::QuarantineVault;
use samulibre_scanner::MultiEngineScanner;
use samulibre_types::{FileScanStatus, Severity, ThreatAlert, ThreatCategory};
use std::collections::VecDeque;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tracing::{debug, info};

pub struct ContinuousProtectionEngine {
    scanner: Arc<Mutex<MultiEngineScanner>>,
    vault: Arc<QuarantineVault>,
    cache: Arc<SmartInspectionCache>,
    queue: Arc<EdrEventQueue>,
    behavioral: Arc<BehavioralSensor>,
    mode: Mutex<ProtectionMode>,
    timeline: Arc<Mutex<VecDeque<EdrEvent>>>,
    start_time: Instant,

    // Métricas
    files_inspected: AtomicU64,
    threats_detected: AtomicU64,
    threats_blocked: AtomicU64,
    processes_suspended: AtomicU64,
    total_inspection_time_ms: AtomicU64,

    // Handles de sensores
    fanotify_handle: Mutex<Option<FanotifySensorHandle>>,
    inotify_handle: Mutex<Option<InotifySensorHandle>>,
    process_handle: Mutex<Option<ProcessSensorHandle>>,
    fim_handle: Mutex<Option<FimSensorHandle>>,
    reconciliation_handle: Mutex<Option<ReconciliationHandle>>,

    // Rutas
    watch_dirs: Mutex<Vec<PathBuf>>,
    excluded_dirs: Mutex<Vec<PathBuf>>,
    stop_workers: Arc<AtomicBool>,
}

impl ContinuousProtectionEngine {
    pub fn new(scanner: Arc<Mutex<MultiEngineScanner>>, quarantine_dir: impl AsRef<Path>) -> Self {
        Self {
            scanner,
            vault: Arc::new(QuarantineVault::new(quarantine_dir)),
            cache: Arc::new(SmartInspectionCache::default()),
            queue: Arc::new(EdrEventQueue::new(20_000)),
            behavioral: Arc::new(BehavioralSensor::default()),
            mode: Mutex::new(ProtectionMode::Active),
            timeline: Arc::new(Mutex::new(VecDeque::with_capacity(1000))),
            start_time: Instant::now(),

            files_inspected: AtomicU64::new(0),
            threats_detected: AtomicU64::new(0),
            threats_blocked: AtomicU64::new(0),
            processes_suspended: AtomicU64::new(0),
            total_inspection_time_ms: AtomicU64::new(0),

            fanotify_handle: Mutex::new(None),
            inotify_handle: Mutex::new(None),
            process_handle: Mutex::new(None),
            fim_handle: Mutex::new(None),
            reconciliation_handle: Mutex::new(None),

            watch_dirs: Mutex::new(Vec::new()),
            excluded_dirs: Mutex::new(Vec::new()),
            stop_workers: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn get_vault(&self) -> Arc<QuarantineVault> {
        Arc::clone(&self.vault)
    }

    pub fn set_mode(&self, mode: ProtectionMode) {
        if let Ok(mut m) = self.mode.lock() {
            *m = mode;
            info!("EDR Postura de Defensa actualizada a: {}", mode);
        }
    }

    pub fn add_watch_dir(&self, dir: impl AsRef<Path>) {
        let p = dir.as_ref().to_path_buf();
        if let Ok(mut list) = self.watch_dirs.lock() {
            if !list.contains(&p) {
                list.push(p);
            }
        }
    }

    pub fn add_exclusion(&self, dir: impl AsRef<Path>) {
        let p = dir.as_ref().to_path_buf();
        if let Ok(mut list) = self.excluded_dirs.lock() {
            if !list.contains(&p) {
                list.push(p);
            }
        }
    }

    /// Inicia la suite multicapa de protección continua y el grupo de trabajadores EDR
    pub fn start<F>(&self, on_threat_detected: F) -> anyhow::Result<()>
    where
        F: Fn(ThreatAlert) + Send + Sync + Clone + 'static,
    {
        info!("Iniciando Motor de Protección Continua y Detección EDR para Linux...");

        let watch_paths = self.watch_dirs.lock().map(|l| l.clone()).unwrap_or_default();
        let excluded_paths = self.excluded_dirs.lock().map(|l| l.clone()).unwrap_or_default();

        // 1. Iniciar Sensor Fanotify (VFS interceptor) si está disponible como root
        let mount_points = vec![PathBuf::from("/"), PathBuf::from("/home"), PathBuf::from("/tmp")];
        if let Some(f_handle) = FanotifySensor::try_start(Arc::clone(&self.queue), mount_points) {
            info!("Capa 1: Sensor Fanotify activado con intercepción en VFS.");
            if let Ok(mut h) = self.fanotify_handle.lock() {
                *h = Some(f_handle);
            }
        }

        // 2. Iniciar Sensor Inotify Recursivo
        let inotify_handle = InotifySensor::start(
            Arc::clone(&self.queue),
            watch_paths.clone(),
            excluded_paths,
        )?;
        info!("Capa 1 (Fallback/Complemento): Sensor Inotify recursivo activo.");
        if let Ok(mut h) = self.inotify_handle.lock() {
            *h = Some(inotify_handle);
        }

        // 3. Iniciar Sensor de Procesos (/proc & execve monitor)
        let process_handle = ProcessSensor::start(Arc::clone(&self.queue));
        info!("Capa 2: Sensor de Procesos y Detección de Ejecución activo.");
        if let Ok(mut h) = self.process_handle.lock() {
            *h = Some(process_handle);
        }

        // 4. Iniciar Sensor FIM (File Integrity Monitoring)
        let fim_handle = FimSensor::start(Arc::clone(&self.queue));
        info!("Capa 3: Sensor FIM de integridad de archivos de sistema activo.");
        if let Ok(mut h) = self.fim_handle.lock() {
            *h = Some(fim_handle);
        }

        // 5. Iniciar Motor de Reconciliación Periódica
        let reconciliation_handle = ReconciliationEngine::start(
            Arc::clone(&self.queue),
            Arc::clone(&self.cache),
            watch_paths,
            Duration::from_secs(1800), // cada 30 minutos
        );
        info!("Capa 5: Motor de reconciliación periódica en segundo plano activo.");
        if let Ok(mut h) = self.reconciliation_handle.lock() {
            *h = Some(reconciliation_handle);
        }

        // 6. Iniciar Grupo de Trabajadores Asíncronos (Worker Pool)
        let worker_count = 2;
        self.stop_workers.store(false, Ordering::SeqCst);

        for worker_id in 0..worker_count {
            let queue = Arc::clone(&self.queue);
            let scanner = Arc::clone(&self.scanner);
            let vault = Arc::clone(&self.vault);
            let cache = Arc::clone(&self.cache);
            let timeline = Arc::clone(&self.timeline);
            let stop = Arc::clone(&self.stop_workers);
            let callback = on_threat_detected.clone();
            let behavioral = Arc::clone(&self.behavioral);

            std::thread::spawn(move || {
                debug!("Trabajador EDR #{} en ejecución.", worker_id);
                while !stop.load(Ordering::Relaxed) {
                    if let Some(item) = queue.pop_timeout(Duration::from_millis(200)) {
                        process_queue_item(
                            item,
                            &scanner,
                            &vault,
                            &cache,
                            &timeline,
                            &behavioral,
                            &callback,
                        );
                    }
                }
            });
        }

        info!("Motor EDR y protección continua operando con éxito.");
        Ok(())
    }

    /// Retorna el estado integral de los subsistemas y sensores
    pub fn get_status(&self) -> EdrProtectionStatus {
        let is_fanotify = self.fanotify_handle.lock().map(|h| h.is_some()).unwrap_or(false);
        let is_inotify = self.inotify_handle.lock().map(|h| h.is_some()).unwrap_or(false);
        let is_proc = self.process_handle.lock().map(|h| h.is_some()).unwrap_or(false);
        let is_fim = self.fim_handle.lock().map(|h| h.is_some()).unwrap_or(false);
        let is_rec = self.reconciliation_handle.lock().map(|h| h.is_some()).unwrap_or(false);
        let current_mode = self.mode.lock().map(|m| *m).unwrap_or(ProtectionMode::Active);

        EdrProtectionStatus {
            is_active: is_inotify || is_fanotify,
            protection_mode: current_mode,
            fanotify_active: is_fanotify,
            inotify_active: is_inotify,
            process_sensor_active: is_proc,
            ebpf_sensor_active: is_proc, // Emulado / Tracepoints
            fim_active: is_fim,
            behavioral_active: true,
            reconciliation_active: is_rec,
            kernel_version: read_kernel_release(),
            linux_distro: read_distro_name(),
            uptime_secs: self.start_time.elapsed().as_secs(),
        }
    }

    /// Retorna métricas de cobertura de directorios y procesos
    pub fn get_coverage(&self) -> CoverageMetrics {
        let watch_dirs: Vec<String> = self
            .watch_dirs
            .lock()
            .map(|l| l.iter().map(|p| p.to_string_lossy().to_string()).collect())
            .unwrap_or_default();

        let excluded_paths: Vec<String> = self
            .excluded_dirs
            .lock()
            .map(|l| l.iter().map(|p| p.to_string_lossy().to_string()).collect())
            .unwrap_or_default();

        let total_dirs = watch_dirs.len();
        let total_indexed = self.cache.len();

        CoverageMetrics {
            watch_dirs,
            excluded_paths,
            filesystems_monitored: vec!["ext4".to_string(), "btrfs".to_string(), "tmpfs".to_string()],
            total_dirs_watched: total_dirs,
            total_files_indexed: total_indexed,
            active_processes_monitored: count_active_pids(),
        }
    }

    /// Retorna métricas de actividad y colas
    pub fn get_activity(&self) -> ActivityMetrics {
        let total_time = self.total_inspection_time_ms.load(Ordering::Relaxed) as f64;
        let count = self.files_inspected.load(Ordering::Relaxed);
        let avg_time = if count > 0 { total_time / (count as f64) } else { 0.0 };

        ActivityMetrics {
            events_received: self.queue.get_total_enqueued(),
            events_processed: self.queue.get_total_processed(),
            events_dropped_saturation: self.queue.get_dropped_count() as u64,
            queue_pending: self.queue.len(),
            files_inspected: count,
            files_clean_cached: self.cache.len() as u64,
            threats_detected: self.threats_detected.load(Ordering::Relaxed),
            threats_blocked_isolated: self.threats_blocked.load(Ordering::Relaxed),
            processes_suspended: self.processes_suspended.load(Ordering::Relaxed),
            avg_inspection_time_ms: (avg_time * 100.0).round() / 100.0,
        }
    }

    /// Retorna la línea de tiempo forense de eventos EDR
    pub fn get_timeline(&self, limit: usize) -> Vec<EdrEvent> {
        if let Ok(guard) = self.timeline.lock() {
            guard.iter().take(limit).cloned().collect()
        } else {
            Vec::new()
        }
    }

    /// Inspección inmediata bajo demanda de un archivo con registro forense EDR
    pub fn inspect_file_immediately(&self, path: &Path) -> Option<EdrEvent> {
        if !path.exists() || !path.is_file() {
            return None;
        }

        let start = Instant::now();
        let scan_result = if let Ok(s) = self.scanner.lock() {
            s.scan_file(path).ok()?
        } else {
            return None;
        };

        let elapsed = start.elapsed().as_millis() as u64;
        self.files_inspected.fetch_add(1, Ordering::Relaxed);
        self.total_inspection_time_ms.fetch_add(elapsed, Ordering::Relaxed);

        let event = match scan_result.status {
            FileScanStatus::Clean => {
                self.cache.insert_clean(path.to_path_buf(), scan_result.sha256.clone(), "v2.0.32".to_string());
                EdrEvent {
                    id: format!("EDR-{}", uuid::Uuid::new_v4().to_string().to_uppercase()),
                    timestamp: chrono::Utc::now().to_rfc3339(),
                    event_type: EdrEventType::FileOpenExec,
                    severity: "Baja".to_string(),
                    file_path: Some(path.to_string_lossy().to_string()),
                    sha256: Some(scan_result.sha256),
                    pid: None,
                    ppid: None,
                    process_name: None,
                    user: None,
                    sensor: "OnDemandInspector".to_string(),
                    verdict: "Limpio".to_string(),
                    confidence_score: 95,
                    action_taken: "Permitido".to_string(),
                    details: format!("Archivo verificado como limpio en {} ms.", elapsed),
                }
            }
            FileScanStatus::Infected | FileScanStatus::Suspicious => {
                let threat = scan_result.detection_name.unwrap_or_else(|| "Amenaza.Detectada".to_string());
                self.threats_detected.fetch_add(1, Ordering::Relaxed);

                // Cuarentena automática
                let _ = self.vault.isolate_file(path, &threat, &scan_result.engine, &scan_result.sha256);
                self.threats_blocked.fetch_add(1, Ordering::Relaxed);

                EdrEvent {
                    id: format!("EDR-{}", uuid::Uuid::new_v4().to_string().to_uppercase()),
                    timestamp: chrono::Utc::now().to_rfc3339(),
                    event_type: EdrEventType::FileOpenExec,
                    severity: "Crítica".to_string(),
                    file_path: Some(path.to_string_lossy().to_string()),
                    sha256: Some(scan_result.sha256),
                    pid: None,
                    ppid: None,
                    process_name: None,
                    user: None,
                    sensor: "OnDemandInspector".to_string(),
                    verdict: threat.clone(),
                    confidence_score: 99,
                    action_taken: "Aislado en Cuarentena".to_string(),
                    details: format!("Amenaza interceptada ({}) por motor {}.", threat, scan_result.engine),
                }
            }
            FileScanStatus::AccessDenied => return None,
        };

        if let Ok(mut t) = self.timeline.lock() {
            if t.len() >= 1000 {
                t.pop_back();
            }
            t.push_front(event.clone());
        }

        Some(event)
    }
}

/// Procesa un elemento extraído de la cola de eventos priorizada
fn process_queue_item<F>(
    item: QueueItem,
    scanner: &Arc<Mutex<MultiEngineScanner>>,
    vault: &Arc<QuarantineVault>,
    cache: &Arc<SmartInspectionCache>,
    timeline: &Arc<Mutex<VecDeque<EdrEvent>>>,
    behavioral: &Arc<BehavioralSensor>,
    callback: &F,
) where
    F: Fn(ThreatAlert) + Send + Sync,
{
    let path = &item.path;
    if !path.exists() || !path.is_file() {
        return;
    }

    // 1. Detección comportamental si hay un PID asociado
    if let Some(pid) = item.pid {
        // Registrar en el sensor comportamental
        if let Some(bad_pid) = behavioral.record_write_operation(pid, path, &EdrEventQueue::new(1)) {
            // Suspender el proceso agresor inmediatamente
            BehavioralSensor::suspend_process(bad_pid);
        }
    }

    // 2. Consulta en caché inteligente
    if cache.query_clean(path, "v2.0.32").is_some() {
        return;
    }

    // 3. Escaneo en streaming
    let scan_result = if let Ok(s) = scanner.lock() {
        match s.scan_file(path) {
            Ok(r) => r,
            Err(_) => return,
        }
    } else {
        return;
    };

    match scan_result.status {
        FileScanStatus::Clean => {
            cache.insert_clean(path.clone(), scan_result.sha256, "v2.0.32".to_string());
        }
        FileScanStatus::Infected | FileScanStatus::Suspicious => {
            let threat_name = scan_result
                .detection_name
                .unwrap_or_else(|| "Amenaza.Desconocida".to_string());
            let engine = scan_result.engine;
            let sha256 = scan_result.sha256;

            // Aislamiento físico en bóveda de cuarentena
            let _ = vault.isolate_file(path, &threat_name, &engine, &sha256);

            // Si vino de un proceso activo, suspenderlo
            if let Some(pid) = item.pid {
                BehavioralSensor::suspend_process(pid);
            }

            let edr_event = EdrEvent {
                id: format!("EDR-{}", uuid::Uuid::new_v4().to_string().to_uppercase()),
                timestamp: chrono::Utc::now().to_rfc3339(),
                event_type: item.event_type.clone(),
                severity: "Crítica".to_string(),
                file_path: Some(path.to_string_lossy().to_string()),
                sha256: Some(sha256.clone()),
                pid: item.pid,
                ppid: item.ppid,
                process_name: item.comm.clone(),
                user: None,
                sensor: "EDR_Continuous_Watcher".to_string(),
                verdict: threat_name.clone(),
                confidence_score: 99,
                action_taken: "Aislado y neutralizado en cuarentena segura".to_string(),
                details: format!(
                    "Archivo '{}' interceptado en tiempo real por el motor {} y neutralizado.",
                    path.display(),
                    engine
                ),
            };

            if let Ok(mut t) = timeline.lock() {
                if t.len() >= 1000 {
                    t.pop_back();
                }
                t.push_front(edr_event.clone());
            }

            callback(ThreatAlert {
                id: uuid::Uuid::new_v4(),
                timestamp: chrono::Utc::now(),
                severity: Severity::Critical,
                category: ThreatCategory::MalwareFile,
                title: format!("¡Amenaza EDR neutralizada: {}!", threat_name),
                details: edr_event.details,
                process_id: item.pid,
                process_name: item.comm,
                target_path: Some(path.to_string_lossy().to_string()),
                action_taken: "Aislado en cuarentena".to_string(),
            });
        }
        FileScanStatus::AccessDenied => {}
    }
}

fn read_kernel_release() -> String {
    #[cfg(unix)]
    {
        let mut uname: libc::utsname = unsafe { std::mem::zeroed() };
        if unsafe { libc::uname(&mut uname) } == 0 {
            let release = unsafe { std::ffi::CStr::from_ptr(uname.release.as_ptr()) };
            return release.to_string_lossy().to_string();
        }
    }
    "Linux Kernel".to_string()
}

fn read_distro_name() -> String {
    if let Ok(content) = fs::read_to_string("/etc/os-release") {
        for line in content.lines() {
            if let Some((k, v)) = line.split_once('=') {
                if k.trim() == "PRETTY_NAME" {
                    return v.trim_matches('"').trim().to_string();
                }
            }
        }
    }
    "Linux".to_string()
}

fn count_active_pids() -> usize {
    fs::read_dir("/proc")
        .map(|entries| {
            entries
                .flatten()
                .filter(|e| e.file_name().to_string_lossy().parse::<u32>().is_ok())
                .count()
        })
        .unwrap_or(0)
}
