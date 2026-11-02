use crate::event_queue::{EdrEventQueue, QueuePriority};
use crate::models::EdrEventType;
use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use tracing::debug;

#[derive(Debug, Clone)]
pub struct ProcessTelemetry {
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub comm: String,
    pub exe_path: Option<PathBuf>,
    pub cmdline: Vec<String>,
    pub is_from_suspicious_location: bool,
}

pub struct ProcessSensorHandle {
    stop_signal: Arc<AtomicBool>,
    thread_handle: Option<JoinHandle<()>>,
}

impl Drop for ProcessSensorHandle {
    fn drop(&mut self) {
        self.stop_signal.store(true, Ordering::SeqCst);
        if let Some(h) = self.thread_handle.take() {
            let _ = h.join();
        }
    }
}

pub struct ProcessSensor;

impl ProcessSensor {
    /// Inicia el sensor de monitoreo de procesos observando `/proc` en un hilo de baja latencia
    pub fn start(queue: Arc<EdrEventQueue>) -> ProcessSensorHandle {
        let stop_signal = Arc::new(AtomicBool::new(false));
        let stop_clone = Arc::clone(&stop_signal);

        let thread_handle = std::thread::spawn(move || {
            let mut known_pids: HashSet<u32> = HashSet::new();

            // Población inicial de PIDs existentes para evitar ráfagas iniciales
            if let Ok(entries) = fs::read_dir("/proc") {
                for entry in entries.flatten() {
                    if let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() {
                        known_pids.insert(pid);
                    }
                }
            }

            debug!("Sensor de procesos inicializado con {} PIDs de línea base.", known_pids.len());

            while !stop_clone.load(Ordering::Relaxed) {
                // Ciclo de escaneo rápido de /proc cada 150 ms
                std::thread::sleep(std::time::Duration::from_millis(150));

                let entries = match fs::read_dir("/proc") {
                    Ok(e) => e,
                    Err(_) => continue,
                };

                let mut current_pids = HashSet::new();

                for entry in entries.flatten() {
                    let file_name = entry.file_name();
                    let name_str = file_name.to_string_lossy();
                    let pid = match name_str.parse::<u32>() {
                        Ok(p) => p,
                        Err(_) => continue,
                    };

                    current_pids.insert(pid);

                    // Si es un PID nuevo, capturarlo e inspeccionarlo inmediatamente
                    if !known_pids.contains(&pid) {
                        if let Some(telemetry) = Self::inspect_proc(pid) {
                            let priority = if telemetry.is_from_suspicious_location {
                                QueuePriority::Critical
                            } else {
                                QueuePriority::High
                            };

                            if let Some(ref exe) = telemetry.exe_path {
                                queue.enqueue(
                                    priority,
                                    exe.clone(),
                                    EdrEventType::ProcessExec,
                                    Some(telemetry.pid),
                                    Some(telemetry.ppid),
                                    Some(telemetry.comm.clone()),
                                );
                            }
                        }
                    }
                }

                known_pids = current_pids;
            }
        });

        ProcessSensorHandle {
            stop_signal,
            thread_handle: Some(thread_handle),
        }
    }

    /// Inspecciona los metadatos de un proceso específico en `/proc`
    pub fn inspect_proc(pid: u32) -> Option<ProcessTelemetry> {
        let proc_dir = PathBuf::from(format!("/proc/{}", pid));
        if !proc_dir.exists() {
            return None;
        }

        // 1. Obtener ruta del ejecutable real
        let exe_path = fs::read_link(proc_dir.join("exe")).ok();

        // 2. Obtener comm (nombre corto del proceso)
        let comm = fs::read_to_string(proc_dir.join("comm"))
            .unwrap_or_else(|_| "desconocido".to_string())
            .trim()
            .to_string();

        // 3. Obtener PPID y UID desde /proc/[pid]/status
        let mut ppid = 0u32;
        let mut uid = 0u32;
        if let Ok(status) = fs::read_to_string(proc_dir.join("status")) {
            for line in status.lines() {
                if let Some(val) = line.strip_prefix("PPid:") {
                    ppid = val.trim().parse::<u32>().unwrap_or(0);
                } else if let Some(val) = line.strip_prefix("Uid:") {
                    if let Some(first) = val.split_whitespace().next() {
                        uid = first.parse::<u32>().unwrap_or(0);
                    }
                }
            }
        }

        // 4. Obtener argumentos limpios (sanitizados contra tokens y contraseñas)
        let cmdline = match fs::read(proc_dir.join("cmdline")) {
            Ok(bytes) => bytes
                .split(|&b| b == 0)
                .filter(|s| !s.is_empty())
                .map(|s| sanitize_arg(&String::from_utf8_lossy(s)))
                .collect(),
            Err(_) => Vec::new(),
        };

        // 5. Evaluar si se ejecuta desde ubicaciones temporales o anómalas
        let is_from_suspicious_location = if let Some(ref p) = exe_path {
            let p_str = p.to_string_lossy();
            p_str.starts_with("/tmp")
                || p_str.starts_with("/var/tmp")
                || p_str.starts_with("/dev/shm")
                || p_str.contains("/.cache/")
                || p_str.contains("/dev/shm/.")
                || p_str.contains("/tmp/.")
        } else {
            false
        };

        Some(ProcessTelemetry {
            pid,
            ppid,
            uid,
            comm,
            exe_path,
            cmdline,
            is_from_suspicious_location,
        })
    }
}

/// Sanitiza argumentos de línea de comandos para evitar registrar contraseñas o tokens sensibles
fn sanitize_arg(arg: &str) -> String {
    let lower = arg.to_lowercase();
    if lower.contains("pass")
        || lower.contains("token")
        || lower.contains("secret")
        || lower.contains("api_key")
        || lower.contains("auth")
    {
        if let Some((key, _)) = arg.split_once('=') {
            format!("{}=[REDACTED]", key)
        } else {
            "[REDACTED_SECRET]".to_string()
        }
    } else {
        arg.to_string()
    }
}
