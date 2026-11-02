use crate::event_queue::{EdrEventQueue, QueuePriority};
use crate::models::EdrEventType;
use crate::smart_cache::SmartInspectionCache;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;
use tracing::info;

pub struct ReconciliationHandle {
    stop_signal: Arc<AtomicBool>,
    thread_handle: Option<JoinHandle<()>>,
}

impl Drop for ReconciliationHandle {
    fn drop(&mut self) {
        self.stop_signal.store(true, Ordering::SeqCst);
        if let Some(h) = self.thread_handle.take() {
            let _ = h.join();
        }
    }
}

pub struct ReconciliationEngine;

impl ReconciliationEngine {
    /// Inicia el escáner de reconciliación en baja prioridad de I/O
    pub fn start(
        queue: Arc<EdrEventQueue>,
        cache: Arc<SmartInspectionCache>,
        watch_paths: Vec<PathBuf>,
        interval: Duration,
    ) -> ReconciliationHandle {
        let stop_signal = Arc::new(AtomicBool::new(false));
        let stop_clone = Arc::clone(&stop_signal);

        let thread_handle = std::thread::spawn(move || {
            // Espera inicial de 10 segundos tras el arranque
            std::thread::sleep(Duration::from_secs(10));

            while !stop_clone.load(Ordering::Relaxed) {
                info!("Iniciando ciclo de reconciliación periódica para descubrir archivos eludidos...");
                let mut discovered = 0usize;

                for root in &watch_paths {
                    if !root.exists() {
                        continue;
                    }

                    reconcile_recursive(root, &queue, &cache, &stop_clone, &mut discovered);

                    if stop_clone.load(Ordering::Relaxed) {
                        break;
                    }
                }

                info!(
                    "Ciclo de reconciliación finalizado: {} archivos no cacheados encolados para verificación.",
                    discovered
                );

                // Esperar intervalo configurado (ej. 30 minutos)
                let steps = (interval.as_secs() / 2).max(1);
                for _ in 0..steps {
                    if stop_clone.load(Ordering::Relaxed) {
                        break;
                    }
                    std::thread::sleep(Duration::from_secs(2));
                }
            }
        });

        ReconciliationHandle {
            stop_signal,
            thread_handle: Some(thread_handle),
        }
    }
}

fn reconcile_recursive(
    dir: &Path,
    queue: &EdrEventQueue,
    cache: &SmartInspectionCache,
    stop: &AtomicBool,
    count: &mut usize,
) {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };

    for entry in entries.flatten() {
        if stop.load(Ordering::Relaxed) {
            return;
        }

        let path = entry.path();
        let path_str = path.to_string_lossy();

        if path_str.contains("/.git/")
            || path_str.contains("/node_modules/")
            || path_str.contains("/target/")
            || path_str.contains("/.cache/")
            || path_str.contains("/quarantine/")
            || path_str.contains("/proc/")
            || path_str.contains("/sys/")
            || path_str.contains("/dev/")
        {
            continue;
        }

        if path.is_dir() {
            reconcile_recursive(&path, queue, cache, stop, count);
        } else if path.is_file() {
            // Si el archivo no está en la caché limpia, encolarlo con baja prioridad
            if cache.query_clean(&path, "any").is_none() {
                if queue.enqueue(
                    QueuePriority::Low,
                    path,
                    EdrEventType::FileModify,
                    None,
                    None,
                    None,
                ) {
                    *count += 1;
                }
            }
            // Retardo leve de cortesía para mantener uso de CPU < 0.2%
            std::thread::sleep(Duration::from_millis(1));
        }
    }
}
