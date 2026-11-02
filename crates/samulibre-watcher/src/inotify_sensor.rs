use crate::event_queue::{EdrEventQueue, QueuePriority};
use crate::models::EdrEventType;
use notify::{Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::{debug, info};

pub struct InotifySensorHandle {
    _watcher: RecommendedWatcher,
    pub watched_paths: Vec<PathBuf>,
}

pub struct InotifySensor;

impl InotifySensor {
    /// Inicia el sensor inotify con vigilancia recursiva y descubrimiento dinámico de carpetas
    pub fn start(
        queue: Arc<EdrEventQueue>,
        watch_paths: Vec<PathBuf>,
        excluded_paths: Vec<PathBuf>,
    ) -> anyhow::Result<InotifySensorHandle> {
        let excluded_set: Arc<HashSet<PathBuf>> = Arc::new(excluded_paths.into_iter().collect());
        let excluded_cb = Arc::clone(&excluded_set);
        let queue_cb = Arc::clone(&queue);

        let mut watcher = RecommendedWatcher::new(
            move |res: notify::Result<Event>| {
                if let Ok(event) = res {
                    match event.kind {
                        EventKind::Create(_) | EventKind::Modify(_) => {
                            for path in event.paths {
                                // 1. Filtrar pseudo-archivos o rutas excluidas
                                let path_str = path.to_string_lossy();
                                if path_str.contains("/.git/")
                                    || path_str.contains("/node_modules/")
                                    || path_str.contains("/target/")
                                    || path_str.contains("/.cache/")
                                    || path_str.contains("/quarantine/")
                                    || path_str.contains("/.quarantine/")
                                    || path_str.contains("/proc/")
                                    || path_str.contains("/sys/")
                                    || path_str.contains("/dev/")
                                {
                                    continue;
                                }

                                if excluded_cb.iter().any(|exc| path.starts_with(exc)) {
                                    continue;
                                }

                                if path.is_file() {
                                    let is_exec = is_executable_or_script(&path);
                                    let priority = if is_exec {
                                        QueuePriority::High
                                    } else {
                                        QueuePriority::Normal
                                    };

                                    let ev_type = match event.kind {
                                        EventKind::Create(_) => EdrEventType::FileCreate,
                                        _ => EdrEventType::FileModify,
                                    };

                                    queue_cb.enqueue(
                                        priority,
                                        path,
                                        ev_type,
                                        None,
                                        None,
                                        None,
                                    );
                                }
                            }
                        }
                        _ => {}
                    }
                }
            },
            Config::default(),
        )?;

        let mut active_paths = Vec::new();
        for p in watch_paths {
            if p.exists() {
                match watcher.watch(&p, RecursiveMode::Recursive) {
                    Ok(_) => {
                        debug!("inotify: vigilando recursivamente {:?}", p);
                        active_paths.push(p);
                    }
                    Err(e) => {
                        debug!("inotify: no se pudo enlazar {:?}: {}", p, e);
                    }
                }
            }
        }

        info!("Sensor inotify activo con {} rutas base vigiladas recursivamente.", active_paths.len());

        Ok(InotifySensorHandle {
            _watcher: watcher,
            watched_paths: active_paths,
        })
    }
}

/// Comprueba si el archivo tiene atributos o extensiones ejecutables o de scripting
pub fn is_executable_or_script(path: &Path) -> bool {
    // 1. Verificar permiso de ejecución POSIX en Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(metadata) = fs::metadata(path) {
            if (metadata.permissions().mode() & 0o111) != 0 {
                return true;
            }
        }
    }

    // 2. Comprobar extensiones típicas de scripts y binarios
    if let Some(ext) = path.extension().and_then(|s| s.to_str()) {
        let ext_lower = ext.to_lowercase();
        return matches!(
            ext_lower.as_str(),
            "sh" | "bash" | "py" | "pl" | "rb" | "elf" | "bin" | "so" | "run" | "appimage" | "jar"
                | "deb" | "rpm" | "tar" | "gz" | "zip" | "7z" | "php" | "js"
        );
    }

    // 3. Archivos sin extensión en rutas no ocultas suelen ser binarios ELF o scripts de shell
    true
}
