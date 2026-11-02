use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Instant, SystemTime};
use tracing::debug;

#[derive(Debug, Clone)]
pub struct SmartCacheEntry {
    pub sha256: String,
    pub size: u64,
    pub modified: SystemTime,
    pub inode: u64,
    pub signatures_db_version: String,
    pub verified_at: Instant,
}

/// Caché inteligente de análisis con invalidación automática por versión de firmas y metadatos
#[derive(Clone)]
pub struct SmartInspectionCache {
    inner: Arc<Mutex<HashMap<PathBuf, SmartCacheEntry>>>,
    max_capacity: usize,
}

impl Default for SmartInspectionCache {
    fn default() -> Self {
        Self::new(30_000)
    }
}

impl SmartInspectionCache {
    pub fn new(max_capacity: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
            max_capacity,
        }
    }

    /// Consulta si un archivo ya fue analizado y continúa siendo idéntico y válido con la versión actual de firmas
    pub fn query_clean(
        &self,
        path: &Path,
        current_db_version: &str,
    ) -> Option<String> {
        let metadata = fs::metadata(path).ok()?;
        if !metadata.is_file() {
            return None;
        }

        let size = metadata.len();
        let modified = metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH);

        #[cfg(unix)]
        let inode = {
            use std::os::unix::fs::MetadataExt;
            metadata.ino()
        };
        #[cfg(not(unix))]
        let inode = 0u64;

        let cache = self.inner.lock().ok()?;
        if let Some(entry) = cache.get(path) {
            // Verificar congruencia total: tamaño, timestamp, inodo y versión de base de firmas
            if entry.size == size
                && entry.modified == modified
                && entry.inode == inode
                && entry.signatures_db_version == current_db_version
            {
                return Some(entry.sha256.clone());
            }
        }

        None
    }

    /// Registra un archivo como limpio y verificado
    pub fn insert_clean(
        &self,
        path: PathBuf,
        sha256: String,
        signatures_db_version: String,
    ) {
        let metadata = match fs::metadata(&path) {
            Ok(m) => m,
            Err(_) => return,
        };

        let size = metadata.len();
        let modified = metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH);

        #[cfg(unix)]
        let inode = {
            use std::os::unix::fs::MetadataExt;
            metadata.ino()
        };
        #[cfg(not(unix))]
        let inode = 0u64;

        if let Ok(mut cache) = self.inner.lock() {
            if cache.len() >= self.max_capacity {
                // Desalojar el 20% más antiguo
                let remove_count = self.max_capacity / 5;
                let keys: Vec<_> = cache.keys().take(remove_count).cloned().collect();
                for k in keys {
                    cache.remove(&k);
                }
                debug!("Caché de inspección depurada: liberadas {} entradas.", remove_count);
            }

            cache.insert(
                path,
                SmartCacheEntry {
                    sha256,
                    size,
                    modified,
                    inode,
                    signatures_db_version,
                    verified_at: Instant::now(),
                },
            );
        }
    }

    /// Invalida todas las entradas registradas (por ejemplo tras una actualización masiva de firmas)
    pub fn invalidate_all(&self) {
        if let Ok(mut cache) = self.inner.lock() {
            cache.clear();
            debug!("Caché inteligente de inspección invalidada por completo.");
        }
    }

    /// Retorna el número de elementos limpios actualmente en memoria
    pub fn len(&self) -> usize {
        self.inner.lock().map(|c| c.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
