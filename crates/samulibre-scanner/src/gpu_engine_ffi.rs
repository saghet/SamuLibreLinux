use samulibre_types::{FileScanStatus, ScanResult};
use std::ffi::{CStr, CString};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

#[repr(C)]
#[derive(Debug, Clone)]
pub struct SamulibreCScanResult {
    pub status: i32,                     // 0 = Clean, 1 = Infected, 2 = Suspicious, 3 = Error
    pub detection_name: [libc::c_char; 256],
    pub engine_name: [libc::c_char; 64],
    pub entropy: f64,
    pub is_packed: i32,
    pub ml_risk_probability: f32,
    pub ml_verdict: [libc::c_char; 32],
    pub scan_time_ms: u64,
    pub quarantine_recommended: i32,
}

impl Default for SamulibreCScanResult {
    fn default() -> Self {
        unsafe { std::mem::zeroed() }
    }
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct SamulibreCTelemetry {
    pub gpu_temperature_c: f32,
    pub gpu_power_watts: f32,
    pub vram_used_mb: libc::size_t,
    pub vram_total_mb: libc::size_t,
    pub ram_used_mb: libc::size_t,
    pub system_load_1min: f32,
    pub is_throttled: i32,
    pub is_gpu_accelerated: i32,
    pub telemetry_source: [libc::c_char; 32],
}

impl Default for SamulibreCTelemetry {
    fn default() -> Self {
        unsafe { std::mem::zeroed() }
    }
}

#[derive(Debug, Clone)]
pub struct GpuTelemetry {
    pub gpu_temperature_c: f32,
    pub gpu_power_watts: f32,
    pub vram_used_mb: usize,
    pub vram_total_mb: usize,
    pub ram_used_mb: usize,
    pub system_load_1min: f32,
    pub is_throttled: bool,
    pub is_gpu_accelerated: bool,
    pub telemetry_source: String,
}

type FnCreate = extern "C" fn(i32) -> *mut libc::c_void;
type FnDestroy = extern "C" fn(*mut libc::c_void);
type FnIsAccelerated = extern "C" fn(*mut libc::c_void) -> i32;
type FnGetBackendName = extern "C" fn(*mut libc::c_void) -> *const libc::c_char;
type FnScanFile = extern "C" fn(*mut libc::c_void, *const libc::c_char, *mut SamulibreCScanResult) -> i32;
type FnScanBuffer = extern "C" fn(*mut libc::c_void, *const u8, libc::size_t, *const libc::c_char, *mut SamulibreCScanResult) -> i32;
type FnRequestCancel = extern "C" fn(*mut libc::c_void);
type FnResetCancel = extern "C" fn(*mut libc::c_void);
type FnGetTelemetry = extern "C" fn(*mut libc::c_void, *mut SamulibreCTelemetry) -> i32;

pub struct GPUEngineScanner {
    lib_handle: *mut libc::c_void,
    ctx: *mut libc::c_void,
    fn_destroy: FnDestroy,
    fn_is_accelerated: FnIsAccelerated,
    fn_get_backend_name: FnGetBackendName,
    fn_scan_file: FnScanFile,
    fn_scan_buffer: FnScanBuffer,
    fn_request_cancel: FnRequestCancel,
    fn_reset_cancel: FnResetCancel,
    fn_get_telemetry: FnGetTelemetry,
    lock: Mutex<()>,
}

unsafe impl Send for GPUEngineScanner {}
unsafe impl Sync for GPUEngineScanner {}

impl GPUEngineScanner {
    /// Intenta inicializar el motor de aceleración GPU buscando `libsamulibre_gpu.so`
    /// en rutas locales de compilación y librerías del sistema.
    pub fn try_init(profile_mode: i32) -> Option<Self> {
        let mut candidate_paths = vec![
            PathBuf::from("../../gpu-engine/lib/libsamulibre_gpu.so"),
            PathBuf::from("gpu-engine/lib/libsamulibre_gpu.so"),
            PathBuf::from("../gpu-engine/lib/libsamulibre_gpu.so"),
            PathBuf::from("./libsamulibre_gpu.so"),
            PathBuf::from("/usr/local/lib/libsamulibre_gpu.so"),
            PathBuf::from("/usr/lib/libsamulibre_gpu.so"),
        ];

        if let Ok(manifest_dir) = std::env::var("CARGO_MANIFEST_DIR") {
            candidate_paths.insert(0, PathBuf::from(manifest_dir).join("../../gpu-engine/lib/libsamulibre_gpu.so"));
        }
        if let Ok(custom_lib) = std::env::var("SAMULIBRE_GPU_LIB") {
            candidate_paths.insert(0, PathBuf::from(custom_lib));
        }

        let mut lib_handle: *mut libc::c_void = std::ptr::null_mut();

        for candidate in &candidate_paths {
            if candidate.exists() {
                if let Ok(c_path) = CString::new(candidate.to_string_lossy().as_bytes()) {
                    lib_handle = unsafe { libc::dlopen(c_path.as_ptr(), libc::RTLD_NOW) };
                    if !lib_handle.is_null() {
                        tracing::info!("✓ Motor de aceleración GPU cargado desde: {:?}", candidate);
                        break;
                    } else {
                        let err_ptr = unsafe { libc::dlerror() };
                        if !err_ptr.is_null() {
                            let err_str = unsafe { CStr::from_ptr(err_ptr).to_string_lossy() };
                            eprintln!("[GPUEngineScanner] dlopen falló en {:?}: {}", candidate, err_str);
                        }
                    }
                }
            }
        }

        if lib_handle.is_null() {
            // Intentar cargar por nombre de biblioteca dinámica en LD_LIBRARY_PATH
            if let Ok(c_name) = CString::new("libsamulibre_gpu.so") {
                lib_handle = unsafe { libc::dlopen(c_name.as_ptr(), libc::RTLD_NOW) };
            }
        }

        if lib_handle.is_null() {
            return None;
        }

        unsafe {
            macro_rules! load_sym {
                ($sym:expr, $type:ty) => {{
                    let c_sym = CString::new($sym).ok()?;
                    let ptr = libc::dlsym(lib_handle, c_sym.as_ptr());
                    if ptr.is_null() {
                        libc::dlclose(lib_handle);
                        return None;
                    }
                    std::mem::transmute::<*mut libc::c_void, $type>(ptr)
                }};
            }

            let fn_create: FnCreate = load_sym!("samulibre_gpu_create", FnCreate);
            let fn_destroy: FnDestroy = load_sym!("samulibre_gpu_destroy", FnDestroy);
            let fn_is_accelerated: FnIsAccelerated = load_sym!("samulibre_gpu_is_accelerated", FnIsAccelerated);
            let fn_get_backend_name: FnGetBackendName = load_sym!("samulibre_gpu_get_backend_name", FnGetBackendName);
            let fn_scan_file: FnScanFile = load_sym!("samulibre_gpu_scan_file", FnScanFile);
            let fn_scan_buffer: FnScanBuffer = load_sym!("samulibre_gpu_scan_buffer", FnScanBuffer);
            let fn_request_cancel: FnRequestCancel = load_sym!("samulibre_gpu_request_cancel", FnRequestCancel);
            let fn_reset_cancel: FnResetCancel = load_sym!("samulibre_gpu_reset_cancel", FnResetCancel);
            let fn_get_telemetry: FnGetTelemetry = load_sym!("samulibre_gpu_get_telemetry", FnGetTelemetry);

            let ctx = fn_create(profile_mode);
            if ctx.is_null() {
                libc::dlclose(lib_handle);
                return None;
            }

            Some(Self {
                lib_handle,
                ctx,
                fn_destroy,
                fn_is_accelerated,
                fn_get_backend_name,
                fn_scan_file,
                fn_scan_buffer,
                fn_request_cancel,
                fn_reset_cancel,
                fn_get_telemetry,
                lock: Mutex::new(()),
            })
        }
    }

    pub fn is_accelerated(&self) -> bool {
        let _guard = self.lock.lock().unwrap();
        (self.fn_is_accelerated)(self.ctx) != 0
    }

    pub fn get_backend_name(&self) -> String {
        let _guard = self.lock.lock().unwrap();
        let ptr = (self.fn_get_backend_name)(self.ctx);
        if ptr.is_null() {
            return "UNKNOWN".to_string();
        }
        unsafe { CStr::from_ptr(ptr).to_string_lossy().into_owned() }
    }

    pub fn scan_file(&self, path: impl AsRef<Path>) -> Option<ScanResult> {
        let path_ref = path.as_ref();
        let c_path = CString::new(path_ref.to_string_lossy().as_bytes()).ok()?;
        let mut c_res = SamulibreCScanResult::default();

        let ok = {
            let _guard = self.lock.lock().unwrap();
            (self.fn_scan_file)(self.ctx, c_path.as_ptr(), &mut c_res)
        };

        if ok != 1 {
            return None;
        }

        self.convert_to_scan_result(path_ref.to_string_lossy().to_string(), &c_res)
    }

    pub fn scan_buffer(&self, data: &[u8], virtual_name: &str) -> Option<ScanResult> {
        let c_name = CString::new(virtual_name.as_bytes()).ok()?;
        let mut c_res = SamulibreCScanResult::default();

        let ok = {
            let _guard = self.lock.lock().unwrap();
            (self.fn_scan_buffer)(self.ctx, data.as_ptr(), data.len(), c_name.as_ptr(), &mut c_res)
        };

        if ok != 1 {
            return None;
        }

        self.convert_to_scan_result(virtual_name.to_string(), &c_res)
    }

    pub fn request_cancel(&self) {
        let _guard = self.lock.lock().unwrap();
        (self.fn_request_cancel)(self.ctx);
    }

    pub fn reset_cancel(&self) {
        let _guard = self.lock.lock().unwrap();
        (self.fn_reset_cancel)(self.ctx);
    }

    pub fn get_telemetry(&self) -> Option<GpuTelemetry> {
        let mut raw = SamulibreCTelemetry::default();
        let ok = {
            let _guard = self.lock.lock().unwrap();
            (self.fn_get_telemetry)(self.ctx, &mut raw)
        };

        if ok != 1 {
            return None;
        }

        let source = unsafe { CStr::from_ptr(raw.telemetry_source.as_ptr()).to_string_lossy().into_owned() };

        Some(GpuTelemetry {
            gpu_temperature_c: raw.gpu_temperature_c,
            gpu_power_watts: raw.gpu_power_watts,
            vram_used_mb: raw.vram_used_mb,
            vram_total_mb: raw.vram_total_mb,
            ram_used_mb: raw.ram_used_mb,
            system_load_1min: raw.system_load_1min,
            is_throttled: raw.is_throttled != 0,
            is_gpu_accelerated: raw.is_gpu_accelerated != 0,
            telemetry_source: source,
        })
    }

    fn convert_to_scan_result(&self, path_str: String, c_res: &SamulibreCScanResult) -> Option<ScanResult> {
        let detection_name_str = unsafe {
            CStr::from_ptr(c_res.detection_name.as_ptr()).to_string_lossy().into_owned()
        };
        let engine_str = unsafe {
            CStr::from_ptr(c_res.engine_name.as_ptr()).to_string_lossy().into_owned()
        };

        let status = match c_res.status {
            1 => FileScanStatus::Infected,
            2 => FileScanStatus::Suspicious,
            _ => FileScanStatus::Clean,
        };

        let detection = if status != FileScanStatus::Clean && !detection_name_str.is_empty() && detection_name_str != "None" {
            Some(detection_name_str)
        } else {
            None
        };

        Some(ScanResult {
            file_path: path_str,
            sha256: String::new(), // Calculated on demand if infected
            status,
            detection_name: detection,
            engine: format!("SamuLibre GPU Engine ({})", engine_str),
            scan_time_ms: c_res.scan_time_ms,
        })
    }
}

impl Drop for GPUEngineScanner {
    fn drop(&mut self) {
        if !self.ctx.is_null() {
            (self.fn_destroy)(self.ctx);
            self.ctx = std::ptr::null_mut();
        }
        if !self.lib_handle.is_null() {
            unsafe { libc::dlclose(self.lib_handle) };
            self.lib_handle = std::ptr::null_mut();
        }
    }
}
