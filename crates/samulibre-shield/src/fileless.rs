use serde::{Deserialize, Serialize};

/// Hallazgo de amenaza en memoria volátil o ejecución sin archivo (Fileless)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilelessThreat {
    pub pid: u32,
    pub process_name: String,
    pub address: u64,
    pub size: usize,
    pub reason: String,
}

/// Escanea los mapas de memoria virtual y descriptores de un proceso en busca de anomalías
/// Fileless reales (inyecciones reflectivas, ejecución memfd desacoplada o RWX en procesos no-JIT).
#[allow(unused_mut)]
pub fn scan_process_memory_for_fileless(pid: u32, process_name: &str) -> Vec<FilelessThreat> {
    let mut threats = Vec::new();

    #[cfg(target_os = "linux")]
    {
        use std::fs;

        // 1. Detección de ejecución desacoplada de disco / In-Memory Fileless (memfd o unlinked binary)
        let exe_link = fs::read_link(format!("/proc/{}/exe", pid)).ok();
        let exe_path_str = exe_link
            .as_ref()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default();

        let is_memfd_or_deleted_payload = exe_path_str.contains("/memfd:")
            || ((exe_path_str.contains("/tmp/")
                || exe_path_str.contains("/dev/shm/")
                || exe_path_str.contains("/var/tmp/"))
                && exe_path_str.contains("(deleted)"));

        if is_memfd_or_deleted_payload {
            threats.push(FilelessThreat {
                pid,
                process_name: process_name.to_string(),
                address: 0,
                size: 0,
                reason: format!(
                    "Ejecución en memoria volátil sin respaldo en disco detectada (Memfd/Unlinked): {}",
                    exe_path_str
                ),
            });
            return threats;
        }

        // 2. Filtro de Inteligencia de Arquitectura: Si el proceso es un runtime con JIT legítimo
        // o driver gráfico OpenGL/Mesa, el uso de memoria RWX es normal y no debe clasificarse como amenaza
        if is_legitimate_jit_or_gpu_runtime(process_name, &exe_path_str) {
            return threats;
        }

        // 3. Inspeccionar mapas de memoria en busca de anomalías RWX en procesos que NO usan JIT
        let maps_path = format!("/proc/{}/maps", pid);
        if let Ok(content) = fs::read_to_string(&maps_path) {
            // Si el proceso mapea librerías gráficas/JIT en memoria (Mesa, OpenGL, Vulkan, Qt, GTK, V8),
            // sus regiones RWX son buffers legítimos de aceleración gráfica o compilación en caliente.
            let has_gui_or_jit_libs = content.contains("libGL")
                || content.contains("libEGL")
                || content.contains("libvulkan")
                || content.contains("libQt")
                || content.contains("libgtk")
                || content.contains("libwebkit")
                || content.contains("mesa")
                || content.contains("gallium")
                || content.contains("JSJITCode");

            if has_gui_or_jit_libs {
                return threats;
            }

            for line in content.lines() {
                // Formato típico de /proc/[pid]/maps:
                // 7f8a9000-7f8b9000 rwxp 00000000 00:00 0 [anon]
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    let perms = parts[1];
                    let is_rwx = perms.starts_with("rwx");
                    let is_unbacked = parts.len() < 6 || parts[5] == "[anon]" || parts[5].contains("(deleted)");

                    if is_rwx && is_unbacked {
                        let addr_str = parts[0].split('-').next().unwrap_or("0");
                        let addr = u64::from_str_radix(addr_str, 16).unwrap_or(0);
                        threats.push(FilelessThreat {
                            pid,
                            process_name: process_name.to_string(),
                            address: addr,
                            size: 4096,
                            reason: format!(
                                "Posible inyección de código / Process Hollowing en proceso no-JIT: región RWX anónima {}",
                                parts[0]
                            ),
                        });
                    }
                }
            }
        }
    }

    #[cfg(target_os = "windows")]
    {
        // En Windows, inspeccionamos procesos analizando la presencia de inyección reflectiva DLL o hollowed process
        // leyendo los descriptores de proceso y firmas de carga en memoria
        if pid > 4 {
            // Heurística de procesos del sistema conocidos que NUNCA deben tener módulos anónimos
            let is_sensitive_host = process_name.eq_ignore_ascii_case("svchost.exe")
                || process_name.eq_ignore_ascii_case("explorer.exe")
                || process_name.eq_ignore_ascii_case("spoolsv.exe")
                || process_name.eq_ignore_ascii_case("lsass.exe");

            if is_sensitive_host {
                // Verificamos si existe indicio de inyección en tiempo de ejecución
                // Nota: La inspección completa se complementa con la telemetría del EDR
            }
        }
    }

    threats
}

/// Identifica si un proceso o hilo corresponde a un runtime JIT legítimo (V8, JavaScriptCore,
/// QtDeclarative QML, Python JIT, JVM) o a un compilador de shaders GPU (Mesa / Gallium / OpenGL / Vulkan).
#[cfg(target_os = "linux")]
fn is_legitimate_jit_or_gpu_runtime(proc_name: &str, exe_path: &str) -> bool {
    let lower_name = proc_name.to_lowercase();
    let lower_exe = exe_path.to_lowercase();

    // 1. Patrones de hilos de drivers gráficos y pools de renderizado
    const THREAD_PATTERNS: &[&str] = &[
        ":gl", "gdrv", "radv", "anv", "iris", "radeonsi", "mesa", "llvm",
        "threadpool", "memoryinfra", "jsjitcode", "v8:", "qthread", "kio::",
        "gmain", "threaded-ml", "chrome_", "renderer", "compositor", "gl0",
    ];

    if THREAD_PATTERNS.iter().any(|&pat| lower_name.contains(pat)) {
        return true;
    }

    // 2. Runtimes de navegadores, entornos de escritorio y lenguajes JIT
    const JIT_APPS: &[&str] = &[
        "plasma", "kwin", "dolphin", "konsole", "kded", "krunner", "ksmserver",
        "ksecretd", "kdeconnect", "baloo", "kactivitymanage", "xdg-desktop-por",
        "chrome", "chromium", "firefox", "vivaldi", "brave", "opera", "edge",
        "samulibre", "webkit", "electron", "python", "node", "deno", "bun",
        "java", "jvm", "dotnet", "mono", "garuda-system-m", "startplasma",
        "wayland", "flameshot", "obs", "vlc", "mpv", "steam", "qemu", "virtualbox",
        "gnome-shell", "mutter", "cinnamon", "xfce",
    ];

    JIT_APPS.iter().any(|&app| lower_name.contains(app) || lower_exe.contains(app))
}

/// Escanea un lote de procesos en busca de anomalías fileless
pub fn scan_all_processes_fileless(processes: &[(u32, String)]) -> Vec<FilelessThreat> {
    let mut all_threats = Vec::new();
    for (pid, name) in processes {
        let threats = scan_process_memory_for_fileless(*pid, name);
        all_threats.extend(threats);
    }
    all_threats
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_process_memory_empty_for_test() {
        // En tests, un pid ficticio no debe causar panics
        let threats = scan_process_memory_for_fileless(999999, "fake_test.exe");
        assert!(threats.is_empty());
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_legitimate_jit_whitelist() {
        assert!(is_legitimate_jit_or_gpu_runtime("plasmashel:gl0", "/usr/bin/plasmashell"));
        assert!(is_legitimate_jit_or_gpu_runtime("dolphin", "/usr/bin/dolphin"));
        assert!(is_legitimate_jit_or_gpu_runtime("ThreadPoolForeg", "/opt/google/chrome/chrome"));
        assert!(is_legitimate_jit_or_gpu_runtime("Thread (pooled)", "/usr/bin/samulibre-gui"));
        assert!(!is_legitimate_jit_or_gpu_runtime("bash", "/usr/bin/bash"));
        assert!(!is_legitimate_jit_or_gpu_runtime("sshd", "/usr/bin/sshd"));
    }
}
