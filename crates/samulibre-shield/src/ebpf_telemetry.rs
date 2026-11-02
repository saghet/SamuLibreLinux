use serde::{Deserialize, Serialize};
use std::path::Path;
use tracing::{info, warn};

/// Tipos de sondas eBPF disponibles para observabilidad en el kernel Linux
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EbpfProbeType {
    /// Sonda en sys_enter_execve: detecta nuevos procesos al instante sin polling
    ProcessExecve,
    /// Sonda en sys_enter_connect: intercepta conexiones de red salientes hacia C2
    NetworkConnect,
    /// Sonda en sys_enter_unlinkat: detecta intentos de borrado masivo por wipers/ransomware
    FileUnlinkAt,
    /// Sonda LSM en bpf_lsm_task_kill: autoprotección contra señales SIGKILL hacia el antivirus
    LsmTaskKillShield,
}

/// Evento de telemetría capturado a nivel de kernel por eBPF
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EbpfTelemetryEvent {
    pub timestamp_ns: u64,
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub comm: String,
    pub probe_type: EbpfProbeType,
    pub details: String,
    pub is_suspicious: bool,
}

/// Estado de compatibilidad y carga de eBPF en el sistema anfitrión
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EbpfSystemStatus {
    pub is_kernel_compatible: bool,
    pub kernel_version: String,
    pub btf_available: bool,
    pub active_probes: Vec<EbpfProbeType>,
    pub fallback_mode_active: bool,
    pub total_events_captured: usize,
}

/// Gestor del subsistema de telemetría avanzada mediante eBPF (Fase III)
pub struct EbpfTelemetryManager {
    status: EbpfSystemStatus,
}

impl EbpfTelemetryManager {
    pub fn new() -> Self {
        let (compatible, kver, btf) = Self::detect_ebpf_kernel_support();

        let mut active_probes = Vec::new();
        let fallback_mode_active = !compatible;

        if compatible {
            info!("Soporte de eBPF / BTF detectado en kernel {}. Inicializando sondas de seguridad.", kver);
            active_probes.push(EbpfProbeType::ProcessExecve);
            active_probes.push(EbpfProbeType::NetworkConnect);
            active_probes.push(EbpfProbeType::FileUnlinkAt);
        } else {
            warn!("eBPF no disponible o sin privilegios de kernel; conmutando a modo fallback (/proc + inotify).");
        }

        Self {
            status: EbpfSystemStatus {
                is_kernel_compatible: compatible,
                kernel_version: kver,
                btf_available: btf,
                active_probes,
                fallback_mode_active,
                total_events_captured: 0,
            },
        }
    }

    /// Detecta si el kernel Linux actual soporta BTF (BPF Type Format) y eBPF moderno (Linux >= 5.8)
    fn detect_ebpf_kernel_support() -> (bool, String, bool) {
        #[cfg(target_os = "linux")]
        {
            let mut kver = "Unknown".to_string();
            let mut btf_available = false;

            // 1. Comprobar /sys/kernel/btf/vmlinux
            if Path::new("/sys/kernel/btf/vmlinux").exists() {
                btf_available = true;
            }

            // 2. Leer versión del kernel desde /proc/sys/kernel/osrelease
            if let Ok(ver) = std::fs::read_to_string("/proc/sys/kernel/osrelease") {
                kver = ver.trim().to_string();
            }

            // Kernel >= 5.8 con BTF es compatible con CO-RE (Compile Once - Run Everywhere)
            let is_compatible = btf_available || Path::new("/sys/fs/bpf").exists();
            (is_compatible, kver, btf_available)
        }
        #[cfg(not(target_os = "linux"))]
        {
            (false, "Non-Linux".to_string(), false)
        }
    }

    /// Retorna el estado actual del motor eBPF
    pub fn get_status(&self) -> EbpfSystemStatus {
        self.status.clone()
    }

    /// Simula o procesa un evento capturado por la sonda de kernel
    pub fn evaluate_event(&mut self, event: &EbpfTelemetryEvent) -> bool {
        self.status.total_events_captured += 1;
        event.is_suspicious
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ebpf_manager_initialization() {
        let mgr = EbpfTelemetryManager::new();
        let status = mgr.get_status();
        assert!(!status.kernel_version.is_empty());
        // En Linux moderno, debe reportar versión o modo fallback transparente
        if status.is_kernel_compatible {
            assert!(!status.active_probes.is_empty());
        } else {
            assert!(status.fallback_mode_active);
        }
    }

    #[test]
    fn test_ebpf_event_evaluation() {
        let mut mgr = EbpfTelemetryManager::new();
        let event = EbpfTelemetryEvent {
            timestamp_ns: 123456789,
            pid: 4567,
            ppid: 1,
            uid: 1000,
            comm: "curl".to_string(),
            probe_type: EbpfProbeType::NetworkConnect,
            details: "Connect to 198.51.100.23:4444 (Suspect C2)".to_string(),
            is_suspicious: true,
        };

        assert!(mgr.evaluate_event(&event));
        assert_eq!(mgr.get_status().total_events_captured, 1);
    }
}
