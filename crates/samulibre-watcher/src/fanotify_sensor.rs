use crate::event_queue::{EdrEventQueue, QueuePriority};
use crate::models::EdrEventType;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use tracing::{debug, info, warn};

pub struct FanotifySensorHandle {
    stop_signal: Arc<AtomicBool>,
    thread_handle: Option<JoinHandle<()>>,
}

impl Drop for FanotifySensorHandle {
    fn drop(&mut self) {
        self.stop_signal.store(true, Ordering::SeqCst);
        if let Some(handle) = self.thread_handle.take() {
            let _ = handle.join();
        }
    }
}

pub struct FanotifySensor;

impl FanotifySensor {
    /// Comprueba si el kernel actual y el usuario disponen de privilegios para iniciar fanotify
    pub fn is_supported() -> bool {
        #[cfg(target_os = "linux")]
        {
            unsafe {
                // FAN_CLASS_NOTIF (0x00000000) | FAN_CLOEXEC (0x00000001) | FAN_NONBLOCK (0x00000002)
                let fd = libc::syscall(libc::SYS_fanotify_init, 0x00000000u32 | 0x00000001u32 | 0x00000002u32, libc::O_RDONLY);
                if fd >= 0 {
                    libc::close(fd as i32);
                    true
                } else {
                    false
                }
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            false
        }
    }

    /// Inicia el sensor fanotify en un hilo en segundo plano si está disponible
    pub fn try_start(
        queue: Arc<EdrEventQueue>,
        mount_points: Vec<PathBuf>,
    ) -> Option<FanotifySensorHandle> {
        #[cfg(target_os = "linux")]
        {
            if !Self::is_supported() {
                info!("fanotify no disponible (se requieren privilegios root / CAP_SYS_ADMIN). Delegando a inotify recursivo.");
                return None;
            }

            let stop_signal = Arc::new(AtomicBool::new(false));
            let stop_clone = Arc::clone(&stop_signal);

            let thread_handle = std::thread::spawn(move || {
                unsafe {
                    // Inicializar fanotify con flags no bloqueantes
                    let fan_fd = libc::syscall(
                        libc::SYS_fanotify_init,
                        0x00000000u32 | 0x00000001u32 | 0x00000002u32, // NOTIF | CLOEXEC | NONBLOCK
                        libc::O_RDONLY | libc::O_LARGEFILE,
                    ) as i32;

                    if fan_fd < 0 {
                        warn!("Error al inicializar fanotify_init");
                        return;
                    }

                    // Marcar puntos de montaje con FAN_CLOSE_WRITE (0x00000008), FAN_OPEN_EXEC (0x00001000) o FAN_MODIFY (0x00000002)
                    let mask: u64 = 0x00000008 | 0x00001000 | 0x00000002;
                    let mark_flags = 0x00000001 | 0x00000010; // FAN_MARK_ADD | FAN_MARK_MOUNT

                    for mp in &mount_points {
                        if let Ok(c_path) = std::ffi::CString::new(mp.to_string_lossy().as_bytes()) {
                            let res = libc::syscall(
                                libc::SYS_fanotify_mark,
                                fan_fd,
                                mark_flags,
                                mask,
                                libc::AT_FDCWD,
                                c_path.as_ptr(),
                            );
                            if res == 0 {
                                info!("fanotify: punto de montaje marcado con éxito: {:?}", mp);
                            } else {
                                debug!("fanotify: aviso al marcar {:?}: errno {}", mp, *libc::__errno_location());
                            }
                        }
                    }

                    let mut buffer = [0u8; 8192];

                    while !stop_clone.load(Ordering::Relaxed) {
                        let len = libc::read(fan_fd, buffer.as_mut_ptr() as *mut libc::c_void, buffer.len());
                        if len > 0 {
                            let mut offset = 0;
                            while offset + 24 <= len as usize {
                                // Estructura fanotify_event_metadata
                                let event_len = u32::from_ne_bytes(buffer[offset..offset+4].try_into().unwrap()) as usize;
                                let event_mask = u64::from_ne_bytes(buffer[offset+8..offset+16].try_into().unwrap());
                                let fd = i32::from_ne_bytes(buffer[offset+16..offset+20].try_into().unwrap());
                                let pid = i32::from_ne_bytes(buffer[offset+20..offset+24].try_into().unwrap());

                                if fd >= 0 {
                                    // Resolver ruta desde /proc/self/fd/{fd}
                                    let proc_path = format!("/proc/self/fd/{}", fd);
                                    if let Ok(real_path) = fs::read_link(&proc_path) {
                                        let is_exec = (event_mask & 0x00001000) != 0;
                                        let priority = if is_exec {
                                            QueuePriority::Critical
                                        } else {
                                            QueuePriority::High
                                        };

                                        let ev_type = if is_exec {
                                            EdrEventType::FileOpenExec
                                        } else {
                                            EdrEventType::FileCloseWrite
                                        };

                                        queue.enqueue(
                                            priority,
                                            real_path,
                                            ev_type,
                                            if pid > 0 { Some(pid as u32) } else { None },
                                            None,
                                            None,
                                        );
                                    }
                                    libc::close(fd);
                                }

                                if event_len < 24 || offset + event_len > len as usize {
                                    break;
                                }
                                offset += event_len;
                            }
                        } else {
                            std::thread::sleep(std::time::Duration::from_millis(50));
                        }
                    }

                    libc::close(fan_fd);
                }
            });

            Some(FanotifySensorHandle {
                stop_signal,
                thread_handle: Some(thread_handle),
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (queue, mount_points);
            None
        }
    }
}
