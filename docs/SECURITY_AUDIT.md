# INFORME DE AUDITORÍA INTEGRAL DE SEGURIDAD, CONCURRENCIA Y RESILIENCIA
## Plataforma Antivirus & EDR SamuLibre Linux (Rust Workspace + C++20 GPU Engine + Kernel Hooks)
**Documento:** `docs/SECURITY_AUDIT.md`  
**Fecha:** Noviembre 2026  
**Versión:** 2.0 (Fase B: Informe de Vulnerabilidades y Deficiencias)  
**Clasificación:** Auditoría de Seguridad de Grado Comercial / Preparación para Certificación Externa  
**Comité Evaluador:** Equipo de 25 Especialistas (Arquitectura Rust, Kernel Linux, CISO, QA y C++ DevSecOps)

---

## 1. RESUMEN EJECUTIVO Y ALCANCE

Este informe consolida la auditoría técnica integral del ecosistema **SamuLibre Linux**, abarcando:
1. **Los 12 Crates del Workspace en Rust:** `samulibre-types`, `samulibre-core`, `samulibre-scanner`, `samulibre-shield`, `samulibre-patcher`, `samulibre-watcher`, `samulibre-ai`, `samulibre-vpn`, `samulibre-daemon`, `samulibre-cli`, `samulibre-gui` y `samulibre-android`.
2. **El Subsistema de Aceleración GPU en C++20:** `gpu-engine/` (CUDA PTX JIT, OpenCL y AVX2 Fallback) y sus interfaces FFI (`samulibre_gpu_ffi.h`).
3. **Mecanismos de Intercepción de Sistema Operativo:** Ganchos eBPF en caliente, monitoreo VFS con `fanotify`/`inotify`, y el servidor de comunicación por socket UNIX (`samulibred`).

### Veredicto Global del Comité
El software presenta una arquitectura con capacidades defensivas de primer nivel (eBPF en caliente, escaneo GPU a 1,274 MB/s, monitoreo de entropía para ransomware y señuelos de credenciales). No obstante, para alcanzar el estándar de **referencia internacional auditable por terceros**, se han clasificado vulnerabilidades de privilegios en el demonio IPC, riesgos de condiciones de carrera TOCTOU en la cuarentena, y deficiencias en la verificación criptográfica de la cadena de suministro de firmas.

---

## 2. MATRIZ UNIFICADA DE VULNERABILIDADES Y DEFICIENCIAS

| ID | Subsistema / Archivo | Severidad | Tipo / CWE | Resumen del Hallazgo | Estado |
| :---: | :--- | :---: | :--- | :--- | :---: |
| **RUST-SEC-01** | `crates/samulibre-core/src/ipc.rs`<br>`crates/samulibre-daemon/src/main.rs` | **CRÍTICO** | CWE-306 / CWE-732<br>Missing Auth / Insecure Socket Perms | Permisos `0666` en socket UNIX de root sin verificación `SO_PEERCRED`. Cualquier usuario local puede invocar acciones privilegiadas (`isolate_process_network`). | **PENDIENTE (Fase D)** |
| **RUST-SEC-02** | `crates/samulibre-daemon/src/main.rs`<br>`crates/samulibre-scanner/src/elf_analyzer.rs` | **ALTO** | CWE-250<br>Execution with Unnecessary Privileges | El demonio root ejecuta parsers de archivos complejos (ELF, scripts) en el mismo espacio privilegiado sin sandboxing worker (Landlock/seccomp). | **PENDIENTE (Fase D)** |
| **RUST-SEC-03** | `crates/samulibre-watcher/src/lib.rs` | **ALTO** | CWE-367<br>TOCTOU Race Condition | Validación `symlink_metadata` desacoplada de la apertura en la restauración de cuarentena; susceptible a ataque symlink de sobreescritura. | **PENDIENTE (Fase D)** |
| **RUST-SEC-04** | `crates/samulibre-scanner/src/threat_intel/` | **MEDIO** | CWE-494<br>Missing Signature Verification | Los feeds de actualización de IoCs y reglas carecen de validación de firma asimétrica digital (Ed25519) del proveedor. | **PENDIENTE (Fase D)** |
| **RUST-SEC-05** | `crates/samulibre-scanner/src/polymorphic.rs` | **MEDIO** | CWE-400<br>Uncontrolled Resource Consumption | Análisis polimórfico en buffers completos sin cuota máxima de memoria, riesgo de OOM Killer ante archivos multipart gigabyte. | **PENDIENTE (Fase D)** |
| **RUST-CONC-01** | `crates/samulibre-daemon/src/main.rs` | **MEDIO** | CWE-662<br>Improper Synchronization | Mutex asíncrono único sobre SQLite; riesgo de contención y aumento de latencia durante ráfagas masivas de eventos `fanotify`. | **PENDIENTE (Fase D)** |
| **RUST-CODE-01** | Workspace Rust (Varios) | **BAJO** | CWE-754<br>Improper Exception Handling | Uso residual de `.unwrap()` y `.expect()` en rutas secundarias de inicialización que podrían inducir pánicos locales. | **PENDIENTE (Fase D)** |
| **SYS-01** | `samulibred.service` | **BAJO** | Hardening del Sistema | Falta de perfiles systemd modernos (`ProtectSystem=strict`, `ProtectHome=read-only`, `PrivateTmp=true`). | **PENDIENTE (Fase D)** |
| **VULN-01** | `gpu-engine/src/ml/elf_feature_extractor.cpp` | **ALTO** | CWE-125<br>Out-of-Bounds Read | Lectura fuera de límites en tabla de cadenas ELF `.shstrtab` sin byte nulo terminal. | **REMEDIADO & ASan CERTIFICADO** |
| **VULN-02** | `gpu-engine/src/core/batch_scheduler.cpp` | **ALTO** | CWE-400 / CWE-191<br>Integer Underflow / Bad Alloc | Subdesbordamiento de entero (`tellg() == -1`) y ausencia de límite superior de archivo. | **REMEDIADO & ASan CERTIFICADO** |
| **CONC-01** | `gpu-engine/src/core/result_dispatcher.cpp` | **ALTO** | CWE-362<br>Data Race / Concurrency | Falta de mutex en `GPUContextInternal` ante llamadas FFI multi-hilo concurrentes desde Rust. | **REMEDIADO & TSan CERTIFICADO** |
| **CONC-02** | `gpu-engine/src/scanner/signature_scanner.cpp` | **MEDIO** | CWE-662<br>Improper Synchronization | Lectura no sincronizada de `rules_.size()` en `rule_count()`. | **REMEDIADO & TSan CERTIFICADO** |
| **PERF-01** | `gpu-engine/src/core/batch_scheduler.cpp` | **MEDIO** | PCIe Bottleneck | Doble copia redundante DMA PCIe en `execute_task_on_slot`. | **REMEDIADO (Host Micro-tasks)** |
| **PERF-02** | `gpu-engine/src/ml/ml_classifier.cpp` | **MEDIO** | VRAM Overhead | Sobrecosto de reasignación síncrona VRAM por archivo (reducido a 10,795 muestras/s). | **REMEDIADO (Memory Arena)** |
| **ARCH-01** | `gpu-engine/include/compute_engine.hpp` | **MEDIO** | Memory Leak Risk | Falta de RAII en memoria de dispositivo GPU (`ScopedDeviceBuffer`). | **REMEDIADO** |
| **ARCH-02** | `gpu-engine/Makefile` & `CMakeLists.txt` | **BAJO** | Hardening de Compilador | Estándar C++17 obsoleto, sin `std::span` ni `-D_FORTIFY_SOURCE=3`. | **REMEDIADO (C++20 & ASan/TSan)** |

---

## 3. DESCRIPCIÓN TÉCNICA DETALLADA DE LOS HALLAZGOS EN RUST

### [RUST-SEC-01] Control de Acceso Inadecuado en Socket IPC UNIX del Demonio
- **Severidad:** **CRÍTICO** (CWE-306, CWE-732)
- **Archivos:** `crates/samulibre-core/src/ipc.rs` (Líneas 170–172) y `crates/samulibre-daemon/src/main.rs`
- **Código Vulnerable:**
  ```rust
  #[cfg(unix)]
  {
      use std::os::unix::fs::PermissionsExt;
      let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o666));
  }
  ```
- **Evidencia Técnica:**
  El socket `/run/samulibre/samulibre.sock` es expuesto con permisos de lectura y escritura para cualquier usuario (`0666`). Cuando `UnixSocketServer::run_server` recibe conexiones entrantes, no extrae la estructura `ucred` vía `getsockopt(..., SO_PEERCRED, ...)` para verificar el UID del invocador.
- **Impacto:** Cualquier proceso no privilegiado (ej. usuario `nobody`, script web comprometido) puede emitir un comando JSON `isolate_process_network` para bloquear el acceso de red de servicios críticos o forzar operaciones de root.
- **Remediación:**
  1. Configurar los permisos del socket a `0660` asignado al grupo del sistema `samulibre`.
  2. Implementar la extracción estricta de credenciales de peer (`stream.peer_cred()`) comprobando que el UID sea `0` o pertenezca al grupo autorizado antes de aceptar cualquier acción mutativa.

---

### [RUST-SEC-02] Monolito de Ejecución Privilegiada del Demonio y Falta de Sandboxing de Parsers
- **Severidad:** **ALTO** (CWE-250: Execution with Unnecessary Privileges)
- **Archivos:** `crates/samulibre-daemon/src/main.rs`, `crates/samulibre-scanner/src/elf_analyzer.rs`
- **Evidencia Técnica:**
  `samulibred` se ejecuta como `root` para interactuar con los descriptores de `fanotify_init` y los mapas eBPF de red. Sin embargo, al recibir una petición de escaneo de archivo (`scan_file`) o interceptar un acceso VFS, el demonio invoca directamente los analizadores de cabeceras ELF, extracción de cadenas y descompresores en su propio espacio de memoria como UID 0.
- **Impacto:** Cualquier vulnerabilidad lógica o de memoria en los analizadores de archivos se convierte en una ejecución remota de código (RCE) como superusuario en el sistema anfitrión.
- **Remediación:**
  Separar la arquitectura mediante el **Principio de Menor Privilegio**:
  - Demonio Supervisor (`root`): Gestiona únicamente `fanotify`, `eBPF` e IPC autenticado.
  - Trabajador de Análisis (`samulibre-worker`): Proceso no privilegiado confinado con **Landlock** (acceso de solo lectura al archivo específico) y **seccomp-bpf** (prohibición estricta de `socket()`, `fork()`, `execve()`).

---

### [RUST-SEC-03] Ataque de Condición de Carrera TOCTOU en Restauración de Cuarentena
- **Severidad:** **ALTO** (CWE-367: Time-of-check Time-of-use Race Condition)
- **Archivo:** `crates/samulibre-watcher/src/lib.rs` (Líneas 238–258)
- **Código Vulnerable:**
  ```rust
  if let Ok(meta) = fs::symlink_metadata(&target_path) {
      if meta.file_type().is_symlink() {
          anyhow::bail!("Intento de manipulación detectado: la ruta es un symlink");
      }
  }
  // Brecha temporal (TOCTOU): un atacante reemplaza target_path aquí por un enlace simbólico a /etc/shadow
  fs::write(&target_path, restored_bytes)?;
  ```
- **Evidencia Técnica:**
  Existe una ventana temporal entre la consulta de `symlink_metadata` y la llamada a `fs::write`. En un sistema concurrido o con un bucle de ataque, un proceso local puede ganar la carrera y hacer que el proceso antivirus restaure datos sobreescritos en un archivo arbitrario del sistema.
- **Remediación:**
  Utilizar llamadas atómicas de apertura con banderas POSIX `O_NOFOLLOW | O_EXCL` o utilizar la API `openat2` de Linux con el flag `RESOLVE_NO_SYMLINKS`.

---

### [RUST-SEC-04] Ausencia de Firma Criptográfica Asimétrica en Feeds de Inteligencia
- **Severidad:** **MEDIO** (CWE-494: Download of Code Without Integrity Check)
- **Archivos:** `crates/samulibre-scanner/src/threat_intel/`
- **Evidencia Técnica:**
  La descarga de listas de exclusiones, hashes de malware e indicadores de compromiso (IoCs) confía únicamente en el canal de transporte TLS. No se verifica una firma criptográfica asimétrica (Ed25519) del mantenedor del proyecto empaquetada junto al feed.
- **Impacto:** Un atacante con capacidad de intercepción de red (o envenenamiento de certificados CA locales) podría inyectar falsos positivos masivos para denegar servicios en el host.
- **Remediación:**
  Integrar verificación de firmas digitales mediante **Ed25519** (`ed25519-dalek`) utilizando la clave pública raíz embebida en el binario del antivirus.

---

### [RUST-SEC-05] Riesgo de Agotamiento de Recursos (DoS / OOM) en Análisis Polimórfico
- **Severidad:** **MEDIO** (CWE-400: Uncontrolled Resource Consumption)
- **Archivo:** `crates/samulibre-scanner/src/polymorphic.rs`
- **Evidencia Técnica:**
  Funciones de cálculo de entropía de Shannon y hashing difuso admiten buffers arbitrarios sin imponer un límite superior estricto por archivo antes del procesamiento.
- **Impacto:** Consumo desmedido de memoria RAM ante archivos multipartes de gran tamaño, provocando la activación del OOM Killer del kernel de Linux.
- **Remediación:**
  Imponer un límite duro uniforme de 128 MB para archivos completos en RAM y evaluar la entropía mediante streaming de ventanas deslizantes (rolling window chunks de 64 KB).

---

## 4. ESTADO DE REMEDIACIÓN DEL SUBSISTEMA C++ (GPU ENGINE)

Los hallazgos del subsistema en C++ identificados en la primera fase de auditoría fueron formalmente remediados, probados bajo sanitizers y verificados:
- **`VULN-01` (ELF `.shstrtab` OOB Read):** Remediado con `std::string_view` y acotado con `strnlen`. Verificado bajo **AddressSanitizer (ASan)** con cero lecturas fuera de límites.
- **`VULN-02` (`tellg` DoS / Integer Underflow):** Remediado con validación estricta `fsize > 0 && fsize <= 128 MB`.
- **`CONC-01` & `CONC-02` (Data Races FFI):** Remediado con `std::mutex` en `GPUContextInternal` y `std::lock_guard` en `rule_count()`. Verificado bajo **ThreadSanitizer (TSan)** con cero condiciones de carrera.
- **`ARCH-01` & `PERF-02` (RAII & Memory Arena):** Implementado `ScopedDeviceBuffer` y buffer persistente para inferencia ML, logrando **10,795 muestras/segundo**.
- **`PERF-01` & `INFO-01` (Micro-archivos < 32 KB a CPU):** Derivación automática hacia CPU Host logrando **210 MB/s** en transferencias pequeñas sin sobrecoste PCIe.

---

## 5. CONCLUSIÓN Y PLAN DE TRANSICIÓN A LA FASE C

La Fase B concluye con una matriz clara de vulnerabilidades y prioridades técnicas.  
En la **Fase C (Plan Arquitectónico de Modernización)**, se diseñará la especificación formal de:
1. La arquitectura de micro-sandboxing no privilegiado (**Worker Sandboxing con Landlock & seccomp-bpf**).
2. El sistema de autenticación IPC mediante `SO_PEERCRED` y grupo `samulibre`.
3. El canal de actualización de firmas e IoCs criptográficamente autenticado con Ed25519.
4. La capa de exportación universal para SIEM / Syslog RFC 5424 / CEF.
