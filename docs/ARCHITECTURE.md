# ESPECIFICACIÓN ARQUITECTÓNICA DE MODERNIZACIÓN Y DEFENSA MODULAR
## Antivirus & Endpoint Detection and Response (EDR) SamuLibre Linux
**Documento:** `docs/ARCHITECTURE.md`  
**Fecha:** Noviembre 2026  
**Versión:** 2.0 (Fase C: Plan Arquitectónico de Modernización)  
**Clasificación:** Arquitectura Abierta de Grado Comercial / Next-Generation Linux EDR  
**Comité Diseñador:** Equipo de 25 Especialistas (Chief Software Architect, Linux Kernel Engineers, Rust & C++ Leads, CISO)

---

## 1. PRINCIPIOS RECTORES DEL DISEÑO

La transformación arquitectónica de SamuLibre persigue cuatro objetivos primordiales:
1. **Principio de Menor Privilegio (Privilege Separation):** Ningún componente que procese archivos o datos suministrados por atacantes (parsers ELF, descompresores, expresiones regulares, inferencia de red) debe ejecutarse con privilegios de superusuario (`root`).
2. **Modelo Asimétrico Zero-Trust (Host/GPU):** La CPU retiene en todo momento la custodia de seguridad y la autoridad de decisiones; la GPU actúa como coprocesador acelerador matemático aislado sin capacidad de modificar el sistema de archivos ni alterar veredictos de cuarentena.
3. **Inmutabilidad y Grafos Acíclicos de Dependencias (DAG):** Estricta eliminación de referencias cruzadas entre módulos mediante abstracciones de tipos compartidos (`samulibre-types`) e inversión de dependencias con traits de Rust.
4. **Soberanía y Privacidad Operativa (Zero-Cloud Mandate):** Todo el procesamiento heurístico, reglas YARA-X, modelos de inferencia y almacenamiento SQLite WAL operan de forma local y auditable, sin telemetría forzada a servidores externos.

---

## 2. MAPA DE SUBSISTEMAS Y SEPARACIÓN DE PRIVILEGIOS

```mermaid
graph TD
    subgraph Ring0_Kernel ["Kernel de Linux (Ring 0)"]
        eBPF_Patcher["eBPF Virtual Patcher (TC / XDP)"]
        fanotify_VFS["fanotify VFS Interceptor (FAN_ACCESS_PERM)"]
    end

    subgraph Privileged_Daemon ["Demonio Supervisor Privilegiado (Root: samulibred)"]
        DaemonMain["Supervisor IPC & Lifecycle"]
        KernelBridge["Kernel Bridge (eBPF & fanotify Controller)"]
        QuarantineMgr["Quarantine Vault (HMAC & O_NOFOLLOW)"]
        NetfilterCtrl["Adaptive Firewall (nftables engine)"]
        AuthIPC["Authenticated IPC Server (SO_PEERCRED check)"]
    end

    subgraph Sandboxed_Worker ["Trabajador de Análisis Confinado (UID nobody / Landlock + seccomp)"]
        WorkerCoord["Worker Coordinator (IPC Pipe / SCM_RIGHTS)"]
        ELFParser["ELF Static Analyzer (Bounded Spans)"]
        ScriptEngine["Script & Heuristics Analyzer"]
        YARAEngine["YARA-X & Multi-Pattern Matcher"]
        MLModule["Static ML Feature Extractor"]
        PolyModule["Shannon Entropy & Polymorphic Engine"]
    end

    subgraph Acceleration_Tier ["Coprocesador de Aceleración (gpu-engine C++20)"]
        GPUScheduler["BatchScheduler (Triple Pinned Buffers)"]
        CUDA_JIT["CUDA PTX JIT Engine"]
        CPU_AVX2["AVX2 SIMD Fallback"]
        NVML_Mon["NVML Thermal Throttler"]
    end

    subgraph Clients_Tier ["Interfaces de Usuario y Administración"]
        CLI["samulibre-cli (Admin CLI)"]
        GUI["samulibre-gui (Iced Webview / Native UI)"]
        SIEM_Exp["SIEM Exporter (Syslog RFC 5424 / CEF)"]
    end

    fanotify_VFS -.->|Intercept Event| KernelBridge
    KernelBridge --> DaemonMain
    DaemonMain --> AuthIPC
    AuthIPC <==>|Unix Socket (PEERCRED)| CLI & GUI
    
    DaemonMain ==>|SCM_RIGHTS (File Descriptor)| WorkerCoord
    WorkerCoord --> ELFParser & ScriptEngine & YARAEngine & MLModule & PolyModule
    WorkerCoord <==>|C-ABI FFI (Zero-Trust)| GPUScheduler
    GPUScheduler --> CUDA_JIT & CPU_AVX2 & NVML_Mon
    
    WorkerCoord -.->|Verdict: Infection| DaemonMain
    DaemonMain --> QuarantineMgr & NetfilterCtrl
    DaemonMain --> SIEM_Exp
```

---

## 3. ESPECIFICACIÓN DE LOS 18 SUBSISTEMAS ARQUITECTÓNICOS

### 3.1. Core Engine (`samulibre-core`)
- **Propósito:** Núcleo de orquestación, configuración persistente, base de datos local y gestión del ciclo de vida de componentes.
- **Interfaces:** `SamuLibreCoreTrait`, `ConfigurationProvider`, `LifecycleManager`.
- **Privilegio:** No privilegiado por defecto; inicializado por el supervisor o clientes según el contexto.

### 3.2. Real-Time Protection (`samulibre-watcher`)
- **Propósito:** Intercepción proactiva de accesos y escrituras en el VFS antes de la ejecución de binarios.
- **Mecanismos:** `fanotify` con banderas `FAN_ACCESS_PERM | FAN_OPEN_PERM`.
- **Cola y Despacho:** Cola multihilo circular acotada (`EventQueue`) con descarte controlado por prioridad ante picos de I/O para evitar congelar el kernel.

### 3.3. File Scanner (`samulibre-scanner`)
- **Propósito:** Ingesta de archivos locales, cálculo streaming de hashes criptográficos (SHA-256) y despacho al motor de reglas.
- **Límites de Seguridad:** Apertura atómica con `libc::O_NONBLOCK | libc::O_NOFOLLOW`. Tamaño máximo por archivo en memoria: 128 MB. Streaming por fragmentos de 128 KB con verificación continua de cancelación cooperativa (< 0.05 ms).

### 3.4. Malware Detection Engine (`samulibre-scanner`)
- **Propósito:** Síntesis y correlación de veredictos provenientes de firmas, heurística, ML y reputación.
- **Modelo Decisorio:** Ponderación bayesiana multinivel:
  $$\text{Riesgo Final} = \max(\text{Firma}, 0.4 \cdot \text{Heurística} + 0.6 \cdot \text{ML})$$

### 3.5. Signature Engine (`samulibre-scanner::threat_intel`)
- **Propósito:** Búsqueda rápida multihilo de patrones binarios fijos, wildcards y expresiones regulares.
- **Evolución:** Integración del motor compilado nativo **YARA-X** para ejecución segura sin riesgo de pánicos por desreferenciación.

### 3.6. Behavioral Analysis (`samulibre-shield::ransomware_predictive`)
- **Propósito:** Monitoreo dinámico de patrones anómalos de procesos en ejecución.
- **Capacidades:**
  - Detección de ráfagas masivas de modificación de archivos con elevación súbita de entropía de Shannon ($> 7.5$).
  - Monitoreo de descriptores de red activos y conexiones a puertos sospechosos de comando y control (C2).

### 3.7. ELF Analyzer (`samulibre-scanner::elf_analyzer`)
- **Propósito:** Desensamblado estático y extracción de metadatos de ejecutables Linux ELF (32 y 64 bits).
- **Seguridad:** Aislamiento total en el sandbox no privilegiado; verificación matemática estricta de compensaciones (`offsets`), límites de secciones (`sh_offset + sh_size <= file_len`) y tablas de cadenas (`shstrtab`).

### 3.8. Script Analyzer (`samulibre-scanner`)
- **Propósito:** Análisis léxico y heurístico de scripts interpretados (Bash, Python, Perl, PowerShell Linux).
- **Indicadores:** Detección de técnicas de evasión (`base64 -d | sh`, llamadas inversas `/dev/tcp/`, manipulación de `LD_PRELOAD` y ofuscaciones de comillas).

### 3.9. Machine Learning Engine (`samulibre-ai` / `gpu-engine::ml`)
- **Propósito:** Clasificación estática de riesgo mediante modelo vectorial de 32 características extraídas del binario ELF.
- **Ejecución:** Red neuronal monocapa calibrada y optimizada ejecutada en CUDA PTX o CPU SIMD AVX2, con throughput certificado de **10,795 muestras/segundo**.

### 3.10. GPU Acceleration (`gpu-engine`)
- **Propósito:** Coprocesamiento asimétrico de tareas paralelas intensivas (reducción de histogramas de entropía y escaneo masivo de firmas).
- **Control de Recursos:** Monitoreo térmico continuo vía NVML. Si la temperatura excede 82 °C o el driver falla, degradación inmediata e ininterrumpida a CPU AVX2.

### 3.11. Threat Intelligence (`samulibre-scanner::threat_intel`)
- **Propósito:** Ingesta y normalización de indicadores de compromiso (IoCs) de fuentes abiertas (Abuse.ch, MalwareBazaar, URLhaus, CISA KEV).
- **Garantía Criptográfica:** Validación de integridad obligatoria con clave pública **Ed25519** antes de persistir o compilar cualquier actualización de firmas.

### 3.12. Quarantine Manager (`samulibre-watcher::quarantine`)
- **Propósito:** Aislamiento criptográfico y almacenamiento de archivos maliciosos.
- **Mecanismos:**
  - Ofuscación reversible XOR basada en UUID.
  - Firma HMAC-SHA256 en metadatos para impedir alteraciones externas.
  - Restauración atómica con `O_NOFOLLOW | O_EXCL` y permisos estrictos `0644`.

### 3.13. Update Manager (`samulibre-core`)
- **Propósito:** Sincronización atómica de binarios, firmas y reglas del sistema.
- **Transaccionalidad:** Descarga a directorios temporales aislados, verificación de checksum SHA-256 + firma Ed25519, y reemplazo atómico mediante `renameat2(..., RENAME_EXCHANGE)`.

### 3.14. Resource Controller (`gpu-engine::ResourceMonitor`)
- **Propósito:** Control de consumo de CPU, RAM y VRAM para garantizar impacto nulo en la experiencia del usuario.
- **Directivas:** Uso de `nice` POSIX, afinidad de núcleos EcoQoS y límites estrictos de memoria por hilo.

### 3.15. Telemetry Engine (`samulibre-core::event_db`)
- **Propósito:** Registro local de alertas y auditoría de eventos de seguridad.
- **Persistencia:** SQLite en modo WAL (`Write-Ahead Logging`) con canales MPSC desacoplados para evitar contención de bloqueos durante ráfagas de detección.

### 3.16. Security Dashboard (`samulibre-gui`)
- **Propósito:** Visualización reactiva en tiempo real del estado de protección, estadísticas de escaneo y telemetría de hardware.
- **Tecnología:** Interfaz gráfica moderna desacoplada que consume eventos asíncronos vía IPC.

### 3.17. Plugin Architecture (`samulibre-core::plugins`)
- **Propósito:** Extensibilidad modular para reglas personalizadas de escaneo, exportadores y ganchos de mitigación.
- **Contrato:** Interfaces trait de Rust dinámicas compiladas como bibliotecas compartidas con ABI estable o micro-servicios WASM (WebAssembly).

### 3.18. Reporting Engine (`samulibre-cli::report` / `SIEM`)
- **Propósito:** Generación de reportes de auditoría en formatos estándares de la industria.
- **Formatos:** JSON estructurado, Syslog RFC 5424, Common Event Format (CEF) y alineación con las tácticas de **MITRE ATT&CK Enterprise**.

---

## 4. ESPECIFICACIÓN DEL SANDBOX DE ANÁLISIS (LANDLOCK + SECCOMP)

Para remediar definitivamente el riesgo de ejecución de parsers en root (**RUST-SEC-02**), se formaliza el diseño del proceso trabajador confinado:

```
+-------------------------------------------------------------------------------+
|                       PROCESO WORKER: samulibre-worker                        |
+-------------------------------------------------------------------------------+
| 1. Creación: Fork & Drop Privileges -> UID 65534 (nobody)                     |
| 2. Restricción VFS (Landlock):                                                |
|    - LANDLOCK_ACCESS_FS_READ_FILE sobre el descriptor recibido                |
|    - Prohibición total de acceso de lectura/escritura a /etc, /root, /home    |
| 3. Restricción de Syscalls (seccomp-bpf):                                     |
|    - Syscalls permitidas: read, write, close, exit_group, brk, mmap, futex    |
|    - Syscalls bloqueadas: socket, connect, bind, execve, clone, fork, ptrace  |
| 4. Comunicación con el Supervisor:                                            |
|    - Canal IPC anónimo de sólo lectura (UNIX socketpair)                     |
|    - Transferencia del descriptor de archivo mediante SCM_RIGHTS              |
+-------------------------------------------------------------------------------+
```

---

## 5. REFUERZO DE LA COMUNICACIÓN IPC DEL DEMONIO (SO_PEERCRED)

Para subsanar el hallazgo crítico **RUST-SEC-01**:

```rust
// Protocolo de autenticación en UnixSocketServer (Linux)
let cred = stream.peer_cred()?;
let peer_uid = cred.uid();
let peer_gid = cred.gid();

// Política de autorización:
// Solo se admiten conexiones de root (UID 0) o del usuario del grupo samulibre
if peer_uid != 0 && !is_member_of_samulibre_group(peer_gid) {
    warn!("Rechazada conexión IPC no autorizada de UID: {}", peer_uid);
    return Err(anyhow!("Acceso denegado: permisos insuficientes"));
}
```

---

## 6. CONCLUSIÓN Y VERIFICACIÓN ARQUITECTÓNICA

El diseño arquitectónico aquí formalizado garantiza que SamuLibre Linux cumpla con los estándares más rigurosos de **Security by Design**, eliminando dependencias circulares, asegurando la separación de privilegios y blindando los canales de comunicación y actualización.

Esta especificación constituye la base técnica directa para la **Fase D (Corrección de Problemas Críticos y Altos)**.
