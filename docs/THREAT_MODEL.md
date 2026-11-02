# MODELO FORMAL DE AMENAZAS (THREAT MODEL)
## Antivirus & Endpoint Detection and Response (EDR) SamuLibre Linux
**Documento:** `docs/THREAT_MODEL.md`  
**Fecha:** Noviembre 2026  
**Versión:** 2.0  
**Metodología:** STRIDE + MITRE ATT&CK Enterprise Matrix (Linux)  
**Alcance:** Stack Completo de SamuLibre (Workspace Rust, C++20 GPU Engine, eBPF Kernel Hooks, IPC y Daemons)

---

## 1. INTRODUCCIÓN Y OBJETIVOS DEL SISTEMA

SamuLibre Linux está diseñado como una solución de ciberseguridad defensiva para endpoints y servidores Linux, integrando detección por firmas, heurística polimórfica, aprendizaje automático (ML), monitoreo en tiempo real del sistema de archivos (`fanotify`/`inotify`), virtual patching mediante `eBPF` y mitigación proactiva de ransomware y ataques *fileless*.

El propósito de este modelo de amenazas es:
1. Mapear sistemáticamente las superficies de ataque expuestas por la suite.
2. Identificar actores de amenaza y vectores de evasión o subversión.
3. Aplicar la metodología **STRIDE** para caracterizar riesgos en cada subsistema.
4. Establecer las barreras de contención, directivas de menor privilegio y garantías criptográficas necesarias para certificar el software en entornos críticos.

---

## 2. CARACTERIZACIÓN DE ACTORES DE AMENAZA (THREAT ACTORS)

| Actor | Nivel de Habilidad | Motivación | Capacidades / Vectores Típicos |
| :--- | :--- | :--- | :--- |
| **Amenaza Persistente Avanzada (APT)** | Muy Alto (Nivel Estatal) | Espionaje, sabotaje, persistencia sigilosa | Exploits 0-day en parsers, técnicas *living-off-the-land* (LOLBins), inyección directa en memoria sin tocar disco (*fileless*), manipulación de eBPF. |
| **Operadores de Ransomware** | Alto | Extorsión financiera, cifrado masivo | Ataques de ráfagas de escritura de alta entropía, eliminación de backups locales, anulación de servicios defensivos (`kill -9 samulibred`). |
| **Atacante Local sin Privilegios (LPE)** | Medio-Alto | Escalada de privilegios a `root` | Explotación de sockets IPC UNIX mal protegidos, condiciones de carrera TOCTOU en directorios compartidos (`/tmp`), symlink attacks en cuarentena. |
| **Malware Automatizado / Botnets** | Medio | Reclutamiento DDoS, criptominería | Escaneo masivo de puertos SSH, ejecución de scripts bash ofuscados, persistencia vía `cron` y servicios `systemd` manipulados. |
| **Adversario en la Red Local (MITM)** | Medio | Envenenamiento de inteligencia | Falsificación de resoluciones DNS, interceptación de descargas de firmas de antivirus sin verificar firma criptográfica asimétrica. |

---

## 3. SUPERFICIES DE ATAQUE DEL SISTEMA

```
                              SUPERFICIES DE ATAQUE
                                        │
    ┌───────────────────┬───────────────┴───────────────┬───────────────────┐
    ▼                   ▼                               ▼                   ▼
[1. Parsers de      [2. Sockets IPC            [3. Sistema de       [4. Kernel Hooks
  Archivos Untrusted]   UNIX Domain]             Archivos y VFS]        (eBPF & fanotify)]
  - ELF Analyzer      - /run/samulibre/*.sock    - Cuarentena         - TC / XDP filters
  - C++ GPU Scanner   - Mensajes JSON-RPC        - Honey-tokens       - kprobes / tracepoints
  - Descompresores    - Control de procesos      - Directorio /tmp    - Intercepción VFS
```

### 3.1. Superficie 1: Procesamiento y Parsing de Archivos No Confiables
- **Componentes:** `crates/samulibre-scanner`, `crates/samulibre-ai`, `gpu-engine/src/ml/elf_feature_extractor.cpp`.
- **Riesgo:** El antivirus debe ingerir binarios arbitrarios creados maliciosamente para detonar desbordamientos de búfer, desreferenciaciones fuera de límites, o bucles infinitos durante el parsing de secciones ELF, tablas de cadenas (`shstrtab`) o metadatos.

### 3.2. Superficie 2: Mecanismo de Comunicación Inter-Procesos (IPC)
- **Componentes:** `crates/samulibre-core/src/ipc.rs`, `crates/samulibre-daemon/src/main.rs`.
- **Riesgo:** El socket UNIX del demonio expone acciones administrativas (`isolate_process_network`, `scan_file`, `update_threat_intelligence`). Si los permisos del sistema de archivos (`chmod`) o la validación del peer (`SO_PEERCRED`) son deficientes, cualquier usuario local puede abusar de las facultades de `root`.

### 3.3. Superficie 3: Sistema de Cuarentena y Restauración
- **Componentes:** `crates/samulibre-watcher/src/lib.rs` (`QuarantineVault`).
- **Riesgo:** Durante el aislamiento o restauración de un archivo sospechoso, un proceso malicioso podría crear un enlace simbólico (*symlink*) apuntando a archivos críticos del sistema operativo (`/etc/shadow`, `/etc/sudoers`), manipulando la lógica de restauración para sobrescribirlos.

### 3.4. Superficie 4: Ganchos de Kernel eBPF y Notificaciones fanotify
- **Componentes:** `crates/samulibre-patcher/src/ebpf_vpatch.rs`, `crates/samulibre-watcher/src/fanotify_sensor.rs`.
- **Riesgo:** La intercepción de llamadas `open` y `execve` mediante `fanotify` con bloqueo (`FAN_ACCESS_PERM`) puede causar congelamiento del sistema operativo (*system lockup*) si la cola de eventos se satura o si el demonio no responde en un tiempo determinista.

---

## 4. ANÁLISIS DE AMENAZAS MEDIANTE MODELO STRIDE

| Categoría STRIDE | Amenaza Concreta Identificada | Subsistema Afectado | Nivel de Riesgo | Mitigación Actual y Recomendada |
| :--- | :--- | :--- | :---: | :--- |
| **Spoofing** (Suplantación) | Un proceso no autorizado se hace pasar por la GUI o CLI y envía comandos al socket IPC del demonio. | `samulibre-daemon`, `samulibre-core::ipc` | **CRÍTICO** | Comprobar credenciales de socket (`SO_PEERCRED` / UID==0 o grupo autorizado `samulibre`). Rechazar clientes anónimos. |
| **Tampering** (Manipulación) | Un binario malicioso altera los metadatos o archivos cifrados almacenados en el almacén de cuarentena. | `samulibre-watcher::QuarantineVault` | **MEDIO** | Firma criptográfica HMAC en metadatos y ofuscación XOR ligada al UUID. Se recomienda migrar a cifrado autenticado AES-256-GCM. |
| **Repudiation** (Repudio) | Un usuario o proceso malicioso niega haber modificado o borrado un archivo crítico antes de la intervención del EDR. | `samulibre-core::event_db`, SQLite WAL | **BAJO** | Registro estructurado append-only en SQLite WAL con marca de tiempo UTC y hash SHA256 inmutable. |
| **Information Disclosure** | Fuga de información confidencial mediante extracción de cadenas en archivos de memoria mapeada o volcados del proceso. | `samulibre-daemon`, `samulibre-shield` | **MEDIO** | Activación mandatoria de `prctl(PR_SET_DUMPABLE, 0)` para impedir que `gdb` o `ptrace` inspeccionen el proceso antivirus. |
| **Denial of Service** (DoS) | Envío masivo de eventos VFS o archivos bomba de descompresión para colapsar la memoria RAM o congelar la GPU. | `samulibre-watcher`, `gpu-engine` | **ALTO** | Backpressure y cola circular con prioridades en `event_queue.rs`, límite estricto de tamaño en lectura de archivos (128 MB) y derivación de microarchivos a CPU. |
| **Elevation of Privilege** | Explotación de una vulnerabilidad de memoria en el parser de binarios para ejecutar código dentro del proceso root del demonio. | `samulibre-daemon`, parsers ELF | **CRÍTICO** | **Separación de Privilegios:** Aislar el motor de parsing en un proceso worker no privilegiado restringido mediante **Landlock** y **seccomp-bpf**. |

---

## 5. MATRIZ DE DEFENSA EN PROFUNDIDAD (DEFENSE-IN-DEPTH)

```
Nivel 0: Kernel (Hardware / OS)
  └── eBPF XDP/TC Network Virtual Patcher
        └── fanotify pre-execution blocking (FAN_ACCESS_PERM)
              └── Anti-tamper prctl(PR_SET_DUMPABLE, 0)
                    │
Nivel 1: Daemon Privilegiado (samulibred - Root)
  └── Coordinación de ganchos del kernel
  └── Validación criptográfica de IPC (SO_PEERCRED)
  └── Ingesta SQLite WAL & Telemetría EDR
        │
Nivel 2: Sandbox Worker No Privilegiado (Sandboxed Parser)
  └── Landlock (acceso VFS de solo lectura al archivo objetivo)
  └── seccomp-bpf (filtro estricto de syscalls: sin network, sin fork)
  └── Análisis ELF estático, YARA-X, heurística de entropía
        │
Nivel 3: Aceleración GPU Aislada (Zero-Trust Asymmetric Engine)
  └── Memoria de dispositivo acotada (ScopedDeviceBuffer)
  └── Fallback automático a AVX2 en CPU si falla CUDA o hay sobrecalentamiento NVML
```

---

## 6. CONCLUSIONES DEL MODELO DE AMENAZAS

El riesgo primordial para un antivirus/EDR en Linux radica en el **abuso de su propio nivel de privilegios**. Si el analizador de archivos opera como `root`, cualquier falla en la interpretación de un binario suministrado por un atacante convierte al antivirus en un vector de escalada de privilegios (*Privilege Escalation Vector*).

Por lo tanto, la mitigación obligatoria y prioritaria del proyecto es la implementación de la **separación de privilegios mediante procesos trabajadores confinados (Sandboxed Workers)** con Landlock y seccomp.
