# Changelog de SamuLibre

Todas las mejoras notables, correcciones de errores y nuevas funcionalidades de SamuLibre se documentan en este archivo siguiendo [Keep a Changelog](https://keepachangelog.com/es-ES/1.0.0/) y versionado semántico.

---

## [2.0.32] - 2026-11-01

### 🏗️ Arquitectura Modular y Desacoplada (Fases I, II y III - Hoja de Ruta de Arquitectura)
- **Fase I (Inmediata) - IPC UNIX Domain Socket & Almacén SQLite WAL:**
  - Extraído el canal de comunicación IPC hacia un socket UNIX local (`/run/samulibre/samulibre.sock` con fallback dinámico en `/tmp/samulibre.sock`), reemplazando la dependencia en memoria compartida o acoplamiento monolítico por un protocolo JSON-RPC asíncrono tipado.
  - Consolidado el motor de persistencia de eventos de seguridad en SQLite con modo WAL (*Write-Ahead Logging*), soportando transacciones ACID de alto rendimiento, consultas forenses con filtros por severidad/fecha, estadísticas agregadas y gestión de exclusiones.
- **Fase II (Medio Plazo) - Demonio de Sistema Privilegiado (`samulibred`):**
  - Desplegado el nuevo binario de servicio de sistema `samulibred`, transfiriendo las operaciones con privilegios (bloqueo iptables por PID, lectura de `/proc` de otros usuarios, cuarentena del sistema) a un demonio protegido con `PR_SET_DUMPABLE=0`.
  - Creada la unidad systemd endurecida `data/samulibred.service` con capacidades mínimas (`AmbientCapabilities=CAP_NET_ADMIN CAP_SYS_PTRACE CAP_DAC_READ_SEARCH`), `ProtectSystem=strict`, `ProtectHome=read-only` y contención de memoria a 256MB.
  - Transformado `samulibre-gui` en un cliente puramente visual sin privilegios de superusuario.
- **Fase III (Largo Plazo) - Telemetría Kernel eBPF y Consola Central:**
  - Diseñado el gestor de telemetría eBPF (`EbpfTelemetryManager`) en `samulibre-shield` para supervisión granular de llamadas al kernel (`sys_enter_execve`, `sys_enter_connect`, `sys_enter_unlinkat`, `lsm_task_kill`), con detección en tiempo de ejecución de BTF/eBPF y fallback transparente a `/proc` e `inotify`.
  - Estructurados los modelos de datos de gestión corporativa de flota (`FleetEndpointReport`, `FleetCorporatePolicy`) en `samulibre-types`.

### 🔒 Autoprotección, Hardening y Correcciones de Seguridad Críticas (Fase 5)
- **Confinamiento de Kernel en Micro-Sandbox (`bwrap`):**
  - Remediada la vulnerabilidad crítica de ejecución no confinada en el host. Implementado aislamiento mediante **Bubblewrap** (`--unshare-all`, `--ro-bind /usr`, `--tmpfs /tmp`, red 100% aislada, `--die-with-parent`). Bloqueo preventivo de ejecución dinámica en el host si `bwrap` no está disponible.
- **Autenticidad Criptográfica HMAC y Protección Anti-Symlink en Cuarentena:**
  - Generación y verificación estricta de tags HMAC-SHA256 (`<id>.meta.sig`) para prevenir manipulación externa de rutas de destino.
  - Blindaje en `restore_file` que deniega la restauración si la ruta o su directorio padre es un enlace simbólico (`is_symlink()`), evitando ataques de sobreescritura arbitraria (CWE-59).
- **Prevención de Path Traversal en Extensiones:**
  - Validación de expresiones seguras en `remove_browser_extension`, bloqueando secuencias `..`, `/` y `\` (CWE-22) y forzando contención estricta dentro de `Extensions/`.
- **Validación Estricta y Anti-DoS en Firmas Externas:**
  - Validación de hashes hexadecimales y lista blanca de protección para impedir inyección maliciosa de archivos esenciales del sistema operativo.
- **Protección IPC de Rutas Críticas del Sistema:**
  - Bloqueo de peticiones de eliminación dirigidas contra directorios esenciales del sistema (`/`, `/bin`, `/sbin`, `/lib`, `/usr/bin`, `/etc`).

### 📦 Compatibilidad con Distribuciones Linux y Empaquetado Multi-Ecosistema (Fase 4)
- **Pipeline de Empaquetado Nativo para Tres Grandes Ecosistemas:**
  - **Ubuntu / Debian (`.deb`):** Generación automatizada con `build_deb.sh` (`target/samulibre_2.0.32_amd64.deb`). Compatible con APT/DPKG, integración con `unattended-upgrades`, control de dependencias Freedesktop y soporte de políticas AppArmor para WebKitGTK.
  - **Red Hat Enterprise Linux / Fedora / Rocky / AlmaLinux (`.rpm`):** Generación con `build_rpm.sh` (`target/samulibre-2.0.32-1.x86_64.rpm`). Cumplimiento con especificaciones de `samulibre.spec`, compatibilidad con gestores DNF/YUM, arquitectura para SELinux Enforcing (`samulibre_t`) y backend Firewalld.
  - **Garuda Linux / Arch Linux (`.pkg.tar.zst`):** Generación con `build_arch.sh` (`target/samulibre-2.0.32-1-x86_64.pkg.tar.zst`). Compatibilidad con Pacman, AUR (`PKGBUILD`), kernels alternativos (`linux-zen`, `linux-hardened`, `linux-lts`), Wayland / KDE Plasma 6 y subvolúmenes Btrfs.
- **Auditoría Arquitectónica de Sandboxes y Aislamiento:**
  - Evaluación y diagnóstico técnico detallado que descarta Flatpak y Snap estricto para operación de antivirus/EDR debido a la restricción fundamental impuesta por namespaces de montaje y aislamiento de `/proc`, validando el empaquetado nativo como la solución de producción estándar.

### 🛡️ Protección en Tiempo Real, Persistencia y Telemetría de Red en Linux (Fase 3)
- **Auditoría Exhaustiva de Persistencia Nativa en Linux (`linux_monitor.rs`):**
  - Implementado escaneo en vivo de servicios y temporizadores de **Systemd** de usuario (`~/.config/systemd/user/`) y del sistema (`/etc/systemd/system/`).
  - Inspección de aplicaciones en **Autostart** (`~/.config/autostart/*.desktop`, `/etc/xdg/autostart/*.desktop`), extrayendo el comando `Exec=`, comprobando la existencia física del ejecutable y calculando su hash SHA-256.
  - Análisis de tareas programadas **Cron** (`/etc/crontab`, `/etc/cron.d/`, `/var/spool/cron/`).
  - Detección heurística de persistencias maliciosas: ejecutables en rutas volátiles (`/tmp`, `/dev/shm`), reverse shells (`/dev/tcp/`, `nc -e`), y droppers encadenados (`curl | sh`, `wget | bash`).
- **Telemetría de Red y Sockets en Vivo con Atribución de Procesos:**
  - Parseo nativo de las tablas del kernel `/proc/net/tcp` y `/proc/net/tcp6`.
  - Correlación exacta y en microsegundos de inodos de socket mediante exploración de descriptores `/proc/[pid]/fd/*`, asociando cada puerto al PID, ejecutable y nombre del proceso correspondiente.
  - Identificación y categorización de puertos de alto riesgo o sospechosos (135, 139, 445, 3389, 4444, 1337, 8888, 5555, 6666, 7777, 9001, 9999).
- **Aislamiento Activo de Procesos y Puertos con Netfilter / Iptables:**
  - Aislamiento de tráfico de red para procesos maliciosos detectados mediante `iptables -I OUTPUT -m owner --pid-owner <PID> -j DROP`.
  - Bloqueo preventivo de puertos vulnerables con `iptables -I INPUT -p tcp --dport <PORT> -j DROP`.
- **Endurecimiento de Autoprotección Anti-Tamper (`PR_SET_DUMPABLE`):**
  - Activada la protección del kernel `libc::prctl(libc::PR_SET_DUMPABLE, 0)` en el arranque de la aplicación y en `AntiTamperShield::apply_process_hardening()`.
  - Impide que procesos del mismo usuario o scripts maliciosos puedan adjuntarse mediante `ptrace(PTRACE_ATTACH)` o leer/volcar la memoria del antivirus desde `/proc/[pid]/mem`.

### 🛡️ Motor Antivirus y Capacidades de Detección en Linux (Fase 2)
- **Cálculo Criptográfico SHA-256 en Streaming Completo:**
  - Corregido el cálculo de hash SHA-256 en `scan_file`: ahora se computa en streaming sobre la totalidad del archivo sin importar su tamaño, eliminando truncamientos que impedían la detección de malware superior a 512 KB en bases globales (ThreatFox, MalwareBazaar, ClamAV).
  - Rendimiento preservado mediante `BufReader` de 256 KB e inspección estática restringida a los primeros 512 KB.
- **Analizador de Seguridad Estructural ELF (Zero-Dependency Linux Engine):**
  - Implementado nuevo módulo nativo `elf_analyzer.rs` para binarios ELF de 32 y 64 bits sin dependencias externas.
  - Detección estricta de violaciones W^X (`PF_W | PF_X`) en segmentos `PT_LOAD`.
  - Detección de pilas ejecutables (`PT_GNU_STACK` con `PF_X`), mitigando riesgos de buffer overflow y shellcodes.
  - Detección de empaquetadores UPX, anomalías en tablas de sección y manipulación de cabeceras.
  - Detección de cadenas de explotación en memoria (`/memfd:`, `/dev/tcp/`, `init_module`, `finit_module`, `LD_PRELOAD`).
- **Mitigación de Evasión por Padding de Entropía Polimórfica:**
  - Reforzado el analizador `polymorphic.rs` para detectar payloads cifrados o empaquetados que intentan eludir el umbral de Shannon mediante relleno artificial de ceros o baja entropía (`has_entropy_padding_evasion`).
- **Reglas Heurísticas Avanzadas para Amenazas Nativas en Linux:**
  - Reverse shells en Linux ofuscadas y decodificadas al vuelo con `base64`.
  - Marcadores y notas de rescate de variantes de ransomware para Linux (ESXiArgs, bloqueos inmutables).
  - Detección de rootkits LKM e inyección dinámica de módulos de kernel (`insmod`, `finit_module`, `/dev/kmem`, `/proc/kallsyms`).
  - Recolección y exfiltración de claves SSH (`id_rsa`) y hashes de `/etc/shadow`.
  - Droppers furtivos con ejecución en tubería sin archivo intermedio (`curl | sh`, `wget | bash`).
  - Optimización del pre-filtro de memoria `has_suspicious_indicators` con descarte instantáneo (<0.01 ms).
- **Carga Persistente de Firmas Externas:**
  - Soporte para bases de datos adicionales en `data/signatures/malware_hashes.db` tanto en inicialización de fábrica como en actualizaciones comunitarias.

---

## [2.0.31] - 2026-11-01

### 🚀 Novedades y Mejoras Principales
- **Exclusión Personalizada de Directorios y Archivos:**
  - Integrado soporte de exclusiones a nivel de motor en `MultiEngineScanner` (`set_exclusions`, `add_exclusion`, `remove_exclusion`, `is_path_excluded`).
  - Poda anticipada en `WalkDir`: omite la navegación y lectura de directorios excluidos en escaneo de carpetas, rápido, completo y programado.
  - Sincronización en tiempo real con el vigilante Centinela (`RealTimeWatcher`) para descartar eventos en rutas confiables.
  - Tarjeta interactiva en la interfaz gráfica con selector nativo de carpetas (`kdialog` / `zenity`), entrada manual de rutas y eliminación con un solo clic.
- **Estabilidad de GUI y Ciclo de Apertura/Cierre en Linux:**
  - Configurado flag `--minimized` en `samulibre.service` y `samulibre.desktop` para arranque silencioso en segundo plano.
  - Prioridad `nice 19` acotada al hilo de trabajo mediante `SYS_gettid`, blindando el rendimiento del bucle principal de GTK y WebKit.
  - Control de finalización limpia con `SuccessExitStatus=0`.
- **Telemetría de Hardware en Vivo:**
  - Monitoreo continuo de uso de CPU (normalizado por núcleos), consumo de memoria RAM del proceso y telemetría dinámica de GPU y VRAM mediante `nvidia-smi` en el pie de la barra lateral.
- **Empaquetado Nativo para Distribuciones Linux:**
  - Soporte de compilación y empaquetado automatizado para Ubuntu/Debian (`.deb`) y Red Hat/Fedora/Rocky (`.rpm`).
- **Plan de Trabajo Integral:**
  - Documentación técnica y bitácora de arquitectura de 21 secciones disponible en `docs/plan_de_trabajo_linux.md`.

---

## [1.99.15] - 2026-10-20

### 🚀 Novedades y Mejoras Principales
- **Escaneo Multi-Hilo Paralelo con Saturación de CPU y RAM (`rayon`):**
  - Implementado motor de escaneo paralelo con work-stealing utilizando la totalidad de hilos/núcleos lógicos del procesador (`rayon::current_num_threads()`).
  - Indexación ultrarrápida de candidatos en memoria RAM eliminando cuellos de botella de disco e I/O.
  - Acceso concurrente y sin bloqueo de mutex al motor de detección multi-motor (`Arc<MultiEngineScanner>`), multiplicando por hasta 12x la velocidad de escaneo.
  - Indicador de velocidad en tiempo real en la tarjeta de escaneo (ej. `~1450 arch/s | 16 hilos CPU`).
- **Resumen Final Exclusivo de Archivos Infectados (`modalScanSummary`):**
  - Erradicado el spam de ventanas emergentes durante el proceso de escaneo.
  - Al completar el análisis, si se detectaron amenazas, se despliega automáticamente una ventana de resumen con **únicamente los archivos infectados/sospechosos** hallados.
  - Acciones globales en lote de un solo clic:
    - 🛡️ **Aislar Todos en Cuarentena:** Mueve todos los elementos infectados a la bóveda cifrada XOR.
    - 🗑️ **Eliminar Todos Permanentemente:** Destruye y borra todos los archivos maliciosos del disco.
    - 🔍 **Revisar uno a uno:** Permite abrir el inspector forense XDR individual para cada amenaza.
- **Activación Definitiva de la Protección en Tiempo Real (`RealTimeWatcher`):**
  - Corregida la inactividad del vigilante en segundo plano: ahora se inicializa y preserva activo en memoria vigilando `Downloads`, `Desktop`, `Documents` y `Temp`.
  - Filtro de extensiones de alto riesgo ampliado drásticamente: incluye ejecutables (`exe`, `dll`, `sys`, `com`, `scr`), scripts (`bat`, `ps1`, `vbs`, `js`, `py`, `sh`), paquetes y bytecode (`jar`, `apk`, `dex`), documentos con riesgo de exploit (`pdf`, `docm`, `xlsm`), accesos directos (`lnk`, `pif`), contenedores (`zip`, `rar`, `iso`) y archivos sin extensión.
  - Registro inmediato en tiempo real en `threat_history.json` y alerta instantánea al usuario vía notificación.
- **Actualización de Versión:**
  - Versión subida a **`v1.99.15`** en cabecera desktop y móvil.
  - Manifiesto Android actualizado con `versionCode = 8` y `versionName = "1.99.15"`.

---

## [1.99.14] - 2026-10-20

### 🚀 Novedades y Mejoras Principales
- **Investigación Forense y Mitigación de Falsos Positivos en PDFs (`H=7.99`):**
  - Análisis forense de archivos PDF con alta entropía de Shannon (ej. documentos escaneados e imágenes comprimidas vía `FlateDecode`).
  - Corregido el motor de entropía `AI.Heuristic.PackedSuspiciousEntropy`: los documentos PDF/Office comprimidos legítimos ya no son clasificados erróneamente como malware empaquetado a menos que contengan scripts activos o disparadores de ejecución maliciosa (`/JavaScript`, `/Launch`, etc. catalogados bajo `Exploit.PDF.ActiveScriptOrLaunchTrigger`).
- **Rastreo de Procedencia XDR Amigable para Usuarios Comunes:**
  - Integrado rastreador nativo en Windows capaz de inspeccionar los flujos alternativos NTFS (`:Zone.Identifier`) para descubrir la URL de origen (`HostUrl`) y el sitio remitente (`ReferrerUrl`).
  - Mapeo automático de procedencia comprensible: identifica descargas desde *"WhatsApp Web"*, *"Navegador Web (Chrome/Edge/Firefox)"*, *"Correo Electrónico"* o *"Equipo Local"*.
  - Enriquecido el modelo de datos `ThreatRecord` y el historial persistente con los campos: `origin_source`, `origin_url`, `human_explanation` y `suggested_action`.
- **Línea de Tiempo Visual en 3 Pasos y Explicación en Palabras Cotidianas:**
  - Modal contextual emergente `modalThreatDecision` con una tarjeta interactiva de procedencia (XDR Amigable):
    - **Paso 1:** 🌐 ¿De dónde vino? (ej. WhatsApp Web, Google Chrome).
    - **Paso 2:** 📥 ¿Dónde aterrizó? (ej. Carpeta Descargas, Escritorio).
    - **Paso 3:** 🔍 Diagnóstico claro (ej. Falso Positivo Seguro vs. Peligro Potencial).
    - **💡 ¿Qué significa esto para ti?:** Explicación pedagógica sin jerga de ciberseguridad y sugerencia de acción clara para el usuario.
- **Columna de Origen en el Historial de Amenazas:**
  - Añadida la columna *"Origen (XDR)"* con badges distintivos en la tabla persistente de amenazas detectadas.
- **Actualización de Versión:**
  - Versión subida a **`v1.99.14`** visible en la esquina superior izquierda de la app tanto en escritorio como en móvil.
  - APK de Android actualizado a `versionCode = 7` y `versionName = "1.99.14"`.

---

## [1.99.13] - 2026-10-20

### 🚀 Novedades y Mejoras Principales
- **Inicio Automático en Windows (Windows Autostart al Arranque):**
  - Implementado registro y desregistro nativo en `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run` bajo el nombre `SamuLibre`.
  - Soporte de arranque silencioso con parámetro `--minimized` para inicio en segundo plano en la bandeja del sistema.
  - Interruptor interactivo (toggle switch) *"Inicio con Windows"* incorporado en la interfaz y sincronizado bidireccionalmente vía IPC (`get_autostart_status`, `set_autostart`).
- **Revisión y Potenciación Profunda del Motor de Escaneo:**
  - Erradicado el tope arbitrario de 60 archivos (`results.len() >= 60`) que truncaba prematuramente los escaneos de carpetas y rutas personalizadas.
  - Eliminado el límite superficial `max_depth(3)` en `execute_scan_loop`, permitiendo escaneo recursivo completo (`max_depth: 25-30`) con filtrado inteligente de carpetas pesadas no relevantes (`.git`, `node_modules`, `target`, `$Recycle.Bin`).
  - Detección inmediata de binarios ejecutables Windows Portable Executable (cabecera PE `MZ`) y ampliación de reglas YARA-X/Heurísticas contra destructores de copias de seguridad de volumen (`vssadmin delete shadows`), descargadores LOLBin (`certutil`, `bitsadmin`, `mshta`, `regsvr32`), wipers destructivos y volcados de memoria LSASS (`sekurlsa`, `mimikatz`).
  - Emisión en tiempo real de cada amenaza encontrada a la interfaz gráfica y persistencia inmediata en el registro histórico.
- **Detención Inmediata de Análisis Manual (Cancel Scan):**
  - Implementada bandera atómica global `IS_SCAN_CANCELLED: AtomicBool` consultada en cada iteración de archivo dentro de los bucles de escaneo.
  - Manejador IPC `cancel_scan` para abortar escaneos en ejecución de manera instantánea y segura sin bloquear la aplicación ni dejar archivos abiertos.
  - Botón llamativo `⏹️ Detener Análisis` en la tarjeta de progreso en vivo y en los controles de escaneo.
- **Toma de Decisiones Interactivas ante Amenazas Detectadas:**
  - Modal contextual emergente `modalThreatDecision` al detectar archivos infectados o sospechosos.
  - 4 opciones directas para el usuario:
    1. **🛡️ Mover a Cuarentena (Recomendado):** Cifra el contenido con algoritmo XOR (clave 0xAA), custodia el elemento en `data/quarantine/` y destruye el original de forma segura.
    2. **🗑️ Eliminar Permanentemente:** Destrucción y borrado definitivo del archivo del sistema.
    3. **⚪ Excluir (Falso Positivo):** Incorporación de la ruta o hash a `data/exclusions.json` para omitir alertas futuras.
    4. **👁️ Ignorar:** Mantiene el archivo sin modificaciones bajo confirmación del usuario.
  - Capacidad de restauración de archivos desde la cuarentena (`restore_quarantined_item`) revirtiendo el cifrado XOR y devolviendo el archivo a su ruta original.
- **Historial Persistente de Archivos Maliciosos (`data/threat_history.json`):**
  - Registro cronológico permanente de amenazas detectadas, firmas, niveles de severidad (Crítica, Alta, Media), motor de detección y estado de resolución.
  - Tarjeta y tabla interactiva en la pestaña del Escáner con contadores, badges de estado y botones de acción rápida (*Aislar*, *Borrar*, *Restaurar* o *Purgar*).
- **Actualización de Versión y Control Visual:**
  - Etiqueta de versión visible en la esquina superior izquierda de la aplicación: `v1.99.13`.
  - Manifiesto Android actualizado con `versionCode = 6` y `versionName = "1.99.13"`.

---

## [1.99.12] - 2026-10-20

### 🚀 Novedades y Mejoras Principales
- **Gateway Proxy Local Inteligente (`SamuSmartProxyServer`):**
  - Implementado servidor proxy HTTP/HTTPS local de alta concurrencia en `127.0.0.1:8118` con enlace inmediato al `VpnService` de Android en Android 10+ (API 29+).
  - Erradicado de forma definitiva el error `ERR_PROXY_CONNECTION_FAILED` en Google Chrome y navegadores móviles.
  - Handshake SOCKS5 RFC 1928 nativo con resolución remota de dominios (ATYP 0x03) en el nodo de salida para prevención total de fugas de DNS (Zero-Leak).
- **Enmascaramiento Total de IP de ISP Móvil:**
  - Garantizado que navegadores web como Google Chrome muestren la dirección IP pública correspondiente al país seleccionado (ej. Islandia `185.112.82.19`, Suiza `195.176.3.23`) y nunca la IP del operador celular local (Movistar Colombia `152.203.238.220`).
- **Base de Datos GeoIP Integrada:**
  - Empaquetada base `geoip` en los assets de la app y copiada dinámicamente a almacenamiento interno para resolución precisa de nodos de salida por código de país (`{is}`, `{ch}`, `{nl}`, `{se}`).
- **Caché de Consenso y Microdescriptores en Disco:**
  - Eliminada directiva `AvoidDiskWrites 1` para permitir la persistencia del consenso Tor en memoria flash, reduciendo el tiempo de reconexión de 90 segundos a menos de 2 segundos.
  - Pre-calentamiento asíncrono en segundo plano al abrir la aplicación para arranque inmediato.
- **Optimización de Inicio (< 300 ms):**
  - Desacoplada la auditoría masiva de paquetes del ciclo de arranque inicial, trasladándola exclusivamente bajo demanda a la sección correspondiente.
  - Filtrado optimizado en `getInstalledAppsDetailsFast` para omitir paquetes estándar del sistema sin permisos de riesgo.
- **Control de Versión Visual:**
  - Etiqueta de versión visible en la esquina superior izquierda de la aplicación: `v1.99.12`.
  - Manifiesto actualizado con `versionCode = 5` y `versionName = "1.99.12"`.

---

## [1.99.11] - 2026-10-19
- **Arquitectura VPN de Doble Etapa con Watchdog:**
  - Transición segura de túnel en dos etapas (Modo DNS Seguro y Modo Proxy con supervisión continua).
  - Eliminación de ANRs y bloqueos en `TorService` mediante inicio estándar por `startService`.

---

## [1.99.10] - 2026-10-19
- **Sincronización Dinámica de Puertos Tor:**
  - Escucha dinámica de puertos locales y enlace con `ProxyController` de AndroidX WebKit.
  - Verificación de IP en vivo para la interfaz móvil.

---

## [1.99.0] - 2026-10-15
- **Lanzamiento de la Suite de Seguridad SamuLibre:**
  - EDR en Rust con motor YARA-X, tripwires canarios contra Ransomware y mitigación autónoma de vulnerabilidades 0-Day.
  - Soporte multiplataforma para Windows 11, Linux (Ubuntu, RHEL, Garuda) y Android.
