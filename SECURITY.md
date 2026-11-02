# POLÍTICA DE SEGURIDAD Y ARQUITECTURA DE AUTO-DEFENSA (SECURITY.MD) 🔒
## SamuLibre Linux EDR & Antivirus Platform
**Versión:** 2.0+ (Next-Generation Linux Endpoint Protection)  
**Alcance:** Stack Completo (Rust Workspace, C++20 GPU Engine, eBPF Kernel Hooks, Daemons e IPC)

---

## 1. PRINCIPIOS DE AUTO-DEFENSA Y MENOR PRIVILEGIO

En **SamuLibre**, reconocemos una paradoja crítica en la industria de la ciberseguridad: **el software antivirus ejecutado con privilegios elevados (`root`) se convierte frecuentemente en el principal vector de ataque de día cero (*Zero-Day*) para los adversarios.**

Vulnerabilidades de corrupción de memoria en analizadores de formatos de archivo, ataques de enlace simbólico (*symlink traversal*) en motores de cuarentena e inyecciones en procesos de seguridad han comprometido históricamente a suites propietarias.

SamuLibre Linux ha sido diseñado desde su base arquitectónica para erradicar estas superficies de ataque:

### 1.1. Núcleo con Seguridad de Memoria en Rust (Memory-Safe Core)
- El motor principal, el demonio supervisor, los sensores de eventos y los sistemas de cuarentena están implementados en **Rust**, eliminando clases enteras de vulnerabilidades críticas como desbordamientos de búfer (*Buffer Overflow*), uso tras liberación (*Use-After-Free*), doble liberación (*Double Free*) y desreferenciación nula.
- Las primitivas de concurrencia se gestionan mediante tipos seguros de sincronización (`Arc<Mutex<...>>`, canales MPSC acotados con backpressure), previniendo condiciones de carrera (*Data Races*).

### 1.2. Blindaje Atómico Anti-Symlink y Anti-TOCTOU (Anti-LPE)
- **Amenaza:** Atacantes locales sin privilegios intentan crear enlaces simbólicos en directorios compartidos (`/tmp`) apuntando a archivos sensibles del sistema (`/etc/shadow`, `/etc/sudoers`) para engañar al antivirus y lograr que sobrescriba o elimine archivos del sistema durante la cuarentena.
- **Defensa SamuLibre:** `QuarantineVault` utiliza banderas atómicas POSIX **`O_NOFOLLOW`** (`libc::O_NOFOLLOW`) y verifica directamente los metadatos del descriptor abierto (`fstat`). Cualquier intento de manipular rutas con enlaces simbólicos es rechazado de inmediato y reportado al auditor de eventos.

### 1.3. Control de Acceso Estricto en Socket IPC UNIX (`SO_PEERCRED`)
- El socket del demonio privilegiado (`/run/samulibre/samulibre.sock`) opera con permisos restrictivos `0660` asignados al grupo del sistema `samulibre`.
- Todas las conexiones entrantes validan obligatoriamente la identidad local del llamante mediante la llamada al sistema **`SO_PEERCRED`** (`stream.peer_cred()`), denegando cualquier comando privilegiado a usuarios no autorizados.

### 1.4. Anti-Tampering de Memoria a Nivel de Kernel
- El demonio `samulibred` ejecuta al iniciar `prctl(PR_SET_DUMPABLE, 0)`, impidiendo que atacantes locales o procesos no privilegiados utilicen `ptrace`, `gdb` o volcados de memoria `/proc/[pid]/mem` para inspeccionar claves en memoria o alterar el flujo de control del antivirus.

### 1.5. Soberanía Absoluta y Cero Telemetría (Zero-Cloud Mandate)
- SamuLibre opera de forma **100% local y soberana**. No contiene rastreadores analíticos, SDKs publicitarios ni llamadas de telemetría hacia la nube. Todo el análisis de inteligencia, inferencia de red y almacenamiento relacional de eventos (SQLite WAL) se ejecuta en la propia máquina anfitriona.

---

## 2. VERSIONES CON SOPORTE OFICIAL

| Versión | Estado | Actualizaciones de Seguridad |
| :--- | :---: | :---: |
| **v2.0.x (Actual)** | :white_check_mark: Soporte Activo (LTS) | Parches inmediatos |
| **v1.x** | :warning: Mantenimiento | Solo correcciones críticas |
| `< 1.0` | :x: Fin de Ciclo de Vida | Sin soporte |

---

## 3. DIVULGACIÓN COORDINADA DE VULNERABILIDADES (COORDINATED DISCLOSURE)

Agradecemos y respaldamos el trabajo de los investigadores de seguridad y la comunidad de software libre para auditar y reportar vulnerabilidades de forma responsable.

### 3.1. Procedimiento de Reporte Seguro
Si descubres una vulnerabilidad de seguridad en SamuLibre Linux:
1. **No abras un issue público en GitHub.**
2. Reporta la vulnerabilidad de manera confidencial utilizando [GitHub Private Vulnerability Reporting](https://github.com/saghet/SamuLibreLinux/security/advisories/new) o envía un correo cifrado a:  
   📧 **`security@samulibre.org`**
3. Incluye:
   - Descripción detallada del hallazgo y severidad estimada (CVSS si aplica).
   - Pasos reproducibles o prueba de concepto (*PoC*).
   - Componente y versión afectada del software.

### 3.2. Compromiso de Respuesta del Equipo
- **Acuse de recibo:** En un plazo máximo de **24 horas**.
- **Evaluación técnica y confirmación:** En un plazo de **72 horas**.
- **Ventana de remediación coordinada:** Comprometemos la publicación de un parche de seguridad en menos de **14 días** para vulnerabilidades Críticas/Altas, respetando una ventana estándar de 90 días antes de la divulgación pública.
- **Reconocimiento:** Los investigadores que reporten vulnerabilidades verificadas serán incluidos en el **Hall of Fame** oficial del proyecto y en las notas de la versión correspondiente.
