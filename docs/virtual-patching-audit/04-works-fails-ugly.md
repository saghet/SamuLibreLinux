# 04 — Evaluación Tripartita: Lo Bueno, Lo Malo y Lo Feo

**Documento:** `docs/virtual-patching-audit/04-works-fails-ugly.md`  
**Objetivo:** Clasificación rigurosa del estado de ingeniería del módulo de parchado virtual.

---

## A. LO QUE FUNCIONA BIEN

### 1. Detección de Compilación del Kernel Linux
- **Ubicación:** [`crates/samulibre-patcher/src/lib.rs#L1404-L1445`](file:///home/saghet/Documents/SamulibreLinux/crates/samulibre-patcher/src/lib.rs#L1404-L1445)
- **Descripción:** La lectura y descomposición de `/proc/sys/kernel/osrelease` para extraer `major` y `minor` funciona correctamente sin dependencias externas pesadas.
- **Evidencia:** Detecta con precisión que en el kernel `7.2.11-zen1-1-zen` (`major = 7 > 5`), vulnerabilidades del kernel upstream como `CVE-2022-0185` (fs_context) y `CVE-2016-5195` (Dirty COW) están resueltas nativamente por el árbol del kernel.
- **Recomendación:** **Conservar y reutilizar** esta lógica, encapsulándola en un `LinuxKernelInspector` especializado.

### 2. Detección de Parámetros sysctl Actuales
- **Ubicación:** [`crates/samulibre-patcher/src/lib.rs#L573-L582`](file:///home/saghet/Documents/SamulibreLinux/crates/samulibre-patcher/src/lib.rs#L573-L582)
- **Descripción:** La lectura de `/proc/sys/...` para verificar si un parámetro de seguridad ya se encuentra en su valor seguro (`safe_value`) es correcta y no requiere privilegios elevados (lectura pública).
- **Evidencia:** Si `kernel.yama.ptrace_scope` ya tiene el valor `2`, el sistema lo reconoce y evita aplicar mitigaciones redundantes.
- **Recomendación:** **Conservar**, extendiendo la compatibilidad a la lectura de archivos en `/etc/sysctl.d/`.

### 3. Mecanismo de Supresión y Descarte de Reglas
- **Ubicación:** [`crates/samulibre-patcher/src/lib.rs#L836-L861`](file:///home/saghet/Documents/SamulibreLinux/crates/samulibre-patcher/src/lib.rs#L836-L861)
- **Descripción:** El método `dismiss_patch_rule` permite suprimir una regla en memoria y eliminar su archivo correspondiente en `data/cve_rules/dynamic_*.json` de forma limpia.
- **Recomendación:** **Conservar**, añadiendo un registro de auditoría de quién y cuándo suprimió la regla.

---

## B. LO QUE FUNCIONA MAL

### Problema 1: Descarte Silencioso de Errores al Aplicar Parches
- **Ubicación:** `crates/samulibre-patcher/src/lib.rs#L1505` y `L1536`
- **Causa Probable:** Uso de `let _ = cmd.output()` y `let _ = std::fs::write(...)` sin propagar `Result`.
- **Impacto:** Si la aplicación se ejecuta como usuario regular, la mitigación falla por falta de permisos (`EACCES`), pero el sistema reporta que el parche virtual está activo.
- **Severidad:** **CRÍTICA**
- **Solución Recomendada:** Requerir elevación polkit / IPC con el demonio privilegiado `samulibred`, verificar el código de salida de `iptables`/`nftables` o el resultado de la escritura en sysctl, y marcar la regla como `PatchStatus::Failed { reason }` ante cualquier error.

### Problema 2: Inexistencia del Bloqueo Conductual (`BehavioralBlock`)
- **Ubicación:** `crates/samulibre-patcher/src/lib.rs#L1529-L1531`
- **Causa Probable:** Implementación pendiente donde solo se colocó un log informativo `info!("Bloqueo de comportamiento activo...")`.
- **Impacto:** Toda regla que utilice `BehavioralBlock` (incluyendo `CVE-2021-4034 PwnKit`) no ofrece protección alguna frente al atacante.
- **Severidad:** **CRÍTICA**
- **Solución Recomendada:** Conectar las reglas conductuales con el motor EDR (`samulibre-watcher`), utilizando filtros seccomp o sondas eBPF que realmente intercepten la ejecución o el parámetro del proceso atacante.

### Problema 3: Contador de Boletines Pendientes Siempre Erróneo en Linux
- **Ubicación:** `crates/samulibre-patcher/src/lib.rs#L511-L536`
- **Causa Probable:** `get_installed_kbs()` está vacío bajo Linux (`#[cfg(target_os = "windows")]` exclusivo).
- **Impacto:** El subcomando `samulibre patcher kb-scan` y la interfaz gráfica muestran permanentemente que todos los boletines están "PENDIENTES", contradiciendo el resultado de `patcher scan`.
- **Severidad:** **ALTA**
- **Solución Recomendada:** Implementar inspectores de paquetes para distribuciones Linux (`dpkg -l`, `rpm -qa`, `pacman -Q`) y comparar contra los identificadores de parches oficiales (USN, RHSA, ALSA).

### Problema 4: Falta de Persistencia tras Reinicio del Sistema
- **Ubicación:** `crates/samulibre-patcher/src/lib.rs#L1536`
- **Causa Probable:** Solo se escribe en el sistema de archivos virtual `/proc/sys/`.
- **Impacto:** Cuando el equipo se apaga o reinicia, el kernel restablece los parámetros sysctl a los valores por defecto de la distribución. La protección desaparece sin alertar al usuario.
- **Severidad:** **ALTA**
- **Solución Recomendada:** Escribir archivos de configuración persistentes en `/etc/sysctl.d/99-samulibre-vpatch.conf` y persistir reglas de firewall en `nftables` / `iptables-persistent`.

---

## C. LO QUE ESTÁ FEO (Deuda Técnica y Problemas Estructurales)

### 1. Invasión Conceptual de Windows en un Antivirus para Linux
- **Evidencia:** `data/kbs/catalog.json` contiene 6 boletines de Windows 11 (`KB5041585`, `KB5040442`, etc.), y el código fuente incluye referencias activas a `powershell`, `Get-HotFix`, `WUA`, `reg`, `sc` y controladores `.sys`.
- **Impacto:** Genera confusión, multiplica la superficie de errores y da la impresión de que el software es un port incompleto de Windows en lugar de una herramienta nativa para Linux.

### 2. Catálogo Rígido sin Feeds Dinámicos
- **Evidencia:** El catálogo Linux está hardcodeado en `load_linux_cve_catalog()` con solo 5 vulnerabilidades, la más reciente de principios de 2022.
- **Impacto:** SamuLibre no puede proteger a un servidor o estación de trabajo frente a amenazas de 2024, 2025 o 2026 sin recompilar el código fuente.

### 3. Falsa Asociación de Mitigaciones y CVEs
- **Evidencia:** En `load_linux_cve_catalog`:
  - `CVE-2016-5195` (Dirty COW) se asocia a `kernel.yama.ptrace_scope`. Dirty COW fue una vulnerabilidad en el manejo de Copy-On-Write del kernel, que no requería `ptrace` para ser explotada.
  - `CVE-2020-0001` (Android Media Framework en la base oficial NVD) se asocia a KASLR y `kptr_restrict`.
- **Impacto:** Daña la credibilidad técnica de la suite ante auditorías de ciberseguridad o certificaciones externas.

### 4. Desacoplamiento entre el Estado Gráfico y el Kernel
- **Evidencia:** En `data/ui/index.html`, los interruptores cambian de estado inmediatamente tras el clic del usuario, antes de que el backend confirme si el cambio se aplicó con éxito a nivel del kernel.
- **Impacto:** Si la llamada IPC falla o se rechaza, la GUI muestra el interruptor como encendido (verde).
