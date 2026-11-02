# 12 — Criterios de Aceptación y Certificación Interna

**Documento:** `docs/virtual-patching-audit/12-acceptance-criteria.md`  
**Objetivo:** Especificación formal de los criterios obligatorios que deben cumplirse para declarar aprobado y listo para producción el módulo de parchado virtual modernizado (V2).

---

## 1. Criterios de Aceptación Funcional

1. **CA-F01 (Detección Real de Paquetes en Linux):**
   - El sistema debe consultar el gestor de paquetes del sistema operativo (`dpkg`, `rpm` o `pacman`) y listar con precisión de versión qué software vulnerable está presente en el endpoint.
   - Si el paquete vulnerable no está instalado, la vulnerabilidad debe clasificarse como `NotApplicable (Inmune)`.
2. **CA-F02 (Verificación de Kernel Semántica Numérica):**
   - La evaluación de versiones de kernel debe descomponer numéricamente `(major, minor, patch)`. Un kernel `7.2` debe evaluarse inequívocamente como superior a `5.17`.
3. **CA-F03 (Manejo de Errores y Falsa Protección Cero):**
   - Ninguna mitigación puede reportarse como `VirtualPatchActive` si el comando subyacente (`nftables`, `sysctl`, `eBPF`) retornó un código de error o no pudo escribir por falta de permisos.
   - En caso de fallo por permisos, la interfaz y el CLI deben mostrar claramente `PatchStatus::Failed { reason: "Requiere privilegios de root/CAP_SYS_ADMIN" }`.
4. **CA-F04 (Persistencia tras Reinicio):**
   - Toda mitigación basada en sysctl debe escribir en `/etc/sysctl.d/99-samulibre-vpatch.conf` y persistir automáticamente tras reiniciar la máquina sin intervención manual.
5. **CA-F05 (Reversibilidad Garantizada en un Clic):**
   - Al pulsar "Desactivar" en la interfaz o ejecutar `samulibre patcher toggle <CVE> --disable`, el sistema debe restaurar el parámetro original de red o sysctl sin dejar reglas huérfanas en el firewall.

---

## 2. Criterios de Aceptación de Seguridad

1. **CA-S01 (Fin de Mitigaciones Simuladas):**
   - Queda estrictamente prohibido el uso de estrategias como `BehavioralBlock` que solo emiten logs `info!()`. Toda regla debe respaldarse por un mecanismo ejecutable comprobado en el kernel o en la red.
2. **CA-S02 (Firma y Validación de Feeds):**
   - Toda regla descargada dinámicamente de feeds de inteligencia debe verificar su integridad criptográfica mediante firma digital Ed25519 antes de ser incorporada al catálogo del antivirus.
3. **CA-S03 (Principio de Privilegio Mínimo):**
   - La interfaz gráfica (`samulibre-gui`) debe ejecutarse exclusivamente como usuario estándar sin privilegios (`UID > 1000`). Todas las operaciones sobre el kernel deben delegarse al socket UNIX del demonio del sistema `samulibred`.
4. **CA-S04 (Guardrails de Seguridad en IA):**
   - La IA local jamás debe proponer componentes de Windows (`powershell.exe`, `reg add`, `sc config`, `tcpip.sys`) cuando la plataforma en ejecución sea Linux.

---

## 3. Criterios de Rendimiento y Experiencia de Usuario

1. **CA-P01 (Latencia Ultrabaja):**
   - La evaluación de reglas cacheadas en memoria debe resolverse en **menos de 0.05 milisegundos**.
2. **CA-P02 (Consumo en Segundo Plano):**
   - El Centinela periódico no debe consumir más de **0.2% de CPU** en reposo ni más de **25 MB de memoria RAM** en el proceso del demonio.
3. **CA-U01 (Interfaz Honesta y Fidedigna):**
   - La interfaz visual nunca debe marcar como mitigada una vulnerabilidad que no esté verificada a nivel de sistema.
   - Se debe eliminar cualquier texto referente a "KBs de Microsoft" o "Windows Update" en la versión de Linux.
4. **CA-U02 (Centro de Evidencias Criptográficas):**
   - El administrador debe poder visualizar en un clic la evidencia técnica (comando exacto ejecutado, hash del estado del sistema y timestamp) de cada mitigación activa.

---

## 4. Declaración de Cumplimiento

La aprobación final de la modernización requerirá la firma técnica de los especialistas en Kernel Linux, Red, eBPF, UX y QA tras la superación del 100% de estos criterios en las distribuciones Ubuntu 24.04, RHEL 9 y Garuda Linux.
