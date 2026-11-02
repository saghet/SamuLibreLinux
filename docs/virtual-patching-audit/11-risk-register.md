# 11 — Registro de Riesgos Técnicos y Operativos (Risk Register)

**Documento:** `docs/virtual-patching-audit/11-risk-register.md`  
**Objetivo:** Identificación, ponderación y estrategias de tratamiento para los riesgos inherentes y residuales del módulo de parchado virtual.

---

## 1. Escala de Evaluación de Riesgos

- **Probabilidad (P):** 1 (Muy Rara) a 5 (Certeza / Ocurrencia Continua).
- **Impacto (I):** 1 (Insignificante) a 5 (Catastrófico / Compromiso Total).
- **Severidad Inherente (S = P × I):**
  - **1 a 5:** Riesgo Bajo (Verde)
  - **6 a 11:** Riesgo Medio (Amarillo)
  - **12 a 19:** Riesgo Alto (Naranja)
  - **20 a 25:** Riesgo Crítico (Rojo)

---

## 2. Matriz de Riesgos Identificados

| ID | Riesgo Técnico | Categoría | P | I | S | Estrategia de Mitigación Propuesta | P_res | I_res | S_res | Especialista Responsable |
|---|---|:---:|:---:|:---:|:---:|---|:---:|:---:|:---:|---|
| **R-01** | **Falsa sensación de seguridad por descarte silencioso de errores:** Usuarios asumen que están protegidos cuando la escritura sysctl o iptables falló por falta de root. | Seguridad | 5 | 5 | **25** | Eliminar `let _ =`, verificar códigos de retorno en kernel y propagar fallos con cambio de estado visible en la UI (`Failed`). | 1 | 2 | **2** | Arquitecto de Ciberseguridad |
| **R-02** | **Mitigación simulada en PwnKit (`BehavioralBlock` inoperante):** Vulnerabilidades LPE se marcan como mitigadas mediante un log vacío. | Seguridad | 5 | 5 | **25** | Implementar sonda eBPF en `sys_enter_execve` para interceptar variables de explotación reales o marcar la regla como no soportada. | 1 | 2 | **2** | Ingeniero Kernel / eBPF |
| **R-03** | **Pérdida de protección tras reinicio:** Cambios volátiles en `/proc/sys` se borran al reiniciar el sistema operativo. | Estabilidad | 5 | 4 | **20** | Escribir archivos de configuración persistentes en `/etc/sysctl.d/99-samulibre-vpatch.conf` y restaurar con systemd. | 1 | 2 | **2** | Especialista Linux Kernel |
| **R-04** | **Bloqueo accidental de aplicaciones legítimas (Falso Positivo de Red):** Regla nftables errónea bloquea tráfico legítimo de usuario (ej. HTTP/SSH). | Operacional | 3 | 4 | **12** | Validar reglas en staging, implementar timeout de prueba (Deadman's switch) y mecanismo de rollback en un clic. | 1 | 2 | **2** | Especialista Red / Netfilter |
| **R-05** | **Alucinación de reglas por IA (bloquear `powershell.exe` en Linux):** El sintetizador local genera mitigaciones para componentes de Windows en Linux. | Lógica / IA | 4 | 3 | **12** | Guardrails estrictos en Rust que rechazan binarios `.exe` o rutas de Windows en el pipeline de Linux. | 1 | 1 | **1** | Especialista Detección / IA |
| **R-06** | **Inyección de reglas maliciosas en `data/cve_rules/`:** Atacante local deposita JSONs para provocar DoS en la red o relajar parámetros. | Seguridad | 3 | 4 | **12** | Firma digital obligatoria Ed25519 en todas las reglas y permisos `root:root 644` en el directorio de reglas. | 1 | 2 | **2** | Especialista DevSecOps |
| **R-07** | **Incompatibilidad de nombres de kernel en rolling releases (ej. 7.2 vs 5.17):** Parser semántico confunde versiones mayores/menores. | Estabilidad | 3 | 3 | **9** | Comparación numérica descompuesta `(major, minor, patch)` en lugar de comparaciones alfabéticas o flotantes. | 1 | 1 | **1** | Ingeniero Kernel Linux |
| **R-08** | **Sobrecarga de CPU en el Centinela Periódico:** Recorridos intensivos de paquetes saturan recursos del sistema. | Rendimiento | 2 | 3 | **6** | Ejecución en baja prioridad (`SCHED_IDLE`) y caché de inventario invalidado solo ante cambios en `/var/lib/dpkg/` o `/var/lib/pacman/`. | 1 | 1 | **1** | Ingeniero Rendimiento |
