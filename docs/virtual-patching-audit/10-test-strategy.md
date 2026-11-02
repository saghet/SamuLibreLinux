# 10 — Estrategia de Pruebas y Validación (Test Strategy)

**Documento:** `docs/virtual-patching-audit/10-test-strategy.md`  
**Objetivo:** Especificación de pruebas reproducibles, seguras y automatizadas para garantizar la efectividad técnica del parchado virtual.

---

## 1. Principios de Validación del Parchado Virtual

1. **Evidencia de Bloqueo vs. Alerta:** Ninguna prueba se considera superada porque el sistema emita un log o muestre una notificación. La prueba solo es exitosa si el exploit simulado es **efectivamente bloqueado** (código de error `-EPERM`, conexión rechazada o paquete descartado).
2. **Entorno Seguro:** Prohibido el uso de binarios maliciosos reales en el endpoint del usuario. Se utilizan simulaciones controladas de patrones de ataque (ej. llamadas a `execve` con variables de entorno sintéticas de prueba).
3. **Idempotencia y Reversibilidad Obligatoria:** Toda prueba que aplique una mitigación debe ejecutar su procedimiento de reversión y verificar que el sistema operativo regresó a su estado original sin residuos.

---

## 2. Tipos de Pruebas y Escenarios

### 2.1 Pruebas Unitarias de Reglas y Motores
- **`test_strict_error_handling_without_privileges`:**
  - Ejecuta la aplicación de una regla de red o sysctl forzando un entorno sin privilegios de root.
  - Verifica que la función retorne `Err` y que el estado de la regla sea `PatchStatus::Failed`.
- **`test_sysctl_persistence_and_revert`:**
  - Aplica una regla sysctl escribiendo en un archivo temporal representativo de `/etc/sysctl.d/`.
  - Verifica que el contenido coincida exactamente con `safe_value`.
  - Ejecuta `revert` y verifica que el archivo temporal se elimine o contenga `revert_value`.
- **`test_rule_conflict_detection`:**
  - Intenta activar simultáneamente dos reglas que modifican el mismo parámetro sysctl con valores contradictorios (ej. regla A pide `0` y regla B pide `1`).
  - Verifica que el motor lance un error de colisión antes de alterar el sistema.

---

### 2.2 Pruebas de Integración con el Sistema Operativo
- **Escenario 1: Validación de Conectividad de Red tras Regla Nftables:**
  - Se activa una regla de mitigación virtual para un puerto específico (ej. puerto de prueba TCP 44444).
  - Se verifica mediante un socket local que el puerto 44444 queda inaccesible.
  - Se verifica que la navegación web (puerto 443 a `1.1.1.1` o `google.com`) continúe funcionando al 100% sin latencia agregada.
  - Se desactiva la regla y se verifica que el puerto 44444 se desbloquee inmediatamente.
- **Escenario 2: Intercepción eBPF de Argumentos de Explotación:**
  - Se invoca un proceso inocuo de prueba pasando la variable de entorno sintética `TEST_EXPLOIT_PAYLOAD=1`.
  - El filtro eBPF intercepta la llamada `sys_enter_execve`, detecta el patrón y deniega la llamada con `-EPERM`.
  - Se verifica que un proceso legítimo sin esa variable pueda ejecutarse sin impedimentos.

---

### 2.3 Pruebas de Rendimiento y Latencia

| Métrica | Umbral Máximo Tolerable | Método de Medición |
|---|:---:|---|
| **Latencia de verificación en caché** | `< 0.05 ms` | Benchmark en Rust (`criterion`) sobre `scan_and_evaluate`. |
| **Tiempo de aplicación de regla nftables** | `< 15 ms` | Cronometraje de transacción atómica nftables. |
| **Tiempo de persistencia sysctl** | `< 5 ms` | Medición de I/O de archivo en `/etc/sysctl.d/`. |
| **Sobrecarga de CPU en reposo** | `< 0.2%` | Muestreo de `/proc/[pid]/stat` durante el ciclo del Centinela. |
| **Uso de Memoria RAM** | `< 25 MB` | RSS del proceso `samulibred` con 500 reglas cargadas. |

---

## 3. Matriz de Ejecución Automatizada (CI/CD)

```mermaid
graph LR
    Commit["Git Push / PR"] --> Check["cargo check --workspace"]
    Check --> Unit["cargo test -p samulibre-patcher"]
    Unit --> Integration["tests/vpatch_integration.rs (Mocked OS)"]
    Integration --> PackagingDeb["scripts/packaging/build_deb.sh"]
    PackagingDeb --> PackagingRpm["scripts/packaging/build_rpm.sh"]
    PackagingRpm --> PackagingArch["scripts/packaging/build_arch.sh"]
    PackagingArch --> Done["Aprobado para Release"]
```
