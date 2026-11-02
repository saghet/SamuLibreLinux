# ESTRATEGIA DE GOBERNANZA ABIERTA Y ADOPCIÓN INTERNACIONAL
## Antivirus & Endpoint Detection and Response (EDR) SamuLibre Linux
**Documento:** `docs/OPEN_SOURCE_GOVERNANCE.md`  
**Fecha:** Noviembre 2026  
**Versión:** 2.0 (Fase I: Documentación y Gobernanza Open Source)  
**Clasificación:** Estrategia Institucional de Software Libre (OSI-Compliant)  
**Comité Redactor:** Open Source Program Manager, Especialistas en Gobernanza Comunitaria y Abogados de Licenciamiento Tecnológico

---

## 1. POLÍTICA DE LICENCIAMIENTO DE SOFTWARE (OSI COMPLIANCE)

### 1.1. Evaluación y Compatibilidad de Licencias
El ecosistema de SamuLibre Linux adopta una política de licenciamiento compatible con la Open Source Initiative (OSI):
- **Código Principal (Rust Workspace):** Licenciado bajo **Apache License 2.0** / **MIT Dual License**, el estándar de facto de la comunidad Rust, garantizando protección de patentes defensivas, compatibilidad con software comercial y libertad de auditoría.
- **Módulos de Interacción con el Kernel (eBPF):** Licenciados bajo **GPL-2.0-only / Apache-2.0 Dual License**, satisfaciendo los requisitos de la macro `BPF_LICENSE("GPL")` del kernel de Linux para acceder a sondas y ganchos restringidos sin violar licencias del kernel.
- **Subsistema de Aceleración GPU (C++20):** Licenciado bajo **Apache License 2.0**, permitiendo enlace C-ABI con librerías del sistema (`libcuda.so`, `libOpenCL.so`, `libvulkan.so`) sin conflicto de copyleft.

### 1.2. Conformidad de la Cadena de Suministro (SBOM & Supply Chain)
- Todas las dependencias directas e indirectas de `Cargo.lock` son auditadas con `cargo-deny` y `cargo-audit` para impedir la inclusión de componentes con licencias no autorizadas (ej. AGPL restrictiva sin aviso o código sin licencia).
- Generación automatizada de **Software Bill of Materials (SBOM)** en estándares de la industria **SPDX 2.3** y **CycloneDX 1.5** para cada versión pública.

---

## 2. POLÍTICA ESTRICTA CONTRA LA MANIPULACIÓN DE MÉTRICAS (ZERO-ASTROTURFING MANDATE)

> [!IMPORTANT]
> **Código de Integridad Institucional:**  
> La credibilidad en ciberseguridad se forja exclusivamente a través de la eficacia demostrable, el código auditable y la revisión independiente. SamuLibre prohíbe de forma terminante y permanente:
> 1. La compra, intercambio o automatización de estrellas (*stars*), seguidores (*followers*) o bifurcaciones (*forks*) en GitHub.
> 2. El uso de cuentas fantasma (*sockpuppets*) para simular actividad o respaldos artificiales en issues o discusiones.
> 3. La manipulación de métricas de descarga o telemetría falsa.
> 
> Todo intento de alteración artificial de métricas será considerado una falta grave contra la reputación del proyecto y resultará en la expulsión inmediata del responsable del comité técnico.

---

## 3. GESTIÓN Y ORGANIZACIÓN DEL REPOSITORIO EN GITHUB

Para facilitar la colaboración fluida de desarrolladores de Rust, investigadores de malware y administradores de sistemas, el repositorio implementa una taxonomía estricta de etiquetas (*Labels*):

| Etiqueta (Label) | Color | Propósito y Audiencia |
| :--- | :---: | :--- |
| `good first issue` | `#7057ff` | Tareas accesibles para nuevos contribuidores (documentación, firmas simples, pruebas). |
| `help wanted` | `#008672` | Solicitudes de colaboración comunitaria en áreas que requieren apoyo especializado. |
| `security` | `#b60205` | Informes de endurecimiento defensivo o remediaciones de vulnerabilidades (prioridad alta). |
| `performance` | `#1d76db` | Optimizaciones de bajo nivel, latencia de E/S, consumo de memoria o CPU. |
| `gpu` | `#0e8a16` | Cuestiones relacionadas con kernels CUDA PTX, OpenCL, FFI o drivers de video. |
| `kernel / ebpf` | `#d93f0b` | Ganchos VFS con `fanotify`, programas eBPF o compatibilidad con versiones de kernel Linux. |
| `bug` | `#d73a4a` | Fallos confirmados en código productivo con caso reproducible. |
| `enhancement` | `#a2eeef` | Nuevas capacidades o solicitudes de funcionalidades alineadas al roadmap. |

---

## 4. PROGRAMA DE REVISIÓN COMUNITARIA Y ACADÉMICA

El proyecto establece convenios abiertos con la comunidad de investigación:
1. **Universidades e Investigadores Académicos:** Acceso a datasets anonimizados y arneses de pruebas para tesis y publicaciones sobre detección de malware en Linux y computación GPU.
2. **Investigadores de Malware Independientes:** Canal prioritario para proponer nuevas firmas YARA-X e indicadores de compromiso (IoCs) derivados de campañas activas *in-the-wild*.
3. **Auditores de Código Abierto:** Sesiones semestrales de revisión de código (*Open Bug Bounty / Security Review*) con acreditación formal en el Salón de la Fama del proyecto.
