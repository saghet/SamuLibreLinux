# MODELO DE GOBERNANZA DE CÓDIGO ABIERTO (GOVERNANCE.MD)
## Proyecto Open Source SamuLibre Linux
**Fecha de Publicación:** Noviembre 2026  
**Versión:** 2.0 (Fase I: Gobernanza y Comunidad Open Source)  
**Licencia:** Apache License 2.0 / MIT Dual License (OSI-Approved)

---

## 1. MISIÓN Y PRINCIPIOS DE GOBERNANZA

El proyecto **SamuLibre Linux** está dedicado a desarrollar la suite de ciberseguridad, antivirus y EDR de referencia internacional para entornos Linux, caracterizada por:
- **Transparencia Absoluta:** 100% de código auditable sin binarios cerrados ni telemetría forzada.
- **Seguridad Rigurosa:** Principio de menor privilegio, aislamiento en sandboxes y pruebas continuas.
- **Meritocracia Técnica:** Decisiones de arquitectura guiadas por evidencia técnica, métricas reproducibles y consenso de los mantenedores.
- **Ética Comunitaria:** Prohibición estricta de manipular métricas de GitHub (cero bots, cero compras de estrellas o seguidores).

---

## 2. ESTRUCTURA DEL COMITÉ DE GOBERNANZA

El proyecto opera bajo un modelo de **Comité de Dirección Técnica (Technical Steering Committee - TSC)** complementado por responsables de módulos (*Module Maintainers*):

```
+-------------------------------------------------------------------------------+
|               COMITÉ DE DIRECCIÓN TÉCNICA (TSC - 5 MIEMBROS)                  |
|  - Dirección de Arquitectura Rust          - Ingeniería de Kernel Linux      |
|  - Jefatura de Ciberseguridad (CISO)       - Aceleración GPU & C++20         |
|  - Gestión de Comunidad & DevSecOps                                           |
+-------------------------------------------------------------------------------+
                                        │
    ┌───────────────────┬───────────────┴───────────────┬───────────────────┐
    ▼                   ▼                               ▼                   ▼
[Maintainer Core]   [Maintainer Scanner]   [Maintainer Shield]    [Maintainer GPU]
- samulibre-core    - samulibre-scanner    - samulibre-shield     - gpu-engine C++20
- samulibre-daemon  - samulibre-ai         - samulibre-watcher    - CUDA / OpenCL
- IPC / Sockets     - Firmas / YARA        - eBPF / Cuarentena    - FFI C-ABI
```

### Roles y Responsabilidades
1. **Technical Steering Committee (TSC):**
   - Establece la visión estratégica, el roadmap técnico y la política de seguridad.
   - Resuelve empates o discrepancias en propuestas arquitectónicas significativas (RFCs).
   - Administra las credenciales criptográficas de firma de versiones (*Release Signing Keys*).
2. **Maintainers de Módulo:**
   - Tienen derechos de aprobación y merge sobre sus respectivos componentes.
   - Son responsables de revisar pull requests (PRs), evaluar la cobertura de tests y mantener la calidad del código.
3. **Colaboradores (Contributors):**
   - Cualquier miembro de la comunidad que proponga parches, mejoras en la documentación o reportes de incidencias.

---

## 3. PROCESO DE TOMA DE DECISIONES Y RFCs (REQUEST FOR COMMENTS)

Para cambios menores (corrección de errores, optimizaciones locales, adición de firmas):
- Requiere la revisión y aprobación de al menos **un Maintainer** de módulo.

Para cambios arquitectónicos mayores (adición de nuevos crates, modificación del protocolo IPC, cambios en la frontera FFI o nuevos hooks de kernel):
1. **Creación de RFC:** El autor redacta un documento en `docs/rfcs/` explicando motivación, alternativas y pruebas.
2. **Período de Discusión Pública:** Mínimo de **14 días** en GitHub Discussions / Pull Requests.
3. **Aprobación:** Requiere mayoría simple ($\ge 3/5$) de los miembros del TSC.

---

## 4. REVISIÓN DE CÓDIGO Y POLÍTICA DE MERGE (CODE REVIEW MANDATE)

- **Ningún commit directo a `main`:** Todas las modificaciones deben ingresar vía Pull Request.
- **Requisitos de Integración Continua (CI):**
  - Compilación sin errores en Ubuntu Linux y Arch Linux (`cargo check --workspace`).
  - Suite de pruebas automatizadas al 100% (`cargo test --workspace`).
  - Código formateado con `cargo fmt`.
  - Ausencia de advertencias críticas en `cargo clippy`.
- **Firma Criptográfica de Commits:** Se alienta a los colaboradores a firmar sus commits mediante GPG o SSH.
