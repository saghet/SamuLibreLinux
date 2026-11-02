# GUÍA DE CONTRIBUCIÓN COMUNITARIA (CONTRIBUTING.MD) 🛡️
## SamuLibre Linux EDR & Antivirus Project

¡Gracias por tu interés en contribuir a **SamuLibre Linux**, la suite de ciberseguridad abierta y de alto rendimiento para el ecosistema Linux!

---

## 1. CÓMO PUEDES COLABORAR

1. **Nuevas Reglas de Mitigación y Virtual Patching eBPF (`crates/samulibre-patcher`):**
   - Propón reglas para vulnerabilidades críticas recientemente publicadas (CISA KEV) o parches de mitigación a nivel de red y sysctl.
2. **Firmas y Heurística de Detección (`crates/samulibre-scanner`):**
   - Incorpora patrones YARA-X, indicadores de evasión o soporte para nuevos empaquetadores en `polymorphic.rs`.
3. **Optimización de Aceleración GPU (`gpu-engine/`):**
   - Optimiza kernels CUDA PTX, implementaciones OpenCL o vectorizaciones SIMD AVX2/AVX-512 en C++20.
4. **Empaquetado y Distribución Linux:**
   - Ayuda a mantener los paquetes nativos para Debian/Ubuntu (`.deb`), Fedora/RHEL (`.rpm`) y Arch Linux (`PKGBUILD`).
5. **Documentación, Pruebas y Traducciones:**
   - Mejora manuales de respuesta a incidentes, traduce la interfaz de usuario o agrega tests de estrés y fuzzing.

---

## 2. CONFIGURACIÓN DEL ENTORNO DE DESARROLLO

### 2.1. Requisitos Previos
- **Rust:** Versión estable 1.85+ (`rustup default stable`).
- **C++:** GCC 13+ o Clang 16+ con soporte C++20.
- **Herramientas:** `git`, `pkg-config`, `libssl-dev`.

### 2.2. Flujo de Compilación y Pruebas
```bash
# 1. Clonar el repositorio y crear una rama de trabajo
git clone https://github.com/saghet/SamuLibreLinux.git
cd SamuLibreLinux
git checkout -b feat/mi-mejora

# 2. Verificar que el workspace compile limpiamente
cargo check --workspace

# 3. Ejecutar la suite completa de pruebas
cargo test --workspace

# 4. Formatear el código según el estándar del proyecto
cargo fmt --all
```

---

## 3. ESTÁNDARES DE CALIDAD Y DIRECTIVAS DE SEGURIDAD

- **Principio Zero-Telemetry:** Bajo ninguna circunstancia se aceptarán PRs que agreguen telemetría silenciosa o transmitan datos del usuario a servidores externos sin consentimiento explícito.
- **Seguridad en Bloques `unsafe`:** Todo nuevo bloque `unsafe` debe estar justificado documentalmente con un comentario `// SAFETY:` demostrando por qué es estrictamente necesario (ej. llamadas al kernel POSIX o FFI C-ABI).
- **Manejo de Errores Idiomático:** Evita el uso indiscriminado de `.unwrap()` o `.expect()` en el código productivo; utiliza `anyhow::Result` o errores tipados con `thiserror`.

---

## 4. ACUERDO DE LICENCIA DE COLABORADOR (CLA) Y FIRMA DCO

Para mantener la viabilidad del modelo de licenciamiento dual de SamuLibre (versión comunitaria libre bajo **GPL-3.0-or-later** y licencias comerciales alternativas), **todas las contribuciones requieren la aceptación del [Contributor License Agreement (CLA)](CLA.md)**.

### ¿Qué implica el CLA para ti?
- **Tú conservas la propiedad y los derechos de autor (Copyright) sobre tu código.**
- Otorgas a SamuLibre una licencia no exclusiva para distribuir tus aportaciones bajo GPL-3.0 y bajo términos comerciales a empresas.
- Tu autoría y atribución quedarán registradas de manera permanente en el historial de Git.

### Cómo firmar tus commits (Developer Certificate of Origin)
Firma todos tus commits usando el modificador `-s` de Git:
```bash
git commit -s -m "feat(scanner): add heuristic detection for evasive loader"
```
Esto añadirá la línea de certificación:
```text
Signed-off-by: Tu Nombre Real <tu.email@dominio.com>
```

---

## 5. ENVÍO DE PULL REQUESTS (PRS)

1. Asegúrate de que todas las pruebas pasen con `cargo test --workspace`.
2. Redacta mensajes de commit claros siguiendo la convención de [Conventional Commits](https://www.conventionalcommits.org/):
   - `feat(...)`: nueva funcionalidad.
   - `fix(...)`: corrección de un bug o vulnerabilidad.
   - `docs(...)`: mejoras en la documentación.
   - `perf(...)`: optimizaciones de rendimiento.
   - `test(...)`: adición de pruebas automatizadas o fuzzing.
3. Abre el Pull Request en GitHub describiendo el problema que resuelve y las pruebas ejecutadas.
