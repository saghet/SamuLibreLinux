# DECLARACIÓN FORMAL DE DERECHOS DE AUTOR Y TITULARIDAD (COPYRIGHT.MD)
## SamuLibre Linux EDR & Antivirus Project
**Fecha de Actualización:** Noviembre 2026  
**Titular Principal:** SamuLibre Security Team (`copyright@samulibre.org`)  

---

## 1. TITULARIDAD DE LA OBRA COLECTIVA

El software **SamuLibre Linux**, incluyendo la arquitectura de su motor en Rust (los 12 crates del workspace), el subsistema de aceleración GPU en C++20 (`gpu-engine/`), los scripts de empaquetado multi-distribución y la documentación técnica, constituye una **Obra Colectiva Protegida por los Derechos de Autor Internacionales**, de conformidad con el Convenio de Berna para la Protección de las Obras Literarias y Artísticas y la legislación aplicable en materia de propiedad intelectual.

- **Copyright (C) 2024-2026 SamuLibre Security Team y Colaboradores Registrados.**
- Todos los derechos de explotación económica, gestión comunitaria y facultades de licenciamiento dual corresponden al **SamuLibre Security Team** y a los titulares que han suscrito el [Contributor License Agreement (CLA)](CLA.md).

---

## 2. AUDITORÍA DE CONTRIBUCIONES Y AUTORÍA

### 2.1. Código Original del Proyecto
- **100% de los Commits Históricos:** Registrados bajo la identidad del equipo fundador `SamuLibre Security Team <dev@samulibre.org>`.
- No existen cesiones de derechos pendientes ni reclamaciones de autoría de terceros sobre el código base del repositorio.

### 2.2. Consideraciones sobre Código Asistido por Inteligencia Artificial
En estricto apego a las directrices de la Oficina de Derechos de Autor de los Estados Unidos (USCO) y las normativas de la Unión Europea sobre propiedad intelectual:
- Reconocemos que fragmentos o sugerencias individuales generados por asistentes de IA carecen de autoría humana originaria per se.
- No obstante, la concepción del sistema, el diseño arquitectónico de 4 capas, la selección crítica de componentes, la estructuración modular, la corrección de errores de bajo nivel, la validación bajo sanitizers (ASan/UBSan/TSan) y la integración de seguridad son el **resultado directo de un esfuerzo intelectual humano substancial y deliberado**.
- En consecuencia, la obra ensamblada, coordinada y publicada goza de **plena protección legal como obra protegida**.

---

## 3. LÍMITES DE RELICENCIAMIENTO Y CÓDIGO DE TERCEROS

### 3.1. Qué Código PUEDE ser Licenciado Comercialmente por SamuLibre
- Todo el código contenido en `crates/` (los 12 crates originales de SamuLibre).
- Todo el código contenido en `gpu-engine/` (detectores de GPU, planificador de lotes, kernels PTX CUDA, clasificadores de ML estático y despachador FFI C-ABI).
- Toda la documentación, scripts de automatización e interfaces gráficas creadas por el equipo.

### 3.2. Qué Componentes NO son Propiedad de SamuLibre (Límites de Terceros)
- **Dependencias Permisivas de Rust:** Las 402 librerías de terceros especificadas en `THIRD_PARTY_LICENSES.md` retienen el copyright de sus respectivos autores (licenciadas bajo MIT, Apache 2.0, BSD, ISC, etc.). SamuLibre las incorpora cumpliendo sus requisitos de atribución y redistribución.
- **Componentes Copyleft Débiles (MPL-2.0):** Los crates `colored`, `cssparser`, `selectors`, `option-ext` y `dtoa-short` retienen el copyright de sus respectivos mantenedores. Sus archivos fuente originales permanecen bajo MPL-2.0. SamuLibre no comercializa dichos archivos como código cerrado propio, sino que los utiliza como dependencias externas sin alteración.
- **Bibliotecas Dinámicas del Sistema:** Los bindings a `libwebkit2gtk-4.1` y `libgtk-3` (LGPL-2.1+) son propiedad de The GNOME Project y sus respectivos contribuidores. Se enlazan dinámicamente según lo estipulado por la LGPL.
- **Interfaces de Controladores GPU:** Las definiciones de API de NVIDIA CUDA y Khronos OpenCL son propiedad de NVIDIA Corporation y The Khronos Group Inc., respectivamente.

---

## 4. PROCEDIMIENTO DE RECLAMACIONES DE DERECHOS DE AUTOR (DMCA / NOTICE AND TAKEDOWN)

Si eres titular de derechos de autor o su representante legal y consideras de buena fe que algún material contenido en el repositorio vulnera tus derechos:
1. Envía una notificación formal a: 📧 **`dmca@samulibre.org`**.
2. Especifica:
   - Identificación de la obra protegida supuestamente infringida.
   - Enlace o ruta exacta del archivo en el repositorio de SamuLibre.
   - Información de contacto del titular o representante acreditado.
   - Declaración de buena fe y firma electrónica.

El equipo responderá y tomará las medidas oportunas en un plazo máximo de **72 horas**.
