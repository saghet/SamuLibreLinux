# GUÍA DE EVALUACIÓN Y AUDITORÍA INDEPENDIENTE DE TERCEROS
## Antivirus & Endpoint Detection and Response (EDR) SamuLibre Linux
**Documento:** `docs/INDEPENDENT_TESTING.md`  
**Fecha:** Noviembre 2026  
**Versión:** 2.0 (Fase H: Preparación para Auditorías Independientes)  
**Clasificación:** Protocolo Público de Evaluación, Reproducibilidad y Certificación Externa  
**Comité Asesor:** Auditores de Software Libre, Arquitectos QA de Software Crítico y Especialistas en Benchmarks AV

---

## 1. DECLARACIÓN DE TRANSPARENCIA Y POLÍTICA DE CERTIFICACIÓN

> [!IMPORTANT]
> **Aviso de Integridad y Cumplimiento Normativo:**  
> SamuLibre Linux es un proyecto de código abierto auditable. En cumplimiento con los estándares éticos internacionales y las directivas de AMTSO (*Anti-Malware Testing Standards Organization*), **el proyecto nunca afirmará ni sugerirá estar certificado, aprobado o avalado por un laboratorio independiente (como AV-TEST, AV-Comparatives o Virus Bulletin) a menos que exista un informe formal, público y verificable emitido por dicha entidad.**

Esta guía proporciona a investigadores de seguridad independientes, laboratorios de certificación y auditores de código abierto el protocolo completo para:
1. Clonar, verificar la integridad criptográfica y compilar el software de forma determinista (*Reproducible Builds*).
2. Ejecutar suites de pruebas automatizadas y arneses de fuzzing.
3. Evaluar la eficacia de detección frente a muestras de malware reales en entornos aislados.
4. Evaluar la tasa de falsos positivos frente a corpus benignos masivos de Linux.
5. Medir el consumo de recursos (CPU, RAM, VRAM, latencia VFS e impacto en I/O).

---

## 2. PROTOCOLO DE REPRODUCIBILIDAD Y COMPILACIÓN DETERMINISTA

### 2.1. Requisitos del Sistema para Auditores
- **Sistema Operativo:** Distribución Linux moderna de 64 bits (Ubuntu 22.04/24.04 LTS, Arch Linux, Debian 12 o Fedora 40/41).
- **Toolchain de Compilación:**
  - Rust 1.85+ (Edición 2021) con `cargo`.
  - Compilador C++20: GCC 13+ o Clang 16+.
  - CUDA Toolkit 12.0+ (Opcional: para habilitar backend GPU; en su defecto se activa automáticamente el backend CPU AVX2).
- **Dependencias de Sistema:**
  ```bash
  # En distribuciones Debian / Ubuntu:
  sudo apt-get update && sudo apt-get install -y \
      build-essential pkg-config libssl-dev libwebkit2gtk-4.1-dev \
      libgtk-3-dev libayatana-appindicator3-dev iptables
  ```

### 2.2. Verificación de Integridad y Compilación
```bash
# 1. Clonar el repositorio oficial
git clone https://github.com/saghet/SamuLibreLinux.git
cd SamuLibreLinux

# 2. Verificar el lockfile inmutable de dependencias
cargo check --workspace --locked

# 3. Compilación del binario release optimizado
cargo build --release --workspace

# 4. Compilación del motor de aceleración GPU en C++20
cd gpu-engine
make -j$(nproc)
cd ..
```

---

## 3. PROTOCOLO DE PRUEBAS DE EFICACIA Y DETECCIÓN

Las evaluaciones deben llevarse a cabo exclusivamente en máquinas virtuales o entornos de laboratorio físicamente desacoplados de cualquier red corporativa (*Air-Gapped Testbeds*).

### 3.1. Pruebas de Detección de Malware Conocido (Known Threats)
- **Corpus de Prueba Recomendado:**
  - Archivos estándar de prueba **EICAR** (texto plano, archivo comprimido en ZIP, doble compresión).
  - Muestras históricas de malware Linux indexadas en **MalwareBazaar / Abuse.ch** (Mirai, Tsunami, Gafgyt, Kinsing, XorDDos).
- **Comando de Verificación:**
  ```bash
  ./target/release/samulibre-cli scan /ruta/al/corpus/malware/ --format json > detection_report.json
  ```
- **Criterio de Aceptación:** Detección de firmas SHA-256 e indicadores de cadenas sospechosas con un veredicto de `Infected` o `Suspicious` en $\ge 98\%$ del corpus de referencia.

### 3.2. Pruebas Heurísticas y Evasión de Empaquetadores
- **Vectores a Evaluar:**
  - Binarios ELF legítimos empaquetados con **UPX** (`upx -9 sample.elf`).
  - Muestras con técnicas de evasión por relleno de entropía (*Entropy Padding*).
  - Scripts ofuscados con invocaciones en tubería directa (`curl ... | bash`).
  - Ejecutables con segmentos simultáneos de escritura y ejecución (`W+X`).
- **Criterio de Aceptación:** El analizador estructural ELF (`elf_analyzer`) y el evaluador de entropía (`polymorphic`) deben identificar la anomalía y elevar el puntaje de amenaza sin requerir una firma hash preexistente.

---

## 4. PROTOCOLO DE EVALUACIÓN DE FALSOS POSITIVOS (FALSE POSITIVES)

Para certificar que el antivirus no interfiere con las operaciones de un entorno de desarrollo o producción Linux:

### 4.1. Corpus de Validación Benigna
El auditor debe escanear árboles completos de software legítimo:
1. Directorios de sistema limpios: `/usr/bin`, `/usr/lib`, `/lib64` en una instalación base de Ubuntu o Arch Linux.
2. Repositorios de desarrollo con miles de archivos fuente: kernels de Linux compilados, dependencias de Node.js (`node_modules`), artefactos de Rust (`target/debug`).
3. Herramientas de administración de sistemas y virtualización (Docker, Podman, QEMU, Ansible).

### 4.2. Umbral de Aceptación de Falsos Positivos
- **Tasa Máxima Admisible de Falsos Positivos:** $< 0.01\%$ sobre una muestra mínima de **100,000 archivos limpios**.
- Ningún binario fundamental del sistema (`/bin/bash`, `/usr/bin/systemctl`, `/usr/bin/ssh`) debe ser catalogado como malicioso ni derivado a cuarentena.

---

## 5. PROTOCOLO DE MEDICIÓN DE RENDIMIENTO E IMPACTO EN EL SISTEMA

### 5.1. Impacto en Tiempo Real (fanotify VFS Latency)
- **Metodología:** Medir el tiempo de compilación de un proyecto mediano en C/Rust con el demonio activo vs el demonio inactivo.
- **Herramienta:** `hyperfine 'cargo build'` o `time make -j$(nproc)`.
- **Criterio:** La degradación del tiempo total de compilación (*I/O overhead*) debida a la intercepción de `fanotify` no debe exceder el **5.0%**.

### 5.2. Throughput de Escaneo en Silicio Real
- Ejecutar el benchmark oficial de streaming:
  ```bash
  cd gpu-engine
  make benchmark
  ```
- Contrastar métricas obtenidas con la especificación de referencia documentada en [`docs/PERFORMANCE_BENCHMARKS.md`](file:///home/saghet/Documents/SamulibreLinux/docs/PERFORMANCE_BENCHMARKS.md).

---

## 6. MAPA DE AUDITORÍAS INDEPENDIENTES Y ORGANIZACIONES DE LA INDUSTRIA

| Organización / Laboratorio | Alcance de Evaluación | Cobertura Linux | Requisitos y Estado en SamuLibre |
| :--- | :--- | :---: | :--- |
| **AMTSO** *(Anti-Malware Testing Standards Org)* | Directrices metodológicas de pruebas imparciales y reproducibles | Global | El diseño de pruebas de SamuLibre sigue los principios de transparencia de AMTSO. |
| **AV-TEST Institute** | Pruebas de protección corporativa y consumo de recursos | Servidores Linux (Ubuntu / RHEL) | En preparación técnica para postulaciones de prueba formal. |
| **AV-Comparatives** | Detección de malware en el mundo real (*Real-World Protection*) y rendimiento | Evaluaciones periódicas Linux | Mapeo de datasets y protocolo de exclusiones compatible. |
| **Virus Bulletin (VB100)** | Certificación de detección de malware in-the-wild con cero falsos positivos | Plataformas seleccionadas | Criterio de validación adoptado en el arnés de CI. |

---

## 7. CONTACTO PARA AUDITORES E INVESTIGADORES

Para coordinar revisiones de seguridad, acceder a entornos de prueba asistidos o reportar hallazgos de auditoría:
- **Canal de Auditoría Externa:** `security-audit@samulibre.org`
- **Política de Divulgación Coordinada:** [`SECURITY.md`](file:///home/saghet/Documents/SamulibreLinux/SECURITY.md)
