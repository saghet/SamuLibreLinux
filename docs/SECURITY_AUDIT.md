# INFORME DE AUDITORÍA PROFUNDA DE SEGURIDAD, CONCURRENCIA Y RENDIMIENTO
## Subsistema de Aceleración GPU para Antivirus/EDR SamuLibre Linux
**Fecha de Auditoría:** 2 de Noviembre de 2026  
**Estándar Evaluado:** C++17 / C++20  
**Compilador Objetivo:** GCC 16.2.1 x86_64 Linux  
**Clasificación:** Confidencial / Auditoría de Seguridad de Grado Comercial  

---

## 1. RESUMEN EJECUTIVO

Se ha realizado una auditoría estática y dinámica exhaustiva del subsistema en C++ (`gpu-engine/`) y sus interfaces de enlace FFI C-ABI con el motor principal en Rust (`crates/samulibre-scanner`).
El subsistema presenta una arquitectura conceptual sólida basada en el modelo **Asymmetric Zero-Trust** (la CPU retiene la autoridad decisoria y la GPU actúa como coprocesador acelerador). 

No obstante, la auditoría ha identificado **vulnerabilidades de memoria, riesgos de denegación de servicio (DoS), condiciones de carrera (data races) en entornos multi-hilo e ineficiencias de transferencia PCIe** que deben subsanarse obligatoriamente antes de un despliegue comercial o en producción.

---

## 2. ARQUITECTURA ACTUAL Y COMPONENTES AUDITADOS

El subsistema se compone de los siguientes módulos principales en `gpu-engine/`:

1. **GPUDetector (`src/core/gpu_detector.cpp`):**
   Sondea dinámicamente controladores de NVIDIA (`libcuda.so.1`), OpenCL (`libOpenCL.so.1`) y Vulkan (`libvulkan.so.1`) vía `dlopen`.
2. **GPUComputeEngine (`src/core/compute_engine.cpp`):**
   Gestiona el ciclo de vida del backend activo (CUDA, OpenCL o CPU Fallback).
3. **CUDABackend & CPUFallbackBackend (`src/backends/`):**
   Implementaciones concretas de la interfaz `IComputeBackend`.
4. **SignatureScanner (`src/scanner/signature_scanner.cpp`):**
   Búsqueda multipatrón en GPU mediante kernel PTX JIT y cálculo de histograma para Entropía de Shannon.
5. **ELFFeatureExtractor (`src/ml/elf_feature_extractor.cpp`):**
   Parser estático de cabeceras ELF, tablas de secciones, segmentos de programa e indicadores de strings.
6. **MLClassifier (`src/ml/ml_classifier.cpp`):**
   Red neuronal multicapa (MLP) ejecutada en GPU/CPU con vector de 32 características y explicabilidad XAI.
7. **BatchScheduler (`src/core/batch_scheduler.cpp`):**
   Planificador de tareas con buffers de memoria fijada (*pinned memory*) y doble/triple buffering.
8. **ResourceMonitor (`src/core/resource_monitor.cpp`):**
   Monitoreo de telemetría de hardware (NVML / Sysfs) con throttling térmico y token de cancelación atómico.
9. **ResultDispatcher / C-ABI FFI (`src/core/result_dispatcher.cpp`):**
   Exportación de funciones C puras `extern "C"` hacia Rust (`samulibre_gpu_ffi.h`).

---

## 3. MATRIZ DE HALLAZGOS Y VULNERABILIDADES

| ID | Componente | Severidad | Tipo | Resumen del Hallazgo |
| :---: | :--- | :---: | :---: | :--- |
| **VULN-01** | `elf_feature_extractor.cpp` | **ALTO** | Out-of-Bounds Read | Lectura fuera de límites en tabla de cadenas `.shstrtab` sin byte nulo terminal. |
| **VULN-02** | `batch_scheduler.cpp` & `ml_classifier.cpp` | **ALTO** | DoS / Bad Alloc | Subdesbordamiento de entero (`tellg() == -1`) y ausencia de límite máximo en lectura de archivos. |
| **CONC-01** | `result_dispatcher.cpp` | **ALTO** | Data Race / Concurrencia | Falta de exclusión mutua en `GPUContextInternal` ante escaneos concurrentes multi-hilo desde Rust. |
| **CONC-02** | `signature_scanner.cpp` | **MEDIO** | Data Race | Lectura no sincronizada de `rules_.size()` en `rule_count()` sin adquirir `rules_mutex_`. |
| **PERF-01** | `batch_scheduler.cpp` | **MEDIO** | PCIe Bottleneck | Doble copia redundante DMA PCIe en `execute_task_on_slot` hacia GPU. |
| **PERF-02** | `signature_scanner.cpp` & `ml_classifier.cpp` | **MEDIO** | VRAM Overhead | Asignación y liberación continua de memoria VRAM por cada archivo en lugar de pooling reutilizable. |
| **ARCH-01** | `gpu-engine` | **MEDIO** | Memory Leak Risk | Ausencia de encapsulamiento RAII para asignaciones de memoria en dispositivo (`ScopedDeviceBuffer`). |
| **ARCH-02** | `Makefile` & `CMakeLists.txt` | **BAJO** | Hardening & C++20 | Estándar C++17 obsoleto, sin `std::span` y falta de flags de mitigación del compilador (ASan, Fortify, StackProtector). |
| **INFO-01** | `batch_scheduler.cpp` | **INFORMATIVO** | Heurística | Umbral de micro-archivos (< 32 KB) debe derivarse a CPU para evitar sobrecoste PCIe. |

---

## 4. DESCRIPCIÓN DETALLADA DE HALLAZGOS

### [VULN-01] Lectura Fuera de Límites en Tabla de Cadenas ELF (`shstrtab`)
- **Severidad:** **ALTO** (CWE-125: Out-of-bounds Read)
- **Archivo:** `gpu-engine/src/ml/elf_feature_extractor.cpp` (Líneas 152–153)
- **Código Vulnerable:**
  ```cpp
  if (shstrtab && shdr->sh_name < shstrtab_size) {
      std::string sname = shstrtab + shdr->sh_name;
  ```
- **Evidencia Técnica:**
  Si un binario ELF malformado contiene un encabezado de sección cuyo `sh_name` apunta dentro de `shstrtab_size`, pero los bytes subsiguientes carecen de terminador nulo (`'\0'`) antes de que termine la sección, el constructor de `std::string` lee memoria no inicializada o páginas no mapeadas adyacentes hasta encontrar un byte `0x00`.
- **Impacto:** Fallo de segmentación (cuelgue del proceso antivirus) o fuga de datos en memoria.
- **Remediación:** Utilizar `std::string_view` y acotar la longitud mediante `strnlen(shstrtab + shdr->sh_name, shstrtab_size - shdr->sh_name)`.

---

### [VULN-02] DoS por Exceso de Memoria y Subdesbordamiento de `tellg()`
- **Severidad:** **ALTO** (CWE-400: Uncontrolled Resource Consumption, CWE-191: Integer Underflow)
- **Archivo:** `gpu-engine/src/core/batch_scheduler.cpp` (Líneas 102–105, 153–156) y `gpu-engine/src/ml/ml_classifier.cpp` (Líneas 410–414)
- **Código Vulnerable:**
  ```cpp
  std::streamsize fsize = file.tellg();
  ...
  file_disk_buffer.resize(fsize);
  ```
- **Evidencia Técnica:**
  Si la apertura o lectura falla (archivos de solo escritura, pipes FIFO, nodos de dispositivo `/dev/zero`), `tellg()` devuelve `-1`. Al convertirse a `size_t` sin comprobación estricta, produce un valor de $2^{64}-1$ bytes (18 Exabytes), disparando inmediatamente `std::bad_alloc`. Asimismo, no existe un límite superior de archivo (ej. 100 MB), permitiendo a un usuario local congelar el antivirus suministrando un archivo de 20 GB.
- **Impacto:** Denegación de servicio local (DoS) y caída del servicio de monitoreo en tiempo real.
- **Remediación:** Validar `fsize > 0 && fsize <= MAX_ALLOWED_FILE_SIZE` (ej. 128 MB), retornando error controlado si se excede el límite.

---

### [CONC-01] Condición de Carrera en Invocaciones Concurrentes FFI
- **Severidad:** **ALTO** (CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization)
- **Archivo:** `gpu-engine/src/core/result_dispatcher.cpp` (Líneas 108–141)
- **Código Vulnerable:**
  ```cpp
  TaskScanReport rep = internal->scheduler->process_single_task(task);
  ```
  Donde `process_single_task` siempre usa `slots_[0]`:
  ```cpp
  return execute_task_on_slot(task, slots_[0]);
  ```
- **Evidencia Técnica:**
  El handle de contexto `SamulibreGPUContext` es utilizado concurrentemente por múltiples hilos del runtime en Rust (`samulibre-scanner`). Cuando dos hilos escanean archivos a la vez, ambos mutan `slots_[0].pinned_host_buffer` y encolan comandos en el mismo `slots_[0].stream` sin un candado mutex.
- **Impacto:** Corrupción silenciosa de datos de escaneo, veredictos erróneos y errores irrecuperables en el driver CUDA (`CUDA_ERROR_INVALID_VALUE`).
- **Remediación:** Introducir un `std::mutex` en `GPUContextInternal` o implementar una cola de slots libres sincronizada.

---

### [CONC-02] Lectura No Sincronizada en `rule_count()`
- **Severidad:** **MEDIO** (CWE-662: Improper Synchronization)
- **Archivo:** `gpu-engine/src/scanner/signature_scanner.cpp` (Línea 254)
- **Código Vulnerable:**
  ```cpp
  size_t SignatureScanner::rule_count() const {
      return rules_.size();
  }
  ```
- **Evidencia Técnica:**
  `rules_` se modifica bajo `rules_mutex_` en `add_rule()` y `clear_rules()`, pero `rule_count()` no adquiere el cerrojo.
- **Impacto:** Detectable como Data Race por ThreadSanitizer (TSan); comportamiento indefinido según la especificación C++.
- **Remediación:** Proteger con `std::lock_guard<std::mutex>` o migrar a `std::shared_mutex`.

---

### [PERF-01] Transferencia DMA PCIe Doble y Redundante
- **Severidad:** **MEDIO** (Ineficiencia Arquitectónica)
- **Archivo:** `gpu-engine/src/core/batch_scheduler.cpp` (Líneas 180–190)
- **Evidencia Técnica:**
  `BatchScheduler::execute_task_on_slot` transfiere los datos a `slot.device_buffer`, pero a continuación llama a `scanner_.scan_buffer()`, el cual vuelve a reservar otro buffer en GPU y vuelve a copiar los datos desde la memoria host en el stream por defecto.
- **Impacto:** Desperdicio del 50% del ancho de banda PCIe en el bus del sistema y latencias duplicadas.
- **Remediación:** Permitir que `SignatureScanner::scan_buffer` reciba un búfer en dispositivo preexistente y el stream asignado.

---

### [PERF-02] Sobrecosto de Asignación y Liberación VRAM por Archivo
- **Severidad:** **MEDIO** (Fragmentación y Latencia de Driver)
- **Archivo:** `gpu-engine/src/scanner/signature_scanner.cpp` y `gpu-engine/src/ml/ml_classifier.cpp`
- **Evidencia Técnica:**
  En cada escaneo individual de archivo se realizan de 4 a 6 llamadas a `cuMemAlloc_v2` y `cuMemFree_v2`. En el benchmark de ML (300 muestras), esto provocó que la GPU fuera más lenta que la CPU (86 ms vs 22 ms).
- **Impacto:** Cuello de botella en micro-tareas por llamadas síncronas al driver NVIDIA.
- **Remediación:** Implementar un búfer persistente de trabajo (Memory Arena) por stream que se reutilice en cada archivo del lote.

---

### [ARCH-01] Ausencia de RAII en Memoria de Dispositivo GPU
- **Severidad:** **MEDIO** (Fugas de Recursos ante Excepciones)
- **Archivo:** `gpu-engine/include/compute_engine.hpp` y módulos consumidores
- **Evidencia Técnica:**
  Las asignaciones de GPU retornan punteros crudos `void*` que deben liberarse llamando manualmente a `engine_.free_device_buffer(ptr)`. Si se produce una excepción en C++, la VRAM queda ocupada hasta el reinicio del servicio.
- **Remediación:** Crear `ScopedDeviceBuffer` utilizando semántica RAII y movimientos seguros.

---

### [ARCH-02] Modernización a C++20 y Ausencia de Flags de Compilación de Seguridad
- **Severidad:** **BAJO** (Endurecimiento Defensivo)
- **Evidencia Técnica:**
  El compilador del sistema es GCC 16.2.1, pero el código utiliza C++17 y punteros planos con longitud separada en lugar de `std::span<const uint8_t>`. Además, el Makefile actual no incluye:
  - `-D_FORTIFY_SOURCE=3` (detección de desbordamientos en tiempo de ejecución)
  - `-fstack-protector-strong`
  - Perfiles de sanitizers (`ASan`, `UBSan`, `TSan`)
- **Remediación:** Actualizar Makefile a C++20 y crear los targets de depuración y análisis (`make debug-asan`, `make debug-tsan`).

---

## 5. PLAN DE CORRECCIÓN (ETAPA B)

Las remediaciones se aplicarán de forma controlada y modular siguiendo el siguiente orden de prioridad:

1. **Módulo 1: Seguridad y Parsing ELF (`VULN-01`)**
   - Corregir `safe_read` y acotar con `std::string_view` y `strnlen` la lectura de `.shstrtab`.
2. **Módulo 2: Validación de Entradas y Límites de Archivo (`VULN-02`)**
   - Añadir constantes de límites (`MAX_SCAN_FILE_SIZE = 128 MB`), validación estricta de `tellg()` y sanitización de offsets.
3. **Módulo 3: Concurrencia FFI y Thread Safety (`CONC-01`, `CONC-02`)**
   - Añadir `std::mutex` en `GPUContextInternal` y proteger `rule_count()`.
4. **Módulo 4: RAII y Gestión de Memoria GPU (`ARCH-01`, `PERF-02`)**
   - Implementar `ScopedDeviceBuffer` y workspace persistente para ML y escaneo de firmas.
5. **Módulo 5: Eliminación de Copias Redundantes y Heurística de Micro-Archivos (`PERF-01`, `INFO-01`)**
   - Optimizar el flujo de `execute_task_on_slot` y ajustar heurística < 32 KB hacia CPU.
6. **Módulo 6: Modernización C++20 y Hardening del Sistema de Construcción (`ARCH-02`)**
   - Actualizar Makefile y CMakeLists.txt con `-std=c++20`, `-D_FORTIFY_SOURCE=3`, `-fstack-protector-strong`, targets ASan/UBSan y TSan.
7. **Módulo 7: Validación y Pruebas de Regresión**
   - Ejecutar la suite completa bajo ASan/UBSan y certificar cero errores y cero advertencias.
