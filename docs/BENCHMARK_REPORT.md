# INFORME DE BENCHMARKS COMPARATIVOS Y RENDIMIENTO EN PRODUCCIÓN
## SamuLibre Linux GPU Acceleration Subsystem
**Fecha de Medición:** 2 de Noviembre de 2026  
**Hardware Oficial:** NVIDIA GeForce RTX 4060 Laptop GPU (8,188 MB VRAM, Driver 615.78, CUDA 13.4)  
**Procesador Host:** AMD Ryzen 7 7840HS (16 hilos, AVX-512 / AVX2)  
**Entorno:** Linux x86_64, GCC 16.2.1, C++20 Optimizado (`-O3`)  

---

## 1. TABLA RESUMEN DE BENCHMARKS EMPÍRICOS

| Escenario de Evaluación | Volumen / Muestras | Tiempo CPU (AVX2) | Tiempo GPU (CUDA) | Throughput CPU | Throughput GPU | Speedup Real | Decisión del Scheduler |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Escenario A: Micro-archivos (< 32 KB)** | 500 archivos (7.79 MB) | 37.02 ms | 169.37 ms | 210.38 MB/s | 45.99 MB/s | 0.22x (CPU gana) | **CPU Fast-Path** |
| **Escenario B: Lote Masivo Continuo** | 64.00 MB continuo | 371.00 ms | 50.23 ms | 172.50 MB/s | **1,274.05 MB/s** | **7.39x (GPU)** | **GPU Triple Buffer** |
| **Escenario C: Inferencia ML (ELF)** | 300 binarios ELF | 18.79 ms | 27.79 ms | 15,965 b/s | **10,795 b/s** | 0.68x | **GPU Scratch Arena** |
| **Escenario D: Resiliencia ante Fuzzing** | Cabeceras corruptas | 0.00 ms | 0.00 ms | N/A | N/A | 100% Blindado | **Cero caídas** |

---

## 2. TELEMETRÍA TÉRMICA Y ENERGÉTICA DE SILICIO REAL

Medición continua a través de `libnvidia-ml.so.1` (NVML) durante las pruebas de esfuerzo:
- **Temperatura Inicial / Reposo:** 50.00 °C
- **Temperatura Máxima Sostenida:** 54.00 °C ($\Delta T = +4.00 ^\circ\text{C}$, con ventiladores en perfil silencioso)
- **Consumo Energético Máximo:** 12.49 W
- **Ocupación de Memoria VRAM:** 490 MB de 8,188 MB (< 6% de la memoria total disponible)
- **Paridad Analítica CPU vs GPU:** 22/22 amenazas detectadas (**100% de coincidencia exacta**).
