# PROCESO OFICIAL DE LANZAMIENTO Y CICLO DE VIDA DE VERSIONES
## SamuLibre Linux EDR & Antivirus Platform
**Documento:** `docs/RELEASE_PROCESS.md`  
**Fecha:** Noviembre 2026  
**Versión:** 2.0 (Fase J: Preparación de Releases Públicas)  
**Clasificación:** Procedimiento Técnico de DevSecOps y Cadena de Suministro (SLSA Level 3)  
**Responsable:** Release Manager y Comité de Dirección Técnica (TSC)

---

## 1. ESQUEMA DE VERSIONADO (SEMANTIC VERSIONING 2.0.0)

El proyecto SamuLibre Linux se rige estrictamente por **SemVer 2.0.0** con la nomenclatura `vMAJOR.MINOR.PATCH`:
- **MAJOR (ej. v2.0.0):** Cambios arquitectónicos sustanciales o modificaciones con incompatibilidad hacia atrás en la API IPC o ABI FFI.
- **MINOR (ej. v2.1.0):** Incorporación de nuevos motores de detección, compatibilidad con nuevas arquitecturas o nuevas capacidades EDR manteniendo retrocompatibilidad.
- **PATCH (ej. v2.0.33):** Corrección de errores, parches de seguridad, optimizaciones de rendimiento y actualización de reglas de firmas.

---

## 2. LISTA DE VERIFICACIÓN PRE-LANZAMIENTO (RELEASE GATEKEEPING)

Ninguna versión puede ser etiquetada o publicada sin cumplir el 100% de los siguientes criterios:

```
+-------------------------------------------------------------------------------+
|                    CRITERIOS DE APROBACIÓN DE RELEASE (GATE)                  |
+-------------------------------------------------------------------------------+
| [ ] 1. Compilación limpia del Workspace Rust en Release: cargo build --release|
| [ ] 2. Compilación del motor GPU C++20 sin warnings: make -C gpu-engine      |
| [ ] 3. 100% de pruebas unitarias e integración aprobadas (cargo test)         |
| [ ] 4. Fuzzing de parsers (fuzz_parsers_stress.rs) sin fallos en 3,000+ mut.  |
| [ ] 5. Cero fugas y cero carreras de datos certificadas con ASan/UBSan y TSan |
| [ ] 6. Bloques unsafe auditados y justificados documentalmente                |
| [ ] 7. Lockfiles congelados y verificados (cargo check --locked)              |
| [ ] 8. Generación del inventario de dependencias SBOM (CycloneDX / SPDX)      |
| [ ] 9. Generación de firmas criptográficas y archivo SHA256SUMS               |
+-------------------------------------------------------------------------------+
```

---

## 3. PIPELINE DE EMPAQUETADO MULTI-DISTRIBUCIÓN

SamuLibre Linux provee scripts de construcción automatizados en `scripts/packaging/`:

### 3.1. Paquete Debian / Ubuntu (`.deb`)
- **Soporte:** Ubuntu 22.04 LTS, 24.04 LTS, Debian 12 (Bookworm).
- **Ejecución:**
  ```bash
  ./scripts/packaging/build_deb.sh
  ```
- **Artefacto:** `target/debian/samulibre_${VERSION}_amd64.deb`.
- **Contenido:** Binarios (`samulibred`, `samulibre-gui`, `samulibre-cli`), unidades de systemd de sistema y de usuario, iconos Freedesktop multirresolución y accesos `.desktop`.

### 3.2. Paquete Red Hat / Fedora (`.rpm`)
- **Soporte:** Fedora 39/40/41, RHEL 9+, Rocky Linux, AlmaLinux.
- **Ejecución:**
  ```bash
  ./scripts/packaging/build_rpm.sh
  ```
- **Artefacto:** `target/rpm/x86_64/samulibre-${VERSION}-1.x86_64.rpm`.

### 3.3. Paquete Arch Linux / Garuda (`PKGBUILD`)
- **Soporte:** Arch Linux, Garuda Linux, Manjaro.
- **Ejecución:**
  ```bash
  cd scripts/packaging
  makepkg -si
  ```

---

## 4. INTEGRIDAD CRIPTOGRÁFICA Y SEGURIDAD DE LA CADENA DE SUMINISTRO (SLSA L3)

Para garantizar que los binarios descargados por usuarios y administradores no han sido adulterados:

### 4.1. Generación de Hashes SHA-256
Para cada release pública se genera el archivo canónico `SHA256SUMS`:
```bash
sha256sum target/debian/*.deb target/rpm/x86_64/*.rpm target/release/samulibre-* > SHA256SUMS
```

### 4.2. Firma Digital Asimétrica (GPG / Minisign)
El archivo `SHA256SUMS` debe ser firmado por la clave oficial del Technical Steering Committee:
```bash
gpg --armor --detach-sign SHA256SUMS
# Produce el archivo SHA256SUMS.asc verificable con:
gpg --verify SHA256SUMS.asc SHA256SUMS
```

### 4.3. Inventario SBOM (Software Bill of Materials)
Se genera el inventario reproducible de componentes:
```bash
cargo cyclonedx --format json --output-pattern "samulibre-${VERSION}.sbom.json"
```

---

## 5. PROCEDIMIENTO DE PUBLICACIÓN EN GITHUB

1. Crear el tag firmado en Git:
   ```bash
   git tag -s v2.0.32 -m "Release v2.0.32: Next-Gen Linux EDR & Antivirus"
   git push origin v2.0.32
   ```
2. El flujo de GitHub Actions (`.github/workflows/release.yml`) compilará los artefactos en runners limpios y publicará automáticamente el borrador de la versión (*Release Draft*).
3. Adjuntar `SHA256SUMS`, `SHA256SUMS.asc` y el archivo `SBOM`.
4. Publicar la versión con las notas detalladas de cambios (*Changelog*).
